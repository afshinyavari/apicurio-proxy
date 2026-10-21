#!/usr/bin/env bash
# Smoke test of a built image over real TLS and mTLS: the parts unit tests cannot reach
# (TLS listener config, client-certificate authentication, principal mapping rules, policy
# reload). Without Kafka, so certificates get only what the policy file grants.
#
#   e2e/smoke-test.sh <image>
#
# Needs docker, openssl, python3 and curl, and free ports 18080 and 18443.
set -euo pipefail

IMAGE=${1:?usage: $0 <image>}
WORK=$(mktemp -d)
# shellcheck source=e2e/lib.sh
source "$(dirname "$0")/lib.sh"
trap 'cleanup_proxy; rm -rf "$WORK"' EXIT

new_ca
new_cert server "/CN=localhost" "subjectAltName=DNS:localhost"
new_cert payments-app "/O=Acme/CN=payments-app"
new_cert orders-service "/O=Acme/CN=orders-service"
new_cert stranger "/O=Other/CN=stranger"

mkdir "$WORK/policy"
cat > "$WORK/policy/policy.yaml" <<'EOF'
rules:
  - principals: ["CN=payments-app"]
    artifacts: [payments-value]
    actions: [READ, WRITE]
EOF

start_stub_registry
start_proxy "$IMAGE" -e 'PROXY_MTLS_PRINCIPAL_MAPPING_RULES=RULE:^CN=([^,]+),O=Acme$/CN=$1/' \
    -e PROXY_LOG_TLS_HANDSHAKE_LEVEL=TRACE
wait_until_ready

check "readiness is up"                           200 "$(status "$PROXY/q/health/ready")"
check "policy principal reads its artifact"       200 "$(as payments-app "$ARTIFACTS/payments-value")"
check "policy principal is denied other artifact" 403 "$(as payments-app "$ARTIFACTS/orders-value")"
check "certificate without any grant is denied"   403 "$(as orders-service "$ARTIFACTS/orders-value")"
check "certificate no mapping rule matches"       401 "$(as stranger "$ARTIFACTS/orders-value")"
check "request without certificate"               401 "$(status "$ARTIFACTS/payments-value")"
check "client not trusting the proxy's certificate" 000 \
    "$(curl -s -o /dev/null -w '%{http_code}' "$ARTIFACTS/payments-value" || true)"
check "plain HTTP port 8082 is closed"            000 \
    "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 http://localhost:8082/q/health/ready || true)"

# Requests answered 401 never reach the proxy resource, and failed handshakes never become requests
logged "unmatched certificate is logged with its subject" \
    'request="GET /apis/registry/v3/groups/default/artifacts/orders-value" certificate="CN=stranger,O=Other" token=no decision=unauthenticated status=401 reason="No principal mapping rule matches CN=stranger,O=Other"'
logged "request without certificate is logged" \
    'certificate=none token=no decision=unauthenticated status=401 reason="no client certificate and no bearer token"'
logged "failed TLS handshake is logged" 'SSLHandshakeException'

sed -i 's/\[payments-value\]/[payments-value, orders-value]/' "$WORK/policy/policy.yaml"
eventually "changed policy is applied without a restart" 200 15 payments-app "$ARTIFACTS/orders-value"

finish
