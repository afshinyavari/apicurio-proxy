#!/usr/bin/env bash
# Smoke test of a built image over real TLS and mTLS: the parts unit tests cannot reach
# (TLS listener config, client-certificate authentication, principal mapping rules, policy
# reload). Starts a stub registry on the host and the proxy container on the host network.
#
#   e2e/smoke-test.sh <image>
#
# Needs docker, openssl, python3 and curl, and free ports 18080 and 18443.
set -euo pipefail

IMAGE=${1:?usage: $0 <image>}
WORK=$(mktemp -d)
CONTAINER=apicurio-rbac-proxy-smoke-$$
STUB_PID=
FAILED=0

cleanup() {
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    [ -n "$STUB_PID" ] && kill "$STUB_PID" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

# ── certificates: a CA, the server, and three clients ───────────────────────
cd "$WORK"
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 1 -subj "/CN=smoke-ca" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=localhost" 2>/dev/null
printf "subjectAltName=DNS:localhost" > san.ext
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 1 \
    -extfile san.ext 2>/dev/null
for client in payments-app:Acme orders-service:Acme stranger:Other; do
    name=${client%%:*}; org=${client##*:}
    openssl req -newkey rsa:2048 -nodes -keyout "$name.key" -out "$name.csr" -subj "/O=$org/CN=$name" 2>/dev/null
    openssl x509 -req -in "$name.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -out "$name.crt" -days 1 2>/dev/null
done

mkdir policy
cat > policy/policy.yaml <<'EOF'
rules:
  - principals: ["CN=payments-app"]
    artifacts: [payments-value]
    actions: [READ, WRITE]
EOF
chmod -R a+rX "$WORK"

# ── stub registry: answers 200 to every GET ─────────────────────────────────
cat > stub.py <<'EOF'
import http.server
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"stub":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass
http.server.HTTPServer(("127.0.0.1", 18080), Handler).serve_forever()
EOF
python3 stub.py &
STUB_PID=$!

# ── the proxy: mTLS only, with a mapping rule like a broker's ──────────────
docker run -d --name "$CONTAINER" --network host \
    -v "$WORK:/smoke:ro" \
    -e QUARKUS_OIDC_TENANT_ENABLED=false \
    -e PROXY_APICURIO_URL=http://127.0.0.1:18080 \
    -e PROXY_POLICY_FILE=/smoke/policy/policy.yaml \
    -e PROXY_POLICY_RELOAD_INTERVAL=1s \
    -e 'PROXY_MTLS_PRINCIPAL_MAPPING_RULES=RULE:^CN=([^,]+),O=Acme$/CN=$1/' \
    -e PROXY_TLS_CERT=/smoke/server.crt \
    -e PROXY_TLS_KEY=/smoke/server.key \
    -e PROXY_TLS_CA=/smoke/ca.crt \
    -e QUARKUS_HTTP_SSL_PORT=18443 \
    -e QUARKUS_HTTP_INSECURE_REQUESTS=disabled \
    "$IMAGE" >/dev/null

BASE=https://localhost:18443
for _ in $(seq 1 60); do
    curl -sf --cacert ca.crt "$BASE/q/health/ready" >/dev/null 2>&1 && break
    sleep 1
done

status() { curl -s -o /dev/null -w "%{http_code}" --cacert ca.crt "$@" || true; }

expect() {
    local description=$1 expected=$2; shift 2
    local actual
    actual=$(status "$@")
    if [ "$actual" = "$expected" ]; then
        echo "ok    $description ($actual)"
    else
        echo "FAIL  $description: expected $expected, got $actual"
        FAILED=1
    fi
}

client() { echo "--cert $1.crt --key $1.key"; }
ARTIFACTS=$BASE/apis/registry/v3/groups/default/artifacts

# shellcheck disable=SC2046
{
expect "readiness is up"                           200 "$BASE/q/health/ready"
expect "policy principal reads its artifact"       200 $(client payments-app)   "$ARTIFACTS/payments-value"
expect "policy principal is denied other artifact" 403 $(client payments-app)   "$ARTIFACTS/orders-value"
expect "certificate without any grant is denied"   403 $(client orders-service) "$ARTIFACTS/orders-value"
expect "certificate no mapping rule matches"       401 $(client stranger)       "$ARTIFACTS/orders-value"
expect "request without certificate"               401                          "$ARTIFACTS/payments-value"
}
if curl -s -o /dev/null --max-time 2 http://localhost:8082/q/health/ready; then
    echo "FAIL  plain HTTP port 8082 is open"; FAILED=1
else
    echo "ok    plain HTTP port 8082 is closed"
fi

# ── policy reload without a restart ─────────────────────────────────────────
chmod u+w policy policy/policy.yaml
sed -i 's/\[payments-value\]/[payments-value, orders-value]/' policy/policy.yaml
reloaded=000
for _ in $(seq 1 15); do
    # shellcheck disable=SC2046
    reloaded=$(status $(client payments-app) "$ARTIFACTS/orders-value")
    [ "$reloaded" = 200 ] && break
    sleep 1
done
if [ "$reloaded" = 200 ]; then
    echo "ok    changed policy is applied without a restart"
else
    echo "FAIL  changed policy is applied without a restart: got $reloaded"; FAILED=1
fi

if [ "$FAILED" != 0 ]; then
    echo "--- proxy log ---"
    docker logs "$CONTAINER" 2>&1 | tail -50
    exit 1
fi
echo "smoke test passed"
