#!/usr/bin/env bash
# Integration test of a built image against a real Kafka broker: the proxy reads the broker's ACLs
# with its own client certificate (kafka-clients Admin over SSL with PEM files) and authorizes
# certificate callers from them. Broker and proxy map certificate subjects with the same
# ssl.principal.mapping.rules.
#
#   e2e/kafka-integration-test.sh <image>
#
# Needs docker, openssl, python3 and curl, and free ports 18080, 18443 and 19092-19094.
set -euo pipefail

IMAGE=${1:?usage: $0 <image>}
KAFKA_IMAGE=apache/kafka:4.3.1
KAFKA_CONTAINER=apicurio-rbac-proxy-kafka-$$
MAPPING_RULES='RULE:^CN=([^,]+),O=Acme$/CN=$1/,DEFAULT'
WORK=$(mktemp -d)
# shellcheck source=e2e/lib.sh
source "$(dirname "$0")/lib.sh"
trap 'cleanup_proxy; docker rm -f "$KAFKA_CONTAINER" >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT

# ── certificates ────────────────────────────────────────────────────────────
new_ca
new_cert server "/CN=localhost" "subjectAltName=DNS:localhost"
new_cert broker "/O=Acme/CN=broker" "subjectAltName=DNS:localhost"
new_cert proxy-kafka "/O=Acme/CN=apicurio-proxy-kafka"
new_cert orders-service "/O=Acme/CN=orders-service"
new_cert reader "/O=Acme/CN=reader"
# The image expects its stores and their passwords as files in /etc/kafka/secrets.
mkdir "$WORK/kafka-secrets"
openssl pkcs12 -export -in "$WORK/broker.crt" -inkey "$WORK/broker.key" -out "$WORK/kafka-secrets/broker.p12" \
    -name broker -passout pass:changeit
docker run --rm --user "$(id -u)" -v "$WORK:/e2e" --entrypoint keytool "$KAFKA_IMAGE" -importcert -noprompt \
    -alias ca -file /e2e/ca.crt -keystore /e2e/kafka-secrets/truststore.p12 -storetype PKCS12 \
    -storepass changeit >/dev/null 2>&1
echo changeit > "$WORK/kafka-secrets/password"

mkdir "$WORK/policy"
cat > "$WORK/policy/policy.yaml" <<'EOF'
rules:
  # A policy grant that a Kafka DENY must veto.
  - principals: ["CN=orders-service"]
    artifacts: [audit-value]
    actions: [READ, WRITE]
EOF
chmod -R a+rX "$WORK"

# ── Kafka: KRaft, mTLS listener with ACLs, plaintext listener on loopback for the admin tool ──
docker run -d --name "$KAFKA_CONTAINER" --network host -v "$WORK/kafka-secrets:/etc/kafka/secrets:ro" \
    -e CLUSTER_ID=MkU3OEVBNTcwNTJENDM2Qk \
    -e KAFKA_NODE_ID=1 \
    -e KAFKA_PROCESS_ROLES=broker,controller \
    -e KAFKA_LISTENERS=PLAINTEXT://localhost:19092,CONTROLLER://localhost:19093,SSL://localhost:19094 \
    -e KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://localhost:19092,SSL://localhost:19094 \
    -e KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=PLAINTEXT:PLAINTEXT,CONTROLLER:PLAINTEXT,SSL:SSL \
    -e KAFKA_CONTROLLER_LISTENER_NAMES=CONTROLLER \
    -e KAFKA_CONTROLLER_QUORUM_VOTERS=1@localhost:19093 \
    -e KAFKA_INTER_BROKER_LISTENER_NAME=PLAINTEXT \
    -e KAFKA_AUTHORIZER_CLASS_NAME=org.apache.kafka.metadata.authorizer.StandardAuthorizer \
    -e KAFKA_SUPER_USERS=User:ANONYMOUS \
    -e KAFKA_SSL_CLIENT_AUTH=required \
    -e KAFKA_SSL_KEYSTORE_TYPE=PKCS12 \
    -e KAFKA_SSL_KEYSTORE_FILENAME=broker.p12 \
    -e KAFKA_SSL_KEYSTORE_CREDENTIALS=password \
    -e KAFKA_SSL_KEY_CREDENTIALS=password \
    -e KAFKA_SSL_TRUSTSTORE_TYPE=PKCS12 \
    -e KAFKA_SSL_TRUSTSTORE_FILENAME=truststore.p12 \
    -e KAFKA_SSL_TRUSTSTORE_CREDENTIALS=password \
    -e "KAFKA_SSL_PRINCIPAL_MAPPING_RULES=$MAPPING_RULES" \
    -e KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR=1 \
    -e KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR=1 \
    -e KAFKA_TRANSACTION_STATE_LOG_MIN_ISR=1 \
    "$KAFKA_IMAGE" >/dev/null

acl() { docker exec "$KAFKA_CONTAINER" /opt/kafka/bin/kafka-acls.sh --bootstrap-server localhost:19092 "$@" >/dev/null; }

for _ in $(seq 1 60); do
    acl --list >/dev/null 2>&1 && break
    sleep 1
done
acl --list || { echo "FAIL  Kafka did not start"; docker logs "$KAFKA_CONTAINER" 2>&1 | tail -40; exit 1; }

acl --add --allow-principal User:CN=apicurio-proxy-kafka --operation Describe --cluster
acl --add --allow-principal User:CN=orders-service --operation Write --topic orders
acl --add --allow-principal User:CN=reader --operation Read --topic pay --resource-pattern-type prefixed
acl --add --allow-principal 'User:*' --operation All --topic shared
acl --add --deny-principal User:CN=orders-service --operation Write --topic shared
acl --add --deny-principal User:CN=orders-service --operation Write --topic audit

# ── the proxy, reading the ACLs with its own certificate ────────────────────
start_stub_registry
start_proxy "$IMAGE" \
    -e "PROXY_MTLS_PRINCIPAL_MAPPING_RULES=$MAPPING_RULES" \
    -e PROXY_KAFKA_BOOTSTRAP=localhost:19094 \
    -e PROXY_KAFKA_SSL_CERT=/e2e/proxy-kafka.crt \
    -e PROXY_KAFKA_SSL_KEY=/e2e/proxy-kafka.key \
    -e PROXY_KAFKA_SSL_CA=/e2e/ca.crt \
    -e PROXY_KAFKA_ACL_REFRESH_INTERVAL=2s
wait_until_ready

put() { as "$1" -X PUT -H 'Content-Type: application/json' -d '{}' "$2"; }
del() { as "$1" -X DELETE "$2"; }

check "readiness: ACL snapshot loaded from Kafka"    200 "$(status "$PROXY/q/health/ready")"
check "WRITE on topic: read its subject"             200 "$(as orders-service "$ARTIFACTS/orders-value")"
check "WRITE on topic: write its subject"            200 "$(put orders-service "$ARTIFACTS/orders-value")"
check "WRITE on topic: no delete"                    403 "$(del orders-service "$ARTIFACTS/orders-value")"
check "no ACL on another topic"                      403 "$(as orders-service "$ARTIFACTS/invoices-value")"
check "PREFIXED READ: read a matching subject"       200 "$(as reader "$ARTIFACTS/payments-value")"
check "PREFIXED READ: no write"                      403 "$(put reader "$ARTIFACTS/payments-value")"
check "User:* ALLOW applies to everyone"             200 "$(as reader "$ARTIFACTS/shared-key")"
check "DENY WRITE beats User:* ALLOW ALL"            403 "$(put orders-service "$ARTIFACTS/shared-value")"
check "DENY WRITE leaves READ"                       200 "$(as orders-service "$ARTIFACTS/shared-value")"
check "policy grant without ACL"                     200 "$(as orders-service "$ARTIFACTS/audit-value")"
check "Kafka DENY vetoes a policy grant"             403 "$(put orders-service "$ARTIFACTS/audit-value")"

# ── ACL changes reach the proxy on its next refresh ─────────────────────────
acl --add --allow-principal User:CN=orders-service --operation Read --topic invoices
eventually "added ACL is applied"   200 15 orders-service "$ARTIFACTS/invoices-value"
acl --remove --force --allow-principal User:CN=orders-service --operation Write --topic orders
eventually "removed ACL is applied" 403 15 orders-service -X PUT -H 'Content-Type: application/json' -d '{}' \
    "$ARTIFACTS/orders-value"

finish
