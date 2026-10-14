# shellcheck shell=bash
# Helpers shared by the e2e scripts, which source this file after setting WORK (a temp directory
# the files are written to). Certificates are made with openssl, the stub registry runs on
# python3, and the proxy container uses the host network.

PROXY_CONTAINER=apicurio-rbac-proxy-e2e-$$
PROXY=https://localhost:18443
ARTIFACTS=$PROXY/apis/registry/v3/groups/default/artifacts
STUB_PID=
FAILED=0

# new_ca: a CA in ca.crt / ca.key
new_ca() {
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/ca.key" -out "$WORK/ca.crt" -days 1 \
        -subj "/CN=e2e-ca" 2>/dev/null
}

# new_cert <name> <subject> [<extfile line>]: <name>.crt / <name>.key (PKCS#8) signed by the CA
new_cert() {
    local name=$1 subject=$2 ext=${3:-}
    openssl req -newkey rsa:2048 -nodes -keyout "$WORK/$name.key" -out "$WORK/$name.csr" \
        -subj "$subject" 2>/dev/null
    if [ -n "$ext" ]; then
        printf '%s' "$ext" > "$WORK/$name.ext"
        openssl x509 -req -in "$WORK/$name.csr" -CA "$WORK/ca.crt" -CAkey "$WORK/ca.key" -CAcreateserial \
            -out "$WORK/$name.crt" -days 1 -extfile "$WORK/$name.ext" 2>/dev/null
    else
        openssl x509 -req -in "$WORK/$name.csr" -CA "$WORK/ca.crt" -CAkey "$WORK/ca.key" -CAcreateserial \
            -out "$WORK/$name.crt" -days 1 2>/dev/null
    fi
}

# start_stub_registry: answers 200 with a small JSON body to every request on 127.0.0.1:18080
start_stub_registry() {
    cat > "$WORK/stub.py" <<'EOF'
import http.server
class Handler(http.server.BaseHTTPRequestHandler):
    def answer(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        body = b'{"stub":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    do_GET = do_PUT = do_POST = do_DELETE = answer
    def log_message(self, *args):
        pass
http.server.HTTPServer(("127.0.0.1", 18080), Handler).serve_forever()
EOF
    python3 "$WORK/stub.py" &
    STUB_PID=$!
}

# start_proxy <image> [docker run options…]: the proxy over TLS + mTLS on 18443, plain HTTP closed,
# with the server certificate from new_cert server … and the policy in $WORK/policy/policy.yaml
start_proxy() {
    local image=$1; shift
    chmod -R a+rX "$WORK"
    docker run -d --name "$PROXY_CONTAINER" --network host \
        -v "$WORK:/e2e:ro" \
        -e QUARKUS_OIDC_TENANT_ENABLED=false \
        -e PROXY_APICURIO_URL=http://127.0.0.1:18080 \
        -e PROXY_POLICY_FILE=/e2e/policy/policy.yaml \
        -e PROXY_POLICY_RELOAD_INTERVAL=1s \
        -e PROXY_TLS_CERT=/e2e/server.crt \
        -e PROXY_TLS_KEY=/e2e/server.key \
        -e PROXY_TLS_CA=/e2e/ca.crt \
        -e QUARKUS_HTTP_SSL_PORT=18443 \
        -e QUARKUS_HTTP_INSECURE_REQUESTS=disabled \
        "$@" "$image" >/dev/null
}

# wait_until_ready: waits up to 60 s for readiness; it is down until the policy (and, when
# enabled, the first Kafka ACL snapshot) is loaded
wait_until_ready() {
    for _ in $(seq 1 60); do
        curl -sf --cacert "$WORK/ca.crt" "$PROXY/q/health/ready" >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 0
}

# status <curl args…>: the HTTP status, 000 when there is no answer
status() { curl -s -o /dev/null -w "%{http_code}" --cacert "$WORK/ca.crt" "$@" || true; }

# as <client> <curl args…>: a request with the client's certificate
as() { local client=$1; shift; status --cert "$WORK/$client.crt" --key "$WORK/$client.key" "$@"; }

# check <description> <expected> <actual>
check() {
    if [ "$3" = "$2" ]; then
        echo "ok    $1 ($3)"
    else
        echo "FAIL  $1: expected $2, got $3"
        FAILED=1
    fi
}

# eventually <description> <expected> <seconds> <client> <curl args…>: retries until the status
# matches, for changes the proxy picks up by polling
eventually() {
    local description=$1 expected=$2 seconds=$3 client=$4; shift 4
    local actual=000
    for _ in $(seq 1 "$seconds"); do
        actual=$(as "$client" "$@")
        [ "$actual" = "$expected" ] && break
        sleep 1
    done
    check "$description" "$expected" "$actual"
}

# finish: prints the proxy log and fails when a check failed
finish() {
    if [ "$FAILED" != 0 ]; then
        echo "--- proxy log ---"
        docker logs "$PROXY_CONTAINER" 2>&1 | tail -60
        exit 1
    fi
    echo "passed"
}

cleanup_proxy() {
    docker rm -f "$PROXY_CONTAINER" >/dev/null 2>&1 || true
    [ -n "$STUB_PID" ] && kill "$STUB_PID" 2>/dev/null || true
}
