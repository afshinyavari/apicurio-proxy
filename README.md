# Apicurio RBAC proxy

A Quarkus proxy in front of [Apicurio Registry 3](https://www.apicur.io/registry/) that
authenticates every request and authorizes it per artifact before forwarding it unchanged.

- **OIDC** bearer tokens: the token's groups are bound to artifacts and actions in `policy.yaml`.
- **mTLS** client certificates: the certificate's Kafka principal (derived with the brokers' own
  `ssl.principal.mapping.rules`) is authorized by its **Kafka topic ACLs**, read from the cluster.
  Artifacts follow TopicNameStrategy, so WRITE on topic `orders` allows writing `orders-value` and
  `orders-key`. `policy.yaml` can grant a principal more; a Kafka DENY always wins.
- `policy.yaml` is reloaded at runtime when it changes, without a restart.

All settings are listed under [Configuration](#configuration). Deployment, the policy format and
the registry APIs understood are described in [strimzi/README.md](strimzi/README.md), with an
example of the proxy as a sidecar on an operator-managed registry.

## Configuration

Every setting is a Quarkus config property and is set through its environment variable form
(`proxy.kafka.bootstrap` → `PROXY_KAFKA_BOOTSTRAP`). Durations are written like `5s`, `1m`. An
empty value counts as unset. Any other Quarkus property can be set the same way.

### Registry and policy

| Variable | Default | Purpose |
|---|---|---|
| `PROXY_APICURIO_URL` | `http://apicurio:8080` | The registry behind the proxy. Allowed requests are forwarded here unchanged; in a sidecar, `http://127.0.0.1:8080`. |
| `PROXY_POLICY_FILE` | `/opt/rbac/policy.yaml` | The policy file. Missing or invalid at startup fails the start. |
| `PROXY_POLICY_RELOAD_INTERVAL` | `5s` | How often the policy file is checked; changed content is loaded without a restart, an invalid change is logged and ignored. |

### HTTPS listener and client certificates

| Variable | Default | Purpose |
|---|---|---|
| `PROXY_TLS_CERT`, `PROXY_TLS_KEY` | — | The proxy's server certificate and key (PEM, key in PKCS#8). Setting them turns on the HTTPS listener. |
| `PROXY_TLS_CA` | — | PEM file with the CAs client certificates must chain to (may hold several). A client certificate is optional on the listener: requests with a trusted certificate are mTLS callers, others need a bearer token. |
| `QUARKUS_HTTP_SSL_PORT` | `8443` | HTTPS port. |
| `QUARKUS_HTTP_PORT` | `8082` | Plain HTTP port. |
| `QUARKUS_HTTP_INSECURE_REQUESTS` | `enabled` | `disabled` closes the plain HTTP port when TLS is on; recommended in production. |
| `PROXY_MTLS_PRINCIPAL_MAPPING_RULES` | `DEFAULT` | How a certificate subject becomes a Kafka principal: the brokers' `ssl.principal.mapping.rules`, copied verbatim, so the proxy names a caller exactly as Kafka does. `DEFAULT` is the full RFC 2253 subject DN. A certificate no rule matches gets 401; invalid rules fail startup. |

### Kafka ACLs (mTLS callers)

| Variable | Default | Purpose |
|---|---|---|
| `PROXY_KAFKA_BOOTSTRAP` | — | Bootstrap servers of the Kafka cluster whose ACLs authorize certificate callers. Unset: no ACLs are read, and certificate callers get only what `principals` in the policy file grants. |
| `PROXY_KAFKA_SECURITY_PROTOCOL` | `SSL` | `SSL`, or `PLAINTEXT` for a listener without TLS. |
| `PROXY_KAFKA_SSL_CERT`, `PROXY_KAFKA_SSL_KEY` | — | The proxy's own Kafka client certificate and key (PEM, key in PKCS#8). Its principal needs `Describe` on the cluster to read the ACLs. |
| `PROXY_KAFKA_SSL_CA` | — | PEM file with the CAs the Kafka listener's certificate chains to. |
| `PROXY_KAFKA_ACL_REFRESH_INTERVAL` | `30s` | How often the ACLs are read; an ACL change in Kafka takes up to this long to apply. A failed read keeps the last ACLs. |

### OIDC (bearer tokens)

| Variable | Default | Purpose |
|---|---|---|
| `QUARKUS_OIDC_AUTH_SERVER_URL` | — | The OIDC issuer (e.g. `https://keycloak.example.com/realms/acme`). Required unless OIDC is turned off. |
| `QUARKUS_OIDC_ROLES_ROLE_CLAIM_PATH` | `groups` | Token claim holding the caller's groups, matched against `groups` in the policy file; e.g. `realm_access/roles` for Keycloak realm roles. |
| `QUARKUS_OIDC_TOKEN_AUDIENCE` | — | Accept only tokens issued for this audience (optional). |
| `QUARKUS_OIDC_TENANT_ENABLED` | `true` | `false` turns OIDC off: mTLS only, bearer tokens get 401. |

### Operations

| Variable | Default | Purpose |
|---|---|---|
| `QUARKUS_LOG_LEVEL` | `INFO` | Log level. |
| `QUARKUS_LOG_CATEGORY__AUDIT__LEVEL` | `INFO` | The audit log, one line per authenticated request (`principal=… action=… artifact=… decision=… status=…`); `WARN` turns it off. |
| `QUARKUS_SHUTDOWN_TIMEOUT` | `15S` | How long in-flight requests may finish on shutdown. |

Readiness (`/q/health/ready`) is up once the policy file is loaded and, with Kafka ACLs enabled,
the first ACL snapshot has been read; liveness is `/q/health/live`.

## Code

```
se.afshin.yavari.rbac
├── security     who the caller is: certificate subject → Kafka principal (SecurityIdentityAugmentor)
├── authz        whether the caller may: policy file, Authorizer, readiness
│   └── kafka    ACL snapshot from the cluster and Kafka's evaluation rules
├── registry     what a request is about: Apicurio core v3 and ccompat APIs, id resolution, errors
└── proxy        the JAX-RS resource that authorizes, forwards and writes the audit log line
```

## Build and test

Java 21 and Maven:

```bash
mvn package                       # build, with the unit and Quarkus tests
docker build -t apicurio-rbac-proxy .
```

The version comes from the git tag: CI builds with `-Drevision=$(git describe --tags)` (`v1.2.3`
→ `1.2.3`, later commits → `1.2.3-<n>-g<sha>`), and the application reports it on startup. A
local build without `-Drevision` is `0.0.0-SNAPSHOT`.

The image is the Quarkus fast-jar on `ubi9/openjdk-21-runtime`, pinned by tag and digest.

### Tests

| Level | What | Run with |
|---|---|---|
| Unit and Quarkus tests | Request classification, policy parsing and reload, ACL evaluation, authorization decisions, principal mapping, and the HTTP resource end to end with test identities. | `mvn test` |
| Smoke test | The built image over real TLS and mTLS against a stub registry: TLS listener, client-certificate authentication, mapping rules (no match → 401), policy grants (403), plain HTTP closed, policy reload. | `e2e/smoke-test.sh <image>` |
| Kafka integration test | The built image against a real Kafka broker (KRaft, mTLS, ACLs, the same mapping rules); the proxy reads the ACLs with its own certificate. LITERAL and PREFIXED patterns, `User:*`, DENY precedence, the DENY veto on policy grants, ACL changes at runtime. | `e2e/kafka-integration-test.sh <image>` |

The two e2e scripts need Docker, `openssl`, `python3` and `curl`, and use the host network
(ports 18080, 18443 and 19092–19094). The broker version comes from
[e2e/kafka/Dockerfile](e2e/kafka/Dockerfile); `KAFKA_IMAGE=apache/kafka:<version>` runs against
another one.

```bash
mvn package && docker build -t apicurio-rbac-proxy:dev .
e2e/smoke-test.sh apicurio-rbac-proxy:dev
e2e/kafka-integration-test.sh apicurio-rbac-proxy:dev
```

## Pipeline

[`.github/workflows/docker.yml`](.github/workflows/docker.yml) runs on every pull request and every
push to `main`:

1. `mvn package` with the unit and Quarkus tests, versioned from the git tag
2. builds the image and runs the smoke test
3. runs the Kafka integration test against the same image
4. on `main` and on version tags only: builds the image for `linux/amd64` and `linux/arm64` and
   pushes it to Docker Hub

| Trigger | Docker Hub tags |
|---|---|
| push to `main` | `apicurio-rbac-proxy:latest`, `:sha-<short sha>` |
| tag `v1.2.3` | `:1.2.3`, `:1.2`, `:latest` |
| pull request | nothing is pushed |

Pushing needs the repository secrets `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`.

`main` is protected: changes go through a pull request, and the `build` check must pass before it
can be merged. This applies to admins too.

### Dependency updates

[Dependabot](.github/dependabot.yml) checks weekly and opens a pull request for each update, which
runs the full pipeline before it can be merged:

- Maven: Quarkus (BOM and plugin together) in one group, all other Java dependencies in another
- the UBI base image of the `Dockerfile` (tag and digest)
- the Kafka broker of the integration test, newest 4.x (major versions are ignored)
- the GitHub Actions of the workflow
