# Apicurio RBAC proxy

A Quarkus proxy in front of [Apicurio Registry 3](https://www.apicur.io/registry/) that
authenticates every request and authorizes it per artifact before forwarding it unchanged.

- **OIDC** bearer tokens: the token's groups are bound to artifacts and actions in `policy.yaml`.
- **mTLS** client certificates: the certificate's Kafka principal (derived with the brokers' own
  `ssl.principal.mapping.rules`) is authorized by its **Kafka topic ACLs**, read from the cluster.
  Artifacts follow TopicNameStrategy, so WRITE on topic `orders` allows writing `orders-value` and
  `orders-key`. `policy.yaml` can grant a principal more; a Kafka DENY always wins.
- `policy.yaml` is reloaded at runtime when it changes, without a restart.

Deployment, the policy format, the registry APIs understood and all settings are described in
[strimzi/README.md](strimzi/README.md), with an example of the proxy as a sidecar on an
operator-managed registry.

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

1. `mvn package` with the unit and Quarkus tests
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
