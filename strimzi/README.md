# Apicurio RBAC proxy as a Strimzi sidecar

Humans authenticate with OIDC bearer tokens and are authorized by `policy.yaml` (groups →
artifacts). Services authenticate with mTLS client certificates and are authorized by their
**Kafka ACLs**: WRITE on topic `orders` ⇒ READ+WRITE on artifacts `orders-key` / `orders-value`;
READ/DESCRIBE ⇒ READ; DELETE ⇒ DELETE; ALL ⇒ everything. DENY wins, PREFIXED and `*` patterns
work as in Kafka. An OIDC identity is never checked against ACLs. A certificate identity can in
addition be granted access by name in `policy.yaml` (see [Rules that are not Kafka ACLs](#rules-that-are-not-kafka-acls)).

Both mechanisms are active on one HTTPS listener: a request with `Authorization: Bearer …`
goes the OIDC way, a request presenting a trusted client certificate goes the mTLS way, a
request with neither gets 401.

The proxy is written for **Apicurio Registry 3.x** and its core API v3 (`/apis/registry/v3`),
verified against registry 3.3.3 with the Apicurio 3.3.3 and Confluent 8.3 Avro serdes. The
Confluent-compatible API (`/apis/ccompat/v7`) is understood as well; the v2 core API is
treated as registry-wide —
see [Registry APIs](#registry-apis).

## Deployment

`apicurio-operator-sidecar.yaml` is an `ApicurioRegistry3` CR (Apicurio Registry 3 operator,
checked with 3.3.3) with the proxy added as a sidecar through `spec.app.podTemplateSpec`. The
registry API is bound to loopback, so only the proxy in the same pod reaches it; a Service on
8443 and a NetworkPolicy expose just the proxy. The operator's probes use the management port
9000, so port 8080 can be closed to everything outside the pod. The manifest is written for
mTLS only (see [mTLS only](#mtls-only-no-oidc)).

`kafkauser.yaml` (the proxy's `KafkaUser` with `Describe` on `Cluster`, needed for `describeAcls`)
and `certificates.yaml` (the cert-manager `Certificate`s the manifest mounts) go with it.

The manifest takes every certificate from cert-manager and every trust anchor from one CA
bundle; no Strimzi CA Secret is involved (see [Certificates and trust](#certificates-and-trust)).

NetworkPolicy notes: kubelet probes are not blocked by NetworkPolicy in the common CNIs
(Calico, Cilium, OVN); if yours differs, allow ingress from the node CIDR on the probe ports
(8443 and 9000). Check the labels the operator puts on
registry pods (`kubectl get pods --show-labels`) and adjust `podSelector`.

Operator specifics (3.x): the operator's own NetworkPolicy allows 8080 and 9000 only,
so it is switched off (`spec.app.networkPolicy.enabled: false`) in favour of one that allows
8443. The registry UI is switched off as well: it calls the API from the browser, which has
no client certificate. Exposing the proxy outside the cluster needs TLS **passthrough** (an
edge or re-encrypt route terminates TLS and drops the client certificate).

## mTLS only (no OIDC)

Set `QUARKUS_OIDC_TENANT_ENABLED=false` on the proxy and leave `QUARKUS_OIDC_AUTH_SERVER_URL`
out, as the manifest does. Leaving `QUARKUS_OIDC_AUTH_SERVER_URL` out without the
flag fails startup. A request with a trusted client certificate is authorized as usual; a request
without one gets 401, also when it carries a bearer token. To add OIDC later, remove the flag
and set `QUARKUS_OIDC_AUTH_SERVER_URL`; no rebuild is needed.

With no OIDC users, `rules` in `policy.yaml` apply only through `principals`. An example for
a setup where services are authorized by their Kafka ACLs and two certificates need more:

```yaml
rules:
  - principals: ["CN=ci-pipeline"]        # registers and deletes schemas for every topic
    artifacts: ["*"]
    actions: [READ, WRITE, DELETE]
  - principals: ["CN=orders-service"]     # its schemas reference a shared artifact
    artifacts: [common-address]
    actions: [READ]
```

`policy.yaml` must exist and parse even when every service is covered by its ACLs;
`rules: []` is enough.

## Build

The pipeline publishes the image to Docker Hub as `apicurio-rbac-proxy` (`:latest` from `main`,
`:<version>` from a `v<version>` tag); point `image:` in `apicurio-operator-sidecar.yaml` at it. To
build it yourself:

```bash
mvn package
docker build -t registry.example.com/apicurio-rbac-proxy:1.0 .
docker push registry.example.com/apicurio-rbac-proxy:1.0
```

Building, the tests and the pipeline are described in the [top-level README](../README.md).

## Policy file

`policy.yaml` is read from `PROXY_POLICY_FILE` (default `/opt/rbac/policy.yaml`) at startup and
re-read whenever its content changes. The manifest mounts it from the ConfigMap
`apicurio-proxy-policy`:

```bash
kubectl -n kafka create configmap apicurio-proxy-policy --from-file=policy.yaml \
  --dry-run=client -o yaml | kubectl apply -f -
```

Re-applying the ConfigMap is enough; the pods are not restarted. The proxy polls the file
every `PROXY_POLICY_RELOAD_INTERVAL` (default `5s`) and loads it when the content differs:

- **Delay.** Kubelet syncs a ConfigMap volume periodically, so a change usually reaches the
  pod within about a minute. The poll interval adds at most a few seconds on top.
- **Replicas** reload independently and can briefly enforce different policies.
- **A broken file** (invalid YAML, unknown key or action, a rule without `principals`/`groups`,
  `artifacts` or `actions`) is rejected: the proxy keeps the policy it has and logs
  `Reload of … failed, keeping current policy`. At startup a broken file fails the pod instead.
- **`subPath` mounts are never updated** by Kubernetes. Mount the ConfigMap as a directory, as
  the manifest does.

Confirm a reload in the log: `Loaded N policy rules from …`. The image contains an example
`policy.yaml` that is used only when nothing is mounted.

```yaml
rules:
  - groups: [orders-team]           # OIDC groups (token claim "groups")
    principals: ["CN=ci-pipeline"]  # certificate principals (mTLS only)
    artifacts: [orders-value, orders-key]   # exact artifact ids, or "*"
    actions: [READ, WRITE]          # READ | WRITE | DELETE
  - groups: [schema-admin]
    artifacts: ["*"]
    actions: [READ, WRITE, DELETE]
```

A rule applies to a caller in one of its `groups` or named in its `principals`. OIDC groups come
from the token claim `QUARKUS_OIDC_ROLES_ROLE_CLAIM_PATH` (default `groups`). Rule artifacts are
matched exactly: the `-value`/`-key` → topic mapping (TopicNameStrategy) applies to Kafka ACLs only.

### Rules that are not Kafka ACLs

`principals` grants a client certificate access beyond its Kafka ACLs. A certificate request is
allowed when **either** its Kafka ACLs **or** a rule naming its principal allow it, with two limits:

- A Kafka `DENY` on the artifact's topic for the same operation (READ, WRITE, DELETE) or `ALL`
  blocks the rule grant too, so a DENY in Kafka always wins.
- While the ACL source is enabled but has not loaded a snapshot yet, certificate requests are
  denied (a DENY cannot be ruled out). With `PROXY_KAFKA_BOOTSTRAP` unset, only the policy applies.

Principals are written as the proxy derives them from the certificate, i.e. what
`PROXY_MTLS_PRINCIPAL_MAPPING_RULES` produces (by default the subject DN: `CN=<name>` for a
certificate with only a common name; spacing after commas does not matter). A Kafka-style
`User:` prefix is accepted. `principals` never match OIDC callers, and `groups` never match
certificate callers.

## Registry APIs

Every request is reduced to one artifact and one action (READ, WRITE, DELETE) before the
policy is asked. GET is READ, DELETE is DELETE, everything else is WRITE unless stated.

| Request | Artifact | Action |
|---|---|---|
| `…/v3/groups/{g}/artifacts/{a}[/…]` | `{a}` | by method |
| `POST …/v3/groups/{g}/artifacts` (create, serde auto-register) | `artifactId` in the JSON body | WRITE |
| `…/v3/search/versions?artifactId={a}`, `…/v3/search/artifacts?artifactId={a}` (serde lookup by content) | `{a}` | READ, also for POST |
| `…/ids/globalIds/{id}`, `…/ids/contentIds/{id}`, `…/search/…?globalId=` / `?contentId=` | resolved from the registry | READ |
| `/apis/ccompat/v7/subjects/{s}/versions` (register) | `{s}` | WRITE |
| `POST /apis/ccompat/v7/subjects/{s}` (lookup), `POST …/compatibility/subjects/{s}/…` | `{s}` | READ |
| `/apis/ccompat/v7/subjects/{s}/…`, `/config/{s}`, `/mode/{s}` | `{s}` | by method |
| `/apis/ccompat/v7/schemas/ids/{id}[/…]` | resolved from the registry | READ |
| `/apis/ccompat/v7/associations/resources/{ns}/{topic}?associationType=value\|key` | `{topic}-value` / `{topic}-key` | READ |
| anything else: listings, free-text search, `/admin`, `/system`, `/subjects`, `/config`, the v2 API | `*` | by method |

- **Ids are resolved, not trusted.** An id names content, not an artifact, so the proxy asks the
  registry which artifacts hold it (on the API the request came in on) and allows the request
  when the caller may READ **any** of them. Identical content shares one content id across
  artifacts — a `string` key schema used by many topics is one content id — and v3 serdes use
  the content id by default. The `?subject=` hint of ccompat `schemas/ids/{id}` is ignored:
  the registry does not enforce it. An id the registry does not know needs `*`.
- **Ambiguous requests are registry-wide.** A create body with a duplicate or missing
  `artifactId`, a non-JSON create, or a repeated `artifactId` query parameter maps to `*`.
- **Groups are not part of the policy.** `team-a/orders-value` and `default/orders-value` are
  both artifact `orders-value`.
- **Schema references** are fetched by the serde as ordinary artifact reads, so a client needs
  READ on every artifact its schemas reference.
- **Denials are answered in the API's own error format** (v3 problem details,
  ccompat `error_code` 40301) with the denied action and artifact in the
  message, so serdes report them as an authorization error.
- Every request goes to `PROXY_APICURIO_URL` unchanged.

## Certificates and trust

| Object | Keys | Source |
|---|---|---|
| Secret `apicurio-proxy-server-tls` | `tls.crt`, `tls.key` | cert-manager: server certificate for the proxy's Service names |
| Secret `apicurio-proxy-kafka` | `tls.crt`, `tls.key` | cert-manager: the proxy's Kafka client certificate, subject `CN=apicurio-proxy-kafka` |
| Secret `apicurio-registry-kafka` | `tls.crt`, `tls.key` | cert-manager: the registry's Kafka client certificate for kafkasql storage |
| Secret `tls-trust-bundle` | `ca-bundle.crt` | Your CA bundle: trust anchor for client certificates **and** for Kafka |

`certificates.yaml` has the three `Certificate`s. The Kafka listener the proxy and the registry
connect to must present a certificate that chains to a CA in the bundle and must trust the CA
that issues the client certificates; the Strimzi cluster CA and clients CA are not used.

- **Private keys must be PKCS#8** (`-----BEGIN PRIVATE KEY-----`) wherever a Kafka client reads
  them: `apicurio-proxy-kafka` and `apicurio-registry-kafka`. cert-manager writes PKCS#1 unless
  the `Certificate` sets `privateKey.encoding: PKCS8`; with a PKCS#1 key the proxy fails at
  startup with `Invalid PEM keystore configs`. The proxy's server key may be either.
- **The bundle decides who is authenticated.** A client certificate from *any* CA in
  `ca-bundle.crt` passes the TLS handshake; what it may do is then decided by the Kafka ACLs of
  its principal and by `principals` in `policy.yaml`. A certificate with neither gets 403.
- **The certificate subject is the Kafka principal.** The proxy looks up ACLs for the full
  subject DN (`PROXY_MTLS_PRINCIPAL_MAPPING_RULES=DEFAULT`), so `CN=orders-service,O=Org` needs ACLs on exactly
  `User:CN=orders-service,O=Org`. A Strimzi `KafkaUser` (`tls` or `tls-external`) manages ACLs
  for `User:CN=<name>`, which matches a certificate whose subject is only that common name.
- **Subjects with more than a CN need the brokers' mapping rules.** When your PKI adds fields
  such as `O` or `C`, the brokers reduce the subject with `ssl.principal.mapping.rules`, e.g.
  `RULE:^CN=([^,]+),.*$/CN=$1/,DEFAULT` to keep `CN=<name>`. Give the proxy the same string in
  `PROXY_MTLS_PRINCIPAL_MAPPING_RULES`: it evaluates it with Kafka's own mapper, so both derive
  the same principal. A certificate no rule matches gets 401, as Kafka rejects it. The log
  shows the rules in use (`Certificate principals mapped by rules …`).
- **Renewed certificates need a restart.** The proxy and the registry read key material at
  startup, and the registry gets it through env. Restart the pods when cert-manager renews a
  Secret or the bundle changes (e.g. with Stakater Reloader on the four Secrets);
  otherwise connections fail once the old certificate expires.
- `tls-trust-bundle` is mounted as a Secret. If your bundle is a ConfigMap (the trust-manager
  default), change the `trust-bundle` volume to `configMap:` and the registry's `secretKeyRef`
  to `configMapKeyRef`.
- The registry's `spec.app.storage.kafkasql.tls` block of the 3.x operator is not used: it takes
  PKCS12 files with a password. The PEM material is passed as `APICURIO_KAFKA_COMMON_SSL_*` env.

Key material is PEM only. A Strimzi-issued `KafkaUser` Secret has PEM files too (`user.crt`,
`user.key`, `ca.crt`).

## Apply and verify

```bash
kubectl apply -f certificates.yaml -f kafkauser.yaml
kubectl apply -f apicurio-operator-sidecar.yaml
kubectl -n kafka logs deploy/registry-app-deployment -c rbac-proxy | grep -E 'PolicyStore|KafkaAclStore|Listening'
```

Expected on start: `Loaded N policy rules from …` and `Listening on: https://0.0.0.0:8443`.
Readiness is down until the policy is loaded and the first ACL snapshot has been fetched (an
ACL refresh failure is logged as `ACL refresh failed`).

A service with a cert-manager client certificate (Secret `orders-service`):

```bash
kubectl -n kafka get secret orders-service -o jsonpath='{.data.tls\.crt}' | base64 -d > tls.crt
kubectl -n kafka get secret orders-service -o jsonpath='{.data.tls\.key}' | base64 -d > tls.key
kubectl -n kafka get secret tls-trust-bundle -o jsonpath='{.data.ca-bundle\.crt}' | base64 -d > ca-bundle.crt
curl --cert tls.crt --key tls.key --cacert ca-bundle.crt \
     https://registry-rbac.kafka.svc:8443/apis/registry/v3/groups/default/artifacts/orders-value
```

A human with a token:

```bash
curl -H "Authorization: Bearer $TOKEN" --cacert ca-bundle.crt \
     https://registry-rbac.kafka.svc:8443/apis/registry/v3/search/artifacts
```

Every request is one line on the `audit` log category, e.g.
`principal="CN=orders-service" action=WRITE artifact="orders-value" decision=allow status=200 latencyMs=12`;
`principal` is the Kafka principal for mTLS and the token's name for OIDC.

## Notes

- Registry-wide operations (listing, free-text search, create without an artifact id) map to
  artifact `*` and require `ALL` on topic `*` for a certificate identity. Serde traffic —
  auto-register, lookup by content, find-latest and lookups by `globalId` / `contentId` —
  names or resolves to a real artifact, so it works with topic-scoped ACLs
  (see [Registry APIs](#registry-apis)).
- Confluent clients 8.x ask `associations/resources/-/{topic}` before every call. Apicurio
  answers 404, which the client expects; the audit line shows `decision=allow status=404`.
- The Kafka principal derived from a certificate must equal the principal in the ACLs. A
  certificate with subject `CN=<name>` and ACLs on `User:CN=<name>` (what a Strimzi `KafkaUser`
  manages) match with the `DEFAULT` rule. If your brokers rewrite subjects with
  `ssl.principal.mapping.rules`, set `PROXY_MTLS_PRINCIPAL_MAPPING_RULES` to the same rules.
- ACLs are cached and refreshed every `PROXY_KAFKA_ACL_REFRESH_INTERVAL`; a change in Kafka
  takes up to that long to apply. If Kafka is unreachable, the last snapshot stays in use.

## Environment reference

All environment variables, their defaults and what they are for are listed in the
[top-level README](../README.md#configuration).
