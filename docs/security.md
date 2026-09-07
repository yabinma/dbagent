# Security

## mTLS bootstrap (D16)

- probe-gateway runs a self-signed bootstrap CA (PVC or existing Secret).
- Probes enroll via `Bootstrap.Enroll` with a single-use token + CSR.
- Optional `bootstrap_ca_pin` (`sha256:…` or PEM) for untrusted networks.
- No CRL/OCSP in MVP — short-lived certs + registry authorization.

## Write-channel signing (D14)

- ed25519 key pair; private key in Secret / volume; public key in RegisterAck.
- Rotation grace window: `signing.rotation_grace_seconds` (default 600).
- Bootstrap Job creates the signing-key Secret once; helm upgrades must not rotate
  it (see e2e E0 idempotence check and `docs/runbooks/signing-key-rotation.md`).

## Secret handling

Secrets never live in ConfigMaps or committed YAML as literals.

| Secret | Where it lives | How it is consumed |
|---|---|---|
| Postgres DSN (`PG_DSN`) | K8s Secret / Compose secret | `${PG_DSN}` in AppConfig storage block |
| S3 keys | K8s Secret / Compose secret | `${S3_ACCESS_KEY}` / `${S3_SECRET_KEY}` |
| LiteLLM master key | K8s Secret | `${LITELLM_MASTER_KEY}` |
| Dashboard JWT secret | K8s Secret | `${DASHBOARD_JWT_SECRET}` |
| Grafana webhook HMAC | K8s Secret | ingest source `secret: ${GRAFANA_WEBHOOK_SECRET}` |
| Admin bootstrap password | K8s Secret (`ADMIN_INITIAL_PASSWORD`) | bootstrap-admin hook Job only |
| Probe bootstrap token | K8s Secret or Docker secret file | YAML `bootstrap_token` **or** `BOOTSTRAP_TOKEN_FILE` |
| Platform Presto credentials | per-platform Secret / Docker secret | mounted at `credentials_mount` |
| Bootstrap CA key | PVC or `existingSecret` | probe-gateway only |
| ed25519 signing private key | `dbagent-signing-key` Secret | worker + probe-gateway |

### Operators

1. Prefer external secret managers (`existingSecret`) over chart-generated defaults.
2. Rotate per the runbooks under `docs/runbooks/` (signing key, bootstrap CA,
   platform credentials). Never paste secret values into `values.yaml` PRs.
3. On Swarm, use `BOOTSTRAP_TOKEN_FILE` so the enrollment token is a mounted file
   rather than an environment variable (see `docs/configuration.md`).
4. After rotation, confirm probes re-enroll and that `GET /platforms` stays
   `online` before tearing down the old credential.

## Docker socket access on Swarm (design.md §11.2.3 B)

The probe reaches the Docker Engine API by **dialing the mounted unix socket**
(`docker_api_base_url: unix:///var/run/docker.sock`, the default). The shipped
compose and stack files declare no socket-proxy service.

- **The `:ro` mount flag is not a security control.** A read-only bind mount of
  `/var/run/docker.sock` does not make the Engine API read-only. What limits the
  probe to reads is `write_enabled: false` and the signed write channel.
- **Non-root + socket group.** The probe image runs as UID/GID 65532. Operators
  must set `DOCKER_SOCKET_GID` (the host docker group's numeric GID) so the
  process can open a typical `root:docker` `0660` socket — Compose uses
  `group_add`, Swarm uses `user: "65532:${DOCKER_SOCKET_GID}"` (stack schema
  rejects `group_add`); see `docs/deployment/swarm.md`. Startup performs
  `GET /_ping` before enrollment so an `EACCES` failure does not spend the
  single-use bootstrap token.
- A site that forbids socket mounts may run its own proxy and point
  `docker_api_base_url` at `http://<proxy>:<port>`. Understand the cost: a TCP
  proxy in front of the socket grants root-equivalent control of the manager
  node to everything that can reach that port, and the probe sits on the Presto
  overlay network. Use an endpoint-filtering proxy on a dedicated network.

## Identities the product presents

| Identity | Value | Why an operator cares |
|---|---|---|
| Presto client user | `X-Presto-User: dbagent-probe` | appears in the customer's query history and `system.runtime.queries.user`; grant and filter on it, and write per-user resource groups against it |
| Bootstrap CA subject | `CN=dbagent probe-gateway bootstrap CA` | the display string in `openssl x509 -subject`. `bootstrap_ca_pin` pins the SHA-256 of the **DER**, which is per-CA regardless of subject, so no pin an operator holds is invalidated by the name |

## Redaction (Section 8.2)

Catalog secret values are redacted probe-side before evidence leaves the data
plane. Value-based redaction runs on Toolpack envelopes; e2e E2 asserts a
password sentinel never appears in investigation detail or iteration evidence.

## Network posture

probe-gateway's `:8080` internal ExecuteTool listener is cluster-internal only.
When `networkPolicy.enabled=true`, ingress on `:8080` is restricted to
temporal-worker pods. On CNIs that do not enforce NetworkPolicy (e.g. kindnet)
this control is **advisory**.
