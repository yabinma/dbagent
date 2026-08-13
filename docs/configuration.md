
# Configuration reference

All control-plane Python services load one YAML file (Appendix E) with `${ENV_VAR}` interpolation.

## AppConfig fields

- `models`
- `budget_defaults` / `budget_defaults.max_rounds` / `budget_defaults.max_cost_usd` / `budget_defaults.max_wall_seconds`
- `max_calls_per_round`
- `rca_confidence_threshold`
- `display_verbosity`
- `data_egress_policy`
- `tracing` / `tracing.backend` / `tracing.langfuse_host` / `tracing.langfuse_public_key` / `tracing.langfuse_secret_key`
- `signing` / `signing.backend` / `signing.key_path` / `signing.rotation_grace_seconds` / `signing.allow_ephemeral`
- `storage` / `storage.postgres_dsn` / `storage.s3_endpoint` / `storage.s3_bucket` / `storage.s3_access_key` / `storage.s3_secret_key`
- `model_gateway` / `model_gateway.url` / `model_gateway.master_key`
- `temporal` / `temporal.address` / `temporal.namespace` / `temporal.task_queue`
- `ingest` / `ingest.sources` / `ingest.correlation_window_seconds`
- `raw_commands` / `raw_commands.policy` / `raw_commands.timeout_seconds` / `raw_commands.max_output_bytes`
- `probe_gateway` / `probe_gateway.url` / `probe_gateway.timeout_seconds`
- `dashboard` / `dashboard.jwt_secret` / `dashboard.token_ttl_seconds` / `dashboard.password_min_length` / `dashboard.cors_origins` / `dashboard.bootstrap_ca_cert_path`
- `notifications` / `notifications.outbound_webhooks`
- `raw`

## Probe config keys

- `platform_key`, `gateway_address`, `bootstrap_address`, `bootstrap_token`, `bootstrap_ca_pin`
- `coordinator_locator`, `credentials_mount`, `write_enabled`, `insecure_skip_verify`, `state_dir`
- `coordinator_https`, `coordinator_port`, `namespace`, `coordinator_service`, `worker_service`
- `docker_api_base_url` — how the probe reaches the Docker Engine API on Swarm/Docker
  (design.md §11.2.3 B). Default `unix:///var/run/docker.sock`: the probe dials the
  mounted socket directly and the shipped stack contains **no** socket proxy. Accepted
  forms are `unix://<absolute path>`, `http://host:port` and `https://host:port`; any
  other scheme, or a unix path that is missing, not a socket, or not reachable
  (including permission denied), is a fatal startup error raised **before** enrollment
  spends the single-use bootstrap token. For `unix://` the client issues `GET /_ping`
  at construction. The shipped image is non-root (65532); set `DOCKER_SOCKET_GID` on
  compose/stack deploys so the process joins the host docker group — Compose via
  `group_add`, Swarm via `user: "65532:${DOCKER_SOCKET_GID}"`
  (`docs/deployment/swarm.md`).
- `config_paths` — optional per-file override of where platform config lives *inside*
  the coordinator/worker container. Keys are the Appendix B.1 `presto_config` `file`
  values (`config` | `jvm` | `node` | `catalog:<name>`); values are **absolute**
  in-container paths, validated at load time (a relative or empty value is a named
  error). Unset keys keep the `/etc/presto/...` default **per key**. Swarm/Docker only:
  on Kubernetes `ReadConfig` resolves a ConfigMap key, not a path.
- `signing_key_grace_window` — D14 rotation grace (default `10m`): how long the pre-rotation control-plane signing public key keeps verifying write-ops after a mid-session key update (design.md §9.6 / Appendix A.2). Held per probe process so it survives reconnects.

### Complete probe example

This block is the complete surface of `probe/internal/config.Probe` and is kept
**byte-identical** to `probe/internal/config/testdata/appendix-e-example.yaml`,
which a Go unit test loads through `config.Load` — so the documented example is a
file that actually loads, not prose. Note there is **no `probe:` wrapper key and no
leading indentation**: `config.Load` unmarshals top-level keys.

```yaml
platform_key: presto-analytics-us1
gateway_address: probe-gateway.example.com:443
bootstrap_address: probe-gateway.example.com:8443  # Bootstrap.Enroll listener
# (server-TLS-only; separate from gateway_address's mTLS listener)
bootstrap_token: ${BOOTSTRAP_TOKEN}       # single-use; empty after enrollment
# Swarm/compose secret-file alternative: leave this empty and set the env var
# BOOTSTRAP_TOKEN_FILE to the mounted secret path (FP-M6-12)
bootstrap_ca_pin: ""                      # optional: bootstrap CA cert PEM or
# its SHA-256 fingerprint "sha256:<64 hex>" (from the dashboard platform
# page); when set, Enroll verifies the gateway's certificate — removes TOFU
# (Section 8.4a); REQUIRED on untrusted networks
state_dir: /var/lib/dbagent-probe         # persisted enrollment identity
# (client.crt / client.key / ca.crt); must be writable by the runtime UID
credentials_mount: /etc/dbagent-probe/platform-credentials
# Secret keys by convention: username / password / ca.crt (optional)
write_enabled: false                      # true also requires the write RBAC Role
# (K8s) / a write-capable socket (Swarm). The `:ro` socket mount flag is NOT
# a write control — see Part 1 Section 8.1
insecure_skip_verify: false               # test environments only
signing_key_grace_window: 10m             # D14 rotation grace: how long the
# pre-rotation control-plane signing public key keeps verifying write-ops
# after a mid-session key update (Part 1 Section 9.6 / Appendix A.2). Mirrors
# probe-gateway's key of the same name; both are the local expression of the
# control plane's signing.rotation_grace_seconds (default 600). Held per
# probe *process*, so it survives reconnects (A.2 rule 8)

# --- coordinator locator: coordinator_service decides the runtime ---
# Kubernetes (coordinator_service unset):
coordinator_locator: "app=presto,role=coordinator"   # K8s label selector
namespace: presto                         # K8s namespace; ignored on Swarm
# Docker Swarm (coordinator_service set -> the Swarm runtime is selected).
# Both forms appear here because this block is the key reference; a deployed
# file sets one or the other.
coordinator_service: presto-coordinator   # Swarm service name (service DNS)
worker_service: presto-worker             # Swarm service name
# --- shared ---
coordinator_port: 8080                    # default 8080
coordinator_https: false                  # true -> https:// coordinator REST

# --- Swarm/Docker only ---
docker_api_base_url: unix:///var/run/docker.sock
# Default. The probe dials the mounted Docker socket directly; the shipped
# stack contains NO socket proxy (Part 1 Section 8.1 / §11.2.3 B). Accepted
# forms: unix://<abs path> | http://host:port | https://host:port. Any other
# scheme, or a unix path that is missing or is not a socket, is a fatal
# startup error. The http(s) form exists for tests and for a site that runs
# its own (ideally endpoint-filtering, dedicated-network) socket proxy
config_paths:
  # Optional per-file override of where platform config lives INSIDE the
  # coordinator/worker container; keys are Appendix B.1 `presto_config` `file`
  # values, values are ABSOLUTE in-container paths (a relative or empty value
  # is a named load-time error -- Part 1 §11.2.3 A). Unset keys keep the
  # /etc/presto/... defaults, per key:
  #   config -> /etc/presto/config.properties
  #   jvm    -> /etc/presto/jvm.config
  #   node   -> /etc/presto/node.properties
  #   catalog:<name> -> /etc/presto/catalog/<name>.properties
  #   <other> -> /etc/presto/<other>
  # The values below are the prestodb server-tarball layout; quote the
  # catalog:<name> form by convention (Part 1 §11.2.3 A). Ignored on
  # Kubernetes, where ReadConfig resolves a ConfigMap key, not a path.
  config:          /opt/presto-server/etc/config.properties
  jvm:             /opt/presto-server/etc/jvm.config
  node:            /opt/presto-server/etc/node.properties
  "catalog:hive":  /opt/presto-server/etc/catalog/hive.properties
```

### Secret-file convention (`BOOTSTRAP_TOKEN_FILE`)

When `bootstrap_token` is empty after `${ENV_VAR}` expansion, the probe loads the
token from the path in the `BOOTSTRAP_TOKEN_FILE` environment variable (trimmed).
This is the Docker Swarm / Compose secret-file pattern used by
`deploy/compose/probe-swarm-stack.yml`: mount the secret at a path and point
`BOOTSTRAP_TOKEN_FILE` at it so the token never appears in process environment
or in the YAML document.

## Probe-gateway config keys

- `session_listen_addr`, `bootstrap_listen_addr`, `internal_listen_addr`, `postgres_dsn`
- `bootstrap_ca_cert_path`, `bootstrap_ca_key_path`, `signing_public_key_path`, `signing_key_grace_window`
- `gateway_replica`, `heartbeat_timeout`, `heartbeat_check_interval`, `signing_key_poll_interval`, `server_cert_sans`
