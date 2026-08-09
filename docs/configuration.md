
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
- `temporal` / `temporal.address` / `temporal.namespace`
- `ingest` / `ingest.sources` / `ingest.correlation_window_seconds`
- `raw_commands` / `raw_commands.policy` / `raw_commands.timeout_seconds` / `raw_commands.max_output_bytes`
- `probe_gateway` / `probe_gateway.url` / `probe_gateway.timeout_seconds`
- `dashboard` / `dashboard.jwt_secret` / `dashboard.token_ttl_seconds` / `dashboard.password_min_length` / `dashboard.cors_origins` / `dashboard.bootstrap_ca_cert_path`
- `notifications` / `notifications.outbound_webhooks`
- `raw`

## Probe config keys

- `platform_key`, `gateway_address`, `bootstrap_address`, `bootstrap_token`, `bootstrap_ca_pin`
- `coordinator_locator`, `credentials_mount`, `write_enabled`, `insecure_skip_verify`, `state_dir`
- `coordinator_https`, `coordinator_port`, `namespace`, `coordinator_service`, `worker_service`, `docker_api_base_url`
- `signing_key_grace_window` — D14 rotation grace (default `10m`): how long the pre-rotation control-plane signing public key keeps verifying write-ops after a mid-session key update (design.md §9.6 / Appendix A.2). Held per probe process so it survives reconnects.

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
