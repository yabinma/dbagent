# Backup and restore

## Scope

PostgreSQL holds investigations, audit_log, llm_calls, platforms, users and
playbooks. Object storage (MinIO / S3) holds evidence payloads referenced by
`payload_ref` / prompt-response refs. Both must be backed up for a recoverable
system. Bundled chart PostgreSQL (`postgresql.bundled: true`) uses `emptyDir`
and is **dev/e2e only** — do not rely on it for durable state; point production
at an operator-managed database (`postgresql.bundled: false` + external DSN).

## Backup procedure

1. Schedule a maintenance window if you need a consistent multi-store snapshot.
2. **PostgreSQL** (preferred: managed snapshot / PITR from your cloud provider).
   Logical dump alternative:
   ```bash
   pg_dump "$PG_DSN" --format=custom --file="rca-$(date -u +%Y%m%dT%H%M%SZ).dump"
   ```
3. **Object storage**: snapshot the `dbagent` bucket (or `mc mirror` /
   `aws s3 sync` to a cold bucket). Record the bucket name and endpoint from
   `config.storage`.
4. **Kubernetes Secrets** you will need on restore: app Secret (`PG_DSN`, JWT,
   LiteLLM key, …), `dbagent-signing-key`, probe bootstrap CA PVC/Secret, and
   any platform-credential Secrets. Export with care (they are credentials):
   ```bash
   kubectl -n dbagent get secret dbagent-app -o yaml > app-secret.backup.yaml
   kubectl -n dbagent get secret dbagent-signing-key -o yaml > signing-key.backup.yaml
   ```
5. Store dumps and Secret YAMLs in an access-controlled location; encrypt at rest.

## Restore procedure

1. Provision empty PostgreSQL (or restore the managed snapshot first).
2. Restore the logical dump if used:
   ```bash
   pg_restore --clean --if-exists --dbname="$PG_DSN" rca-YYYYMMDDTHHMMSSZ.dump
   ```
3. Restore object storage contents to the configured bucket.
4. Re-apply Secrets **before** starting the control plane (signing key must match
   what enrolled probes already trust — see `signing-key-rotation.md`).
5. `helm upgrade --install` with `postgresql.bundled: false` and the restored DSN.
6. Verify: `GET /healthz` on all services; `GET /api/v1/platforms` shows expected
   rows; spot-check one investigation detail page loads evidence.

## Notes

- Alembic migrations run as a pre-install/pre-upgrade hook; a restore of a
  schema at revision N does not require re-running migrations unless you
  intentionally upgrade past N afterward.
- Do **not** delete `dbagent-signing-key` during restore unless you are also
  re-enrolling every probe.
