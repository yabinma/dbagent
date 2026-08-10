# Upgrade and rollback

## Pre-checks

1. Read the release notes for the target chart / app version.
2. Confirm production values: `postgresql.bundled: false`, external DSN, and a
   durable Temporal backend (`temporal.mode: external` or `chart`). Never upgrade
   a production cluster that still uses bundled emptyDir PostgreSQL as its
   system of record.
3. Take a backup (`backup-restore.md`) before major upgrades.
4. Note the current alembic revision and image tags:
   ```bash
   kubectl -n dbagent get deploy -o wide
   # alembic version_num from the migrate Job logs or a one-off psql query
   ```

## Upgrade procedure

1. Bump `global.appVersion` / image tags (or pull the new chart version).
2. Dry-render and inspect hooks:
   ```bash
   helm template dbagent deploy/charts/dbagent -f your-values.yaml | less
   ```
3. Apply:
   ```bash
   helm upgrade dbagent deploy/charts/dbagent -n dbagent \
     -f your-values.yaml --wait --timeout 10m
   ```
4. Hook order (design §11.1.3): app Secret (−35) → migrate (−20) → signing-key
   (−10) → main Deployments → bootstrap-admin / seed-playbooks (post).
   Bundled PostgreSQL is **pre-install only** and is not recreated on upgrade
   (when enabled for dev).
5. Verify:
   - all Deployments Ready
   - migrate Job succeeded; schema at expected revision
   - `dbagent-signing-key` **byte-identical** before/after (D14 — the
     signing-key Job must not regenerate)
   - `GET /healthz` on ingest, dashboard-api, probe-gateway, dashboard-web
   - probes still `online`

## Rollback procedure

1. `helm rollback dbagent <revision> -n dbagent --wait`
2. If a forward migration is not backward-compatible, restore the database from
   the pre-upgrade backup first (`backup-restore.md`), then roll the chart back.
3. Confirm signing-key Secret still matches enrolled probes; if it was manually
   replaced, follow `signing-key-rotation.md`.

## Upgrading across the `rca-agent` → `dbagent` rename

The product rename (design.md §11.2.3 C) moved the process-level environment
namespace from `RCA_*` to `DBAGENT_*`. **There is no dual read**: a process that
still finds a legacy name in its environment refuses to start and names the
replacement. Rename each of the following before upgrading — this runbook is
the one place operator-facing prose names the old identifiers.

| Old (no longer read) | New |
|---|---|
| `RCA_PG_DSN` | `DBAGENT_PG_DSN` |
| `RCA_POSTGRES_DSN` | `DBAGENT_POSTGRES_DSN` |
| `RCA_WORKER_CONFIG` | `DBAGENT_WORKER_CONFIG` |
| `RCA_GATEWAY_CONFIG` | `DBAGENT_GATEWAY_CONFIG` |
| `RCA_GATEWAY_HOST` | `DBAGENT_GATEWAY_HOST` |
| `RCA_GATEWAY_PORT` | `DBAGENT_GATEWAY_PORT` |
| `RCA_DASHBOARD_CONFIG` | `DBAGENT_DASHBOARD_CONFIG` |
| `RCA_DASHBOARD_HOST` | `DBAGENT_DASHBOARD_HOST` |
| `RCA_DASHBOARD_PORT` | `DBAGENT_DASHBOARD_PORT` |
| `RCA_SIGNING_KEY_PATH` | `DBAGENT_SIGNING_KEY_PATH` |
| `RCA_API_BASE_URL` | `DBAGENT_API_BASE_URL` |
| `RCA_API_UPSTREAM` | `DBAGENT_API_UPSTREAM` |
| `RCA_DOCROOT` | `DBAGENT_DOCROOT` |

The unprefixed names are unchanged and must **not** be prefixed:
`PROBE_CONFIG`, `PROBE_GATEWAY_CONFIG`, `BOOTSTRAP_TOKEN`,
`BOOTSTRAP_TOKEN_FILE`, `PG_DSN`, `S3_ENDPOINT`/`S3_ACCESS_KEY`/`S3_SECRET_KEY`,
`LITELLM_MASTER_KEY`, `DASHBOARD_JWT_SECRET`, `ADMIN_USERNAME`,
`ADMIN_INITIAL_PASSWORD`, `POSTGRES_*`.

The rest of the rename is breaking in the same release and is not migrated for
you (§11.2.3 C.1): the chart directories and names (`deploy/charts/dbagent`,
`deploy/charts/dbagent-probe`), the image coordinates — the registry namespace
moves to `dbagent`, and `deploy/versions.env`'s `REGISTRY` is the single
authoritative source for it — the fixed Secret name
`dbagent-signing-key`, the `app.kubernetes.io/name` labels — which are
immutable selectors, so this is a **reinstall, not an upgrade** — the container
paths (`/etc/dbagent`, `/etc/dbagent-probe`, `/var/lib/dbagent-probe`), the
compose project names (`dbagent-control-plane`, `dbagent-probe`), and the
database/user, S3 bucket and Temporal namespace defaults (all now `dbagent`).
Each of the last three is a configuration value, so an existing deployment
keeps its data by pinning the old value explicitly (`PG_DSN`,
`storage.s3.bucket`, `temporal.namespace`) rather than by migrating anything.
A probe with an existing state volume must have it remounted at
`/var/lib/dbagent-probe` or re-enroll with a fresh bootstrap token.

## Notes

- `helm uninstall` leaves hook-created resources (app Secret, bundled PG if any,
  and the signing-key Secret created over the API). Full teardown commands are
  in `docs/deployment/kubernetes.md` **Uninstall**. Deleting the signing-key
  Secret rotates the fleet's trust root — avoid unless intentional.
- Image-only rollbacks that skip `helm rollback` still need matching schema and
  signing keys.
