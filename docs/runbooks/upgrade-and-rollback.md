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
   kubectl -n rca get deploy -o wide
   # alembic version_num from the migrate Job logs or a one-off psql query
   ```

## Upgrade procedure

1. Bump `global.appVersion` / image tags (or pull the new chart version).
2. Dry-render and inspect hooks:
   ```bash
   helm template rca-agent deploy/charts/rca-agent -f your-values.yaml | less
   ```
3. Apply:
   ```bash
   helm upgrade rca-agent deploy/charts/rca-agent -n rca \
     -f your-values.yaml --wait --timeout 10m
   ```
4. Hook order (design §11.1.3): app Secret (−35) → migrate (−20) → signing-key
   (−10) → main Deployments → bootstrap-admin / seed-playbooks (post).
   Bundled PostgreSQL is **pre-install only** and is not recreated on upgrade
   (when enabled for dev).
5. Verify:
   - all Deployments Ready
   - migrate Job succeeded; schema at expected revision
   - `rca-agent-signing-key` **byte-identical** before/after (D14 — the
     signing-key Job must not regenerate)
   - `GET /healthz` on ingest, dashboard-api, probe-gateway, dashboard-web
   - probes still `online`

## Rollback procedure

1. `helm rollback rca-agent <revision> -n rca --wait`
2. If a forward migration is not backward-compatible, restore the database from
   the pre-upgrade backup first (`backup-restore.md`), then roll the chart back.
3. Confirm signing-key Secret still matches enrolled probes; if it was manually
   replaced, follow `signing-key-rotation.md`.

## Notes

- `helm uninstall` leaves hook-created resources (app Secret, bundled PG if any,
  and the signing-key Secret created over the API). Full teardown commands are
  in `docs/deployment/kubernetes.md` **Uninstall**. Deleting the signing-key
  Secret rotates the fleet's trust root — avoid unless intentional.
- Image-only rollbacks that skip `helm rollback` still need matching schema and
  signing keys.
