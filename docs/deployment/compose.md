# Deploy with Docker Compose

```bash
# Infrastructure only (M1 behaviour)
docker compose -f deploy/compose/control-plane.yml up -d

# Full product (profile apps)
docker compose -f deploy/compose/control-plane.yml --profile apps up -d
```

Pins live in `deploy/versions.env`. Application images must be built first via `deploy/docker/build.sh`.

The compose project is `dbagent-control-plane`, and the application database,
user and password all default to `dbagent` (design.md §11.2.3 C.4). **Changing
`POSTGRES_DB` does not rename anything inside an already-initialized volume — it
silently creates an empty database**, so an operator upgrading from the previous
defaults keeps their data by setting `PG_DSN` explicitly instead
(`docs/runbooks/upgrade-and-rollback.md` names the old values).
The same reasoning and the same escape hatch apply to the S3 bucket
(`storage.s3.bucket`) and the Temporal namespace (`temporal.namespace`), whose
defaults are also now `dbagent`.

After the one-shot jobs complete, **change the bootstrap admin password**
(`POST /auth/change-password`) before any other dashboard call:
`bootstrap_admin` creates the account with `must_change_password=true`, and every
other endpoint returns 403 `password_change_required` until then.
