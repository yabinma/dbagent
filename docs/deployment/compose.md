# Deploy with Docker Compose

```bash
# Infrastructure only (M1 behaviour)
docker compose -f deploy/compose/control-plane.yml up -d

# Full product (profile apps)
docker compose -f deploy/compose/control-plane.yml --profile apps up -d
```

Pins live in `deploy/versions.env`. Application images must be built first via `deploy/docker/build.sh`.
