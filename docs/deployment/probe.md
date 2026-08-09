# Probe deployment

One probe per Presto cluster (D11).

- **Kubernetes:** `deploy/charts/rca-probe` — read Role always bound; write Role only when `writeEnabled: true`.
- **Compose:** `deploy/compose/probe.yml` with read-only Docker socket.
- **Swarm:** `deploy/compose/probe-swarm-stack.yml`.

## Health probes

The probe process opens **no listening port**. Its Deployment therefore carries no HTTP liveness/readiness probe; readiness is observed via platform status (`GET /platforms` → `online`) after registration.
