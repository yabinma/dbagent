# Probe deployment

One probe per Presto cluster (D11).

- **Kubernetes:** `deploy/charts/dbagent-probe` — read Role always bound; write Role only when `writeEnabled: true`.
- **Compose:** `deploy/compose/probe.yml` with read-only Docker socket and required `DOCKER_SOCKET_GID` (`group_add`).
- **Swarm:** `deploy/compose/probe-swarm-stack.yml` — same socket + `DOCKER_SOCKET_GID` via `user: "65532:${DOCKER_SOCKET_GID}"` (Swarm rejects `group_add`).

On Docker/Swarm the image runs as non-root 65532. Export the host docker group
GID before deploy (`export DOCKER_SOCKET_GID="$(stat -c '%g' /var/run/docker.sock)"`);
details in `docs/deployment/swarm.md`.

## Health probes

The probe process opens **no listening port**. Its Deployment therefore carries no HTTP liveness/readiness probe; readiness is observed via platform status (`GET /platforms` → `online`) after registration.
