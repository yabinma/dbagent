# Delivery-artifact tests

Hermetic offline assertions for Dockerfiles, Helm charts, compose files, docs,
and the CI workflow (design.md §11.1.3).

**Required tools (hard failure if missing, never skip):**

- `helm` — pin `HELM_VERSION` in `deploy/versions.env`
- `docker` / `docker compose` — for compose config validation

Runs inside the CI `functional` job via `tests/delivery` on the pytest path.
