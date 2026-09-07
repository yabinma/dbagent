# dbagent

> We recognize AI's capabilities and firmly believe it can greatly enhance human productivity. Yet throughout the production process, humans always bear unshirkable responsibility. Therefore, when designing AI systems, we uphold one core principle: **Trust, but verify.**

**Self-hosted, open-source root-cause-analysis and remediation agent for data
platforms.**

An alert arrives on a webhook; dbagent opens an investigation and drives an
iterative *collect → analyze → collect again* loop against the live platform
until it reaches a confident root cause, then proposes a remediation that a
human approves in the dashboard before it is executed and verified. Every
round, command, model call, cost and approver is persisted, auditable and
replayable.

- **Target platform (Phase 1):** PrestoDB 0.295–0.299 (assertions baselined on
  0.298), running on Kubernetes or Docker Swarm.
- **Deployment:** self-hosted only — Helm umbrella chart, or Docker
  Compose/Swarm. No SaaS.
- **Deliberately out of scope:** anomaly detection and alerting (dbagent starts
  from an alert you already have), and automatic code PRs (it reports the code
  location and a fix suggestion, it does not merge).
- **License:** Apache-2.0.

Full operator documentation lives in [`docs/`](docs/README.md).

## How it works

1. **Ingest** — an alert source (Grafana, Jenkins, a human, anything that can
   POST) sends an HMAC-signed event to `ingest-gateway`'s `POST /api/v1/events`.
   The event is normalized, deduplicated and correlated by fingerprint, and
   starts a Temporal `InvestigationWorkflow`.
2. **Investigate** — `temporal-worker` runs the loop: plan → collect evidence
   from the platform through the probe → analyze with an LLM → collect again.
   The loop is bounded on three axes at once (rounds, cost, wall time), all
   configurable per platform.
3. **Conclude** — the investigation produces an RCA report and dispositions the
   proposed action into one of three tiers: *ignore* (summary only),
   *auto-remediate* (playbooks that passed a maturity threshold; disabled at
   launch) or *approve-then-remediate*.
4. **Approve** — a human approves in the dashboard's approval queue. Every
   mutating step is signed by the control plane and verified by the probe
   before it executes.
5. **Verify** — after remediation, dbagent re-checks the platform and closes
   the case as resolved, or reopens it.
6. **Audit** — every iteration, tool call, prompt/response and approval is
   persisted; evidence payloads go to object storage, traces to the built-in
   trace store (or Langfuse, by config switch).

## Components

Six product images. See [`docs/architecture.md`](docs/architecture.md) for
ports, communication paths and the deployment topology.

| Image | Language | Responsibility |
|---|---|---|
| `dashboard-web` | React + nginx | The SPA operators use; nginx proxies `/api/*` to `dashboard-api` so the browser sees one origin. |
| `dashboard-api` | Python/FastAPI | Admin auth, platform CRUD, bootstrap-token issuance, investigations / approvals / audit / metrics endpoints. |
| `ingest-gateway` | Python/FastAPI | The external front door for alert events: HMAC verification, dedup/correlation, workflow start. |
| `temporal-worker` | Python | Runs the investigation workflow and all of its activities (plan, collect, RCA, remediation, verification, audit, notifications). |
| `probe-gateway` | Go | The only control-plane service probes talk to: terminates their outbound mTLS gRPC sessions and dispatches tool calls to the probe owning a given platform. |
| `probe` | Go | Runs next to the monitored platform. Reads the platform's API and the local runtime (Kubernetes API / Docker Engine API); executes signed remediation steps only when write-enabled. One per platform. |

Supporting infrastructure, part of every deployment but not built here:
PostgreSQL, an S3-compatible object store, the Temporal server, and
`model-gateway` (a LiteLLM proxy fronting whichever LLM backends you configure
— local vLLM/Ollama, Bedrock, Vertex, Azure, or a provider API).

## Architecture

The system splits into two domains that are deployed separately:

- **Control plane** — the five control-plane services plus
  Postgres/Temporal/S3/model-gateway. One instance serves any number of
  monitored platforms.
- **Data plane** — one `probe` per monitored platform, deployed *at* that
  platform. The probe always dials out, so **no inbound port is opened on the
  data-plane side**.

Component diagram, per-service ports, the six communication paths and the
per-deployment-kind placement table:
[`docs/architecture.md`](docs/architecture.md). Trust model, redaction and
network posture: [`docs/security.md`](docs/security.md).

## Getting started

### 1. Install the control plane

| Target | Guide |
|---|---|
| Kubernetes (Helm) | [`docs/deployment/kubernetes.md`](docs/deployment/kubernetes.md) |
| Docker Compose (evaluation / dev) | [`docs/deployment/compose.md`](docs/deployment/compose.md) |

Images are built from this repo with `deploy/docker/build.sh`; every external
image and toolchain version is pinned in
[`deploy/versions.env`](deploy/versions.env).

After the one-shot install jobs finish, log in to the dashboard as the
bootstrap admin and **change the password** — every other endpoint returns
`403 password_change_required` until you do.

### 2. Onboard a Presto platform

The registration flow is deliberately credential-less at the start: the control
plane never stores platform credentials.

1. Create the platform in the dashboard, and issue a **single-use bootstrap
   token** for it.
2. Deploy the probe next to that platform with the token —
   [`docs/deployment/probe.md`](docs/deployment/probe.md) for the three
   deployment kinds, [`docs/deployment/swarm.md`](docs/deployment/swarm.md) for
   the full Swarm sequence.
3. The probe enrolls over mTLS, auto-detects the deployment kind, Presto
   version, auth scheme and TLS, and reports its manifest. It goes straight to
   `online` for a no-auth target, or to `pending_credentials` otherwise.
4. For `pending_credentials`, create the platform-credentials Secret the
   dashboard shows you (`kubectl create secret` / `docker secret create`). The
   probe notices it, re-runs its connectivity test, and goes `online`.

### 3. Point your alert source at the gateway

Send alert events to `POST /api/v1/events` on `ingest-gateway`, signed with the
shared HMAC secret. Outbound notifications (Slack-compatible webhooks) are
configured per [`docs/notifications.md`](docs/notifications.md).

### 4. Work cases in the dashboard

Overview → cases → case detail (rounds, evidence, RCA report, cost and trace)
→ approval queue → admin. Write-channel remediation is only reachable for
platforms explicitly configured with `write_enabled: true`.

### Reference and operations

- [Configuration reference](docs/configuration.md) — every control-plane,
  probe and probe-gateway config key.
- [Toolpack reference](docs/toolpack-reference.md) — the catalog of read-only
  tools and write-ops the probe exposes.
- [Security](docs/security.md) — mTLS bootstrap, write-channel signing, secret
  handling, redaction, network posture.
- Runbooks — [signing-key rotation](docs/runbooks/signing-key-rotation.md),
  [platform-credential rotation](docs/runbooks/platform-credential-rotation.md),
  [bootstrap-CA rotation](docs/runbooks/bootstrap-ca-rotation.md),
  [upgrade and rollback](docs/runbooks/upgrade-and-rollback.md),
  [backup and restore](docs/runbooks/backup-restore.md).

## Development

### Prerequisites

Python 3.12, Go 1.26.4, Node 20, Docker, Helm and kind — exact pins in
[`deploy/versions.env`](deploy/versions.env). Docker is required for more than
image builds: the functional and benchmark tiers spin up real ephemeral
Postgres/MinIO containers and a real Temporal dev server.

### Generated code — regenerate before your first build

`gen/go`, `gen/python`, `libs/py/rca_common/rca_common/schemas/generated` and
`web/src/types/generated` are gitignored and never committed:

```bash
scripts/gen-proto.sh                          # gen/go, gen/python  (from proto/*.proto)
schemas/generate-pydantic.sh                  # rca_common generated schemas (from schemas/*.schema.json)
cd schemas && npm ci && node generate-ts.js   # web/src/types/generated
```

CI regenerates these fresh in every job that needs them; see the
"Generated-code policy" note at the top of `.github/workflows/ci.yml`.

### Repository layout

```
proto/          gRPC contract (buf-managed) — single source of truth for probe ↔ probe-gateway
schemas/        JSON Schema source of truth (AlertEvent, RCAReport, Plan, …)
libs/py/        rca_common — shared Python library (config, signing, db)
services/       gateway/ worker/ dashboard-api/ (Python) · probe-gateway/ (Go)
probe/          the data-plane probe (Go)
web/            React dashboard
deploy/         charts/ (Helm) · compose/ · docker/ · versions.env
docs/           operator documentation
tests/          the cross-service tiers: functional/ benchmark/ delivery/ e2e/ mocks/
```

Unit tests live next to the code they test (a `tests/` subfolder per Python
project, `_test.go` files per Go package); the top-level `tests/` tree holds
only the cross-service tiers. `rca` survives as a *domain* noun (the
`rca_common` library, the `RCAReport` schema, the `rca` agent role) — the
product itself is `dbagent` everywhere.

### Running the tests

The commands below are exactly what CI runs, gate by gate
(`.github/workflows/ci.yml` is the source of truth).

**Unit — Python.** Each project gets its own venv, as in CI. The isolation is
deliberate: a shared venv hides a service importing a package its own image
does not install.

```bash
# rca_common (repeat the same shape for the other three)
cd libs/py/rca_common
python -m venv .venv && .venv/bin/pip install -e ".[test]"
.venv/bin/python -m pytest tests/ --cov=rca_common --cov-report=term-missing
bash ../../../scripts/py-coverage-check.sh 80 rca_common
```

| Project | Venv | Coverage modules |
|---|---|---|
| `libs/py/rca_common` | `libs/py/rca_common/.venv` | `rca_common` |
| `services/worker` | `services/worker/.venv` | `worker`, `scripts` |
| `services/gateway` | `services/gateway/.venv` | `gateway` |
| `services/dashboard-api` | `services/dashboard-api/.venv` | `dashboard_api` |

**Unit — Go and web:**

```bash
go test ./... -race -timeout 300s -p 1     # -p 1: packages spin up real Postgres testcontainers
bash scripts/go-coverage-check.sh 80

cd web && npm ci && npm test               # vitest + per-file coverage thresholds
```

**Functional** (checkpoint suite + the delivery-artifact tier). Needs Docker,
and `helm` on PATH — a missing binary is a hard failure, never a skip. This
tier runs from one combined venv:

```bash
python -m venv services/worker/.venv
services/worker/.venv/bin/pip install -e libs/py/rca_common \
  -e "services/worker[test]" -e "services/gateway[test]" -e "services/dashboard-api[test]"

services/worker/.venv/bin/python -m pytest \
  services/worker/tests services/gateway/tests services/dashboard-api/tests \
  tests/functional tests/delivery tests/mocks/llm -v \
  --ignore=tests/functional/m2_probe_link

go test ./tests/functional/... -timeout 300s   # real probe + probe-gateway over real mTLS
```

See [`tests/delivery/README.md`](tests/delivery/README.md) for what the
delivery tier asserts (Dockerfiles, charts, compose files, docs, `ci.yml`).

**Benchmark.** Every performance-sensitive path has an entry in
[`tests/benchmark/thresholds.yaml`](tests/benchmark/thresholds.yaml) with its
threshold and the test that measures it; the CI `benchmark` job runs one step
per entry. The Postgres-scale bars share one seeded fixture:

```bash
services/worker/.venv/bin/python -m pytest tests/benchmark/test_pg_scale.py -v -s
go test ./probe/internal/redact/... -run TestB5 -v      # e.g. redaction over a 1 MiB payload
```

Thresholds are calibrated against CI's reference runner (`ubuntu-latest`,
4 vCPU); a number measured on a bigger dev box is diagnostic only.

**End-to-end.** Fresh kind cluster → the whole product → real Presto → the
fault scenarios, on a 1500 s budget:

```bash
bash tests/e2e/run.sh          # KEEP_CLUSTER=1 to keep the cluster for debugging
```

Scenario table and fixture constraints:
[`tests/e2e/README.md`](tests/e2e/README.md).

### CI and the test bars

`lint → unit → functional → benchmark → e2e`, each gate blocking the next, plus
two independent jobs: `manifest-guard` (deliberately dependency-free, so a
skipped upstream job cannot skip the guard) and `images` (builds all six).

The bars CI enforces:

- 100% pass rate — no skips standing in for failures.
- \>80% line coverage at every level: per Go package, per Python module, per
  web directory. The only sanctioned exclusions are generated code and
  `main()`.
- A functional test per checkpoint in
  [`tests/functional/checkpoints.yaml`](tests/functional/checkpoints.yaml), and
  a benchmark per entry in `tests/benchmark/thresholds.yaml`. Both manifests
  carry an honesty rule enforced by `tests/functional/test_manifests.py`: an
  entry may not stay `deferred` or unmapped once the code it covers has
  shipped.
