# Architecture

How the six product images fit together, where each one runs, and how they
talk to each other. See `docs/deployment/{kubernetes,swarm,compose}.md` for
how to stand a topology up, `docs/security.md` for the trust model in detail,
and `docs/toolpack-reference.md` for the tool catalog the probe exposes.

## Services

| Image | Language | Responsibility | Listens on |
|---|---|---|---|
| `dashboard-web` | React + nginx (unprivileged) | Static SPA; nginx reverse-proxies `/api/*` to dashboard-api so the browser only ever sees one origin. | `:8080` (container) |
| `dashboard-api` | Python/FastAPI | Admin auth (JWT), platform CRUD, bootstrap-token issuance, investigations/playbooks/audit views. Doubles as the image for the `dbagent-dashboard-bootstrap-admin` one-shot. | `:8081` |
| `ingest-gateway` | Python/FastAPI | External front door: `POST /api/v1/events`. Verifies the source's HMAC, normalizes/dedups/correlates the alert, and starts a Temporal `InvestigationWorkflow`. | `:8080` |
| `temporal-worker` | Python | Runs `InvestigationWorkflow` and every Activity (planner, collector, RCA, remediation planning/execution/verification, audit, notifications) by polling the `rca-worker` Temporal task queue. No inbound listener. Same image backs three one-shot jobs: `migrate` (alembic), `signing-key` (generates the ed25519 signing key), `seed-playbooks`. | — |
| `probe-gateway` | Go | The only control-plane service that talks to probes. Terminates probes' outbound mTLS gRPC sessions, runs bootstrap enrollment, and exposes a control-plane-internal plaintext HTTP API (`POST /internal/v1/execute`) so temporal-worker can dispatch tool calls to whichever probe owns a given `platform_key`. | `:8443` (gRPC session), `:8444` (gRPC bootstrap), `:8080` (`internal_listen_addr`, internal HTTP dispatch) |
| `probe` | Go | Runs next to the thing being investigated. Reads the target's own API/config and the local container runtime (Kubernetes API or Docker Engine API) for logs/JVM diagnostics/resource stats, and — only when write-enabled — executes signed remediation steps. One per monitored platform. | — (outbound only) |

Supporting infrastructure (not product images, but part of every deployment):
PostgreSQL (cases/audit/registry/traces/playbooks/users, and Temporal's own
persistence backend, in separate databases on the same instance), an
S3-compatible store (evidence payloads, raw alert payloads, LLM
prompts/responses), the Temporal server itself, and `model-gateway` (a LiteLLM
proxy in front of whichever LLM backends are configured — local vLLM/Ollama,
Bedrock, Vertex, Azure, or a provider's API directly).

All control-plane services are stateless and horizontally scalable except
`probe-gateway`, which shards connection ownership by `platform_key` (recorded
in PostgreSQL) — a single replica is sufficient below that scale.

## Two domains: control plane and data plane

The six services split into two groups that are deployed, and often run,
completely separately:

- **Control plane** — `dashboard-web`, `dashboard-api`, `ingest-gateway`,
  `temporal-worker`, `probe-gateway`, plus Postgres/Temporal/S3/model-gateway.
  One instance serves any number of monitored platforms. Ships as a Helm chart
  (`deploy/charts/dbagent`) or a Compose project (`deploy/compose/control-plane.yml`,
  `--profile apps`).
- **Data plane** — one `probe` per monitored platform, deployed *at* that
  platform: a Kubernetes Deployment in the target namespace
  (`deploy/charts/dbagent-probe`) or a Docker Swarm service attached to the
  target's own overlay network (`deploy/compose/probe-swarm-stack.yml`). The
  probe needs read access to the platform's runtime (and Docker-socket or K8s
  API reach), so it deliberately runs as close to it as possible rather than
  as part of the control plane.

Nothing on the data-plane side needs an inbound port opened to it — see
*Communication paths* below.

```
┌────────────────────────── Control Plane ───────────────────────────────┐
│                                                                        │
│  ingest-gateway ──start_workflow──▶ Temporal Server ◀── temporal-worker│
│   (FastAPI)                         (PG backend)         │ Workflow:   │
│      ▲ HMAC webhook                                      │ Investigation
│      │                                                   │ Activities: │
│  [alert sources]                                         │ plan/collect│
│                                                          │ /analyze/   │
│  dashboard-api ◀──────── PostgreSQL ────────────────────▶│ remediate/  │
│  (FastAPI)               (cases/audit/trace/registry)    │ verify/audit│
│      │                        │                          │      │      │
│  dashboard-web            S3-compatible store             │      ▼      │
│  (React)                  (evidence/large payloads)  model-gateway     │
│                                                       (LiteLLM Proxy)   │
│  probe-gateway (Go) ◀── Activity calls (:8080 internal)   │ vLLM/Ollama,│
│      ▲ gRPC bidi stream (probe connects outbound)          │ Bedrock,    │
└──────┼───────────────────────────────────────────────────│ Vertex, ... │
       │                                                                  │
┌──────┼───────── Data Plane (co-located with target) ─┬────────────────┘
│   probe (Go, one per monitored platform)              │
│   K8s: Deployment + RBAC        Swarm: service + docker socket        │
│   ├─ read-only diagnostic channel (Toolpack + gated raw commands)     │
│   ├─ write channel (signed RemediationSteps only)                     │
│   └─ credentials: mounted K8s/Docker Secret (fixed path)              │
│         │ REST/SQL /v1/*        │ K8s API / Docker Engine API         │
│      Presto coordinator        runtime environment                    │
└─────────────────────────────────────────────────────────────────────────┘
```

(design.md §3.1 — this file mirrors that diagram; §3.1 is the source of truth
if the two ever disagree.)

## Communication paths

**1. Alert ingestion.** An external source (Grafana, etc.) posts to
`ingest-gateway`'s `POST /api/v1/events`. After HMAC verification and
fingerprint dedup/correlation, ingest-gateway starts an `InvestigationWorkflow`
on the Temporal server (`:7233`).

**2. Investigation execution.** `temporal-worker` polls the `rca-worker` task
queue and runs the workflow's Activities (plan → collect → analyze →
remediate → verify → audit), calling out to `model-gateway` for LLM calls and
to `probe-gateway` for anything that needs the target platform.

**3. Tool dispatch (collector/remediation → probe).** An Activity calls
probe-gateway's internal HTTP API, `POST /internal/v1/execute`
(`probe_gateway.url`, default `:8080`, cluster-internal only — `docs/security.md`
*Network posture*). probe-gateway looks up which live gRPC session owns the
request's `platform_key`, forwards the task down that session, waits
synchronously, and returns the result over HTTP. This endpoint's response is a
reduced `{task_id, exit_code, data, redacted, truncated}` shape — not the same
as the signed `ToolResultEnvelope` the probe produces internally — since it is
a trusted intra-control-plane call, not the untrusted probe↔gateway link.

**4. Probe ↔ probe-gateway (the only data-plane link).** The probe always
initiates. It bootstraps once against `:8444` with a single-use token (mTLS
client certificate issued on success — design.md §8.4a), then holds a
long-lived mTLS gRPC session on `:8443` over which probe-gateway pushes
ToolCall/RawCommand/Write tasks and the probe streams results back. **Zero
inbound ports on the data-plane side** — this is why a probe can sit inside a
customer's Swarm/K8s cluster with no firewall exception needed.

**5. Probe → target platform.** Two mechanisms, both local to wherever the
probe runs: the platform's own REST/SQL API (read-only account), and the local
container runtime — Kubernetes API (RBAC-scoped `get/list/watch`) or the
mounted Docker Engine API socket. Any config-shaped output is redacted
(key-based and value-based; design.md §8.2) before it ever leaves the probe.

**6. Registration.** `Registration Flow v3` (design.md §8.4): create the
platform in the dashboard → issue a bootstrap token → deploy the probe with it
→ probe auto-detects deployment kind, Presto version, auth scheme, TLS →
reports a manifest and either goes straight `online` (no-auth target) or
`pending_credentials` (the dashboard then shows copy-paste
`kubectl create secret` / `docker secret create` instructions) → probe detects
the credentials appearing and re-runs its connectivity test → `online`.

**7. Dashboard.** The browser talks only to `dashboard-web`'s origin;
`dashboard-web`'s nginx proxies `/api/*` to `dashboard-api` server-side, so
there is no separate origin or CORS configuration involved.

**8. Remediation (write channel).** Only reachable when a platform has
`write_enabled: true`. Each `RemediationStep` is signed by temporal-worker's
ed25519 key before dispatch through the same probe-gateway path as step 3; the
probe verifies the signature against its current (or, during rotation,
previous) signing key before executing anything mutating. The write channel
never accepts ad-hoc writes from the investigation loop directly — only
pre-signed steps.

## Where each service runs, per deployment kind

| | Kubernetes | Docker Swarm | Docker Compose (dev/e2e) |
|---|---|---|---|
| Control plane | `deploy/charts/dbagent` (one Helm release) | `deploy/compose/control-plane.yml --profile apps` | same file, no `--profile apps` needed beyond infra-only mode |
| probe | `deploy/charts/dbagent-probe` (Deployment + RBAC, in the target namespace) | `deploy/compose/probe-swarm-stack.yml` (service on a manager node, joined to the target's *existing* overlay network) | `deploy/compose/probe.yml` (single container, `host.docker.internal`) |

The Swarm and Kubernetes cases are the two the M6 real-cluster acceptance
walkthrough exercises (`docs/acceptance/m6-real-cluster-walkthrough.md`);
Compose is the local/CI-only path.
