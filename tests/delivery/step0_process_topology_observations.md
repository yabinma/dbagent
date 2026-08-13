# Step 0 — live classified process trees (unchanged images)

Recorded **before** any errata-pass-8 implementation work, from images
built at head `2a2e348` (`deploy/docker/build.sh` inputs as they stand).
Enumeration: host-side `/proc/<pid>/task/*/children` walk of each
container's init PID (`docker inspect .State.Pid`), identity from
`/proc/<pid>/comm` and `/proc/<pid>/cmdline`, plus `docker top`.
This is the local-container form of §11's node-side `crictl` + `/proc`
mechanism (design.md §11.3.5 batch step 0).

**Stack:** Linux 6.8.0-137-generic x86_64, 16 cores, Docker 28.3.3
(rootless), Python 3.12.3. Images tagged `step0/<name>:shipped` and
`<name>:sha-2a2e348` (product tag; registry from `deploy/versions.env`).

| Image | Image id (sha256 prefix) | Entrypoint | Observed tree | Table row | Verdict |
|---|---|---|---|---|---|
| `dashboard-web` | `8c2f04533e44…` | `/docker-entrypoint.sh` → exec `nginx -g "daemon off;"` | **1** nginx master (`nginx: master process nginx -g daemon off;`) + **16** nginx workers (`nginx: worker process`); every process `comm=nginx`. `worker_processes auto;` in the image config (autotune script not armed). Count tracks host cores (16). | one nginx master + ≥ 1 nginx workers, every process `nginx` (shape, not a count) | **MATCH** |
| `temporal-worker` | `1a0fad5e2eca…` | `python -m worker.worker_main` | **1** process, `comm=python`, cmdline `python -m worker.worker_main`; `/proc/.../task/*/children` empty | exactly 1 | **MATCH** |
| `dashboard-api` | `8dc725f9f65f…` | `dbagent-dashboard-api` | **1** process, `comm=dbagent-dashboa`, cmdline `/opt/venv/bin/python /opt/venv/bin/dbagent-dashboard-api`; no children | exactly 1 | **MATCH** |
| `probe-gateway` | `8239e3235bba…` | `/usr/local/bin/probe-gateway` | **1** process, `comm=probe-gateway`, cmdline `/usr/local/bin/probe-gateway`; several threads, **zero** child processes (`docker top` one row) | exactly 1 (Go static binary) | **MATCH** |
| `probe` | `c3321b8ca761…` | `/usr/local/bin/probe` | exec-form single static binary on `gcr.io/distroless/static:nonroot`. Live serving snapshot is blocked by enrollment (no real gateway); every start observed a single `/usr/local/bin/probe` process and no descendants before exit. Same packaging as `probe-gateway`, which was observed live at cardinality 1. | exactly 1 (Go static binary) | **MATCH** |

`dashboard-web` only reaches the master+workers shape once nginx finishes
startup. With the image default upstream `dashboard-api` unresolvable,
nginx exits at `[emerg] host not found in upstream` after the master
alone is visible. Observation used `DBAGENT_API_UPSTREAM=http://127.0.0.1:9/`
so the serving tree is the one the table describes; `/healthz` returned 200.

No row mismatched Section 11's table. Implementation proceeds.

# Step 2 — live classified process tree (rebuilt ingest-gateway)

Recorded **after** FP-IG-20's `create_worker_app` / `workers=W` landing, from
the freshly built image (`deploy/docker/ingest-gateway.Dockerfile` with the
working-tree `gateway.main`). Same host-side `/proc/<pid>/task/*/children`
walk of the container init PID as step 0, identity from `comm`/`cmdline`,
plus `docker top`. This is §11.3.5 batch step 2's gate: compare the built
image's classified tree to Section 11's `ingest-gateway` row and stop on
mismatch.

**Stack:** Linux 6.8.0-137-generic x86_64, 16 cores, Docker 28.3.3
(rootless), Python 3.12.3. Image tagged `step2/ingest-gateway:new` and
`ingest-gateway:step2` (product tag; registry from `deploy/versions.env`).
Serving snapshot used a
Temporal auto-setup (`temporalio/auto-setup:1.24.2`) on the same docker
network so worker lifespan `Client.connect` could complete; `/healthz`
returned 200. In-image stack: uvicorn 0.52.2, Python 3.12.13.

| Image | Image id (sha256 prefix) | Entrypoint | Observed tree | Table row | Verdict |
|---|---|---|---|---|---|
| `ingest-gateway` | `211b928b9c07…` | `python -m gateway.main` | **1** uvicorn supervisor (`comm=python`, cmdline `python -m gateway.main`) + **1** `multiprocessing.resource_tracker` (`/opt/venv/bin/python -B -c from multiprocessing.resource_tracker import main;main(6)`) + **4** serving workers (`/opt/venv/bin/python -B -c from multiprocessing.spawn import spawn_main; spawn_main(...) --multiprocessing-fork`). Supervisor children = tracker + 4 spawn workers. Roles distinguished by cmdline. W=4 from `DBAGENT_GATEWAY_WORKERS`. | exactly `W + 2`: one supervisor, one resource_tracker, W spawn workers | **MATCH** |

No mismatch. The table's ingest-gateway census holds on the built image.
