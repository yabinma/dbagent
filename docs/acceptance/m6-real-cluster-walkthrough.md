# M6 real-cluster walkthrough

status: pending

Human acceptance gate (not a CI job). Run the two-phase walkthrough against
real Presto 0.298 infrastructure — one Kubernetes cluster and one Docker Swarm
cluster — and paste each run's report into the matching block below.

## The procedure (design.md §11.2.3 E.1)

Seven steps. Steps 3, 4 and 6 are the reason this is two phases: the driver
cannot deploy your probe, and a probe deployed *with* credentials never enters
the state this gate is about.

1. **Create the platform** in the dashboard — driver, phase 1. Idempotent: an
   existing platform is accepted, `409` included.
2. **Admissibility gate, then issue the one-time bootstrap token** — driver,
   phase 1. The gate reads the platform's status *before* any token call; a
   platform that is already `online`, `degraded` or `offline` is refused here,
   without issuing anything.
3. **Hand the token to the operator** — driver, phase 1. The raw token is
   written to `--token-out` with mode `0600` and nowhere else: not to the
   report, not to stdout, not to the log. The admin API returns the token only
   from the issue call, so there is no second chance to read it.
4. **Deploy the probe WITHOUT the platform credentials**, using the token from
   step 3 — operator, while phase 1 is polling. No `platform-credentials`
   Secret on Kubernetes; no `platform_username` / `platform_password` Docker
   secrets on Swarm.
5. **Phase 1 polls until the platform reports `pending_credentials`** and
   writes the phase-1 artifact.
6. **Install the credentials** — operator: `kubectl create secret` /
   `docker secret create` + `docker service update --secret-add`. Nothing else
   changes; do **not** redeploy the probe by hand, because the automatic
   transition is what step 7 exists to witness.
7. **Phase 2 resumes the artifact**, polls until `online`, runs every Toolpack
   tool, removes the now-consumed token file, and writes the complete report.

### Invocations

**Admin password.** Shipped Compose and Helm initialize the bootstrap admin with
`ADMIN_INITIAL_PASSWORD` defaulting to `admin-change-me`. The walkthrough
driver's CLI default is `admin`, which will not authenticate against a fresh
default deployment — always pass the real value explicitly (or set
`E2E_ADMIN_PASS`). The phase-1 artifact deliberately carries no credential, so
phase 2 must receive the **same effective password** as phase 1: either the
initial value again, or the value set via `--new-admin-password` /
`E2E_ADMIN_NEW_PASS` if phase 1 performed the forced first-login change.

Phase 1 (leave it running; perform step 4 in another terminal):

```bash
python tests/e2e/manual/real_cluster_walkthrough.py \
  --phase pre-credentials \
  --deployment k8s --platform-key <PLATFORM_KEY> \
  --dashboard-url https://<dashboard-host> \
  --admin-password "${ADMIN_INITIAL_PASSWORD:-admin-change-me}" \
  --out phase1.json --token-out ./bootstrap-token.txt
```

Phase 2, after step 6 — pass the **same** `--token-out` you gave phase 1, and
the **effective** admin password (same as phase 1 unless you set a new one):

```bash
python tests/e2e/manual/real_cluster_walkthrough.py \
  --phase post-credentials --resume phase1.json \
  --deployment k8s --platform-key <PLATFORM_KEY> \
  --dashboard-url https://<dashboard-host> \
  --execute-url http://<probe-gateway-internal>:8080 \
  --admin-password "${ADMIN_INITIAL_PASSWORD:-admin-change-me}" \
  --out walkthrough-report.json --token-out ./bootstrap-token.txt
```

A signed-off report must carry
`registration.pending_credentials_witnessed: true` and
`summary.failures == 0`, and must never carry a `bootstrap_token` key — the
report is committed here, and the bootstrap token is a live single-use
credential. The driver replaces it with `bootstrap_token_issued` and
`bootstrap_token_sha256`.

## Kubernetes deployment

```
deployment: k8s
presto_version: 0.298
platform_key:
cluster:
date:
operator:
```

report (paste the contents of `walkthrough-report.json`):

```json
```

## Swarm deployment

```
deployment: swarm
presto_version: 0.300
platform_key: presto-b6971n
cluster: small-0.300-202608080729-262d89e8-b6971n-Yabin-Ma-eng (engyabinmab6971n.ibm.prestodb.dev)
date: 2026-08-10
operator: Max Ma
```

report (paste the contents of `walkthrough-report.json`):

```json
{
  "phase": "complete",
  "deployment": "swarm",
  "platform_key": "presto-b6971n",
  "started_at": "2026-08-10T13:04:10.029961+00:00",
  "finished_at": "2026-08-10T13:12:07.833361+00:00",
  "presto_version": "0.300",
  "tools": [
    {"name": "presto_list_queries", "args": {"state": "ALL", "since": "1h", "limit": 20}, "ok": true, "envelope_valid": true, "error": null},
    {"name": "swarm_tasks", "args": {}, "ok": true, "envelope_valid": true, "error": null},
    {"name": "presto_cluster_info", "args": {}, "ok": true, "envelope_valid": true, "error": null},
    {"name": "presto_config", "args": {"component": "coordinator", "file": "config"}, "ok": true, "envelope_valid": true, "error": null},
    {"name": "presto_jmx", "args": {"mbean": "heap"}, "ok": true, "envelope_valid": true, "error": null},
    {"name": "presto_nodes", "args": {"include_failed": true}, "ok": true, "envelope_valid": true, "error": null},
    {"name": "presto_query_detail", "args": {"query_id": "20260810_130650_00018_zbtpu", "sections": ["basic", "error", "stats"]}, "ok": true, "envelope_valid": true, "error": null},
    {"name": "presto_query_json_section", "args": {"query_id": "20260810_130650_00018_zbtpu", "jsonpath": "$.queryStats"}, "ok": true, "envelope_valid": true, "error": null},
    {"name": "presto_session_properties", "args": {}, "ok": true, "envelope_valid": true, "error": null},
    {"name": "jvm_heap_histo", "args": {"target": "c8fc0f3992261cd8bd98165032f17abddf9bec99c77242b98fc9c7aa3882deb6", "top": 20}, "ok": true, "envelope_valid": true, "error": null},
    {"name": "jvm_thread_dump", "args": {"target": "c8fc0f3992261cd8bd98165032f17abddf9bec99c77242b98fc9c7aa3882deb6"}, "ok": true, "envelope_valid": true, "error": null},
    {"name": "container_logs", "args": {"target": "c8fc0f3992261cd8bd98165032f17abddf9bec99c77242b98fc9c7aa3882deb6", "since": "30m", "lines": 200}, "ok": true, "envelope_valid": true, "error": null},
    {"name": "docker_events", "args": {"since": "1h", "type": "warning"}, "ok": true, "envelope_valid": true, "error": null},
    {"name": "docker_inspect", "args": {"target": "c8fc0f3992261cd8bd98165032f17abddf9bec99c77242b98fc9c7aa3882deb6"}, "ok": true, "envelope_valid": true, "error": null},
    {"name": "k8s_describe", "args": {}, "ok": false, "envelope_valid": false, "skipped": true, "reason": "k8s-only tool; deployment=swarm (Appendix B.2 pair not registered by the probe)", "error": null},
    {"name": "k8s_events", "args": {}, "ok": false, "envelope_valid": false, "skipped": true, "reason": "k8s-only tool; deployment=swarm (Appendix B.2 pair not registered by the probe)", "error": null},
    {"name": "k8s_pods", "args": {}, "ok": false, "envelope_valid": false, "skipped": true, "reason": "k8s-only tool; deployment=swarm (Appendix B.2 pair not registered by the probe)", "error": null},
    {"name": "pod_logs", "args": {}, "ok": false, "envelope_valid": false, "skipped": true, "reason": "k8s-only tool; deployment=swarm (Appendix B.2 pair not registered by the probe)", "error": null},
    {"name": "resource_usage", "args": {"selector": "all"}, "ok": true, "envelope_valid": true, "error": null}
  ],
  "registration": {
    "mode": "two_phase",
    "steps": [
      {"ok": true, "status_code": 201, "name": "create_platform"},
      {"ok": true, "status_code": 200, "name": "issue_bootstrap_token"},
      {"polls": 11, "ok": true, "observed_at": "2026-08-10T13:04:41.970127+00:00", "name": "start_probe_without_credentials", "status": "pending_credentials"},
      {"name": "install_credentials", "ok": true, "note": "operator installs the Secret / Docker secret out of band; the probe is not redeployed, because the automatic transition is what the next step exists to witness"},
      {"name": "assert_online", "status": "online", "ok": true, "observed_at": "2026-08-10T13:06:05.784954+00:00", "polls": 1}
    ],
    "bootstrap_token_sha256": "sha256:fe73a367691dbc54bd52125ceb443b5d930c32875b85d73b34277cd539019b0a",
    "gate_status": "created",
    "pending_credentials_witnessed": true,
    "bootstrap_token_issued": true,
    "auth": {"password_changed": true},
    "token_file_removed": true
  },
  "summary": {"tools_total": 19, "tools_ok": 15, "tools_skipped": 4, "failures": 0}
}
```
