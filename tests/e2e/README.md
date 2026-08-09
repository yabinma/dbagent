# e2e suite

Fresh kind cluster → green Section 13 scenarios (design.md §11.1 / §12 / §13).

```bash
bash tests/e2e/run.sh
```

Product budget: **1500 s** on `run.sh`'s clock (inside CI `timeout-minutes: 30`).

## Automated scenarios

| ID | §13 | Fault injection | Notes |
|---|---|---|---|
| E0 | — | none | install smoke + helm upgrade idempotence |
| B1 | 14.4 | none (load) | 1 000 alerts/s **paced** for 30 s (5× the 200/s base), 0 errors, p99 < 150 ms, and the entailed `audit_log` rows read back through dashboard-api |
| E1 | 13.1 | rewrite `query.max-memory-per-node` **inside** `data.config.properties` of `presto-worker-config` (the only key the worker mounts, via `subPath`), restart, then run a heavy `tpch` aggregation | RCA → `presto.adjust_memory_config` → approve → RESOLVED; settle window 15–60 s; the remediated value is read back off the real ConfigMap |
| E2 | 13.3 | mount a catalog `broken.properties` carrying a password sentinel on the coordinator | sentinel never in evidence; every `kubectl` step fails closed |
| E3 | 13.5 | switch the coordinator to the file resource-group manager (`hardConcurrencyLimit: 1`), submit 6 long joins, and confirm a `QUEUED` backlog through Presto's own `/v1/query` **before** the alert | CLOSED_SUMMARY, no playbook; the constraint is then removed and the backlog must drain |
| E4 | 13.6 | start a long-running query | `presto.kill_query` with the right `query_id` → RESOLVED |

## Manual / real-cluster

§13.2 (coordinator full-GC hang) and §13.4 (single-worker network isolation)
require real heap pressure / NetworkPolicy-enforcing CNI — see
`docs/acceptance/m6-real-cluster-walkthrough.md` and
`tests/e2e/manual/real_cluster_walkthrough.py`.

## E1 fixture constraints

E1's mock-LLM remediation fixture **must not** set `settle_seconds` on the
`presto.adjust_memory_config` action, and the workflow input must not set
`settle_seconds_override`. Phase 6 seeds `platforms.config.remediation.settle_seconds=15`.

It proposes **128MB**, not a larger value: the fixture JVM runs `-Xmx1G` and
`query.max-total-memory-per-node` is `256MB`, so anything above that is
incompatible with the cluster it is remediating.

Phase 6 also seeds `platforms.config.remediation_targets`. Resource locators
come from that block and never from the LLM (`worker/playbooks.py`); without it
`default_locators()` returns namespace `presto`, which does not exist in this
cluster, and E1's remediation would target nothing.

## Admin credentials

`ADMIN_INITIAL_PASSWORD` must satisfy the dashboard-api's own
`password_min_length` (12), because phase 4 clears `must_change_password` by
POSTing it to `/api/v1/auth/change-password`. One value is used by the chart
values, `run.sh` and both Python clients;
`tests/delivery/test_delivery_e2e_fixtures.py` asserts both properties without a
cluster.
