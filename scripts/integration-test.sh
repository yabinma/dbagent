#!/usr/bin/env bash
#
# integration-test.sh -- run the parts of the suite that need Docker networking.
#
# WHY THIS EXISTS
#
#   Claude Code's Bash sandbox (`sandbox.enabled: true`) runs every command in a network
#   namespace containing only loopback and no routes at all. Docker still works there --
#   it talks to the daemon over a Unix socket -- so containers start normally and then
#   nothing can connect to them. Every testcontainers-backed test therefore fails, and it
#   fails confusingly: Go dies after 60s inside Ryuk with
#   `wait until ready: external check: check target: retries: 588 address: localhost:32779`.
#
#   That is not fixable by configuration. The sandbox's 127.0.0.1 is not the host's, the
#   Docker bridge has no route, and no `sandbox.network` setting on Linux shares the host
#   namespace (`allowLocalBinding` and friends are macOS-only). So the Docker-dependent
#   tests have to run OUTSIDE the sandbox, and this script is the single entry point that
#   does, listed in `sandbox.excludedCommands` in ~/.claude/settings.json:
#
#       "sandbox": {
#         "excludedCommands": [
#           "/opt/gitspace/dbagent/scripts/integration-test.sh*",
#           "bash /opt/gitspace/dbagent/scripts/integration-test.sh*"
#         ]
#       }
#
#   INVOKE IT BY ABSOLUTE PATH, AS THE TOP-LEVEL COMMAND. This matters more than it
#   looks: whether the exclusion applies depends on how the invocation is embedded in the
#   surrounding shell command, and the failure is silent. Measured 2026-08-15:
#
#       /opt/.../scripts/integration-test.sh preflight            -> EXCLUDED  (ok)
#       /opt/.../scripts/integration-test.sh preflight | head -1  -> EXCLUDED  (ok)
#       cd /opt/gitspace/dbagent; scripts/integration-test.sh ... -> SANDBOXED (fails)
#       cd /opt/gitspace/dbagent && scripts/integration-test.sh   -> SANDBOXED (fails)
#       for t in preflight; do scripts/integration-test.sh $t; done -> SANDBOXED (fails)
#
#   So: no wrapping in loops, no `cd && ...` chains, no relative paths. The two entries
#   above are anchored and listed twice (bare and `bash `-prefixed) so they match under
#   prefix-style matching (the `docker *` form the docs use) as well as glob matching.
#
#   The preflight guard below exists precisely because this failure is silent: a
#   non-matching invocation refuses in under a second instead of producing 60s-per-package
#   Ryuk timeouts that look like flaky Docker.
#
#   One reviewed, version-controlled entry point is deliberately narrower than excluding
#   `go test *` or `pytest *`, which would exempt any invocation anywhere with any flags
#   (including `go test -exec`, which will run an arbitrary binary for you).
#
#   CI needs none of this for the go and py tiers: GitHub-hosted runners have normal
#   networking, so `ci.yml` runs those tests directly.
#
#   The b1 tier is the exception, and it is deliberate: ci.yml's `benchmark` job step 17
#   runs `bash scripts/integration-test.sh b1` -- THIS script -- so the gating CI-scale
#   route and the local one are one launcher rather than two that can drift. That wrapper
#   step is pinned by equality in tests/functional/test_manifests.py.
#
# WHAT IT RUNS
#
#   Exactly what ci.yml runs, so that green here means green there. If you change a test
#   command in ci.yml, change it here too -- the whole value of this script is that the
#   two agree.
#
# TRACKED, NOT LOCAL-ONLY (GC-1 FP-GC1-2)
#
#   This file used to be gitignored and local-only. It is now version-controlled and is
#   the SINGLE carrier of the B1 reference deployment: `.github/workflows/ci.yml` invokes
#   `bash scripts/integration-test.sh b1` for the merge-gating CI-scale benchmark, and a
#   developer runs the identical target locally. That is the whole point -- CI and local
#   cannot drift apart, because there is only one topology and one set of assertions.
#
#   `tests/functional/test_manifests.py` pins the workflow step body, this script's
#   container flags, the placement contract, the marker selections and the cleanup scope
#   by equality, so a silent edit to either side is a named test failure.
#
# THE REST OF THE SUITE STILL RUNS SANDBOXED
#
#   Only the Docker-dependent tests need this. Everything else runs fine inside the
#   sandbox, and should keep running there:
#
#       go test -short ./...        # -short skips every testcontainers test; all green
#       npm test / vitest           # no Docker
#
#   The Go tests already gate themselves on `testing.Short()`, so that split is the
#   project's own existing convention, not something invented here.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 1

WHAT="${1:-all}"

case "$WHAT" in
  all|go|py|python|preflight|smoke|d0_2a|d0_2c|d0_2d|d0_3a|d0_3b|d0_3c|d0_4|d0_4_workers|sp_1|sp_1_run|sp_1_sg4|rm_1|rm_1_run|lv_1|lv_1_run|b1|b1_product|b1_latency_basis|b1_topology_probe) ;;
  -h|--help|help)
    # QUOTED heredoc: this block contains backticks and angle brackets that must print
    # literally. Unquoted, bash treats `go test -exec <anything>` as a command
    # substitution and the line renders empty with a syntax error on stderr. (The
    # refusal message below is deliberately UNquoted -- it interpolates $REPO_ROOT.)
    cat <<'EOF'
usage: scripts/integration-test.sh [all|go|py|preflight|smoke|b1|b1_product|b1_latency_basis|b1_topology_probe|d0_2a|d0_2c|d0_2d|d0_3a|d0_3b|d0_3c|d0_4|d0_4_workers|sp_1|sp_1_run|sp_1_sg4|rm_1|rm_1_run|lv_1|lv_1_run]

  all  (default)  go + py + b1 + b1_product -- the local acceptance route
  b1              the resource-declared CI-scale B1 benchmark (gating; the
                  same target ci.yml runs). It ALWAYS runs its container-free
                  coverage phase first, on one allowed CPU. It then reads this
                  host's exact CPU model and routes on the tracked decision
                  carrier tests/benchmark/b1_topology_decision.json: a model
                  with a ratified topology runs the live gate under exactly
                  that topology, over the first two complete SMT sibling pairs;
                  any other model records a named non-gating reason and starts
                  no workload. There is no fixed 2/1/1 layout any more, and no
                  first-four-CPUs fallback. A missing or corrupt carrier fails
                  the target rather than reading as an unratified model.
  b1_product      the recorded, non-gating 1000 req/s product-promise run on
                  measured-role-exclusive cores; needs >= 8 logical CPUs
  b1_latency_basis
                  the isolated CPU-basis oracle (B1-LATENCY-BASIS-1). The same
                  selected CI-scale route, plus the FP-IG-18 node that compares
                  measured gateway CPU per request against the recorded chart
                  basis. Explicit only: never part of `all`, never part of the
                  ordinary `b1` result, and in CI only behind a manual
                  workflow_dispatch input. It exits 3 with
                  basis_oracle_unobserved:<reason> and starts no workload when
                  the ledger is unrecorded/invalid or this runner is not the
                  recorded signature identity.
  b1_topology_probe
                  GC-3 topology discovery: the 28 closed placements of the
                  CI-scale burst, measured once each and recorded. Manual only
                  (workflow_dispatch), never part of `all` or ordinary CI. A
                  candidate that misses the bar is DATA, not a failure; the
                  target fails only on a broken measurement.
  go              go test ./... -race -timeout 300s -p 1
  py              the functional/service pytest tiers that use testcontainers
  preflight       run only the checks, no tests -- confirms in ~1s that the
                  sandbox exclusion is live and Docker is reachable
  smoke           one real testcontainers test per runtime, Go + Python (~10s)
                  -- proves end to end that a container's published port is
                  actually reachable from both

NOTE: there is deliberately no pass-through for extra flags. This script runs
UNSANDBOXED, and forwarding arbitrary arguments would reopen exactly what the
narrow exemption exists to prevent (e.g. `go test -exec <anything>`).

Must run OUTSIDE the Claude Code sandbox -- see the header of this file.
EOF
    exit 0 ;;
  *)
    echo "integration-test.sh: unknown target '$WHAT' (want: all | go | py | preflight | smoke | b1 | b1_product | b1_latency_basis | b1_topology_probe | d0_2a | d0_2c | d0_2d | d0_3a | d0_3b | d0_3c | d0_4 | d0_4_workers | sp_1 | sp_1_run | sp_1_sg4 | rm_1 | rm_1_run | lv_1 | lv_1_run)" >&2
    exit 2 ;;
esac

# ---------------------------------------------------------------------------
# Preflight: refuse to run inside the sandbox.
#
# Without this the failure mode is a 60-second-per-package timeout ending in a Ryuk
# message about an unreachable port, which reads like flaky infrastructure and sends
# people looking at Docker. It is not flaky and Docker is fine -- the exclusion simply
# did not apply. Fail in a second, and say so.
#
# The test is behavioural rather than a check for bubblewrap specifically: the sandbox's
# namespace has no global-scope address at all, and a machine that can reach a published
# container port always has one.
# ---------------------------------------------------------------------------
if [ "$(ip -o addr show scope global 2>/dev/null | wc -l)" -eq 0 ]; then
  cat >&2 <<EOF
integration-test.sh: REFUSING TO RUN -- this shell has no route to anything.

  No global-scope network address is present, which means this is running inside the
  Claude Code Bash sandbox (/proc/1/comm = $(cat /proc/1/comm 2>/dev/null || echo '?')).
  Every testcontainers test would start its container and then fail to connect to it,
  after burning 60s per package in Ryuk.

  This script must be excluded from the sandbox. In ~/.claude/settings.json:

      "sandbox": {
        "excludedCommands": [
          "$REPO_ROOT/scripts/integration-test.sh*",
          "bash $REPO_ROOT/scripts/integration-test.sh*"
        ]
      }

  If those entries are already there, the pattern did not match how this was invoked.
  Invoke it by ABSOLUTE PATH -- a relative path from another cwd matches neither entry.

  Background: ~/.claude/SANDBOX-NETWORK.md
EOF
  exit 3
fi

if ! docker info >/dev/null 2>&1; then
  echo "integration-test.sh: cannot reach the Docker daemon (DOCKER_HOST=${DOCKER_HOST:-unset})" >&2
  exit 3
fi

# `preflight` stops here: everything above is the part that tells you whether a real run
# CAN work. Worth its own target so that confirming the excludedCommands entry costs a
# second instead of a full suite -- and so a failed exclusion is discovered before, not
# five minutes into, the run it would have wrecked.
if [ "$WHAT" = preflight ]; then
  echo "integration-test.sh: preflight OK"
  echo "  outside the sandbox : $(ip -o addr show scope global | awk '{print $2}' | sort -u | tr '\n' ' ')"
  echo "  docker              : $(docker version --format '{{.Server.Version}}' 2>/dev/null) via ${DOCKER_HOST:-default socket}"
  echo "  rca_common venv     : $([ -x libs/py/rca_common/.venv/bin/python ] && echo present || echo MISSING)"
  echo "  worker venv         : $([ -x services/worker/.venv/bin/python ] && echo present || echo MISSING)"
  exit 0
fi

# ---------------------------------------------------------------------------
# Anti-drift: assert this script's commands still match ci.yml.
#
# This file holds its own copy of ci.yml's command strings. That is a drift hazard this
# project has already been bitten by: the `-p 1` fix had to be applied to ci.yml,
# scripts/go-coverage-check.sh AND EXPECTED_GO_TEST_COMMANDS together, precisely because
# a stale copy is silent. Since GC-1 the file is tracked, so
# tests/functional/test_manifests.py pins it too -- but the local check below still fires
# first and names the drifted string.
#
# So the copy checks itself. If ci.yml changes and this script does not, you get a loud
# failure naming the drifted string instead of a local "green" that CI will contradict.
# Same equality-pinning idea the manifest guard uses, in ten lines.
# ---------------------------------------------------------------------------
CI_YML=".github/workflows/ci.yml"
assert_matches_ci() {
  local missing=0 s
  for s in "$@"; do
    if ! grep -qF -- "$s" "$CI_YML" 2>/dev/null; then
      echo "DRIFT: this script runs a command that no longer appears in $CI_YML:" >&2
      printf '         %s\n' "$s" >&2
      missing=1
    fi
  done
  if [ "$missing" -ne 0 ]; then
    cat >&2 <<'EOF'
       Local green would NOT mean CI green. Reconcile before trusting this run:
       update this script to match ci.yml (and remember ci.yml's own strings are
       pinned by equality in tests/functional/test_manifests.py).
EOF
    return 1
  fi
  return 0
}

FAILED=()
run_step() {
  local name="$1"; shift
  echo
  echo "=============================================================="
  echo "  $name"
  echo "=============================================================="
  if "$@"; then
    echo "--- PASS: $name"
  else
    echo "--- FAIL: $name" >&2
    FAILED+=("$name")
  fi
}

# ---------------------------------------------------------------------------
# Go
#
# -p 1 is load-bearing, not tidiness: registry and tests/functional/m2_probe_link each
# spin up their own ephemeral Postgres, and run concurrently they starve each other for
# Docker and CPU until the later container becomes unreachable. ci.yml carries the same
# flag and the same comment.
#
# registry/pg_test.go shells out to libs/py/rca_common/.venv/bin/python -m alembic, so
# that venv must exist with the [test] extra installed.
# ---------------------------------------------------------------------------
go_tests() {
  assert_matches_ci 'go test ./... -race -timeout 300s -p 1' || return 1
  if [ ! -x libs/py/rca_common/.venv/bin/python ]; then
    echo "missing libs/py/rca_common/.venv -- registry/pg_test.go needs it for alembic." >&2
    echo "  python -m venv libs/py/rca_common/.venv && libs/py/rca_common/.venv/bin/pip install -e 'libs/py/rca_common[test]'" >&2
    return 1
  fi
  if ! libs/py/rca_common/.venv/bin/python -c 'import alembic' 2>/dev/null; then
    echo "libs/py/rca_common/.venv exists but has no alembic -- reinstall with the [test] extra." >&2
    return 1
  fi
  go test ./... -race -timeout 300s -p 1
}

# ---------------------------------------------------------------------------
# Python
#
# Mirrors ci.yml's "Run Python functional tests" step, including its --ignore set (those
# tiers run in their own CI jobs with their own fixtures) and the FP-M6-31 A10(v)
# environment-hygiene precondition: no PYTHON*/PYTEST* variable may be set for the
# measured invocation, or the guard's own assertions are meaningless.
# ---------------------------------------------------------------------------
py_tests() {
  assert_matches_ci \
    'services/worker/tests services/gateway/tests' \
    '--ignore=tests/functional/m2_probe_link' \
    '--ignore=services/gateway/tests/test_b1_ingest_burst.py' \
    '--ignore=tests/delivery/test_delivery_sizing_ledger.py' || return 1
  if [ ! -x services/worker/.venv/bin/python ]; then
    echo "missing services/worker/.venv -- see ci.yml's 'Install test deps' step." >&2
    return 1
  fi

  local bad
  bad="$(awk 'BEGIN { for (k in ENVIRON) { p = substr(k, 1, 6); if (p != "PYTHON" && p != "PYTEST") continue; print k } }')"
  if [ -n "$bad" ]; then
    printf 'FP-M6-31 A10(v): forbidden PYTHON*/PYTEST* environment key set:\n%s\n' "$bad" >&2
    return 1
  fi

  services/worker/.venv/bin/python -m pytest \
    services/worker/tests services/gateway/tests \
    services/dashboard-api/tests \
    tests/functional tests/delivery tests/mocks/llm -v \
    --ignore=tests/functional/m2_probe_link \
    --ignore=services/gateway/tests/test_b1_ingest_burst.py \
    --ignore=tests/delivery/test_delivery_sizing_ledger.py
}

# D0.2-a diagnostic (design/section-11.3-ingest-capacity.md §11.3.3 AG). A named
# target rather than argument pass-through, for the same reason every other target is
# named: forwarding arbitrary arguments would reopen what the narrow sandbox exemption
# exists to prevent. Diagnostic only under §14.4 rule 1 -- it starts a Postgres, drives
# the shipped IngestService._ingest_txn directly, and writes its record into design/.
# Both this target and design/d0_2a_replay.py are gitignored, so the instrument leaves
# no tracked change.
d0_2a() {
  if [ ! -x services/worker/.venv/bin/python ]; then
    echo "missing services/worker/.venv -- see ci.yml's 'Install test deps' step." >&2
    return 1
  fi
  services/worker/.venv/bin/python design/d0_2a_replay.py
}

d0_2c() {
  if [ ! -x services/worker/.venv/bin/python ]; then
    echo "missing services/worker/.venv -- see ci.yml's 'Install test deps' step." >&2
    return 1
  fi
  services/worker/.venv/bin/python design/d0_2c_sleep_sweep.py
}

d0_2d() {
  if [ ! -x services/worker/.venv/bin/python ]; then
    echo "missing services/worker/.venv -- see ci.yml's 'Install test deps' step." >&2
    return 1
  fi
  services/worker/.venv/bin/python design/d0_2d_worker_ab.py
}

d0_3a() {
  if [ ! -x services/worker/.venv/bin/python ]; then
    echo "missing services/worker/.venv -- see ci.yml's 'Install test deps' step." >&2
    return 1
  fi
  services/worker/.venv/bin/python design/d0_3a_driver_split.py
}

d0_3b() {
  if [ ! -x services/worker/.venv/bin/python ]; then
    echo "missing services/worker/.venv -- see ci.yml's 'Install test deps' step." >&2
    return 1
  fi
  services/worker/.venv/bin/python design/d0_3b_dispatch_split.py
}

d0_3c() {
  if [ ! -x services/worker/.venv/bin/python ]; then
    echo "missing services/worker/.venv -- see ci.yml's 'Install test deps' step." >&2
    return 1
  fi
  services/worker/.venv/bin/python design/d0_3c_conn_vs_inflight.py
}

d0_4() {
  if [ ! -x services/worker/.venv/bin/python ]; then
    echo "missing services/worker/.venv -- see ci.yml's 'Install test deps' step." >&2
    return 1
  fi
  services/worker/.venv/bin/python design/d0_4_member_split.py
}

d0_4_workers() {
  if [ ! -x services/worker/.venv/bin/python ]; then
    echo "missing services/worker/.venv -- see ci.yml's 'Install test deps' step." >&2
    return 1
  fi
  services/worker/.venv/bin/python design/d0_4_member_split.py --dry-run-workers
}

sp_1() {
  if [ ! -x services/worker/.venv/bin/python ]; then
    echo "missing services/worker/.venv -- see ci.yml's 'Install test deps' step." >&2
    return 1
  fi
  services/worker/.venv/bin/python design/sp_1_wire_split.py --self-test
  services/worker/.venv/bin/python design/sp_1_wire_split.py --dry-run
}

# The real SP-1 session (§11.3.3 AQ). Long-running: 14 product steps across two
# arms plus two SG4 stub brackets, each starting its own gateway and Postgres, so
# it needs Docker and must run outside the sandbox like every d0_* runner. Writes
# design/sp_1_results.json; renders no verdict -- WS0-WS5 is applied at review.
sp_1_run() {
  if [ ! -x services/worker/.venv/bin/python ]; then
    echo "missing services/worker/.venv -- see ci.yml's 'Install test deps' step." >&2
    return 1
  fi
  services/worker/.venv/bin/python design/sp_1_wire_split.py --run
}

# The real RM-1 session (§11.3.3 AS). Long-running: three arms across the profile's
# own shape plus two RG4 stub brackets, each starting its own gateway and Postgres,
# so it needs Docker and must run outside the sandbox like every d0_*/sp_1 runner.
# Writes design/rm_1_results.json; renders no verdict -- RM0-RM5 is applied at review.
rm_1_run() {
  if [ ! -x services/worker/.venv/bin/python ]; then
    echo "missing services/worker/.venv -- see ci.yml's 'Install test deps' step." >&2
    return 1
  fi
  services/worker/.venv/bin/python design/rm_1_driver_ceiling.py --run
}

# SG4's own exercise. A separate target because it needs Postgres via testcontainers,
# which no sandboxed shell can reach (no route to a published container port), while
# sp_1 above is deliberately container-free so it runs anywhere. SG4 is the break-test
# a server-side WS3 rests on, so its production-path exercise must actually execute
# somewhere -- the d0_4_workers precedent.
sp_1_sg4() {
  if [ ! -x services/worker/.venv/bin/python ]; then
    echo "missing services/worker/.venv -- see ci.yml's 'Install test deps' step." >&2
    return 1
  fi
  services/worker/.venv/bin/python design/sp_1_wire_split.py --dry-run-sg4
}

rm_1() {
  if [ ! -x services/worker/.venv/bin/python ]; then
    echo "missing services/worker/.venv -- see ci.yml's 'Install test deps' step." >&2
    return 1
  fi
  services/worker/.venv/bin/python design/rm_1_driver_ceiling.py --self-test
  services/worker/.venv/bin/python design/rm_1_driver_ceiling.py --dry-run
}

# LV-1 self-test + dry-run (AW). Container-free: arm T is a Transport stub and
# arm P is an in-process keep-alive acceptor. The real session is lv_1_run.
lv_1() {
  if [ ! -x services/worker/.venv/bin/python ]; then
    echo "missing services/worker/.venv -- see ci.yml's 'Install test deps' step." >&2
    return 1
  fi
  services/worker/.venv/bin/python design/lv_1_leg_witness.py --self-test
  services/worker/.venv/bin/python design/lv_1_leg_witness.py --dry-run
}

# The real LV-1 session (§11.3.3 AW). Four arm-blocks at the profile shape
# (T, P, P, T). Writes design/lv_1_results.json; renders no verdict --
# LV0-LV3 is applied at review. Not dispatched from this implement pass.
lv_1_run() {
  if [ ! -x services/worker/.venv/bin/python ]; then
    echo "missing services/worker/.venv -- see ci.yml's 'Install test deps' step." >&2
    return 1
  fi
  services/worker/.venv/bin/python design/lv_1_leg_witness.py --run
}

# ---------------------------------------------------------------------------
# B1 -- the resource-declared reference deployment (GC-1, FP-GC1-1..4).
#
# Both B1 routes run here and nowhere else: ci.yml's benchmark job invokes
# `bash scripts/integration-test.sh b1`, and a developer runs the same target
# locally, so the CI-scale gate is one deployment with one set of assertions.
#
# The allocation is SCHEDULER AFFINITY, not CFS bandwidth. Revision 0.4 of this
# slice declared per-role CPU quotas and measured what that costs: a bursty
# role spends its fractional 100 ms allowance early and is then suspended for
# the rest of the period, so the gateway was throttled in 43 of 307 periods
# while averaging only 1.15 of its 2.00 declared cores, PostgreSQL in 65 of
# 308, and CI-scale p99 came out at 614-794 ms against a 150 ms bar. Exact,
# pairwise-disjoint CPU sets give a role its full declared cores at any instant
# and never suspend it for accounting reasons. NOTHING here applies --cpus,
# --cpu-period, --cpu-quota or --cpuset-cpus to a measured role; cgroup
# counters survive only as reported diagnostics on the fingerprint.
#
# Why containers at all. Each role needs an independent, inspectable identity
# and lifecycle, and the driver cannot simply spawn the gateway as a child: they
# would share one container and one accounting boundary with no independent
# witness. Affinity is then applied per role -- `taskset` on the driver and
# gateway container commands, and the closed CAP_SYS_NICE helper on the
# Docker-owned PostgreSQL tree, in BOTH profiles.
#
# Nothing here accepts a profile value from the caller: the target takes no
# arguments, the rates and cardinalities are literals in this file and in
# services/gateway/tests/b1_reference_profile.py, and the JSON below is a
# launch contract the fixture re-checks against those Python constants.
# ---------------------------------------------------------------------------

B1_IMAGE_TAG="dbagent-review-runner:b1"
B1_RUN_MOUNT="/run/dbagent-b1"
B1_RUN_LABEL_KEY="dbagent.b1.run"
B1_ROLE_LABEL_KEY="dbagent.b1.role"
B1_DRIVER_NAME_PREFIX="dbagent-b1-driver-"
B1_RUN_ID=""
B1_RUN_DIR=""
B1_CLEANUP_FAILED=0
B1_RUN_DIR_FAILED=0
# GC-3: the review-runner image is built once per invocation and reused by
# every arm of the 28-arm discovery sweep. Rebuilding per arm would put a
# multi-minute, uncontrolled compile on the measured host between measurements.
B1_IMAGE_BUILT=0
# GC-3 (FP-GC3-4): the ordinary route's own record. The launcher writes it,
# prints its percent-encoded canonical form once, and never copies it into
# B1_RUN_DIR -- the live witness joins decision to fingerprint through the
# tracked carrier on the read-only source mount instead.
B1_ROUTE_RECORD=""

# The daemon endpoint is a host fact, not a profile input: CI's rootful daemon
# listens on /var/run/docker.sock, a rootless developer daemon does not. The
# container destination is always /var/run/docker.sock so the driver and the
# pin helper find it with no DOCKER_HOST of their own.
b1_docker_socket() {
  case "${DOCKER_HOST:-}" in
    "")       printf '%s' "/var/run/docker.sock" ;;
    unix://*) printf '%s' "${DOCKER_HOST#unix://}" ;;
    *)        printf '%s' "" ;;
  esac
}

b1_expand_cpu_list() {
  local spec="$1" part lo hi c
  local -a parts=() out=()
  IFS=',' read -r -a parts <<< "$spec"
  for part in "${parts[@]}"; do
    case "$part" in
      *-*) lo="${part%%-*}"; hi="${part##*-}"
           for ((c = lo; c <= hi; c++)); do out+=("$c"); done ;;
      "")  ;;
      *)   out+=("$part") ;;
    esac
  done
  printf '%s\n' "${out[@]}"
}

# Canonical Linux CPU-list syntax (0-3,8) -- the fixture refuses any other form.
b1_canonical_cpu_list() {
  local start="" prev="" rendered="" cpu
  for cpu in "$@"; do
    if [ -z "$start" ]; then
      start="$cpu"; prev="$cpu"; continue
    fi
    if [ "$cpu" -eq $((prev + 1)) ]; then prev="$cpu"; continue; fi
    if [ "$start" -eq "$prev" ]; then rendered="${rendered:+$rendered,}$start"; else rendered="${rendered:+$rendered,}$start-$prev"; fi
    start="$cpu"; prev="$cpu"
  done
  if [ -n "$start" ]; then
    if [ "$start" -eq "$prev" ]; then rendered="${rendered:+$rendered,}$start"; else rendered="${rendered:+$rendered,}$start-$prev"; fi
  fi
  printf '%s' "$rendered"
}

# The launcher's own available CPUs, sorted, before any role is narrowed.
# `taskset -pc $$` is sched_getaffinity(0) for this shell: on a four-vCPU
# runner it is the whole machine, on a many-core host it is whatever this
# process was allowed. That is what makes a local run reproduce the four-core
# shape instead of expanding with the host.
#
# GC-3 (FP-GC3-4): ordinary b1 reads this array EXACTLY ONCE and keeps it. Its
# roles are no longer the first four entries -- they are the selected
# topology's mapping over the first two COMPLETE SMT SIBLING PAIRS inside this
# set, rendered by `contract-selected`. The product route still takes the
# first eight entries as 4/3/1 and is unchanged.
b1_available_cpus() {
  local affinity
  affinity="$(taskset -pc $$ 2>/dev/null | sed 's/.*: *//')"
  [ -n "$affinity" ] || return 1
  b1_expand_cpu_list "$affinity" | sort -n -u
}

B1_CPU_TOPOLOGY_ROOT="/sys/devices/system/cpu"

# One CPU's canonical kernel thread-sibling list, or nothing.
b1_thread_siblings() {
  local path="$B1_CPU_TOPOLOGY_ROOT/cpu$1/topology/thread_siblings_list"
  [ -r "$path" ] || return 1
  tr -d ' \n' < "$path"
}

# The complete two-thread sibling pairs inside the allowed set, ONE CANONICAL
# LINUX CPU LIST PER LINE ("0-1", or "0,8" on a host whose siblings are not
# adjacent ids), ordered by minimum CPU id. A pair is admitted only when the
# kernel list holds exactly two CPUs, both are allowed, each member names the
# identical two-member set, and the set was not already taken. Everything else
# is simply not a pair -- there is no repair and no partial admission, because
# a wrong answer here would silently move the measured topology.
#
# The RENDERING is a contract, not a display choice. Each line is passed
# unchanged as one `--pairs` word to `b1_topology_probe.py contract-selected`,
# whose parser accepts canonical Linux CPU-list syntax and nothing else; the
# space-separated "lo hi" this used to print was not a CPU list at all, so the
# gating branch could not render its own ratified topology (review round 1 C1).
# `b1_canonical_cpu_list` is the one renderer in this file, and the product
# route and the probe planner already speak it.
b1_complete_sibling_pairs() {
  local -a allowed=("$@")
  local cpu raw lo hi taken=" " allowed_list=" ${allowed[*]} "
  local -a members=()
  for cpu in "${allowed[@]}"; do
    raw="$(b1_thread_siblings "$cpu")" || continue
    mapfile -t members < <(b1_expand_cpu_list "$raw" | sort -n -u)
    [ "${#members[@]}" -eq 2 ] || continue
    lo="${members[0]}"; hi="${members[1]}"
    case "$allowed_list" in *" $lo "*) ;; *) continue ;; esac
    case "$allowed_list" in *" $hi "*) ;; *) continue ;; esac
    [ "$(b1_expand_cpu_list "$(b1_thread_siblings "$lo")" | sort -n -u | tr '\n' ',')" = "$lo,$hi," ] || continue
    [ "$(b1_expand_cpu_list "$(b1_thread_siblings "$hi")" | sort -n -u | tr '\n' ',')" = "$lo,$hi," ] || continue
    case "$taken" in *" $lo-$hi "*) continue ;; esac
    taken="$taken$lo-$hi "
    printf '%s\n' "$(b1_canonical_cpu_list "$lo" "$hi")"
  done
}

# Empty this run's directory through the same root-capable path that filled it.
#
# The driver container runs as the runner image's default user, root, and
# writes into the run mount: pytest's cache tree, the profile's generated
# gateway.yaml and gateway.log. On a ROOTLESS daemon -- every developer host
# here -- container root IS the invoking user, so those files are already ours
# and this never runs. On a ROOTFUL daemon -- every GitHub-hosted runner -- it
# is uid 0, the directories it creates inside the mount are root-owned and mode
# 0755, and the unprivileged `runner` user cannot unlink their contents: a
# plain `rm -rf` fails with EACCES after a perfectly good measurement. Measured
# on CI 2026-09-16: both manual topology-probe dispatches lost 27 of 28 arms
# that way after a green arm 0, and the ordinary b1 step of the preceding
# benchmark run hit the same three path shapes. (The run ids stay in
# design/fix.md and tests/functional/test_b1_cleanup_run_dir.py: this file is
# a GC-3 sizing carrier, which may carry no diagnostic run id at all.)
#
# The removal therefore happens where the privilege is, in one short-lived
# container over the same mount, carrying this run's labels so it is never
# anonymous. Only the CONTENTS go: the mount point itself is busy, and it is
# the host-owned mktemp directory the shell must drop anyway -- so the removal
# the target checks, and the surviving-directory test that follows it, stay
# exactly where they were. Chowning the tree back to `id -u` instead would be
# wrong on precisely one of the two daemons: under rootless, container uid N
# is host subuid 100000+N, so handing the files to "1000" hands them to a
# stranger. Deleting as root is the same operation on both.
#
# This function's own exit status is deliberately not an oracle: whether the
# run directory is gone is, and b1_cleanup tests that immediately afterwards.
b1_purge_run_dir() {
  [ "$B1_IMAGE_BUILT" -eq 1 ] || return 0
  docker run --rm \
    --label "${B1_RUN_LABEL_KEY}=${B1_RUN_ID}" \
    --label "${B1_ROLE_LABEL_KEY}=cleanup" \
    -v "$B1_RUN_DIR":"$B1_RUN_MOUNT" \
    "$B1_IMAGE_TAG" \
    find "$B1_RUN_MOUNT" -mindepth 1 -delete >/dev/null 2>&1
  return 0
}

# Fail-safe lifecycle guard. The driver fixture owns both siblings and stops
# them in reverse order; this removes anything carrying THIS run's label if the
# driver died before it could, verifies the filtered list is then empty, and
# only then drops the run directory. A cleanup that cannot finish fails the
# target -- a leaked container on a measured role's CPUs would silently contend
# with the next measurement.
#
# The two failures are reported and carried SEPARATELY. Both still fail the
# target, but they are not the same diagnosis -- a surviving container contends
# for a measured role's CPUs, a surviving run directory does not -- and
# conflating them made every rootful-Docker cleanup announce "left containers
# behind" over a container census that was empty.
b1_cleanup() {
  [ -n "$B1_RUN_ID" ] || return 0
  local ids
  ids="$(docker ps -aq --filter "label=${B1_RUN_LABEL_KEY}=${B1_RUN_ID}" 2>/dev/null)"
  if [ -n "$ids" ]; then
    # shellcheck disable=SC2086
    docker rm -f $ids >/dev/null 2>&1
  fi
  ids="$(docker ps -aq --filter "label=${B1_RUN_LABEL_KEY}=${B1_RUN_ID}" 2>/dev/null)"
  if [ -n "$ids" ]; then
    echo "integration-test.sh: run ${B1_RUN_ID} left containers behind: $(echo "$ids" | tr '\n' ' ')" >&2
    B1_CLEANUP_FAILED=1
  fi
  if [ -n "$B1_RUN_DIR" ] && [ -d "$B1_RUN_DIR" ]; then
    # Quietly first: on a rootless daemon this is the whole story, and the
    # EACCES lines a rootful daemon prints here are about files the purge
    # below is about to remove anyway.
    rm -rf "$B1_RUN_DIR" 2>/dev/null
    if [ -d "$B1_RUN_DIR" ]; then
      b1_purge_run_dir
      rm -rf "$B1_RUN_DIR"
    fi
    if [ -d "$B1_RUN_DIR" ]; then
      echo "integration-test.sh: run ${B1_RUN_ID} could not remove its run directory ${B1_RUN_DIR}" >&2
      B1_RUN_DIR_FAILED=1
    fi
  fi
  # The purge is itself a container of this run, created after the census
  # above, so census again -- "a container carrying this run's label does not
  # outlive cleanup" has to hold for the cleanup role too. Measured here
  # 2026-09-16: `docker run --rm` returns only once the daemon has removed the
  # record (8/8 probes read empty), so this normally finds nothing; the
  # force-removal is kept because a container that merely LAGS is not a leak,
  # and only one that survives removal contends with the next measurement.
  ids="$(docker ps -aq --filter "label=${B1_RUN_LABEL_KEY}=${B1_RUN_ID}" 2>/dev/null)"
  if [ -n "$ids" ]; then
    # shellcheck disable=SC2086
    docker rm -f $ids >/dev/null 2>&1
    ids="$(docker ps -aq --filter "label=${B1_RUN_LABEL_KEY}=${B1_RUN_ID}" 2>/dev/null)"
  fi
  if [ -n "$ids" ]; then
    echo "integration-test.sh: run ${B1_RUN_ID} left containers behind: $(echo "$ids" | tr '\n' ' ')" >&2
    B1_CLEANUP_FAILED=1
  fi
  return 0
}

b1_prepare() {
  local sock
  sock="$(b1_docker_socket)"
  if [ -z "$sock" ] || [ ! -S "$sock" ]; then
    echo "integration-test.sh: no Docker socket to mount (DOCKER_HOST=${DOCKER_HOST:-unset})" >&2
    return 1
  fi
  B1_SOCKET="$sock"
  B1_RUN_ID="$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')"
  if [ "${#B1_RUN_ID}" -ne 32 ]; then
    echo "integration-test.sh: could not generate a 32-hex run id" >&2
    return 1
  fi
  B1_RUN_DIR="$(mktemp -d -t dbagent-b1-XXXXXXXXXX)" || return 1
  mkdir -p "$B1_RUN_DIR/coverage" "$B1_RUN_DIR/pytest-cache" "$B1_RUN_DIR/pycache" || return 1
  chmod 0777 "$B1_RUN_DIR" "$B1_RUN_DIR/coverage" "$B1_RUN_DIR/pytest-cache" \
    "$B1_RUN_DIR/pycache" || return 1
  # The runner image declares VOLUME mountpoints under /workspace (FP-RR-1,
  # deploy/review-runner/Dockerfile) so its Python shims shadow any host
  # virtualenv. Docker materialises each one as an anonymous volume at
  # `docker run` and creates the mountpoint if it is missing -- which it
  # cannot do inside the read-only /workspace bind below (EROFS), so on a
  # fresh checkout, where these gitignored directories do not yet exist, the
  # driver never starts. Creating them here gives CI the shape a developer
  # host already has. They stay empty: the anonymous volume mounts over them.
  mkdir -p "$REPO_ROOT/libs/py/rca_common/.venv" "$REPO_ROOT/services/worker/.venv" || return 1
  # The probe sweep is already under way when this runs for arms 1..N, and the
  # window it covers -- the first arm's multi-minute image build -- is the one
  # most likely to be killed. Replacing the collector with a bare cleanup for
  # the duration would lose the `invalid` artifact GC-3 §3.3 promises on a kill
  # (review.md 2026-09-16 W1), so ADD to the trap instead of overwriting it.
  if [ "${B1_PROBE_FINISHED:-1}" -eq 0 ]; then
    trap 'b1_cleanup; b1_topology_probe_finish' EXIT TERM INT
  else
    trap 'b1_cleanup' EXIT TERM INT
  fi
  if [ "$B1_IMAGE_BUILT" -eq 0 ]; then
    docker build -t dbagent-review-runner:b1 -f deploy/review-runner/Dockerfile . || return 1
    B1_IMAGE_BUILT=1
  fi
}

# -X pycache_prefix keeps the interpreter out of the repository's own
# __pycache__ directories. Those are gitignored host artefacts, they arrive
# through the read-only /workspace mount, and a host-written .pyc whose
# source mtime and size still match is loaded in preference to the source --
# carrying the HOST's absolute co_filename into the container, where that
# path does not exist. Measured 2026-09-15: 32 container-free tests went red
# that way, purely because pytest could not resolve their own source. CI's
# fresh checkout never has those files, so without this flag the local route
# is not the same deployment CI runs. It is an interpreter flag rather than
# PYTHONPYCACHEPREFIX on purpose: no PYTHON* key enters the measured process.
#
# The driver container. --network host so the gateway sibling is reachable at
# 127.0.0.1; --pid host so the existing per-worker socket census and worker
# identity checks can read the sibling gateway's process tree during the
# measured window (visibility only: the driver gets no added capability). It
# runs beneath its own declared CPU, and carries no bandwidth control at all.
b1_run_driver() {
  local script="$1" cpuset="$2"
  docker run --rm \
    --name "${B1_DRIVER_NAME_PREFIX}${B1_RUN_ID}" \
    --label "${B1_RUN_LABEL_KEY}=${B1_RUN_ID}" \
    --label "${B1_ROLE_LABEL_KEY}=driver" \
    --network host \
    --pid host \
    -v "$REPO_ROOT":/workspace:ro \
    -v "$B1_RUN_DIR":"$B1_RUN_MOUNT" \
    -v "$B1_SOCKET":/var/run/docker.sock \
    -w /workspace \
    "$B1_IMAGE_TAG" \
    taskset -c "$cpuset" bash "$B1_RUN_MOUNT/$script"
}

# The container-free coverage phase, written ONCE and used by BOTH selected
# routes: the ordinary gating `b1` and the explicit `b1_latency_basis`
# oracle run the same traced selection, over the same files, at the same
# bar. It is factored here rather than duplicated so the two can never
# become two different coverage contracts -- the delivery pin counts
# exactly one traced pytest command and exactly one report per covered
# file in this whole script.
b1_write_coverage_driver() {
  # Container-free coverage phase. No live fixture and no full-window
  # self-witness ever runs under the tracer: its unmeasured overhead would
  # consume the driver's single declared CPU.
  #
  # Coverage is reported over the four files this slice changes -- first as
  # one aggregate, then file by file, all at --fail-under=81. The aggregate is
  # scoped to the same four files on purpose: an unscoped report also counts
  # gateway/ingest.py, rca_common and the e2e profile copy, which this
  # harness-unit selection imports but is not the instrument for (the
  # unit-gateway job owns those, at its own --cov-fail-under=81). Counting them
  # here would make the number a statement about product code that no test in
  # this phase exercises.
  cat > "$B1_RUN_DIR/driver-coverage.sh" <<'B1_CI_SCALE_COVERAGE'
set -uo pipefail
cd /workspace
env -u PYTHON_VERSION -u PYTHON_PIP_VERSION -u PYTHON_GET_PIP_URL -u PYTHON_GET_PIP_SHA256 python3 -B -X pycache_prefix=/run/dbagent-b1/pycache -m coverage run --branch --data-file=/run/dbagent-b1/coverage/.coverage -m pytest services/gateway/tests/test_b1_ingest_burst.py -v -s -m 'not b1_live and not b1_product and not b1_latency_basis and not b1_topology_probe' -o cache_dir=/run/dbagent-b1/pytest-cache || exit $?
env -u PYTHON_VERSION -u PYTHON_PIP_VERSION -u PYTHON_GET_PIP_URL -u PYTHON_GET_PIP_SHA256 python3 -B -X pycache_prefix=/run/dbagent-b1/pycache -m coverage report --data-file=/run/dbagent-b1/coverage/.coverage --fail-under=81 --include=/workspace/services/gateway/tests/b1_reference_profile.py,/workspace/services/gateway/tests/test_b1_ingest_burst.py,/workspace/scripts/b1-affinity-helper.py,/workspace/services/gateway/tests/b1_topology_probe.py || exit $?
env -u PYTHON_VERSION -u PYTHON_PIP_VERSION -u PYTHON_GET_PIP_URL -u PYTHON_GET_PIP_SHA256 python3 -B -X pycache_prefix=/run/dbagent-b1/pycache -m coverage report --data-file=/run/dbagent-b1/coverage/.coverage --fail-under=81 --include=/workspace/services/gateway/tests/b1_reference_profile.py || exit $?
env -u PYTHON_VERSION -u PYTHON_PIP_VERSION -u PYTHON_GET_PIP_URL -u PYTHON_GET_PIP_SHA256 python3 -B -X pycache_prefix=/run/dbagent-b1/pycache -m coverage report --data-file=/run/dbagent-b1/coverage/.coverage --fail-under=81 --include=/workspace/services/gateway/tests/test_b1_ingest_burst.py || exit $?
env -u PYTHON_VERSION -u PYTHON_PIP_VERSION -u PYTHON_GET_PIP_URL -u PYTHON_GET_PIP_SHA256 python3 -B -X pycache_prefix=/run/dbagent-b1/pycache -m coverage report --data-file=/run/dbagent-b1/coverage/.coverage --fail-under=81 --include=/workspace/scripts/b1-affinity-helper.py || exit $?
env -u PYTHON_VERSION -u PYTHON_PIP_VERSION -u PYTHON_GET_PIP_URL -u PYTHON_GET_PIP_SHA256 python3 -B -X pycache_prefix=/run/dbagent-b1/pycache -m coverage report --data-file=/run/dbagent-b1/coverage/.coverage --fail-under=81 --include=/workspace/services/gateway/tests/b1_topology_probe.py || exit $?
B1_CI_SCALE_COVERAGE
}

# The ordinary CI-scale route: an UNCONDITIONAL container-free coverage phase,
# then a model-routed live phase.
#
# GC-3 (FP-GC3-4) split the old single driver script in two, and the order is
# the contract. Coverage runs first, on one allowed CPU, with no placement
# contract, no gateway or PostgreSQL sibling and no host-model or carrier read
# at all -- so the same aggregate and four per-file --fail-under=81 reports are
# observed locally, on every randomly assigned CI runner model, and even before
# a missing carrier makes the target fail. Its driver container is test
# infrastructure, not the CI-scale workload.
#
# Only afterwards is the exact host CPU model read -- once, by the shared
# reader in the planner, before pair discovery, before a placement contract and
# before any live process -- and looked up in the tracked decision carrier. A
# `selected` model runs the unchanged failure-producing gate under its own
# ratified topology; every other model records an explicit non-gating reason
# and starts no workload. No topology literal, role mapping, carrier parse,
# second model read or second allowed-CPU read exists in this shell.
b1() {
  assert_matches_ci 'bash scripts/integration-test.sh b1' || return 1
  local -a cpus=()
  mapfile -t cpus < <(b1_available_cpus)
  if [ "${#cpus[@]}" -lt 1 ]; then
    echo "integration-test.sh: b1 needs a usable scheduler-affinity operation (taskset)" >&2
    return 1
  fi
  b1_prepare || return 1
  b1_write_coverage_driver
  b1_run_driver driver-coverage.sh "${cpus[0]}"
  local rc=$?
  if [ "$rc" -ne 0 ]; then
    b1_cleanup
    trap - EXIT TERM INT
    return "$rc"
  fi

  # Pre-placement routing. `route` reads and canonicalises the host model once
  # through the same reader the discovery artifact records its identity with,
  # validates the whole schema-2 carrier, performs one exact key lookup and
  # writes the closed record. It exits 0 for a gating or a recorded route and
  # nonzero only for a missing or corrupt carrier -- infrastructure corruption
  # is not an unratified SKU.
  local route_disposition route_topology
  B1_ROUTE_RECORD="${RUNNER_TEMP:-/tmp}/b1-topology-route-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}.json"
  python3 "$B1_PROBE_PLANNER" route \
    --decision "$REPO_ROOT/tests/benchmark/b1_topology_decision.json" \
    --out "$B1_ROUTE_RECORD"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    b1_cleanup
    trap - EXIT TERM INT
    return "$rc"
  fi
  # The shell's ONLY branch values, from one closed read. It never parses JSON,
  # rereads the carrier, chooses a model or reconstructs a topology.
  IFS=$'\t' read -r route_disposition route_topology < <(
    python3 "$B1_PROBE_PLANNER" route-fields --route "$B1_ROUTE_RECORD"
  )
  rc=$?
  if [ "$rc" -ne 0 ] || [ -z "$route_disposition" ]; then
    echo "integration-test.sh: b1 could not read the route record $B1_ROUTE_RECORD" >&2
    b1_cleanup
    trap - EXIT TERM INT
    return 1
  fi
  if [ "$route_disposition" = "recorded" ] && [ "$route_topology" = "none" ]; then
    echo "integration-test.sh: b1 recorded a non-gating route; no live workload ran. See $B1_ROUTE_RECORD"
    b1_cleanup
    trap - EXIT TERM INT
    if [ "$B1_CLEANUP_FAILED" -ne 0 ] || [ "$B1_RUN_DIR_FAILED" -ne 0 ]; then return 1; fi
    return 0
  fi
  if [ "$route_disposition" != "gating" ] || [ -z "$route_topology" ] || [ "$route_topology" = "none" ]; then
    echo "integration-test.sh: b1 read an unusable route ($route_disposition/$route_topology)" >&2
    b1_cleanup
    trap - EXIT TERM INT
    return 1
  fi

  # A ratified model. Only now does the target need four allowed CPUs, and
  # only over the SAME array coverage's one-CPU floor was evaluated on.
  if [ "${#cpus[@]}" -lt 4 ]; then
    echo "integration-test.sh: b1 needs at least 4 available logical CPUs, this host offers ${#cpus[@]}" >&2
    b1_cleanup
    trap - EXIT TERM INT
    return 1
  fi
  # GC-3 (FP-GC3-1): the CI-scale reference deployment is defined over two
  # complete two-thread SMT sibling pairs, because a CPU id proves nothing
  # about a physical core -- `0-1` is one core on a hosted four-vCPU guest
  # and two different cores on the i7 replica. A host without two complete pairs
  # cannot host this measurement; it gets a named prerequisite failure and
  # never four unrelated CPUs. This is NOT a skip: the target returns nonzero.
  local -a sibling_pairs=()
  mapfile -t sibling_pairs < <(b1_complete_sibling_pairs "${cpus[@]}")
  if [ "${#sibling_pairs[@]}" -lt 2 ]; then
    echo "integration-test.sh: b1 needs two complete two-thread SMT sibling pairs inside its allowed CPU set ($(b1_canonical_cpu_list "${cpus[@]}")); this host offers ${#sibling_pairs[@]}" >&2
    b1_cleanup
    trap - EXIT TERM INT
    return 1
  fi
  # The planner is the single topology authority here too: the shell supplies
  # the observed pairs and the route-selected class, and gets back the written
  # schema-3 contract's driver CPU list. No role mapping, cardinality, profile
  # or model value crosses this boundary.
  local driver_cpus
  driver_cpus="$(python3 "$B1_PROBE_PLANNER" contract-selected \
    --topology "$route_topology" \
    --pairs "${sibling_pairs[0]}" "${sibling_pairs[1]}" \
    --run-id "$B1_RUN_ID" \
    --out "$B1_RUN_DIR/placement.json")"
  rc=$?
  if [ "$rc" -ne 0 ] || [ -z "$driver_cpus" ]; then
    echo "integration-test.sh: b1 could not render the selected topology $route_topology" >&2
    b1_cleanup
    trap - EXIT TERM INT
    return 1
  fi
  cat > "$B1_RUN_DIR/driver-live.sh" <<'B1_CI_SCALE_LIVE'
set -uo pipefail
cd /workspace
env -u PYTHON_VERSION -u PYTHON_PIP_VERSION -u PYTHON_GET_PIP_URL -u PYTHON_GET_PIP_SHA256 python3 -B -X pycache_prefix=/run/dbagent-b1/pycache -m pytest services/gateway/tests/test_b1_ingest_burst.py -v -s -m 'b1_live and not b1_product and not b1_latency_basis and not b1_topology_probe' -o cache_dir=/run/dbagent-b1/pytest-cache || exit $?
B1_CI_SCALE_LIVE
  b1_run_driver driver-live.sh "$driver_cpus"
  rc=$?
  b1_cleanup
  trap - EXIT TERM INT
  if [ "$B1_CLEANUP_FAILED" -ne 0 ] || [ "$B1_RUN_DIR_FAILED" -ne 0 ]; then return 1; fi
  return "$rc"
}

# B1-LATENCY-BASIS-1 (FP-B1LB-6) -- the ISOLATED CPU-basis oracle.
#
# Same GC-3 route file, same selected topology contract, same container
# ownership, same verified cleanup and the same container-free coverage phase
# as `b1`. The ONE difference is the live marker expression: it adds the
# `b1_latency_basis` node (FP-IG-18) to the ordinary CI-scale selection. That
# node compares a measured gateway CPU cost against the RECORDED chart basis,
# which is a requalification question, not the merge gate -- coupling it to
# `b1` would recreate exactly the perturbation GC-1 isolated it from.
#
# It is absent from `all` and from default CI; ci.yml reaches it only through
# a `workflow_dispatch` whose `b1_latency_basis` input is explicitly true.
#
# It FAILS CLOSED twice, and neither failure is a skip:
#   * before any container exists, when the sizing ledger is unrecorded or
#     invalid -- there is no right-hand side to compare against; and
#   * immediately after routing, when this runner is not the exact recorded
#     signature identity -- a measurement of another CPU model, topology or
#     image is not a measurement of the recorded basis's population.
# Both print `basis_oracle_unobserved:<reason>` and exit 3, so a rotated
# runner is reported as unobserved rather than counted as an oracle pass.
b1_latency_basis() {
  assert_matches_ci 'bash scripts/integration-test.sh b1_latency_basis' || return 1
  local -a cpus=()
  mapfile -t cpus < <(b1_available_cpus)
  if [ "${#cpus[@]}" -lt 1 ]; then
    echo "integration-test.sh: b1_latency_basis needs a usable scheduler-affinity operation (taskset)" >&2
    return 1
  fi
  # Precondition 1: a recorded, fully qualified ledger, BEFORE b1_prepare.
  "$REPO_ROOT/services/worker/.venv/bin/python" "$REPO_ROOT/tests/delivery/test_delivery_sizing_ledger.py" basis-oracle-preflight --values "$REPO_ROOT/deploy/charts/dbagent/values.yaml" --decision "$REPO_ROOT/tests/benchmark/b1_topology_decision.json"
  local rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "integration-test.sh: b1_latency_basis did not observe the CPU-basis oracle; no workload ran" >&2
    return "$rc"
  fi
  b1_prepare || return 1
  b1_write_coverage_driver
  b1_run_driver driver-coverage.sh "${cpus[0]}"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    b1_cleanup
    trap - EXIT TERM INT
    return "$rc"
  fi

  local route_disposition route_topology
  B1_ROUTE_RECORD="${RUNNER_TEMP:-/tmp}/b1-topology-route-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}.json"
  python3 "$B1_PROBE_PLANNER" route \
    --decision "$REPO_ROOT/tests/benchmark/b1_topology_decision.json" \
    --out "$B1_ROUTE_RECORD"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    b1_cleanup
    trap - EXIT TERM INT
    return "$rc"
  fi
  IFS=$'\t' read -r route_disposition route_topology < <(
    python3 "$B1_PROBE_PLANNER" route-fields --route "$B1_ROUTE_RECORD"
  )
  rc=$?
  if [ "$rc" -ne 0 ] || [ -z "$route_disposition" ]; then
    echo "integration-test.sh: b1_latency_basis could not read the route record $B1_ROUTE_RECORD" >&2
    b1_cleanup
    trap - EXIT TERM INT
    return 1
  fi
  # Precondition 2: this runner IS the recorded signature identity. A recorded
  # GC-3 route reports its own canonical reason here, before pair discovery and
  # before any live fixture.
  "$REPO_ROOT/services/worker/.venv/bin/python" "$REPO_ROOT/tests/delivery/test_delivery_sizing_ledger.py" basis-oracle-route --values "$REPO_ROOT/deploy/charts/dbagent/values.yaml" --decision "$REPO_ROOT/tests/benchmark/b1_topology_decision.json" --route "$B1_ROUTE_RECORD"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "integration-test.sh: b1_latency_basis did not observe the CPU-basis oracle; no workload ran" >&2
    b1_cleanup
    trap - EXIT TERM INT
    return "$rc"
  fi
  if [ "$route_disposition" != "gating" ] || [ -z "$route_topology" ] || [ "$route_topology" = "none" ]; then
    echo "integration-test.sh: b1_latency_basis read an unusable route ($route_disposition/$route_topology)" >&2
    b1_cleanup
    trap - EXIT TERM INT
    return 1
  fi
  if [ "${#cpus[@]}" -lt 4 ]; then
    echo "integration-test.sh: b1_latency_basis needs at least 4 available logical CPUs, this host offers ${#cpus[@]}" >&2
    b1_cleanup
    trap - EXIT TERM INT
    return 1
  fi
  local -a sibling_pairs=()
  mapfile -t sibling_pairs < <(b1_complete_sibling_pairs "${cpus[@]}")
  if [ "${#sibling_pairs[@]}" -lt 2 ]; then
    echo "integration-test.sh: b1_latency_basis needs two complete two-thread SMT sibling pairs inside its allowed CPU set ($(b1_canonical_cpu_list "${cpus[@]}")); this host offers ${#sibling_pairs[@]}" >&2
    b1_cleanup
    trap - EXIT TERM INT
    return 1
  fi
  local driver_cpus
  driver_cpus="$(python3 "$B1_PROBE_PLANNER" contract-selected \
    --topology "$route_topology" \
    --pairs "${sibling_pairs[0]}" "${sibling_pairs[1]}" \
    --run-id "$B1_RUN_ID" \
    --out "$B1_RUN_DIR/placement.json")"
  rc=$?
  if [ "$rc" -ne 0 ] || [ -z "$driver_cpus" ]; then
    echo "integration-test.sh: b1_latency_basis could not render the selected topology $route_topology" >&2
    b1_cleanup
    trap - EXIT TERM INT
    return 1
  fi
  cat > "$B1_RUN_DIR/driver-latency-basis.sh" <<'B1_LATENCY_BASIS_LIVE'
set -uo pipefail
cd /workspace
env -u PYTHON_VERSION -u PYTHON_PIP_VERSION -u PYTHON_GET_PIP_URL -u PYTHON_GET_PIP_SHA256 python3 -B -X pycache_prefix=/run/dbagent-b1/pycache -m pytest services/gateway/tests/test_b1_ingest_burst.py -v -s -m 'b1_live and not b1_product and not b1_topology_probe' -o cache_dir=/run/dbagent-b1/pytest-cache || exit $?
B1_LATENCY_BASIS_LIVE
  b1_run_driver driver-latency-basis.sh "$driver_cpus"
  rc=$?
  b1_cleanup
  trap - EXIT TERM INT
  if [ "$B1_CLEANUP_FAILED" -ne 0 ] || [ "$B1_RUN_DIR_FAILED" -ne 0 ]; then return 1; fi
  return "$rc"
}

# The product promise: 1000 req/s for 30 s with four gateway CPUs exclusive of
# the PostgreSQL and driver sets. Local only, and deliberately absent from CI --
# a public standard runner has four total vCPUs and there is no larger-runner
# budget. Its three product comparisons are recorded as met/missed on the
# fingerprint; placement, accounting and record integrity still gate.
b1_product() {
  local -a cpus=()
  mapfile -t cpus < <(b1_available_cpus)
  if [ "${#cpus[@]}" -eq 0 ]; then
    echo "integration-test.sh: b1_product needs a usable scheduler-affinity operation (taskset)" >&2
    return 1
  fi
  if [ "${#cpus[@]}" -lt 8 ]; then
    echo "integration-test.sh: b1_product needs at least 8 available logical CPUs, this host offers ${#cpus[@]}" >&2
    return 1
  fi
  # Product 4/3/1 over the first eight available CPUs (FP-GC1-3).
  local gateway_cpus postgres_cpus driver_cpus
  gateway_cpus="$(b1_canonical_cpu_list "${cpus[0]}" "${cpus[1]}" "${cpus[2]}" "${cpus[3]}")"
  postgres_cpus="$(b1_canonical_cpu_list "${cpus[4]}" "${cpus[5]}" "${cpus[6]}")"
  driver_cpus="$(b1_canonical_cpu_list "${cpus[7]}")"
  b1_prepare || return 1
  cat > "$B1_RUN_DIR/placement.json" <<B1_PRODUCT_CONTRACT
{
  "schema": 2,
  "runId": "${B1_RUN_ID}",
  "profile": "product-exclusive",
  "minimumHostLogicalCpus": 8,
  "mechanism": "sched-affinity",
  "roles": {
    "gateway": {"allowedCpus": "${gateway_cpus}"},
    "postgres": {"allowedCpus": "${postgres_cpus}"},
    "driver": {"allowedCpus": "${driver_cpus}"}
  }
}
B1_PRODUCT_CONTRACT
  cat > "$B1_RUN_DIR/driver-product.sh" <<'B1_PRODUCT_DRIVER'
set -uo pipefail
cd /workspace
env -u PYTHON_VERSION -u PYTHON_PIP_VERSION -u PYTHON_GET_PIP_URL -u PYTHON_GET_PIP_SHA256 python3 -B -X pycache_prefix=/run/dbagent-b1/pycache -m pytest services/gateway/tests/test_b1_ingest_burst.py -v -s -m b1_product -o cache_dir=/run/dbagent-b1/pytest-cache || exit $?
B1_PRODUCT_DRIVER
  b1_run_driver driver-product.sh "$driver_cpus"
  local rc=$?
  b1_cleanup
  trap - EXIT TERM INT
  if [ "$B1_CLEANUP_FAILED" -ne 0 ] || [ "$B1_RUN_DIR_FAILED" -ne 0 ]; then return 1; fi
  return "$rc"
}

# ---------------------------------------------------------------------------
# GC-3 -- the B1 reference-topology discovery route (FP-GC3-1/2).
#
# A MANUAL measurement instrument, not a gate. `ci.yml` starts it only from a
# `workflow_dispatch` with `b1_topology_probe=true`; it is in no job's `needs:`
# and in no local composite target. It measures the closed 28-arm candidate set
# -- seven topology classes x two orientations x two round-robin rounds -- each
# under the UNCHANGED CI-scale workload, and records one truthful met/missed
# value per unchanged comparison.
#
# The separation this rests on: a candidate that misses the bar is DATA. This
# target fails only when the measurement itself is broken -- a missing or
# duplicated arm, a placement or topology that was not observed, an accounting
# or lifecycle failure, or an artifact that cannot be written. Asserting the
# bar per arm would stop the sweep at the first expected miss and destroy the
# evidence the decision needs.
#
# Nothing here authors a topology. The stdlib-only planner in
# services/gateway/tests/b1_topology_probe.py enumerates the closed set on the
# host, and the Python parser inside the driver independently reconstructs and
# compares every mapping before a single request is offered.
# ---------------------------------------------------------------------------

B1_PROBE_PLANNER="services/gateway/tests/b1_topology_probe.py"
B1_PROBE_ACCUMULATOR=""
B1_PROBE_PLAN=""
B1_PROBE_ARTIFACT=""
B1_PROBE_FINISHED=1
B1_PROBE_FAILED_ARM=""
B1_PROBE_FAILED_EXIT=0

# In CI the name resolves byte-for-byte to ci.yml's upload `path:`. A local run
# keeps its own retained, run-scoped name so two local sweeps cannot overwrite
# each other's evidence.
b1_topology_probe_artifact_path() {
  local temp="${RUNNER_TEMP:-/tmp}"
  if [ -n "${GITHUB_RUN_ID:-}" ] && [ -n "${GITHUB_RUN_ATTEMPT:-}" ]; then
    printf '%s/b1-topology-probe-%s-%s.json' "$temp" "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT"
  else
    printf '%s/b1-topology-probe-local-%s-1.json' "$temp" "$1"
  fi
}

# EXIT-trap safe, and idempotent. However the sweep ends -- all arms done, an
# arm failed, the runner was killed -- the collector runs exactly once over the
# immutable plan and whatever records exist, and writes `complete` or a closed
# `invalid` naming the missing arms. A best-effort invalid artifact never
# converts a broken sweep into success: this returns the collector's status.
b1_topology_probe_finish() {
  [ "$B1_PROBE_FINISHED" -eq 0 ] || return 0
  B1_PROBE_FINISHED=1
  local -a failure=()
  if [ -n "$B1_PROBE_FAILED_ARM" ]; then
    failure=(--failed-arm "$B1_PROBE_FAILED_ARM" --exit-code "$B1_PROBE_FAILED_EXIT")
  fi
  python3 "$B1_PROBE_PLANNER" collect \
    --plan "$B1_PROBE_PLAN" \
    --records "$B1_PROBE_ACCUMULATOR/records" \
    --out "$B1_PROBE_ARTIFACT" ${failure[@]+"${failure[@]}"}
  local rc=$?
  echo "integration-test.sh: b1_topology_probe artifact retained at $B1_PROBE_ARTIFACT"
  return "$rc"
}

# One arm: a fresh run id, a fresh run directory, a fresh driver container, a
# fresh database, a fresh warmup and a fresh measured window. Nothing crosses
# arms, and the validated record is copied OUT of the run mount before the
# per-arm cleanup can remove it.
b1_topology_probe_arm() {
  local index="$1" rc=0 driver_cpus
  B1_RUN_ID=""
  B1_RUN_DIR=""
  B1_CLEANUP_FAILED=0
  B1_RUN_DIR_FAILED=0
  b1_prepare || return 1
  trap 'b1_cleanup; b1_topology_probe_finish' EXIT TERM INT
  driver_cpus="$(python3 "$B1_PROBE_PLANNER" contract \
    --plan "$B1_PROBE_PLAN" --arm "$index" --run-id "$B1_RUN_ID" \
    --out "$B1_RUN_DIR/placement.json" --context "$B1_RUN_DIR/probe-context.json")"
  rc=$?
  if [ "$rc" -eq 0 ]; then
    cp "$B1_PROBE_ACCUMULATOR/driver-probe.sh" "$B1_RUN_DIR/driver-probe.sh" || rc=1
  fi
  if [ "$rc" -eq 0 ]; then
    b1_run_driver driver-probe.sh "$driver_cpus"
    rc=$?
  fi
  if [ "$rc" -eq 0 ]; then
    if [ -f "$B1_RUN_DIR/arm-record.json" ]; then
      cp "$B1_RUN_DIR/arm-record.json" \
        "$(printf '%s/records/record-%02d.json' "$B1_PROBE_ACCUMULATOR" "$index")" || rc=1
    else
      echo "integration-test.sh: arm $index (run ${B1_RUN_ID}, dir ${B1_RUN_DIR}) wrote no record" >&2
      rc=1
    fi
  fi
  b1_cleanup
  trap 'b1_topology_probe_finish' EXIT TERM INT
  if [ "$B1_CLEANUP_FAILED" -ne 0 ]; then
    echo "integration-test.sh: arm $index left containers behind; the sweep stops here" >&2
    return 1
  fi
  if [ "$B1_RUN_DIR_FAILED" -ne 0 ]; then
    echo "integration-test.sh: arm $index could not remove its run directory; the sweep stops here" >&2
    return 1
  fi
  return "$rc"
}

b1_topology_probe() {
  assert_matches_ci 'bash scripts/integration-test.sh b1_topology_probe' || return 1
  local outer_run_id planned index rc=0 collect_rc=0
  outer_run_id="$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')"
  if [ "${#outer_run_id}" -ne 32 ]; then
    echo "integration-test.sh: could not generate a 32-hex probe run id" >&2
    return 1
  fi
  # The accumulator and the final artifact live OUTSIDE every per-arm
  # B1_RUN_DIR on purpose: the ordinary b1_cleanup removes a run directory
  # after each arm, and a record stored there would be deleted with it.
  B1_PROBE_ACCUMULATOR="$(mktemp -d -t dbagent-b1-probe-XXXXXXXXXX)" || return 1
  B1_PROBE_PLAN="$B1_PROBE_ACCUMULATOR/plan.json"
  mkdir -p "$B1_PROBE_ACCUMULATOR/records" || return 1
  B1_PROBE_ARTIFACT="$(b1_topology_probe_artifact_path "$outer_run_id")"
  B1_PROBE_FAILED_ARM=""
  B1_PROBE_FAILED_EXIT=0
  B1_PROBE_FINISHED=0
  trap 'b1_topology_probe_finish' EXIT TERM INT

  # The planner is the single topology authority. If this host has no two
  # complete SMT sibling pairs it writes one `invalid` artifact with
  # failureCode `unsupported_topology` and runs no candidate at all, so a
  # rerun on a suitable host costs nothing and no measurement is invented.
  planned="$(python3 "$B1_PROBE_PLANNER" plan --out "$B1_PROBE_PLAN" --artifact "$B1_PROBE_ARTIFACT")"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    B1_PROBE_FINISHED=1
    trap - EXIT TERM INT
    echo "integration-test.sh: b1_topology_probe wrote an invalid artifact at $B1_PROBE_ARTIFACT" >&2
    return "$rc"
  fi

  # The container-free coverage phase runs with `b1`; this target is the
  # untraced live sweep only. The probe marker selects the single dual-
  # marked node in the live-only module, whose file is the command's ONLY
  # positional operand -- that is what keeps the frozen sizing-ledger producer
  # test_b1_ingest_burst.py collected by exactly one CI job (FP-IG-26).
  cat > "$B1_PROBE_ACCUMULATOR/driver-probe.sh" <<'B1_TOPOLOGY_PROBE_DRIVER'
set -uo pipefail
cd /workspace
env -u PYTHON_VERSION -u PYTHON_PIP_VERSION -u PYTHON_GET_PIP_URL -u PYTHON_GET_PIP_SHA256 python3 -B -X pycache_prefix=/run/dbagent-b1/pycache -m pytest services/gateway/tests/b1_topology_probe_live.py -v -s -m b1_topology_probe -o cache_dir=/run/dbagent-b1/pytest-cache || exit $?
B1_TOPOLOGY_PROBE_DRIVER

  for ((index = 0; index < planned; index++)); do
    echo "--- b1_topology_probe arm $((index + 1)) of $planned"
    b1_topology_probe_arm "$index"
    rc=$?
    if [ "$rc" -ne 0 ]; then
      B1_PROBE_FAILED_ARM="$index"
      B1_PROBE_FAILED_EXIT="$rc"
      echo "integration-test.sh: arm $index failed ($rc); stopping the sweep after cleanup" >&2
      break
    fi
  done
  b1_topology_probe_finish
  collect_rc=$?
  trap - EXIT TERM INT
  if [ "$rc" -ne 0 ]; then return "$rc"; fi
  return "$collect_rc"
}

# One real testcontainers test per runtime, hardcoded -- no caller-supplied filter, for
# the same reason there is no argument pass-through. Both legs start a Postgres, migrate
# it with alembic and connect, so a pass proves the whole chain the sandbox breaks:
# container start and published-port reachability. Both runtimes are covered because they
# reach the containers by different code paths (Go's own driver; psycopg2 under pytest),
# and a fix that works for one is not automatically proof for the other.
smoke_test() {
  local rc=0
  echo "--- Go leg"
  go test ./services/probe-gateway/internal/registry/... \
    -run TestPG_GetPlatform_NotFound -count=1 -v -timeout 120s || rc=1
  echo "--- Python leg"
  services/worker/.venv/bin/python -m pytest \
    services/dashboard-api/tests/test_auth.py -q --no-header -x || rc=1
  return "$rc"
}

case "$WHAT" in
  smoke)     run_step "Smoke (one testcontainers test per runtime: Go + Python)" smoke_test ;;
  all)       run_step "Go (go test ./... -race -p 1)" go_tests
             run_step "Python (functional + service tiers)" py_tests
             run_step "B1 CI-scale (resource-declared, gating)" b1
             run_step "B1 product promise (recorded, non-gating)" b1_product ;;
  go)        run_step "Go (go test ./... -race -p 1)" go_tests ;;
  py|python) run_step "Python (functional + service tiers)" py_tests ;;
  d0_2a)     run_step "D0.2-a direct _ingest_txn replay (diagnostic)" d0_2a ;;
  d0_2c)     run_step "D0.2-c HTTP sweep, _ingest_txn stubbed to calibrated sleep (diagnostic)" d0_2c ;;
  d0_2d)     run_step "D0.2-d worker-count A/B, same host same session (diagnostic)" d0_2d ;;
  d0_3a)     run_step "D0.3-a driver split: 1 driver process vs P (diagnostic)" d0_3a ;;
  d0_3b)     run_step "D0.3-b dispatch split: threadpool vs loop (diagnostic)" d0_3b ;;
  d0_3c)     run_step "D0.3-c open connections vs in-flight (diagnostic)" d0_3c ;;
  d0_4)      run_step "D0.4 member split: lattice subtraction arms (diagnostic)" d0_4 ;;
  d0_4_workers) run_step "D0.4 worker co-listener registration exercise (diagnostic)" d0_4_workers ;;
  sp_1)      run_step "SP-1 wire split: self-test + dry-run (diagnostic)" sp_1 ;;
  sp_1_run)  run_step "SP-1 wire split: the real session, needs Docker (diagnostic)" sp_1_run ;;
  sp_1_sg4)  run_step "SP-1 SG4 stub-bracket exercise, needs Docker (diagnostic)" sp_1_sg4 ;;
  rm_1)      run_step "RM-1 driver ceiling: self-test + dry-run (diagnostic)" rm_1 ;;
  rm_1_run)  run_step "RM-1 driver ceiling: the real session, needs Docker (diagnostic)" rm_1_run ;;
  lv_1)      run_step "LV-1 leg witness: self-test + dry-run (diagnostic)" lv_1 ;;
  lv_1_run)  run_step "LV-1 leg witness: the real session (diagnostic)" lv_1_run ;;
  b1)        run_step "B1 CI-scale (resource-declared, gating)" b1 ;;
  b1_product) run_step "B1 product promise (recorded, non-gating)" b1_product ;;
  b1_latency_basis) run_step "B1 CPU-basis oracle (isolated, explicit)" b1_latency_basis ;;
  b1_topology_probe) run_step "B1 topology discovery (28 arms, recorded, manual)" b1_topology_probe ;;
esac

echo
if [ "${#FAILED[@]}" -eq 0 ]; then
  echo "integration-test.sh: ALL PASSED ($WHAT)"
  exit 0
fi
printf 'integration-test.sh: FAILED (%s):\n' "$WHAT" >&2
printf '  - %s\n' "${FAILED[@]}" >&2
exit 1
