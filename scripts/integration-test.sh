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
#   The B1 tier is the exception, and it is deliberate: `b1_product` needs a Docker
#   daemon, the host PID namespace and scheduler affinity over at least eight logical
#   CPUs. Since bench-on-demand (FP-BOD-1/2) no CI job runs it at all: it is measured on
#   a developer host before a release and after a change to the ingest write path. See
#   docs/runbooks/bench-on-demand.md.
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
#   the SINGLE carrier of the B1 reference deployment: one target, `b1_product`, one
#   placement contract and one set of assertions, so there is nothing for a second copy
#   to drift from.
#
#   `tests/functional/test_manifests.py` pins this script's container flags, the
#   placement contract, the marker selections and the cleanup scope by equality, and
#   `tests/functional/test_bench_on_demand.py` pins that the retired CI-scale, oracle and
#   topology-probe targets are refused, so a silent edit is a named test failure.
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
  all|go|py|python|preflight|smoke|d0_2a|d0_2c|d0_2d|d0_3a|d0_3b|d0_3c|d0_4|d0_4_workers|sp_1|sp_1_run|sp_1_sg4|rm_1|rm_1_run|lv_1|lv_1_run|b1_product) ;;
  -h|--help|help)
    # QUOTED heredoc: this block contains backticks and angle brackets that must print
    # literally. Unquoted, bash treats `go test -exec <anything>` as a command
    # substitution and the line renders empty with a syntax error on stderr. (The
    # refusal message below is deliberately UNquoted -- it interpolates $REPO_ROOT.)
    cat <<'EOF'
usage: scripts/integration-test.sh [all|go|py|preflight|smoke|b1_product|d0_2a|d0_2c|d0_2d|d0_3a|d0_3b|d0_3c|d0_4|d0_4_workers|sp_1|sp_1_run|sp_1_sg4|rm_1|rm_1_run|lv_1|lv_1_run]

  all  (default)  go + py + b1_product -- the local acceptance route
  b1_product      the on-demand 1000 req/s product-promise B1 run on
                  measured-role-exclusive cores (gateway 4 / PostgreSQL 3 /
                  driver 1); needs >= 8 logical CPUs. It FAILS the run when the
                  offer is not fully served, when any request errors, or when
                  the placement, accounting or record-integrity checks fail; the
                  due-time p99 is printed as met or missed and is not the bar.
                  Run it before every v* tag and after a change to the ingest
                  write path -- see docs/runbooks/bench-on-demand.md. A host that
                  cannot host it gets this target's non-zero refusal; there is no
                  recorded route that exits 0 without measuring anything.
  go              go test ./... -race -coverprofile=... -covermode=atomic
                  -timeout 300s -p 1 (one pass), then the >80% per-package
                  coverage gate on that same profile -- exactly as CI's unit-go
  py              the functional/service pytest tiers that use testcontainers
  preflight       run only the checks, no tests -- confirms in ~1s that the
                  sandbox exclusion is live and Docker is reachable
  smoke           one real testcontainers test per runtime, Go + Python (~10s)
                  -- proves end to end that a container's published port is
                  actually reachable from both

RELAY OVERRIDE: when this shell has no global-scope address, the two admitted
targets -- preflight and b1_product -- can still run, but only after this script
has proved host-network reachability through your own Docker socket. Ask for the
proof, and point TMPDIR at a directory the host daemon can bind-mount (the script
sets neither for you):

    DBAGENT_DOCKER_RELAY=prove TMPDIR=<directory-the-host-daemon-can-bind-mount> \
      /opt/gitspace/dbagent/scripts/integration-test.sh preflight

Every other target keeps the refusal below. See the preflight block in this file.

NOTE: there is deliberately no pass-through for extra flags. This script runs
UNSANDBOXED, and forwarding arbitrary arguments would reopen exactly what the
narrow exemption exists to prevent (e.g. `go test -exec <anything>`).

Must run OUTSIDE the Claude Code sandbox -- see the header of this file.
EOF
    exit 0 ;;
  *)
    echo "integration-test.sh: unknown target '$WHAT' (want: all | go | py | preflight | smoke | b1_product | d0_2a | d0_2c | d0_2d | d0_3a | d0_3b | d0_3c | d0_4 | d0_4_workers | sp_1 | sp_1_run | sp_1_sg4 | rm_1 | rm_1_run | lv_1 | lv_1_run)" >&2
    exit 2 ;;
esac

# ---------------------------------------------------------------------------
# Preflight: refuse to run inside the sandbox, unless an admitted target has
# proved a route for itself.
#
# Without this the failure mode is a 60-second-per-package timeout ending in a Ryuk
# message about an unreachable port, which reads like flaky infrastructure and sends
# people looking at Docker. It is not flaky and Docker is fine -- the exclusion simply
# did not apply. Fail in a second, and say so.
#
# The legacy gate is behavioural rather than a check for bubblewrap specifically, and
# it is deliberately narrow: the count of global-scope addresses is read from
# /usr/bin/ip and from nowhere else, so whatever a caller's PATH calls `ip` is never
# consulted. A count greater than zero is the ordinary host and CI; it takes the
# existing `docker info` check, unchanged. A count of zero refuses exactly as it
# always has, with one exception -- one of the two admitted targets (preflight,
# b1_product) whose caller asked for it with
# DBAGENT_DOCKER_RELAY=prove AND for which this script has then proved host-network
# reachability itself: a local unix socket, a mktemp directory the daemon can see
# through a bind mount, and a `--network host` client that completed a TCP handshake
# with a `--network host` listener started through the caller's own socket. The
# request admits nothing on its own; only the proof does. That is the supported route
# for a jailed reviewer whose Docker socket is relayed from the host, and it replaces
# the PATH `ip` shim, which made the count non-zero by asserting a route no one had
# observed.
# ---------------------------------------------------------------------------
# RELAY_GATE_BEGIN
# Function definitions only. tests/functional/test_integration_relay_preflight.py
# sources this region verbatim, so nothing between the two markers may run at
# source time; the single top-level call sits just after RELAY_GATE_END.
#
# Two house rules this region keeps deliberately, both of them load-bearing
# elsewhere in the tree:
#
#   * no `||`-fallback that swallows a command's status. The launcher may carry
#     none (tests/functional/test_manifests.py's rejected-escape inventory and
#     tests/delivery/test_delivery_b1_profile.py's weakening inventory scan this
#     whole file), and none is needed: the script runs without `set -e`, so a
#     status no one reads is already ignored. Every command below whose status
#     is not the verdict is followed by the check that IS the verdict.
#   * continuation lines of the probe `docker run` commands are indented two
#     spaces, not four. A four-space host-network continuation line is a pinned,
#     must-be-unique literal of b1_run_driver further down this file, and a copy
#     of it up here would take a manifest mutation's place and silence it.

relay_address_count() {
  if [ ! -x /usr/bin/ip ]; then
    echo 0
    return 0
  fi
  /usr/bin/ip -o addr show scope global 2>/dev/null | wc -l | tr -d '[:space:]'
}

relay_target_admitted() {
  case "$1" in
    preflight|b1_product) return 0 ;;
    *) return 1 ;;
  esac
}

relay_legacy_refuse() {
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
}

relay_legacy_docker_info() {
  if ! docker info >/dev/null 2>&1; then
    echo "integration-test.sh: cannot reach the Docker daemon (DOCKER_HOST=${DOCKER_HOST:-unset})" >&2
    exit 3
  fi
}

# One first line, one reason from the closed list in the relay proof below, and
# for two of those reasons one further line saying what the caller must change.
relay_fail() {
  echo "integration-test.sh: REFUSING TO RUN -- relay override did not prove host-network reachability ($1)." >&2
  case "$1" in
    relay_probe_image_absent)
      echo "integration-test.sh: probe image postgres:16-alpine is not present locally; this preflight does not pull it." >&2 ;;
    relay_probe_mount_invisible)
      echo "integration-test.sh: the mktemp directory was not visible to the daemon through its bind mount; set TMPDIR to a directory the host daemon can see." >&2 ;;
  esac
  exit 3
}

# Prints one path, or nothing, and never exits: the caller decides, in its own
# shell, so a refusal is not swallowed by a command substitution.
relay_docker_socket_path() {
  case "${DOCKER_HOST:-}" in
    "")        printf '%s\n' /var/run/docker.sock ;;
    unix:///*) printf '%s\n' "${DOCKER_HOST#unix://}" ;;
    *)         return 0 ;;
  esac
}

# Idempotent, and installed as an EXIT trap before the first probe artefact
# exists. The removal's own status is not a verdict; the second census is.
relay_probe_cleanup() {
  if [ -n "${srv_name:-}" ]; then
    /usr/bin/docker rm -f "$srv_name" >/dev/null 2>&1
  fi
  if [ -n "${probe_id:-}" ]; then
    ids="$(/usr/bin/docker ps -aq --filter "label=dbagent.relay-probe=${probe_id}" 2>/dev/null)"
    if [ -n "$ids" ]; then
      # shellcheck disable=SC2086
      /usr/bin/docker rm -f $ids >/dev/null 2>&1
      ids="$(/usr/bin/docker ps -aq --filter "label=dbagent.relay-probe=${probe_id}" 2>/dev/null)"
      if [ -n "$ids" ]; then
        RELAY_CLEANUP_FAILED=1
      fi
    fi
  fi
  if [ -n "${probe_dir:-}" ]; then
    rm -rf "$probe_dir"
  fi
}

# The listener: one container, host network, loopback only, one port, no
# published port and no password.
relay_probe_server() {
  /usr/bin/timeout 30 /usr/bin/docker run -d --name "$srv_name" \
  --network host \
  --label "dbagent.relay-probe=${probe_id}" \
  -e POSTGRES_HOST_AUTH_METHOD=trust \
  postgres:16-alpine \
  postgres -c listen_addresses=127.0.0.1 -c port="${probe_port}" >/dev/null
}

# The single client, run once after the real server logged its IPv4 listen line
# and a ready line after it. Its non-zero status is the only producer of
# relay_probe_unreachable: without --network host this same command fails, and
# that failure is the missing host network.
relay_probe_client() {
  /usr/bin/timeout 10 /usr/bin/docker run --rm \
  --network host \
  --label "dbagent.relay-probe=${probe_id}" \
  --entrypoint pg_isready \
  postgres:16-alpine \
  -h 127.0.0.1 -p "${probe_port}" -U postgres -t 2 \
  >/dev/null
}

# The whole proof, one shot: unix socket, absolute docker client, local image,
# bind-mount visibility of a mktemp directory, then one host-network listener
# and one host-network client. No pull, no second port, no retry.
relay_prove() {
  sock="$(relay_docker_socket_path)"
  if [ -z "$sock" ]; then
    relay_fail relay_socket_not_unix
  fi
  if [ ! -S "$sock" ]; then
    relay_fail relay_socket_absent
  fi
  if [ ! -x /usr/bin/docker ] || [ ! -x /usr/bin/timeout ]; then
    relay_fail relay_probe_setup_failed
  fi
  if ! /usr/bin/timeout 5 /usr/bin/docker info >/dev/null 2>&1; then
    relay_fail relay_docker_info_failed
  fi
  if ! /usr/bin/timeout 15 /usr/bin/docker image inspect postgres:16-alpine >/dev/null 2>&1; then
    relay_fail relay_probe_image_absent
  fi

  probe_id="$(od -An -tx1 -N8 /dev/urandom | tr -d ' \n')"
  if [ "${#probe_id}" -ne 16 ]; then
    relay_fail relay_probe_setup_failed
  fi
  srv_name="dbagent-relay-probe-${probe_id}"
  probe_dir=""
  RELAY_CLEANUP_FAILED=0
  trap relay_probe_cleanup EXIT

  probe_dir="$(mktemp -d -t dbagent-relay-XXXXXXXXXX)" || relay_fail relay_probe_setup_failed
  printf 'visible\n' > "$probe_dir/sentinel"
  mount_out="$(/usr/bin/timeout 15 /usr/bin/docker run --rm \
  --label "dbagent.relay-probe=${probe_id}" \
  -v "${probe_dir}:/probe:ro" \
  --entrypoint /bin/cat \
  postgres:16-alpine /probe/sentinel 2>/dev/null)"
  if [ "$mount_out" != visible ]; then
    relay_fail relay_probe_mount_invisible
  fi

  probe_port=$((20000 + (RANDOM % 12000)))
  if ! relay_probe_server; then
    relay_fail relay_probe_bind_failed
  fi

  # Readiness is the ORDERED pair. On a fresh data directory the image's
  # entrypoint first runs a temporary server with listen_addresses='' which logs
  # a ready line of its own; that server never logs an IPv4 listen line, so the
  # pair cannot match until the real server is listening on this probe's port.
  # Capture the log and match it; a pipe into `grep -q` can SIGPIPE the logger
  # under this script's pipefail and turn a found line into a failure.
  listen_line="listening on IPv4 address \"127.0.0.1\", port ${probe_port}"
  ready_line="database system is ready to accept connections"
  deadline=$((SECONDS + 20))
  ready=0
  running=""
  while [ "$SECONDS" -lt "$deadline" ]; do
    running="$(/usr/bin/docker inspect -f '{{.State.Running}}' "$srv_name" 2>/dev/null)"
    if [ "$running" != "true" ]; then
      break
    fi
    logs="$(/usr/bin/docker logs "$srv_name" 2>&1)"
    case "$logs" in
      *"$listen_line"*"$ready_line"*) ready=1; break ;;
    esac
    sleep 1
  done
  if [ "$ready" -ne 1 ]; then
    if [ "$running" = "true" ]; then
      relay_fail relay_probe_timeout
    fi
    relay_fail relay_probe_bind_failed
  fi

  if ! relay_probe_client; then
    relay_fail relay_probe_unreachable
  fi

  relay_probe_cleanup
  trap - EXIT
  if [ "$RELAY_CLEANUP_FAILED" -ne 0 ]; then
    relay_fail relay_probe_cleanup_failed
  fi
  return 0
}

relay_gate_counted() {
  local count="$1" target="$2" request="$3"
  if [ "$count" -gt 0 ]; then
    relay_legacy_docker_info
    PREFLIGHT_MODE=legacy
    return 0
  fi
  if ! relay_target_admitted "$target"; then
    relay_legacy_refuse
  fi
  case "$request" in
    "") relay_legacy_refuse ;;
    prove) ;;
    *) relay_fail relay_request_invalid ;;
  esac
  if ! relay_prove; then
    relay_fail relay_probe_setup_failed
  fi
  PREFLIGHT_MODE=relay
  return 0
}

# Runs in the script's own shell: a refusal is an exit 3, and an exit inside a
# command substitution would leave the script running.
relay_gate() {
  local count
  count="$(relay_address_count)"
  relay_gate_counted "$count" "$WHAT" "${DBAGENT_DOCKER_RELAY-}"
}

relay_print_preflight() {
  if [ "$PREFLIGHT_MODE" = relay ]; then
    echo "integration-test.sh: preflight OK (relay override)"
    echo "  relay proof         : host-network reachability verified"
    echo "  docker              : $(/usr/bin/docker version --format '{{.Server.Version}}' 2>/dev/null) via ${DOCKER_HOST:-default socket}"
    echo "  admitted targets    : preflight b1_product"
  else
    echo "integration-test.sh: preflight OK"
    echo "  outside the sandbox : $(/usr/bin/ip -o addr show scope global | awk '{print $2}' | sort -u | tr '\n' ' ')"
    echo "  docker              : $(docker version --format '{{.Server.Version}}' 2>/dev/null) via ${DOCKER_HOST:-default socket}"
  fi
  echo "  rca_common venv     : $([ -x libs/py/rca_common/.venv/bin/python ] && echo present || echo MISSING)"
  echo "  worker venv         : $([ -x services/worker/.venv/bin/python ] && echo present || echo MISSING)"
}
# RELAY_GATE_END

PREFLIGHT_MODE=legacy
relay_gate

# `preflight` stops here: everything above is the part that tells you whether a real run
# CAN work. Worth its own target so that confirming the excludedCommands entry costs a
# second instead of a full suite -- and so a failed exclusion is discovered before, not
# five minutes into, the run it would have wrecked.
if [ "$WHAT" = preflight ]; then
  relay_print_preflight
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
#
# ci-runtime-1 FP-CIR1-3/5: one -race pass writes the coverage profile, and the
# coverage gate reads that same file. Both literals are pinned against ci.yml. The
# profile path is the same literal /tmp path CI uses, so the anti-drift check stays
# exact; a profile left behind by an earlier run can never turn a failed Go run green,
# because the checker is not reached after a non-zero Go result.
# ---------------------------------------------------------------------------
go_tests() {
  assert_matches_ci \
    'go test ./... -race -coverprofile=/tmp/dbagent-ci-go.coverprofile -covermode=atomic -timeout 300s -p 1' \
    'bash scripts/go-coverage-check.sh 80 /tmp/dbagent-ci-go.coverprofile' || return 1
  if [ ! -x libs/py/rca_common/.venv/bin/python ]; then
    echo "missing libs/py/rca_common/.venv -- registry/pg_test.go needs it for alembic." >&2
    echo "  python -m venv libs/py/rca_common/.venv && libs/py/rca_common/.venv/bin/pip install -e 'libs/py/rca_common[test]'" >&2
    return 1
  fi
  if ! libs/py/rca_common/.venv/bin/python -c 'import alembic' 2>/dev/null; then
    echo "libs/py/rca_common/.venv exists but has no alembic -- reinstall with the [test] extra." >&2
    return 1
  fi
  go test ./... -race -coverprofile=/tmp/dbagent-ci-go.coverprofile -covermode=atomic -timeout 300s -p 1 || return 1
  bash scripts/go-coverage-check.sh 80 /tmp/dbagent-ci-go.coverprofile
}

# ---------------------------------------------------------------------------
# Python
#
# Mirrors ci.yml's "Run Python functional tests" step and the FP-M6-31 A10(v)
# environment-hygiene precondition: no PYTHON*/PYTEST* variable may be set for the
# measured invocation, or the guard's own assertions are meaningless. It carries that
# step's --ignore set (those tiers run in their own CI jobs with their own fixtures)
# EXCEPT one entry: CI's broad pytest also ignores tests/functional/test_manifests.py,
# because the independent manifest-guard job owns it there (ci-runtime-1 FP-CIR1-2).
# This local route is an intentional superset and still collects it once, so a local
# run keeps the manifest and CI-pin checks.
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
# One B1 route runs here and nowhere else: `b1_product`, the on-demand product
# profile. The CI-scale route, its per-model topology carrier, the recorded
# non-gating route and the CPU-basis oracle were deleted by bench-on-demand
# (FP-BOD-2); a host that cannot host this target gets a non-zero refusal, not
# an exit 0 with no workload.
#
# The allocation is SCHEDULER AFFINITY, not CFS bandwidth. Revision 0.4 of this
# slice declared per-role CPU quotas and measured what that costs: a bursty
# role spends its fractional 100 ms allowance early and is then suspended for
# the rest of the period, so the gateway was throttled in 43 of 307 periods
# while averaging only 1.15 of its 2.00 declared cores, PostgreSQL in 65 of
# 308, and the measured p99 came out at 614-794 ms against a 150 ms bar. Exact,
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
# Docker-owned PostgreSQL tree.
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
# The review-runner image is built once per invocation and reused.
B1_IMAGE_BUILT=0
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
# bench-on-demand (FP-BOD-2): the product route is the only route, and it
# takes the first eight entries of this array as 4/3/1.
b1_available_cpus() {
  local affinity
  affinity="$(taskset -pc $$ 2>/dev/null | sed 's/.*: *//')"
  [ -n "$affinity" ] || return 1
  b1_expand_cpu_list "$affinity" | sort -n -u
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
  trap 'b1_cleanup' EXIT TERM INT
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

# The product promise: 1000 req/s for 30 s with four gateway CPUs exclusive of
# the PostgreSQL and driver sets. Local only, and deliberately absent from CI --
# a public standard runner has four total vCPUs and there is no larger-runner
# budget.
#
# bench-on-demand (FP-BOD-3): this is a GATE, not a recording. Two of the three
# product comparisons are failure-producing asserts in
# test_b1_product_exclusive_reference_profile -- `errors == 0` and
# `served == offered` -- so a run that errored or did not serve its whole offer
# FAILS this target, and the placement, accounting and record-integrity checks
# still fail it as before. Only the due-time p99 stays recorded: it is
# serialized as met/missed on the fingerprint, no node asserts it, and
# `product_p99_lt_150_ms=missed` neither fails this target nor refuses a
# release. See docs/runbooks/bench-on-demand.md.
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
  all)       run_step "Go (go test ./... -race + coverage, one pass, -p 1; >80% gate)" go_tests
             run_step "Python (functional + service tiers)" py_tests
             run_step "B1 product promise (on-demand, gating)" b1_product ;;
  go)        run_step "Go (go test ./... -race + coverage, one pass, -p 1; >80% gate)" go_tests ;;
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
  b1_product) run_step "B1 product promise (on-demand, gating)" b1_product ;;
esac

echo
if [ "${#FAILED[@]}" -eq 0 ]; then
  echo "integration-test.sh: ALL PASSED ($WHAT)"
  exit 0
fi
printf 'integration-test.sh: FAILED (%s):\n' "$WHAT" >&2
printf '  - %s\n' "${FAILED[@]}" >&2
exit 1
