#!/usr/bin/env bash
# Zero → green e2e entrypoint (design.md FP-M6-15). Fails if total wall time > 1500s.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
# shellcheck disable=SC1091
source deploy/versions.env

START=$(date +%s)
BUDGET=1500
KEEP_CLUSTER="${KEEP_CLUSTER:-0}"
PHASE_LOG="/tmp/rca-e2e/phases.txt"
mkdir -p /tmp/rca-e2e
: >"$PHASE_LOG"

# On phase failure, dump cluster state into /tmp/rca-e2e so the CI step
# "Upload phase timing and pod logs on failure" actually has pod logs /
# describes / events (not only phases.txt). Best-effort: never mask the
# original failure exit. Bound every kubectl call so a wedged API server
# cannot hang past the job timeout and cancel the artifact upload.
collect_failure_diagnostics() {
  local dir="/tmp/rca-e2e/diagnostics"
  local ktimeout=(--request-timeout=20s)
  mkdir -p "$dir"
  echo "collect_failure_diagnostics: writing to $dir" | tee -a "$PHASE_LOG"
  if ! command -v kubectl >/dev/null 2>&1; then
    echo "kubectl not available; skipping cluster diagnostics" | tee -a "$PHASE_LOG"
    return 0
  fi
  kubectl "${ktimeout[@]}" get nodes -o wide >"$dir/nodes-wide.txt" 2>&1 || true
  kubectl "${ktimeout[@]}" describe node >"$dir/describe-nodes.txt" 2>&1 || true
  kubectl "${ktimeout[@]}" get pods -A -o wide >"$dir/pods-wide.txt" 2>&1 || true
  kubectl "${ktimeout[@]}" get events -A --sort-by='.lastTimestamp' >"$dir/events.txt" 2>&1 || true
  kubectl "${ktimeout[@]}" describe pods -n dbagent >"$dir/describe-dbagent-pods.txt" 2>&1 || true
  # Per-pod current + previous logs (previous catches OOMKilled restarts).
  local pod
  for pod in $(kubectl "${ktimeout[@]}" get pods -n dbagent -o name 2>/dev/null || true); do
    local safe
    safe=$(echo "$pod" | tr '/:' '--')
    kubectl "${ktimeout[@]}" logs -n dbagent "$pod" --all-containers --tail=500 \
      >"$dir/logs-${safe}.txt" 2>&1 || true
    kubectl "${ktimeout[@]}" logs -n dbagent "$pod" --all-containers --previous --tail=200 \
      >"$dir/logs-${safe}-previous.txt" 2>&1 || true
  done

  # Platform status as the dashboard API reports it — not collected by the
  # kubectl dumps above, and the moment the platform reached `online` is
  # otherwise missing from the failure artifact.
  echo "==== platform status (dashboard API) ====" | tee -a "$PHASE_LOG"
  python3 - <<'PY' | tee "$dir/platform-status.txt" || true
import json, os, urllib.error, urllib.request

dash = os.environ.get("E2E_DASHBOARD_URL", "http://127.0.0.1:30081").rstrip("/")
user = os.environ.get("E2E_ADMIN_USER", "admin")
password = os.environ.get("E2E_ADMIN_PASS", "admin-e2e-password")
try:
    req = urllib.request.Request(
        f"{dash}/api/v1/auth/login",
        data=json.dumps({"username": user, "password": password}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        login = json.loads(resp.read().decode() or "{}")
    token = login.get("access_token") or login.get("token") or ""
    if not token:
        print("platform-status: login returned no token", login)
        raise SystemExit(0)
    req = urllib.request.Request(
        f"{dash}/api/v1/platforms",
        headers={"Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        body = json.loads(resp.read().decode() or "{}")
    plats = body.get("items") or body.get("platforms") or body
    print("platform-status:", json.dumps(plats, default=str))
    if isinstance(plats, list):
        for p in plats:
            if not isinstance(p, dict):
                continue
            key = p.get("platform_key") or p.get("key") or p.get("id")
            print(f"  {key}: status={p.get('status')!r}")
except Exception as exc:  # noqa: BLE001 — diagnostics must never mask the failure
    print(f"platform-status: unavailable: {exc}")
PY
}

LIVE_LOG_SIDECAR_PID=""

# Signal *pid* and wait until it is actually gone. "kill succeeded" is not
# "it exited". Escalate to SIGKILL; report if it never disappears.
# Only the in-shell LIVE_LOG_SIDECAR_PID is trusted — a leftover PID
# file is never read (it could name an unrelated process).
_stop_pid_until_gone() {
  local pid="$1"
  local label="${2:-process}"
  local i=0
  if [[ -z "$pid" ]]; then
    return 0
  fi
  if ! kill -0 "$pid" 2>/dev/null; then
    wait "$pid" 2>/dev/null || true
    return 0
  fi
  kill "$pid" 2>/dev/null || true
  while kill -0 "$pid" 2>/dev/null; do
    i=$((i + 1))
    if (( i == 20 )); then
      kill -KILL "$pid" 2>/dev/null || true
    fi
    if (( i > 40 )); then
      echo "stop_live_log_sidecar: ${label} pid ${pid} still present after SIGKILL" | tee -a "$PHASE_LOG"
      return 1
    fi
    sleep 0.1
  done
  wait "$pid" 2>/dev/null || true
  return 0
}

stop_live_log_sidecar() {
  local pid="${LIVE_LOG_SIDECAR_PID:-}"
  LIVE_LOG_SIDECAR_PID=""
  if [[ -z "$pid" ]]; then
    return 0
  fi
  _stop_pid_until_gone "$pid" "sidecar" || true
}

# Per-pod-UID `kubectl logs -f` followers so a failure line emitted in the
# last moments before a scenario's finally-restart is still captured.
# Polling snapshots miss that window; following by name also misses
# replacements (the stream dies with the old UID). Discovery of new UIDs
# is polled; each UID is followed continuously until kubectl exits.
start_live_log_sidecar() {
  local dir="/tmp/rca-e2e/diagnostics/live"
  local ktimeout=(--request-timeout=20s)
  local poll="${LIVE_LOG_POLL_S:-5}"
  mkdir -p "$dir"
  echo "start_live_log_sidecar: writing to $dir (poll ${poll}s, per-uid follow)" | tee -a "$PHASE_LOG"
  if ! command -v kubectl >/dev/null 2>&1; then
    echo "kubectl not available; skipping live log sidecar" | tee -a "$PHASE_LOG"
    return 0
  fi
  stop_live_log_sidecar || true
  (
    set +e
    uid_dir="$dir/followers"
    rm -rf "$uid_dir"
    mkdir -p "$uid_dir"

    stop_followers() {
      local pidfile fpid i any
      for pidfile in "$uid_dir"/*.pid; do
        [[ -f "$pidfile" ]] || continue
        fpid=$(cat "$pidfile" 2>/dev/null || true)
        [[ -n "$fpid" ]] || continue
        kill "$fpid" 2>/dev/null || true
      done
      i=0
      while (( i < 20 )); do
        any=0
        for pidfile in "$uid_dir"/*.pid; do
          [[ -f "$pidfile" ]] || continue
          fpid=$(cat "$pidfile" 2>/dev/null || true)
          [[ -n "$fpid" ]] || continue
          if kill -0 "$fpid" 2>/dev/null; then
            any=1
            if (( i == 10 )); then
              kill -KILL "$fpid" 2>/dev/null || true
            fi
          fi
        done
        (( any == 0 )) && break
        i=$((i + 1))
        sleep 0.1
      done
      for pidfile in "$uid_dir"/*.pid; do
        [[ -f "$pidfile" ]] || continue
        fpid=$(cat "$pidfile" 2>/dev/null || true)
        wait "$fpid" 2>/dev/null || true
        rm -f "$pidfile"
      done
    }
    cleanup() {
      trap - EXIT TERM INT
      stop_followers
      exit 0
    }
    trap cleanup EXIT TERM INT

    while true; do
      : >"$uid_dir/current"
      while IFS=$'\t' read -r name uid; do
        [[ -n "${name:-}" && -n "${uid:-}" ]] || continue
        printf '%s\n' "$uid" >>"$uid_dir/current"
        safe=$(printf '%s' "pod/${name}" | tr '/:' '--')
        pidfile="$uid_dir/${uid}.pid"
        fpid=""
        if [[ -f "$pidfile" ]]; then
          fpid=$(cat "$pidfile" 2>/dev/null || true)
        fi
        if [[ -z "$fpid" ]] || ! kill -0 "$fpid" 2>/dev/null; then
          kubectl "${ktimeout[@]}" logs -f -n dbagent "pod/${name}" --all-containers --tail=500 \
            >>"$dir/follow-${safe}-${uid}.txt" 2>&1 &
          echo $! >"$pidfile"
        fi
        kubectl "${ktimeout[@]}" logs -n dbagent "pod/${name}" --all-containers --previous --tail=200 \
          >"$dir/previous-${safe}-${uid}.txt" 2>&1 || true
      done < <(kubectl "${ktimeout[@]}" get pods -n dbagent \
        -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.metadata.uid}{"\n"}{end}' \
        2>/dev/null || true)
      sleep "$poll"
    done
  ) &
  LIVE_LOG_SIDECAR_PID=$!
  echo "start_live_log_sidecar: pid ${LIVE_LOG_SIDECAR_PID}" | tee -a "$PHASE_LOG"
}

phase() {
  local name="$1" budget="$2"
  shift 2
  local pstart=$(date +%s)
  echo "==> phase: $name (budget ${budget}s)"
  if ! "$@"; then
    echo "phase $name FAILED" | tee -a "$PHASE_LOG"
    collect_failure_diagnostics || true
    exit 1
  fi
  local elapsed=$(( $(date +%s) - pstart ))
  echo "phase $name: ${elapsed}s / ${budget}s" | tee -a "$PHASE_LOG"
  if (( elapsed > budget )); then
    echo "WARN: phase $name overran budget (${elapsed}s > ${budget}s)" | tee -a "$PHASE_LOG"
  fi
}

check_budget() {
  local total=$(( $(date +%s) - START ))
  if (( total > BUDGET )); then
    echo "run.sh: total wall time ${total}s exceeds ${BUDGET}s gate" | tee -a "$PHASE_LOG"
    cat "$PHASE_LOG"
    exit 1
  fi
}

# When sourced (e.g. delivery tests exercising phase/collect_failure_diagnostics),
# stop after function definitions so the full e2e pipeline does not run.
if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
  return 0
fi

phase "preflight" 20 bash -c '
  for b in helm docker kind buf; do
    command -v "$b" >/dev/null || { echo "missing required binary: $b"; exit 1; }
  done
  source deploy/versions.env
'

phase "build_and_cluster" 500 bash -c '
  set -euo pipefail
  source deploy/versions.env
  # Concurrent: images + pulls + kind
  (
    bash deploy/docker/build.sh
    docker build -t rca-mockllm:e2e -f tests/e2e/mockllm/Dockerfile tests/
  ) &
  pid_build=$!
  (
    fail=0
    for img in "$POSTGRES_IMAGE" "$MINIO_IMAGE" "$MINIO_MC_IMAGE" "$LITELLM_IMAGE" \
               "$TEMPORAL_AUTOSETUP_IMAGE" "$PRESTO_IMAGE"; do
      if ! docker pull "$img"; then
        echo "ERROR: docker pull failed for $img" >&2
        fail=1
      fi
    done
    exit $fail
  ) &
  pid_pull=$!
  kind delete cluster --name rca-e2e 2>/dev/null || true
  kind create cluster --name rca-e2e --config tests/e2e/kind-cluster.yaml
  wait $pid_build
  wait $pid_pull
'

phase "kind_load" 130 bash -c '
  set -euo pipefail
  source deploy/versions.env
  SHORT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo dev)
  REG="${REGISTRY}"
  VER="${APP_VERSION}"
  imgs=(
    "${REG}/ingest-gateway:${VER}"
    "${REG}/temporal-worker:${VER}"
    "${REG}/probe-gateway:${VER}"
    "${REG}/dashboard-api:${VER}"
    "${REG}/dashboard-web:${VER}"
    "${REG}/probe:${VER}"
    "rca-mockllm:e2e"
    "$POSTGRES_IMAGE" "$MINIO_IMAGE" "$MINIO_MC_IMAGE"
    "$LITELLM_IMAGE" "$TEMPORAL_AUTOSETUP_IMAGE" "$PRESTO_IMAGE"
  )
  pids=()
  for img in "${imgs[@]}"; do
    kind load docker-image "$img" --name rca-e2e &
    pids+=($!)
  done
  fail=0
  for pid in "${pids[@]}"; do
    if ! wait "$pid"; then
      fail=1
    fi
  done
  exit $fail
'

phase "helm_dbagent" 180 bash -c '
  set -euo pipefail
  kubectl create namespace dbagent --dry-run=client -o yaml | kubectl apply -f -
  # Mock LLM must be up before model-gateway starts (MOCK_LLM_URL=http://mock-llm:8090).
  kubectl apply -n dbagent -f tests/e2e/mockllm/deployment.yaml
  kubectl -n dbagent rollout status deploy/mock-llm --timeout=120s
  # Notification capture for E2 redaction of outbound payloads (FP-M6-17).
  kubectl apply -n dbagent -f tests/e2e/webhook-capture/deployment.yaml
  kubectl -n dbagent rollout status deploy/webhook-capture --timeout=120s
  helm upgrade --install dbagent deploy/charts/dbagent \
    -n dbagent --create-namespace \
    -f tests/e2e/values-dbagent.yaml \
    --wait --timeout 5m
  # Clear must_change_password so subsequent API calls (platform seed, pytest) work.
  python3 - <<'"'"'PY'"'"'
import json, time, urllib.error, urllib.request

DASH = "http://127.0.0.1:30081"
USER = "admin"
PASS = "admin-e2e-password"

def req(method, url, data=None, headers=None):
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    body = None if data is None else json.dumps(data).encode()
    r = urllib.request.Request(url, data=body, headers=h, method=method)
    with urllib.request.urlopen(r, timeout=15) as resp:
        raw = resp.read().decode() or "{}"
        return resp.status, (json.loads(raw) if raw.strip() else {})

token = None
for _ in range(60):
    try:
        _, login = req("POST", f"{DASH}/api/v1/auth/login", {"username": USER, "password": PASS})
        token = login.get("access_token") or login.get("token")
        if token:
            break
    except Exception as exc:  # noqa: BLE001
        print("login wait:", exc)
    time.sleep(2)
if not token:
    raise SystemExit("phase4: could not login to clear must_change_password")

# change-password clears must_change_password (same password is fine for e2e).
try:
    req(
        "POST",
        f"{DASH}/api/v1/auth/change-password",
        {"old_password": PASS, "new_password": PASS},
        headers={"Authorization": f"Bearer {token}"},
    )
except urllib.error.HTTPError as e:
    # 204 has empty body — urlopen may still succeed; other codes fail.
    if e.code not in (204, 200):
        raise SystemExit(f"phase4: change-password failed: {e.code} {e.read()}")
print("phase4: admin must_change_password cleared")
PY
'

phase "deploy_presto" 150 bash -c '
  set -euo pipefail
  kubectl apply -n dbagent -f tests/e2e/presto/
  kubectl -n dbagent rollout status deploy/presto-coordinator --timeout=120s
  kubectl -n dbagent wait --for=condition=Ready pod -l app=presto --timeout=120s
  # D2: prove the coordinator *stayed* up — a crashloop can briefly report
  # Ready (successThreshold window) then die. Settle, re-check Ready, and
  # require restartCount == 0.
  sleep 15
  kubectl -n dbagent wait --for=condition=Ready pod -l app=presto,role=coordinator --timeout=30s
  rc=$(kubectl -n dbagent get pod -l app=presto,role=coordinator \
    -o jsonpath="{.items[0].status.containerStatuses[0].restartCount}")
  if [ "${rc:-1}" != "0" ]; then
    echo "deploy_presto: coordinator restartCount=${rc} (expected 0) — crashlooping" >&2
    kubectl -n dbagent describe pod -l app=presto,role=coordinator >&2 || true
    kubectl -n dbagent logs -l app=presto,role=coordinator --tail=80 >&2 || true
    exit 1
  fi
'

# Create platform + issue bootstrap token BEFORE installing the probe (C2.3/C2.5).
# 60 s is design.md Section 11.1.3's approved phase-6 allocation; the phase table
# totals 1480 s, 20 s under the 1500 s gate. `helm --wait --timeout` below is a
# failure ceiling, not the expected cost: every image is already loaded into kind
# by phase 3, so the probe install is a scheduling wait.
phase "helm_dbagent_probe" 60 bash -c '
  set -euo pipefail
  BOOTSTRAP_TOKEN=$(python3 - <<'"'"'PY'"'"'
import json, time, urllib.error, urllib.request

DASH = "http://127.0.0.1:30081"
USER = "admin"
PASS = "admin-e2e-password"
PLATFORM = "presto-e2e"

def req(method, url, data=None, headers=None):
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    body = None if data is None else json.dumps(data).encode()
    r = urllib.request.Request(url, data=body, headers=h, method=method)
    with urllib.request.urlopen(r, timeout=15) as resp:
        raw = resp.read().decode() or "{}"
        return resp.status, (json.loads(raw) if raw.strip() else {})

token = None
for _ in range(30):
    try:
        _, login = req("POST", f"{DASH}/api/v1/auth/login", {"username": USER, "password": PASS})
        token = login.get("access_token") or login.get("token")
        if token:
            break
    except Exception as exc:  # noqa: BLE001
        print("login wait:", exc)
    time.sleep(2)
if not token:
    raise SystemExit("phase6: could not login")

auth = {"Authorization": f"Bearer {token}"}

# Ensure platform exists before probe enrolls.
try:
    req(
        "POST",
        f"{DASH}/api/v1/platforms",
        {
            "platform_key": PLATFORM,
            "platform_type": "presto",
            "deployment": "k8s",
            "display_name": PLATFORM,
        },
        headers=auth,
    )
except urllib.error.HTTPError as e:
    if e.code not in (409, 400):
        raise

# Seed settle_seconds=15 (E1 settle window) AND the real resource locators.
# Without remediation_targets the worker falls back to default_locators(), whose
# namespace is "presto" (playbooks.py) — E1 would then patch a ConfigMap in a
# namespace that does not exist in this cluster.
PLATFORM_CONFIG = {
    "remediation": {"settle_seconds": 15},
    "remediation_targets": {
        "namespace": "dbagent",
        "worker_configmap": "presto-worker-config",
        "coordinator_configmap": "presto-coordinator-config",
        "worker_workload_kind": "deployment",
        "worker_workload_name": "presto-worker",
        "coordinator_workload_kind": "deployment",
        "coordinator_workload_name": "presto-coordinator",
        "config_file_key": "config.properties",
    },
}
status, body = req(
    "PATCH",
    f"{DASH}/api/v1/platforms/{PLATFORM}",
    {"config": PLATFORM_CONFIG},
    headers=auth,
)
print("phase6 platform config seed:", status, body, file=__import__("sys").stderr)
if status not in range(200, 300):
    raise SystemExit(f"phase6: platform config seed failed status={status} body={body}")
cfg = (body.get("config") or {}) if isinstance(body, dict) else {}
settle = (cfg.get("remediation") or {}).get("settle_seconds")
targets = cfg.get("remediation_targets") or {}
if settle != 15:
    raise SystemExit(f"phase6: settle_seconds not seeded (got {settle!r}) body={body}")
for key, want in PLATFORM_CONFIG["remediation_targets"].items():
    if targets.get(key) != want:
        raise SystemExit(
            f"phase6: remediation_targets.{key}={targets.get(key)!r} != {want!r}"
        )

# Issue a real single-use bootstrap token for the probe chart.
status, tok_body = req(
    "POST",
    f"{DASH}/api/v1/platforms/{PLATFORM}/bootstrap-token",
    headers=auth,
)
bootstrap = tok_body.get("token") or tok_body.get("bootstrap_token") or ""
if not bootstrap:
    raise SystemExit(f"phase6: bootstrap-token empty status={status} body={tok_body}")
# Only the token on stdout — captured into BOOTSTRAP_TOKEN.
print(bootstrap, end="")
PY
)
  if [[ -z "${BOOTSTRAP_TOKEN}" ]]; then
    echo "phase6: empty bootstrap token" >&2
    exit 1
  fi
  helm upgrade --install dbagent-probe deploy/charts/dbagent-probe \
    -n dbagent -f tests/e2e/values-dbagent-probe.yaml \
    --set "bootstrapToken=${BOOTSTRAP_TOKEN}" \
    --wait --timeout 2m
  echo "phase6: dbagent-probe installed with issued bootstrap token"
'

env_hygiene_gate() {
  bad="$(awk 'BEGIN { for (k in ENVIRON) { p = substr(k, 1, 6); if (p != "PYTHON" && p != "PYTEST") continue; print k } }')"; if [ -n "$bad" ]; then printf 'e2e env hygiene: forbidden PYTHON*/PYTEST* environment key present before the measured invocation:\n%s\n' "$bad" >&2; exit 1; fi
}
trap 'stop_live_log_sidecar' EXIT
start_live_log_sidecar
env_hygiene_gate
phase "pytest_e2e" 420 bash -c '
  python3 -m pip install -q -e libs/py/rca_common -e "services/worker[test]" \
    -e "services/gateway[test]" -e "services/dashboard-api[test]"
  python3 -m pytest tests/e2e -v --tb=short
'
stop_live_log_sidecar

if [[ "$KEEP_CLUSTER" != "1" ]]; then
  phase "teardown" 20 bash -c 'kind delete cluster --name rca-e2e || true'
fi

TOTAL=$(( $(date +%s) - START ))
echo "==== phase timing table ===="
cat "$PHASE_LOG"
echo "TOTAL: ${TOTAL}s (gate ${BUDGET}s)"
if (( TOTAL > BUDGET )); then
  exit 1
fi
echo "e2e green"
