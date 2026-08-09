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

phase() {
  local name="$1" budget="$2"
  shift 2
  local pstart=$(date +%s)
  echo "==> phase: $name (budget ${budget}s)"
  if ! "$@"; then
    echo "phase $name FAILED" | tee -a "$PHASE_LOG"
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

phase "helm_rca_agent" 180 bash -c '
  set -euo pipefail
  kubectl create namespace rca --dry-run=client -o yaml | kubectl apply -f -
  # Mock LLM must be up before model-gateway starts (MOCK_LLM_URL=http://mock-llm:8090).
  kubectl apply -n rca -f tests/e2e/mockllm/deployment.yaml
  kubectl -n rca rollout status deploy/mock-llm --timeout=120s
  # Notification capture for E2 redaction of outbound payloads (FP-M6-17).
  kubectl apply -n rca -f tests/e2e/webhook-capture/deployment.yaml
  kubectl -n rca rollout status deploy/webhook-capture --timeout=120s
  helm upgrade --install rca-agent deploy/charts/rca-agent \
    -n rca --create-namespace \
    -f tests/e2e/values-rca-agent.yaml \
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
  kubectl apply -n rca -f tests/e2e/presto/
  kubectl -n rca rollout status deploy/presto-coordinator --timeout=120s
  kubectl -n rca wait --for=condition=Ready pod -l app=presto --timeout=120s
'

# Create platform + issue bootstrap token BEFORE installing the probe (C2.3/C2.5).
# 60 s is design.md Section 11.1.3's approved phase-6 allocation; the phase table
# totals 1480 s, 20 s under the 1500 s gate. `helm --wait --timeout` below is a
# failure ceiling, not the expected cost: every image is already loaded into kind
# by phase 3, so the probe install is a scheduling wait.
phase "helm_rca_probe" 60 bash -c '
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
        "namespace": "rca",
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
  helm upgrade --install rca-probe deploy/charts/rca-probe \
    -n rca -f tests/e2e/values-rca-probe.yaml \
    --set "bootstrapToken=${BOOTSTRAP_TOKEN}" \
    --wait --timeout 2m
  echo "phase6: rca-probe installed with issued bootstrap token"
'

env_hygiene_gate() {
  bad="$(awk 'BEGIN { for (k in ENVIRON) { p = substr(k, 1, 6); if (p != "PYTHON" && p != "PYTEST") continue; print k } }')"; if [ -n "$bad" ]; then printf 'e2e env hygiene: forbidden PYTHON*/PYTEST* environment key present before the measured invocation:\n%s\n' "$bad" >&2; exit 1; fi
}
env_hygiene_gate
phase "pytest_e2e" 420 bash -c '
  python3 -m pip install -q -e libs/py/rca_common -e "services/worker[test]" \
    -e "services/gateway[test]" -e "services/dashboard-api[test]"
  python3 -m pytest tests/e2e -v --tb=short
'

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
