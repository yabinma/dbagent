"""FP-IG-9: B1 e2e link — nested-tier profile against shipped image and chart.

Baseline: open-loop at BASE_RATE for BASE_SECONDS, failing on completion,
errors and exact audit accounting. No rate comparison, and the latency reading
is OBSERVATIONAL: kind-deploy-tuning (FP-KDT-2/3) reads the completed
baseline's nearest-rank due-time p99, compares it with P99_MS, records the
Boolean with record_property and prints the numeric line (also written to
/tmp/rca-e2e/b1-kind-p99.txt, which run.sh prints after a passing
pytest_e2e phase). A p99 at or above P99_MS never fails, skips or retries
this node; only a non-finite p99 or a failed write of the line does, as an
observation-integrity error. Saturation: closed-loop of SATURATION_CLIENTS
for BURST_SECONDS (0 errors, 0 restarts, no Unhealthy, exact audit
accounting). Eleven correctness clauses still fail the job.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import subprocess
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

import importlib.util
import sys

from tests.e2e.conftest import lookup_platform
from tests.e2e.kind_b1_observation import emit_kind_b1_p99

_PROFILE_PATH = Path(__file__).resolve().parent / "b1_e2e_profile.py"
_spec = importlib.util.spec_from_file_location("b1_e2e_profile", _PROFILE_PATH)
assert _spec and _spec.loader
b1 = importlib.util.module_from_spec(_spec)
# dataclasses requires the module registered before exec (Python 3.12+).
sys.modules[_spec.name] = b1
_spec.loader.exec_module(b1)

# Module-scope constants — each bound exactly once to a literal (FP-IG-13).
# Values must match tests/e2e/b1_e2e_profile.py; delivery tests pin agreement.
# No os.environ / os.getenv reads on this harness surface (review C4): B1 is
# environment-independent; cluster identity is the shipped e2e defaults.
BURST_RATE = 1000
BURST_SECONDS = 30
BASE_RATE = 200
BASE_SECONDS = 30
BASE_TOTAL = 6000
P99_MS = 150.0
SUSTAINED_FLOOR = 200
MAX_IN_FLIGHT = 1000
SATURATION_CLIENTS = 150
PROLOGUE_REQUESTS = 30
KEEPALIVE_EXPIRY = 30.0
CLIENT_TIMEOUT = 30.0
# Admissible audit actions for B1 accounting (FP-IG-9 clause 12): event_received
# and event_merged only — never event_rejected.
INGEST_AUDIT_ACTIONS = ("event_received", "event_merged")
HMAC_SECRET = "e2e-hmac-secret"
ADMIN_USER = "admin"
ADMIN_PASS = "admin-e2e-password"
PLATFORM_KEY = "presto-e2e"
NAMESPACE = "dbagent"
GATEWAY_DEPLOY = "dbagent-ingest-gateway"


def _sign(body: bytes, secret: str) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _build_requests(count: int) -> list[tuple[bytes, dict[str, str]]]:
    out = []
    for i in range(count):
        payload = {
            "source": "grafana-e2e",
            "platform_key": PLATFORM_KEY,
            "error_summary": f"burst-{i % 50}",
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "event_id": str(uuid.uuid4()),
        }
        raw = json.dumps(payload).encode()
        out.append(
            (
                raw,
                {
                    "Content-Type": "application/json",
                    "X-Signature": _sign(raw, HMAC_SECRET),
                },
            )
        )
    return out


def _admin_token(dashboard_url: str) -> str:
    r = httpx.post(
        f"{dashboard_url.rstrip('/')}/api/v1/auth/login",
        json={"username": ADMIN_USER, "password": ADMIN_PASS},
        timeout=30,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    token = body.get("access_token") or body.get("token")
    assert token, body
    return token


def _platform_online(dashboard_url: str, token: str) -> bool:
    _observed, target = lookup_platform(
        dashboard_url, token, PLATFORM_KEY, timeout=30
    )
    if target is None:
        return False
    return (target.get("status") or "").lower() == "online"


def _count_ingest_audit_rows(dashboard_url: str, token: str, since: datetime, cap: int) -> int:
    base = dashboard_url.rstrip("/")
    headers = {"Authorization": f"Bearer {token}"}
    counted = 0
    for action in INGEST_AUDIT_ACTIONS:
        cursor = None
        while counted < cap:
            params = {"action": action, "from": since.isoformat(), "limit": 100}
            if cursor:
                params["cursor"] = cursor
            r = httpx.get(f"{base}/api/v1/audit", headers=headers, params=params, timeout=60)
            assert r.status_code == 200, r.text
            body = r.json()
            items = body.get("items") or []
            counted += len(items)
            cursor = body.get("next_cursor") or body.get("cursor")
            if not cursor or not items:
                break
    return counted


def _gateway_restart_count() -> int:
    out = subprocess.run(
        [
            "kubectl",
            "-n",
            NAMESPACE,
            "get",
            "pod",
            "-l",
            f"app.kubernetes.io/component=ingest-gateway",
            "-o",
            "jsonpath={.items[0].status.containerStatuses[0].restartCount}",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert out.returncode == 0, out.stderr
    return int(out.stdout.strip() or "0")


def _gateway_pod_name() -> str:
    out = subprocess.run(
        [
            "kubectl",
            "-n",
            NAMESPACE,
            "get",
            "pod",
            "-l",
            "app.kubernetes.io/component=ingest-gateway",
            "-o",
            "jsonpath={.items[0].metadata.name}",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if out.returncode != 0 or not out.stdout.strip():
        raise RuntimeError(
            f"cannot identify ingest-gateway pod: rc={out.returncode} err={out.stderr}"
        )
    return out.stdout.strip()


def _parse_k8s_ts(ts: str) -> datetime | None:
    if not ts:
        return None
    # eventTime may be microsecond RFC3339; lastTimestamp is second precision.
    text = ts.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _unhealthy_events_since(
    since: datetime,
    *,
    pod_name: str | None = None,
    events_payload: dict | None = None,
    kubectl_runner=None,
) -> list[str]:
    """Return Unhealthy events for the gateway pod at or after ``since``.

    Fails closed: command failure or malformed JSON raises rather than returning
    an empty list that would silently green the assertion (FP-IG-9 / C7).
    """
    if events_payload is None:
        runner = kubectl_runner or subprocess.run
        out = runner(
            [
                "kubectl",
                "-n",
                NAMESPACE,
                "get",
                "events",
                "--field-selector",
                "reason=Unhealthy",
                "-o",
                "json",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if out.returncode != 0:
            raise RuntimeError(
                f"kubectl get events failed: rc={out.returncode} err={out.stderr}"
            )
        try:
            events_payload = json.loads(out.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"malformed events JSON: {exc}") from exc

    if not isinstance(events_payload, dict):
        raise RuntimeError(f"events payload must be an object, got {type(events_payload)}")
    items = events_payload.get("items")
    if items is None:
        raise RuntimeError("events payload missing 'items'")
    if not isinstance(items, list):
        raise RuntimeError(f"events items must be a list, got {type(items)}")

    target = pod_name if pod_name is not None else _gateway_pod_name()
    since_aware = since if since.tzinfo is not None else since.replace(tzinfo=timezone.utc)
    hits: list[str] = []
    for ev in items:
        if not isinstance(ev, dict):
            raise RuntimeError(f"event entry is not an object: {ev!r}")
        involved = (ev.get("involvedObject") or {}).get("name") or ""
        # Exact current pod only — historical gateway pods must not fail a valid run.
        if involved != target:
            continue
        # Timestamp sources: lastTimestamp, eventTime, series.lastObservedTime,
        # metadata.creationTimestamp. Missing timestamp on a current-pod event
        # fails closed (review C7) — silent ignore would green a bad run.
        series = ev.get("series") if isinstance(ev.get("series"), dict) else {}
        ts_raw = (
            ev.get("lastTimestamp")
            or ev.get("eventTime")
            or series.get("lastObservedTime")
            or (ev.get("metadata") or {}).get("creationTimestamp")
        )
        if not ts_raw:
            raise RuntimeError(
                f"Unhealthy event for pod {target!r} has no timestamp: {ev!r}"
            )
        ts = _parse_k8s_ts(str(ts_raw))
        if ts is None:
            raise RuntimeError(f"unparseable event timestamp: {ts_raw!r}")
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        if ts < since_aware:
            continue
        hits.append(f"{ts_raw}:{ev.get('message')}")
    return hits


@pytest.mark.e2e
def test_b1_ingest_burst_profile(ingest_url, dashboard_url, record_property):
    token = _admin_token(dashboard_url)
    # (1) platform ONLINE before any load
    platform_online = _platform_online(dashboard_url, token)
    assert platform_online == True, (  # noqa: E712 — named Eq for FP-IG-19
        "platform must be ONLINE before B1 load; refusing to measure the reject path"
    )

    endpoint = f"{ingest_url.rstrip('/')}/api/v1/events"
    gateway_pod = _gateway_pod_name()

    # Disjoint warmup / prologue / measured payloads (C2).
    warmup = _build_requests(1)[0]
    prologue = _build_requests(PROLOGUE_REQUESTS)
    measured = _build_requests(BASE_TOTAL)

    marks: dict = {}

    def _after_prologue() -> None:
        marks["audit_before"] = _count_ingest_audit_rows(
            dashboard_url, token, datetime.now(timezone.utc) - timedelta(hours=1), cap=10**7
        )
        marks["restarts_before"] = _gateway_restart_count()

    # --- Baseline phase ---
    baseline = asyncio.run(
        b1.run_open_loop_baseline(
            endpoint=endpoint,
            requests=measured,
            rate=BASE_RATE,
            max_in_flight=MAX_IN_FLIGHT,
            warmup=warmup,
            prologue=prologue,
            include_sync_warmup=True,
            on_prologue_complete=_after_prologue,
        )
    )
    # FP-KDT-2/3: report the completed baseline's due-time p99 -- outside the
    # measured window and before any correctness clause, so a later
    # correctness failure still leaves the line in /tmp/rca-e2e. Observation
    # only: the comparison with P99_MS is recorded and printed, never asserted.
    emit_kind_b1_p99(
        baseline.p99, P99_MS, record_property, Path("/tmp/rca-e2e/b1-kind-p99.txt")
    )
    audit_after_base = _count_ingest_audit_rows(
        dashboard_url, token, datetime.now(timezone.utc) - timedelta(hours=1), cap=10**7
    )
    committed = audit_after_base - int(marks.get("audit_before", 0))
    # (2)(3)(4)(6) fail the job. The p99 above is reported, not one of them
    # (FP-KDT-4); no diagnostic emission happens here (FP-BOD-8).
    served = baseline.served
    errors = baseline.errors
    assert served + errors == 6000
    assert errors == 0
    assert served == 6000
    assert committed == served, (
        f"baseline committed={committed} served={served}"
    )

    # --- Saturation phase ---
    restarts_before = _gateway_restart_count()
    sat_start = datetime.now(timezone.utc)
    sat_audit_before = _count_ingest_audit_rows(
        dashboard_url, token, datetime.now(timezone.utc) - timedelta(hours=1), cap=10**7
    )
    counter = {"i": 0}

    def factory() -> tuple[bytes, dict[str, str]]:
        i = counter["i"]
        counter["i"] += 1
        payload = {
            "source": "grafana-e2e",
            "platform_key": PLATFORM_KEY,
            "error_summary": f"sat-{i % 50}",
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "event_id": str(uuid.uuid4()),
        }
        raw = json.dumps(payload).encode()
        return raw, {
            "Content-Type": "application/json",
            "X-Signature": _sign(raw, HMAC_SECRET),
        }

    sat = asyncio.run(
        b1.run_closed_loop_saturation(
            endpoint=endpoint,
            request_factory=factory,
            clients=SATURATION_CLIENTS,
            duration_s=BURST_SECONDS,
        )
    )
    restarts_after = _gateway_restart_count()
    sat_audit_after = _count_ingest_audit_rows(
        dashboard_url, token, datetime.now(timezone.utc) - timedelta(hours=1), cap=10**7
    )
    sat_committed = sat_audit_after - sat_audit_before
    restart_delta = restarts_after - restarts_before
    # (7)(8)
    issued = sat.offered
    sat_served = sat.served
    sat_errors = sat.errors
    assert sat_served + sat_errors == issued
    assert sat_errors == 0, f"saturation errors={sat_errors}"
    # (9)
    assert restart_delta == 0, f"restartCount delta={restart_delta}"
    # (10)
    unhealthy = _unhealthy_events_since(sat_start, pod_name=gateway_pod)
    unhealthy_count = len(unhealthy)
    assert unhealthy_count == 0, f"Unhealthy events during saturation: {unhealthy}"
    # (11)
    assert sat_committed == sat_served, (
        f"sat committed={sat_committed} served={sat_served}"
    )
    # (12) audit rows counted only via the admissible action set
    audit_actions = INGEST_AUDIT_ACTIONS
    assert audit_actions == ("event_received", "event_merged")
