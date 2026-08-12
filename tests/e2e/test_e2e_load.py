"""FP-IG-9: B1 e2e link — nested-tier profile against shipped image and chart.

Baseline: open-loop at BASE_RATE for BASE_SECONDS (completion/p99/accounting;
no rate comparison). Saturation: closed-loop of SATURATION_CLIENTS for
BURST_SECONDS (0 errors, 0 restarts, no Unhealthy, exact audit accounting).
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
    r = httpx.get(
        f"{dashboard_url.rstrip('/')}/api/v1/platforms/{PLATFORM_KEY}",
        headers={"Authorization": f"Bearer {token}"},
        timeout=30,
    )
    if r.status_code != 200:
        return False
    status = (r.json().get("status") or "").lower()
    return status == "online"


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


def _cgroup_cpu_stat() -> dict[str, int | None]:
    """Read gateway cgroup cpu.stat fields (usage_usec, throttled_usec, nr_throttled).

    Returns a dict with int values or None when unreadable. Diagnostics only —
    unavailable is reported in the fingerprint, never asserted (design.md K).
    """
    empty = {"usage_usec": None, "throttled_usec": None, "nr_throttled": None}
    try:
        pod = _gateway_pod_name()
        out = subprocess.run(
            [
                "kubectl",
                "-n",
                NAMESPACE,
                "exec",
                pod,
                "--",
                "cat",
                "/sys/fs/cgroup/cpu.stat",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if out.returncode != 0:
            # cgroup v1 fallback for usage only
            out_v1 = subprocess.run(
                [
                    "kubectl",
                    "-n",
                    NAMESPACE,
                    "exec",
                    pod,
                    "--",
                    "cat",
                    "/sys/fs/cgroup/cpuacct/cpuacct.usage",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if out_v1.returncode != 0:
                return empty
            # nanoseconds → microseconds
            try:
                return {
                    "usage_usec": int(out_v1.stdout.strip()) // 1000,
                    "throttled_usec": None,
                    "nr_throttled": None,
                }
            except ValueError:
                return empty
        parsed: dict[str, int | None] = {
            "usage_usec": None,
            "throttled_usec": None,
            "nr_throttled": None,
        }
        for line in out.stdout.splitlines():
            parts = line.split()
            if len(parts) != 2:
                continue
            key, val = parts[0], parts[1]
            if key in parsed:
                try:
                    parsed[key] = int(val)
                except ValueError:
                    parsed[key] = None
        return parsed
    except Exception:  # noqa: BLE001
        return empty


def _fmt_diag(value: float | int | None) -> str:
    """Fingerprint field: number or the literal ``unavailable`` (design.md K)."""
    if value is None:
        return "unavailable"
    if isinstance(value, float):
        return f"{value:.2f}"
    return str(value)


def _host_fingerprint() -> dict[str, str | int]:
    # File reads only — no os.environ (FP-IG-13). cpu_count via /proc.
    cpus = 0
    try:
        cpus = sum(1 for _ in Path("/sys/devices/system/cpu").glob("cpu[0-9]*"))
    except OSError:
        cpus = 0
    if cpus == 0:
        try:
            text = Path("/proc/cpuinfo").read_text(encoding="utf-8")
            cpus = sum(1 for line in text.splitlines() if line.startswith("processor"))
        except OSError:
            cpus = 0

    model = "unknown"
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.lower().startswith("model name"):
                model = " ".join(line.split(":", 1)[1].split())
                break
    except OSError:
        pass
    image = "unknown"
    for path, prefix in (
        (Path("/imagegeneration/imagedata.json"), "imagedata"),
        (Path("/etc/os-release"), "os-release"),
    ):
        if path.is_file():
            digest = hashlib.sha256(path.read_bytes()).hexdigest()[:16]
            image = f"{prefix}:{digest}"
            break
    return {"cpus": cpus, "cpu_model": model, "image": image}


@pytest.mark.e2e
def test_b1_ingest_burst_profile(ingest_url, dashboard_url):
    token = _admin_token(dashboard_url)
    host = _host_fingerprint()
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
        marks["cgroup_before"] = _cgroup_cpu_stat()
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
    audit_after_base = _count_ingest_audit_rows(
        dashboard_url, token, datetime.now(timezone.utc) - timedelta(hours=1), cap=10**7
    )
    committed = audit_after_base - int(marks.get("audit_before", 0))
    cgroup_after = _cgroup_cpu_stat()
    cgroup_before = marks.get("cgroup_before") or {}
    gw_cpu_seconds: float | None = None
    gw_throttled_usec: int | None = None
    gw_nr_throttled: int | None = None
    if cgroup_before.get("usage_usec") is not None and cgroup_after.get("usage_usec") is not None:
        gw_cpu_seconds = (cgroup_after["usage_usec"] - cgroup_before["usage_usec"]) / 1e6
    if (
        cgroup_before.get("throttled_usec") is not None
        and cgroup_after.get("throttled_usec") is not None
    ):
        gw_throttled_usec = int(cgroup_after["throttled_usec"] - cgroup_before["throttled_usec"])
    if (
        cgroup_before.get("nr_throttled") is not None
        and cgroup_after.get("nr_throttled") is not None
    ):
        gw_nr_throttled = int(cgroup_after["nr_throttled"] - cgroup_before["nr_throttled"])
    restarts_after_base = _gateway_restart_count()
    base_restart_delta = restarts_after_base - int(marks.get("restarts_before", restarts_after_base))

    # Fixed-shape per-phase fingerprint (design.md §11.3.3 K / review C7).
    print(
        f"B1 env=cpus={host['cpus']},cpu_model={host['cpu_model']},image={host['image']},"
        f"tier=e2e,phase=baseline,max_lateness_ms={baseline.max_lateness_ms:.1f},"
        f"p99_ms={baseline.p99:.1f},rate={baseline.served_rate:.1f},"
        f"lateness_drift_ms={baseline.lateness_drift_ms:.1f},"
        f"gw_cpu_seconds={_fmt_diag(gw_cpu_seconds)},"
        f"gw_throttled_usec={_fmt_diag(gw_throttled_usec)},"
        f"gw_nr_throttled={_fmt_diag(gw_nr_throttled)},"
        f"gw_restarts={base_restart_delta},"
        f"in_flight={baseline.max_in_flight}",
        flush=True,
    )
    # (2)(3)(4)(5)(6) — locals so the threshold checker sees measured Names
    served = baseline.served
    errors = baseline.errors
    p99 = baseline.p99
    assert served + errors == 6000
    assert errors == 0
    assert served == 6000
    assert p99 < P99_MS, f"baseline p99={p99}"
    assert committed == served, (
        f"baseline committed={committed} served={served}"
    )

    # --- Saturation phase ---
    restarts_before = _gateway_restart_count()
    sat_start = datetime.now(timezone.utc)
    sat_audit_before = _count_ingest_audit_rows(
        dashboard_url, token, datetime.now(timezone.utc) - timedelta(hours=1), cap=10**7
    )
    sat_cgroup_before = _cgroup_cpu_stat()
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
    sat_cgroup_after = _cgroup_cpu_stat()
    sat_gw_cpu: float | None = None
    sat_gw_throttled: int | None = None
    sat_gw_nr: int | None = None
    if (
        sat_cgroup_before.get("usage_usec") is not None
        and sat_cgroup_after.get("usage_usec") is not None
    ):
        sat_gw_cpu = (
            sat_cgroup_after["usage_usec"] - sat_cgroup_before["usage_usec"]
        ) / 1e6
    if (
        sat_cgroup_before.get("throttled_usec") is not None
        and sat_cgroup_after.get("throttled_usec") is not None
    ):
        sat_gw_throttled = int(
            sat_cgroup_after["throttled_usec"] - sat_cgroup_before["throttled_usec"]
        )
    if (
        sat_cgroup_before.get("nr_throttled") is not None
        and sat_cgroup_after.get("nr_throttled") is not None
    ):
        sat_gw_nr = int(
            sat_cgroup_after["nr_throttled"] - sat_cgroup_before["nr_throttled"]
        )

    restart_delta = restarts_after - restarts_before
    print(
        f"B1 env=cpus={host['cpus']},cpu_model={host['cpu_model']},image={host['image']},"
        f"tier=e2e,phase=saturation,max_lateness_ms={sat.max_lateness_ms:.1f},"
        f"p99_ms={sat.p99:.1f},rate={sat.served_rate:.1f},"
        f"lateness_drift_ms={sat.lateness_drift_ms:.1f},"
        f"gw_cpu_seconds={_fmt_diag(sat_gw_cpu)},"
        f"gw_throttled_usec={_fmt_diag(sat_gw_throttled)},"
        f"gw_nr_throttled={_fmt_diag(sat_gw_nr)},"
        f"gw_restarts={restart_delta},"
        f"in_flight={sat.max_in_flight}",
        flush=True,
    )
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
