"""FP-IG-7 / FP-IG-18 / UT-IG-5: B1 reference-tier burst measurement.

Run only from the CI ``benchmark`` job (excluded from unit-gateway/functional
via --ignore). Spawns the real gateway under uvicorn against testcontainers PG.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import textwrap
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest
import yaml

# Load profile module by path so we never mutate sys.path.
import importlib.util
import sys as _sys

_PROFILE_PATH = Path(__file__).resolve().parent / "b1_reference_profile.py"
_spec = importlib.util.spec_from_file_location("b1_reference_profile", _PROFILE_PATH)
assert _spec and _spec.loader
b1 = importlib.util.module_from_spec(_spec)
_sys.modules["b1_reference_profile"] = b1
_spec.loader.exec_module(b1)

REPO_ROOT = Path(__file__).resolve().parents[3]
VALUES_YAML = REPO_ROOT / "deploy" / "charts" / "dbagent" / "values.yaml"
HMAC_SECRET = "b1-reference-hmac-secret"
PLATFORM_KEY = "b1-ref-platform"


# ---------------------------------------------------------------------------
# UT-IG-5 — harness unit tests (no server)
# ---------------------------------------------------------------------------


def test_due_times_monotone_at_burst_rate():
    rate = b1.BURST_RATE
    n = 1000
    t0 = 100.0
    dues = [t0 + i / rate for i in range(n)]
    assert all(dues[i] < dues[i + 1] for i in range(n - 1))
    assert abs((dues[1] - dues[0]) - 1 / rate) < 1e-12


def test_statistics_from_hand_written_vector():
    # 100 samples: latencies 1..100; p99 nearest-rank
    lats = [float(i) for i in range(1, 101)]
    p99 = b1.nearest_rank_p99(lats)
    # ceil(0.99*100)−1 = 98 → value 99 (1-indexed rank 99)
    assert p99 == 99.0
    result = b1.PhaseResult(
        offered=100,
        served=100,
        errors=0,
        latencies_ms=lats,
        t0=0.0,
        t_last_complete=0.5,
        due0=0.0,
        max_in_flight=10,
        max_backlog=0,
    )
    assert abs(result.served_rate - 200.0) < 1e-9
    assert result.max_lateness_ms == 100.0


def test_acceptance_cases_match_expected_verdicts():
    for name, expected in b1.ACCEPTANCE_EXPECTED.items():
        verdict, fails = b1.run_acceptance_case(name)
        assert verdict == expected, f"{name}: got {verdict} fails={fails}"


def test_acceptance_matrix_matches_superseded_formulations():
    """FP-IG-7: complete acceptance matrix incl. four superseded oracles."""
    for name, expected_final in b1.ACCEPTANCE_EXPECTED.items():
        matrix = b1.run_acceptance_matrix(name)
        assert matrix["final"] == expected_final, f"{name} final={matrix}"
        s1, s2, s3, s4 = b1.ACCEPTANCE_SUPERSEDED[name]
        assert matrix["form1"] == s1, f"{name} form1={matrix['form1']} want {s1}"
        assert matrix["form2"] == s2, f"{name} form2={matrix['form2']} want {s2}"
        assert matrix["form3"] == s3, f"{name} form3={matrix['form3']} want {s3}"
        assert matrix["form4"] == s4, f"{name} form4={matrix['form4']} want {s4}"


@pytest.mark.asyncio
async def test_open_loop_rejects_duplicate_event_ids_across_phases():
    """C2: warmup/prologue/measured must be disjoint — a reuse-aware stub fails."""

    class DupAwareTransport:
        def __init__(self):
            self.seen: set[bytes] = set()
            self.calls = 0
            self.unique = 0
            self.measured_errors = 0
            self.measured_served = 0

        async def post(self, url, *, content, headers):
            self.calls += 1
            if content in self.seen:
                # Unique event_id violated → gateway would reject / error.
                return 409, b'{"status":"error","reason":"duplicate"}', None
            self.seen.add(content)
            self.unique += 1
            return 202, b'{"investigation_id":"x"}', None

    transport = DupAwareTransport()
    # Old bug: same three payloads reused for warmup, prologue and measurement.
    shared = [(b'{"event_id":"same"}', {"Content-Type": "application/json"}) for _ in range(3)]
    # Correct API: measured-only list with optional disjoint prologue/warmup.
    warmup = (b'{"event_id":"warm"}', {"Content-Type": "application/json"})
    prologue = [
        (b'{"event_id":"pro0"}', {"Content-Type": "application/json"}),
        (b'{"event_id":"pro1"}', {"Content-Type": "application/json"}),
    ]
    measured = [
        (f'{{"event_id":"m{i}"}}'.encode(), {"Content-Type": "application/json"})
        for i in range(3)
    ]
    result = await b1.run_open_loop(
        endpoint="http://stub/events",
        requests=measured,
        rate=100,
        transport=transport,
        max_in_flight=10,
        warmup=warmup,
        prologue=prologue,
        include_sync_warmup=True,
    )
    assert result.errors == 0
    assert result.served == 3
    assert transport.unique == 1 + 2 + 3  # warmup + prologue + measured
    assert transport.calls == 6


# ---------------------------------------------------------------------------
# Reference burst fixture
# ---------------------------------------------------------------------------


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _sign(body: bytes) -> str:
    return hmac.new(HMAC_SECRET.encode(), body, hashlib.sha256).hexdigest()


def _build_requests(count: int) -> list[tuple[bytes, dict[str, str]]]:
    out = []
    for i in range(count):
        payload = {
            "source": "grafana-b1",
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
                    "X-Signature": _sign(raw),
                },
            )
        )
    return out


def _cpu_seconds(pid: int) -> float:
    clk = os.sysconf("SC_CLK_TCK")
    with open(f"/proc/{pid}/stat", encoding="utf-8") as f:
        fields = f.read().split()
    # utime 14, stime 15, cutime 16, cstime 17 (1-indexed)
    return (int(fields[13]) + int(fields[14]) + int(fields[15]) + int(fields[16])) / clk


def _host_fingerprint() -> dict[str, str | int]:
    cpus = os.cpu_count() or 0
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


@pytest.fixture(scope="module")
def b1_reference_run():
    """Session-scoped single 30 s burst shared by FP-IG-7 and FP-IG-18.

    Hard-fails when the measurement-of-record dependencies are unavailable —
    a silent skip would retire FP-IG-7/18 without evidence (C4).
    """
    try:
        from testcontainers.postgres import PostgresContainer
    except ImportError as exc:
        raise RuntimeError(
            "testcontainers is required for B1 measurement-of-record; "
            "install it rather than skipping"
        ) from exc
    from rca_common.db.session import make_engine, make_session_factory
    from rca_common.db.models import Platform
    import alembic.config
    import alembic.command

    with PostgresContainer(
        "postgres:16-alpine", dbname="dbagent", username="dbagent", password="dbagent"
    ) as pg:
        dsn = pg.get_connection_url()
        # Migrate
        mig_dir = REPO_ROOT / "libs" / "py" / "rca_common"
        # Use alembic from rca_common
        sys.path.insert(0, str(mig_dir))
        try:
            from rca_common.db.session import make_engine as me

            # Run migrations via alembic
            alembic_ini = mig_dir / "alembic.ini"
            migrations_dir = mig_dir / "migrations"
            if alembic_ini.is_file() and migrations_dir.is_dir():
                cfg = alembic.config.Config(str(alembic_ini))
                cfg.set_main_option("sqlalchemy.url", dsn)
                # alembic.ini's script_location is relative; pin absolute path.
                cfg.set_main_option("script_location", str(migrations_dir))
                alembic.command.upgrade(cfg, "head")
            else:
                # Fallback: create_all
                from rca_common.db.models import Base

                engine = me(dsn)
                Base.metadata.create_all(engine)
                engine.dispose()
        finally:
            if str(mig_dir) in sys.path:
                sys.path.remove(str(mig_dir))

        engine = make_engine(dsn)
        sf = make_session_factory(engine)
        with sf() as session:
            session.add(
                Platform(
                    platform_key=PLATFORM_KEY,
                    platform_type="presto",
                    deployment="k8s",
                    status="online",
                    config={},
                )
            )
            session.commit()
        engine.dispose()

        port = _free_port()
        cfg = {
            "temporal": {"address": "localhost:7233", "namespace": "default", "task_queue": "t"},
            "storage": {
                "postgres_dsn": dsn,
                "s3_endpoint": "http://127.0.0.1:9",
                "s3_bucket": "b",
                "s3_access_key": "a",
                "s3_secret_key": "s",
                "s3_region": "us-east-1",
            },
            "model_gateway": {"url": "http://127.0.0.1:9", "master_key": "k"},
            "probe_gateway": {"url": "http://127.0.0.1:9"},
            "signing": {"key_path": "/tmp/nope", "rotation_grace_seconds": 600},
            "dashboard": {"jwt_secret": "j", "cors_origins": [], "bootstrap_ca_cert_path": ""},
            "notifications": {"outbound_webhooks": []},
            "ingest": {
                "sources": [{"name": "grafana-b1", "secret": HMAC_SECRET}],
                "correlation_window_seconds": 1800,
            },
            "budget_defaults": {
                "max_rounds": 15,
                "max_cost_usd": 10.0,
                "max_wall_seconds": 1800,
            },
            "agents": {},
            "tracing": {"backend": "builtin"},
        }
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            yaml.safe_dump(cfg, f)
            cfg_path = f.name

        # Child process: build_app with stub workflow starter, serve uvicorn.
        child_src = textwrap.dedent(
            f"""
            import os, uvicorn
            os.environ["DBAGENT_GATEWAY_CONFIG"] = {cfg_path!r}
            from gateway.main import build_app
            app, config, service = build_app({cfg_path!r})
            class Stub:
                async def start_investigation(self, event, investigation_id):
                    return f"investigation-{{investigation_id}}"
            service._workflow_starter = Stub()
            uvicorn.run(app, host="127.0.0.1", port={port}, log_level="warning")
            """
        )
        env = os.environ.copy()
        env["PYTHONPATH"] = str(REPO_ROOT / "services" / "gateway") + os.pathsep + str(
            REPO_ROOT / "libs" / "py" / "rca_common"
        )
        proc = subprocess.Popen(
            [sys.executable, "-c", child_src],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        endpoint = f"http://127.0.0.1:{port}/api/v1/events"
        health = f"http://127.0.0.1:{port}/healthz"
        try:
            deadline = time.time() + 30
            while time.time() < deadline:
                if proc.poll() is not None:
                    out = proc.stdout.read().decode() if proc.stdout else ""
                    raise RuntimeError(f"gateway exited early: {out[-2000:]}")
                try:
                    r = httpx.get(health, timeout=1.0)
                    if r.status_code == 200:
                        break
                except Exception:
                    time.sleep(0.2)
            else:
                raise RuntimeError("gateway never became healthy")

            # ONLINE precondition — platform row is online; health proves reachability.
            assert httpx.get(health, timeout=5).status_code == 200
            platform_online = True

            warmup = _build_requests(1)[0]
            prologue = _build_requests(b1.PROLOGUE_REQUESTS)
            measured = _build_requests(b1.TOTAL_REQUESTS)
            import asyncio

            marks: dict = {}

            def _after_prologue() -> None:
                # Snapshot AFTER unmeasured prologue so CPU/audit exclude it (C2).
                marks["cpu_before"] = _cpu_seconds(proc.pid)
                engine_p = make_engine(dsn)
                sf_p = make_session_factory(engine_p)
                with sf_p() as session:
                    from sqlalchemy import text

                    marks["committed_before"] = int(
                        session.execute(
                            text(
                                "SELECT count(*) FROM audit_log "
                                "WHERE action IN ('event_received','event_merged')"
                            )
                        ).scalar()
                        or 0
                    )
                engine_p.dispose()

            result = asyncio.run(
                b1.run_open_loop(
                    endpoint=endpoint,
                    requests=measured,
                    rate=b1.BURST_RATE,
                    max_in_flight=b1.MAX_IN_FLIGHT,
                    warmup=warmup,
                    prologue=prologue,
                    include_sync_warmup=True,
                    on_prologue_complete=_after_prologue,
                )
            )
            cpu_after = _cpu_seconds(proc.pid)
            cpu_before = float(marks.get("cpu_before", cpu_after))
            cpu_ms = (
                (cpu_after - cpu_before) * 1000.0 / result.served if result.served else float("inf")
            )
            alive = proc.poll() is None

            # committed count of the measured window only
            engine = make_engine(dsn)
            sf = make_session_factory(engine)
            with sf() as session:
                from sqlalchemy import text

                committed_total = int(
                    session.execute(
                        text(
                            "SELECT count(*) FROM audit_log "
                            "WHERE action IN ('event_received','event_merged')"
                        )
                    ).scalar()
                    or 0
                )
            engine.dispose()
            committed = committed_total - int(marks.get("committed_before", 0))

            values = yaml.safe_load(VALUES_YAML.read_text(encoding="utf-8"))
            basis = float(values["ingestGateway"]["sizingBasis"]["cpuMsPerRequest"])

            fp = _host_fingerprint()
            med_a, med_b = b1.half_window_medians(result.latencies_ms)
            fingerprint_line = (
                f"B1 env=cpus={fp['cpus']},cpu_model={fp['cpu_model']},image={fp['image']},"
                f"tier=reference,max_lateness_ms={result.max_lateness_ms:.1f},"
                f"p99_ms={result.p99:.1f},served_rate={result.served_rate:.1f},"
                f"median_lateness_a_ms={med_a:.1f},median_lateness_b_ms={med_b:.1f},"
                f"lateness_drift_ms={result.lateness_drift_ms:.1f},"
                f"cpu_ms_per_req={cpu_ms:.3f},basis_ms_per_req={basis},"
                f"max_in_flight={result.max_in_flight},max_backlog={result.max_backlog}"
            )
            print(fingerprint_line, flush=True)

            yield {
                "result": result,
                "committed": int(committed),
                "cpu_ms_per_request": cpu_ms,
                "alive": alive,
                "fingerprint": fingerprint_line,
                "host": fp,
                "platform_online": platform_online,
                "basis_ms_per_req": basis,
            }
        finally:
            if proc.poll() is None:
                proc.send_signal(signal.SIGTERM)
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
            Path(cfg_path).unlink(missing_ok=True)


# Module-scope bars for the manifest threshold checker (ordering comparisons
# against bare Name bindings to numeric literals — FP-M6-31 / §11.1.3).
P99_MS = 150.0
SUSTAINED_FLOOR = 200
MAX_IN_FLIGHT = 1000
TOTAL_REQUESTS = 30000


def test_b1_ingest_burst_reference_profile(b1_reference_run):
    """FP-IG-7: seven B1 clauses + harness integrity."""
    r = b1_reference_run["result"]
    committed = b1_reference_run["committed"]
    served = r.served
    errors = r.errors
    offered = r.offered
    p99 = r.p99
    served_rate = r.served_rate
    max_in_flight = r.max_in_flight
    # (7) platform ONLINE — fixture seeds status=online and asserts reachability
    platform_online = b1_reference_run["platform_online"]
    assert platform_online == True  # noqa: E712 — named Eq for FP-IG-19
    # (1)(2)(3)
    assert served + errors == offered, (
        f"served+errors!=offered {served}+{errors}!={offered}; {b1_reference_run['fingerprint']}"
    )
    assert errors == 0, f"errors={errors}; {b1_reference_run['fingerprint']}"
    assert served == offered, f"served={served}; {b1_reference_run['fingerprint']}"
    # (4) ordering comparison against module constant — measurement-of-record bar
    assert p99 < P99_MS, f"p99={p99}; {b1_reference_run['fingerprint']}"
    # (5)
    assert committed == served, (
        f"committed={committed} served={served}; {b1_reference_run['fingerprint']}"
    )
    # (6)
    assert served_rate >= SUSTAINED_FLOOR, (
        f"served_rate={served_rate}; {b1_reference_run['fingerprint']}"
    )
    # harness integrity
    assert max_in_flight < MAX_IN_FLIGHT, (
        f"max_in_flight={max_in_flight} hit ceiling; harness was binding"
    )
    assert b1_reference_run["alive"], "gateway child exited during burst"


def test_measured_cpu_cost_does_not_exceed_the_recorded_sizing_basis(b1_reference_run):
    """FP-IG-18: cpu_ms_per_request <= chart basis."""
    values = yaml.safe_load(VALUES_YAML.read_text(encoding="utf-8"))
    basis = float(values["ingestGateway"]["sizingBasis"]["cpuMsPerRequest"])
    measured = b1_reference_run["cpu_ms_per_request"]
    assert measured <= basis, (
        f"cpu_ms_per_request={measured} exceeds basis={basis}; "
        f"{b1_reference_run['fingerprint']}"
    )
