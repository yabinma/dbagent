"""FP-IG-7 / FP-IG-18 / UT-IG-5: B1 reference-tier burst measurement.

Run only from the CI ``benchmark`` job (excluded from unit-gateway/functional
via --ignore). Spawns the real gateway under uvicorn against testcontainers PG.
"""
from __future__ import annotations

import ast
import asyncio
import hashlib
import hmac
import json
import math
import os
import re
import signal
import socket
import select
import subprocess
import sys
import tempfile
import textwrap
import time
import uuid
from datetime import datetime, timezone
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path

import httpcore
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


def test_serve_benchmark_passes_connection_ceiling_carrier(monkeypatch):
    """UT-IG-14 harness-side: B1 child passes the same serve carrier as main()."""
    from gateway.main import (
        BACKLOG,
        DEFAULT_MAX_CONNECTIONS_PER_WORKER,
        DEFAULT_TIMEOUT_KEEP_ALIVE_S,
    )

    called: dict = {}

    def fake_run(*args, **kwargs):
        called["args"] = args
        called["kwargs"] = kwargs

    monkeypatch.setattr("uvicorn.run", fake_run)
    b1.serve_benchmark(host="127.0.0.1", port=18080)
    assert called["kwargs"]["limit_concurrency"] == DEFAULT_MAX_CONNECTIONS_PER_WORKER
    assert called["kwargs"]["timeout_keep_alive"] == DEFAULT_TIMEOUT_KEEP_ALIVE_S
    assert called["kwargs"]["backlog"] == BACKLOG


# ---------------------------------------------------------------------------
# UT-IG-15 — histogram serializer, proc census parser, peak reducer (no server)
# ---------------------------------------------------------------------------


def test_status_histogram_serializer_sorts_and_counts():
    codes = [202, 202, 200, 503, 599, 202]
    assert b1.serialize_status_histogram(codes) == "200:1;202:3;503:1;599:1"
    assert sum(int(pair.split(":")[1]) for pair in b1.serialize_status_histogram(codes).split(";")) == len(
        codes
    )


def test_proc_tcp_established_parser_counts_matching_remote_port(tmp_path):
    serve_port = 0x1F90  # 8080
    remote_hex = f"{serve_port:04X}"
    tcp = textwrap.dedent(
        f"""
          sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
           0: 0100007F:EA60 0100007F:{remote_hex} 01 00000000:00000000 00000000:00000000 00000000     0        0 1 1 0000000000000000 20 4 30 10 40
           1: 0100007F:EA61 0100007F:{remote_hex} 06 00000000:00000000 00000000:00000000 00000000     0        0 2 1 0000000000000000 20 4 30 10 40
           2: 0100007F:EA62 0100007F:0050 01 00000000:00000000 00000000:00000000 00000000     0        0 3 1 0000000000000000 20 4 30 10 40
        """
    )
    tcp6 = textwrap.dedent(
        f"""
          sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
           0: 0000000000000000:0000000000000000:0000000000000000:0000000000000000:0100007F:EA70 0000000000000000:0000000000000000:0000000000000000:0000000000000000:0100007F:{remote_hex} 01 00000000:00000000 00000000:00000000 00000000     0        0 4 1 0000000000000000 20 4 30 10 40
        """
    )
    tcp_path = tmp_path / "tcp"
    tcp6_path = tmp_path / "tcp6"
    tcp_path.write_text(tcp, encoding="utf-8")
    tcp6_path.write_text(tcp6, encoding="utf-8")
    assert b1.count_established_to_serve_port(
        serve_port, tcp_path=tcp_path, tcp6_path=tcp6_path
    ) == 2


def test_proc_tcp_established_parser_returns_unavailable_on_malformed(tmp_path):
    bad = tmp_path / "tcp"
    good = tmp_path / "tcp6"
    bad.write_text("not a proc table\nbroken row\n", encoding="utf-8")
    good.write_text("  sl  local rem st\n", encoding="utf-8")
    assert (
        b1.count_established_to_serve_port(8080, tcp_path=bad, tcp6_path=good)
        == b1.UNAVAILABLE
    )


def test_proc_tcp_established_parser_returns_unavailable_on_unreadable(tmp_path):
    missing = tmp_path / "nonexistent_tcp"
    good = tmp_path / "tcp6"
    good.write_text("  sl  local rem st\n", encoding="utf-8")
    assert (
        b1.count_established_to_serve_port(8080, tcp_path=missing, tcp6_path=good)
        == b1.UNAVAILABLE
    )


def test_peak_established_reducer_returns_max_or_unavailable():
    assert b1.peak_established_from_samples([1, 5, 3]) == 5
    assert b1.peak_established_from_samples([b1.UNAVAILABLE, b1.UNAVAILABLE]) == b1.UNAVAILABLE
    assert b1.peak_established_from_samples([b1.UNAVAILABLE, 2]) == 2


# ---------------------------------------------------------------------------
# UT-IG-16 — shed probe classifier and probe-size arithmetic (no server)
# ---------------------------------------------------------------------------


def test_shed_probe_outcome_classifier_precedence():
    min_est = 8
    assert b1.classify_shed_probe_outcome(
        [(503, False), (200, False)], established_count=8, pigeonhole_minimum_count=min_est
    ) == "fired"
    assert b1.classify_shed_probe_outcome(
        [(503, False), (None, True)], established_count=8, pigeonhole_minimum_count=min_est
    ) == "fired"
    assert b1.classify_shed_probe_outcome(
        [(200, False), (200, False)], established_count=8, pigeonhole_minimum_count=min_est
    ) == "absent"
    assert b1.classify_shed_probe_outcome(
        [(200, False), (None, True)], established_count=8, pigeonhole_minimum_count=min_est
    ) == "timeout"
    assert b1.classify_shed_probe_outcome(
        [(503, False)], established_count=7, pigeonhole_minimum_count=min_est
    ) == b1.UNAVAILABLE


def test_probe_connection_count_recomputed_from_imported_constants():
    from gateway.main import DEFAULT_MAX_CONNECTIONS_PER_WORKER

    expected = (
        b1.INGEST_GATEWAY_WORKERS * (DEFAULT_MAX_CONNECTIONS_PER_WORKER - 1)
        + 1
        + b1.PROBE_SLACK
    )
    assert (
        b1.probe_connection_count(
            workers=b1.INGEST_GATEWAY_WORKERS,
            ceiling_per_worker=DEFAULT_MAX_CONNECTIONS_PER_WORKER,
        )
        == expected
    )


@pytest.mark.asyncio
async def test_run_open_loop_with_serve_port_records_peak_census():
    """Census sampler runs during the measured window when serve_port is set."""

    class StubTransport:
        async def post(self, url, *, content, headers):
            return 202, b'{"status":"ok"}', None

    measured = [
        (b'{"event_id":"a"}', {"Content-Type": "application/json"}),
        (b'{"event_id":"b"}', {"Content-Type": "application/json"}),
    ]
    result = await b1.run_open_loop(
        endpoint="http://stub/events",
        requests=measured,
        rate=1000,
        transport=StubTransport(),
        max_in_flight=10,
        warmup=(b'{"event_id":"w"}', {"Content-Type": "application/json"}),
        include_sync_warmup=True,
        serve_port=65534,
    )
    assert result.peak_established_connections in (
        0,
        b1.UNAVAILABLE,
    ) or isinstance(result.peak_established_connections, int)


@pytest.mark.asyncio
async def test_run_shed_probe_fired_against_inline_ceiling_server():
    """run_shed_probe connect-all-then-request path against a shedding server."""
    ceiling = 4
    min_est = b1.pigeonhole_minimum(workers=1, ceiling_per_worker=ceiling)
    active = 0

    async def handler(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        nonlocal active
        active += 1
        slot = active
        try:
            await reader.read(4096)
            if slot <= ceiling - 1:
                writer.write(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
                )
            else:
                writer.write(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Connection: close\r\n\r\n"
                )
            await writer.drain()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    host, port = server.sockets[0].getsockname()[:2]
    try:
        outcome = await b1.run_shed_probe(
            host,
            port,
            workers=1,
            ceiling_per_worker=ceiling,
        )
        assert outcome == "fired"
        assert min_est == 4
    finally:
        server.close()
        await server.wait_closed()


def _parse_b1_env_field(line: str, field: str) -> str:
    prefix = f"{field}="
    for part in line.split(","):
        if part.startswith(prefix):
            return part[len(prefix) :]
    raise KeyError(field)


def _is_never_served_status_code(code: int) -> bool:
    """HTTP codes that are errors without body inspection (200 stays ambiguous)."""
    if code in (503, 599):
        return True
    return 400 <= code < 600 and code != 200


def test_b1_fingerprint_line_carries_terminal_fields(b1_reference_run):
    """FP-IG-35: three reported-only fields present and reconciled."""
    from collections import Counter

    line = b1_reference_run["fingerprint"]
    result = b1_reference_run["result"]
    hist_raw = _parse_b1_env_field(line, "status_histogram")
    peak_raw = _parse_b1_env_field(line, "peak_established_connections")
    shed = _parse_b1_env_field(line, "shed_probe")

    assert hist_raw == b1.serialize_status_histogram(result.status_codes)
    hist_counts: Counter[int] = Counter()
    for pair in hist_raw.split(";"):
        if pair:
            code, count = pair.split(":")
            hist_counts[int(code)] = int(count)
    assert hist_counts == Counter(result.status_codes)
    assert sum(hist_counts.values()) == result.offered
    never_served_hist = sum(
        count for code, count in hist_counts.items()
        if _is_never_served_status_code(code)
    )
    assert never_served_hist <= result.errors
    assert hist_counts.get(202, 0) <= result.served

    assert peak_raw.isdigit() or peak_raw == b1.UNAVAILABLE
    assert shed in {"fired", "absent", "timeout", b1.UNAVAILABLE}


def test_b1_fingerprint_line_locates_the_in_flight_population(b1_reference_run):
    """FP-IG-37: pool census fields present, reconciled, two safe inequalities."""
    line = b1_reference_run["fingerprint"]
    result = b1_reference_run["result"]

    peak_pool_conn_raw = _parse_b1_env_field(line, "peak_pool_connections")
    peak_pool_requests_raw = _parse_b1_env_field(line, "peak_pool_requests")
    assert line.index("peak_pool_connections=") < line.index("peak_pool_requests=") < line.index("peak_pool_queued=")
    peak_pool_q_raw = _parse_b1_env_field(line, "peak_pool_queued")
    pool_seen_raw = _parse_b1_env_field(line, "pool_connections_seen")

    for raw, quantity in (
        (peak_pool_conn_raw, result.peak_pool_connections),
        (peak_pool_requests_raw, result.peak_pool_requests),
        (peak_pool_q_raw, result.peak_pool_queued),
        (pool_seen_raw, result.pool_connections_seen),
    ):
        assert raw.isdigit() or raw == b1.UNAVAILABLE
        expected = str(quantity) if isinstance(quantity, int) else quantity
        assert raw == expected

    if isinstance(result.peak_pool_queued, int):
        assert result.peak_pool_queued <= result.max_in_flight
    if isinstance(result.pool_connections_seen, int) and isinstance(
        result.peak_pool_connections, int
    ):
        assert result.pool_connections_seen >= result.peak_pool_connections


def test_b1_fingerprint_line_carries_the_per_worker_census(b1_reference_run):
    """FP-IG-38: per-worker census fields present and reconciled."""
    line = b1_reference_run["fingerprint"]
    result = b1_reference_run["result"]
    workers_pre = b1_reference_run["workers_pre"]

    peaks_raw = _parse_b1_env_field(line, "worker_established_peaks")
    peak_worker_raw = _parse_b1_env_field(line, "peak_worker_established")

    expected_peaks_str = b1.serialize_worker_established_peaks(
        result.worker_established_peaks
    )
    expected_peak_worker = (
        str(result.peak_worker_established)
        if isinstance(result.peak_worker_established, int)
        else result.peak_worker_established
    )

    assert peaks_raw.isdigit() or "+" in peaks_raw or peaks_raw == b1.UNAVAILABLE
    assert peak_worker_raw.isdigit() or peak_worker_raw == b1.UNAVAILABLE
    assert peaks_raw == expected_peaks_str
    assert peak_worker_raw == expected_peak_worker

    if peaks_raw != b1.UNAVAILABLE:
        peak_parts = [int(x) for x in peaks_raw.split("+")]
        assert len(peak_parts) == len(workers_pre)
        assert peak_worker_raw.isdigit()
        assert int(peak_worker_raw) == max(peak_parts)


def _parse_leg_triple(raw: str) -> tuple[float, float, float]:
    parts = raw.split("/")
    assert len(parts) == 3, raw
    return float(parts[0]), float(parts[1]), float(parts[2])


def test_b1_fingerprint_line_decomposes_the_headline_lateness(b1_reference_run):
    """FP-IG-39: both leg fields present, numeric, wired to this run."""
    line = b1_reference_run["fingerprint"]
    result = b1_reference_run["result"]

    split_raw = _parse_b1_env_field(line, "p99_leg_split")
    p99s_raw = _parse_b1_env_field(line, "leg_p99s")
    p99_ms_raw = _parse_b1_env_field(line, "p99_ms")

    peak_at = line.index("peak_worker_established=")
    split_at = line.index("p99_leg_split=")
    p99s_at = line.index("leg_p99s=")
    assert peak_at < split_at < p99s_at

    assert "/" in split_raw and split_raw != b1.UNAVAILABLE
    assert "/" in p99s_raw and p99s_raw != b1.UNAVAILABLE
    split_vals = _parse_leg_triple(split_raw)
    p99s_vals = _parse_leg_triple(p99s_raw)
    assert all(math.isfinite(v) for v in split_vals + p99s_vals)

    assert split_raw == b1.serialize_leg_triple(result.p99_leg_split)
    assert p99s_raw == b1.serialize_leg_triple(result.leg_p99s)

    for vec in (
        result.pre_dispatch_slip_ms,
        result.start_lag_ms,
        result.attempt_duration_ms,
    ):
        assert len(vec) == result.offered
        assert all(v >= -b1.LEG_SUM_TOLERANCE_MS for v in vec)

    idx = result.p99_index
    assert idx is not None
    raw_triple = (
        result.pre_dispatch_slip_ms[idx],
        result.start_lag_ms[idx],
        result.attempt_duration_ms[idx],
    )
    assert abs(sum(raw_triple) - result.p99) <= b1.LEG_SUM_TOLERANCE_MS
    parsed_p99 = float(p99_ms_raw)
    assert abs(sum(split_vals) - parsed_p99) <= b1.LEG_LINE_TOLERANCE_MS


# ---------------------------------------------------------------------------
# UT-IG-19 — per-request station decomposition (no product server)
# ---------------------------------------------------------------------------


def _stub_payload(event_id: str) -> tuple[bytes, dict[str, str]]:
    return (
        json.dumps({"event_id": event_id}).encode(),
        {"Content-Type": "application/json"},
    )


class _QuantumTransport:
    """Stub that awaits a pinned quantum, then returns the served class."""

    def __init__(self, quantum_s: float):
        self.quantum_s = quantum_s

    async def post(self, url, *, content, headers):
        await asyncio.sleep(self.quantum_s)
        return 202, b'{"status":"ok"}', None


class _HoldThenQuantumTransport:
    """Attempts 0 and 1 wait on ``release`` then S; later attempts take S."""

    def __init__(self, quantum_s: float, release: asyncio.Event):
        self.quantum_s = quantum_s
        self.release = release
        self._arrivals = 0
        self.second_arrival = asyncio.Event()

    async def post(self, url, *, content, headers):
        self._arrivals += 1
        n = self._arrivals
        if n <= 2:
            if n == 2:
                self.second_arrival.set()
            await self.release.wait()
            await asyncio.sleep(self.quantum_s)
        else:
            await asyncio.sleep(self.quantum_s)
        return 202, b'{"status":"ok"}', None


@pytest.mark.asyncio
async def test_leg_derivation_runs_after_window_complete(monkeypatch):
    """C1 [live path]: CPU-window hook fires before named O(N) derivation."""
    order: list[str] = []
    real_derive = b1.derive_leg_vectors

    def _wrapped(*args, **kwargs):
        order.append("derive")
        return real_derive(*args, **kwargs)

    monkeypatch.setattr(b1, "derive_leg_vectors", _wrapped)
    n = 4
    measured = [_stub_payload(f"w{i}") for i in range(n)]
    result = await b1.run_open_loop(
        endpoint="http://stub/events",
        requests=measured,
        rate=50,
        transport=_QuantumTransport(1.0 / 50),
        max_in_flight=n,
        include_sync_warmup=False,
        on_window_complete=lambda: order.append("window"),
    )
    assert order == ["window", "derive"], order
    assert len(result.pre_dispatch_slip_ms) == n


def test_window_complete_precedes_derivation_in_source():
    """C1 [live path]: hook call site is before the named derive call."""
    src = _PROFILE_PATH.read_text(encoding="utf-8")
    hook_at = src.index("on_window_complete()")
    derive_at = src.index("= derive_leg_vectors(")
    assert hook_at < derive_at


def test_b1_fixture_samples_cpu_after_on_window_complete():
    """C1 [consumer path]: cpu_after is the hook sample, not a post-return read."""
    src = Path(__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    hook = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_after_window":
            hook = node
    assert hook is not None
    hook_src = ast.get_source_segment(src, hook)
    assert hook_src is not None
    assert "tree_cpu_seconds" in hook_src
    assert "cpu_after" in hook_src

    hooked = False
    cpu_after_from_marks = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if (
                    kw.arg == "on_window_complete"
                    and isinstance(kw.value, ast.Name)
                    and kw.value.id == "_after_window"
                ):
                    hooked = True
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "cpu_after"
        ):
            seg = ast.get_source_segment(src, node)
            assert seg is not None
            assert "tree_cpu_seconds" not in seg
            assert "marks" in seg
            cpu_after_from_marks = True
    assert hooked
    assert cpu_after_from_marks


@pytest.mark.asyncio
async def test_ut_ig19_leg_reconciliation():
    """UT-IG-19 (1) [live path]: per-request sum identity against a quantum stub."""
    rate = 50
    delta_s = 1.0 / rate
    quantum_s = 2 * delta_s
    n = 8
    measured = [_stub_payload(f"m{i}") for i in range(n)]
    result = await b1.run_open_loop(
        endpoint="http://stub/events",
        requests=measured,
        rate=rate,
        transport=_QuantumTransport(quantum_s),
        max_in_flight=n,
        include_sync_warmup=False,
    )
    quantum_ms = quantum_s * 1000.0
    assert len(result.pre_dispatch_slip_ms) == n
    for i in range(n):
        total = (
            result.pre_dispatch_slip_ms[i]
            + result.start_lag_ms[i]
            + result.attempt_duration_ms[i]
        )
        assert abs(total - result.latencies_ms[i]) <= b1.LEG_SUM_TOLERANCE_MS
        assert result.attempt_duration_ms[i] >= quantum_ms
        assert result.pre_dispatch_slip_ms[i] >= -b1.LEG_SUM_TOLERANCE_MS


@pytest.mark.asyncio
async def test_ut_ig19_gate_placement():
    """UT-IG-19 (2) [live path]: d_i is after the gate; hold-run is sync-based."""
    delta_s = 20 * (10**-3)
    rate = int(round(1.0 / delta_s))
    assert abs(1.0 / rate - delta_s) < 1e-12
    k = 10
    quantum_s = k * delta_s
    n = 8
    measured = [_stub_payload(f"g{i}") for i in range(n)]
    result = await b1.run_open_loop(
        endpoint="http://stub/events",
        requests=measured,
        rate=rate,
        transport=_QuantumTransport(quantum_s),
        max_in_flight=2,
        include_sync_warmup=False,
    )
    for i in range(2, n):
        bound = (math.floor(i / 2) * quantum_s - i * delta_s) * 1000.0
        if bound > 0:
            assert result.pre_dispatch_slip_ms[i] >= bound - b1.LEG_SUM_TOLERANCE_MS

    release = asyncio.Event()
    hold = _HoldThenQuantumTransport(quantum_s, release)
    hold_n = 4
    hold_measured = [_stub_payload(f"h{i}") for i in range(hold_n)]

    async def _release_after_second_arrival() -> None:
        await hold.second_arrival.wait()
        await asyncio.sleep(2 * delta_s)
        release.set()

    releaser = asyncio.create_task(_release_after_second_arrival())
    hold_result = await b1.run_open_loop(
        endpoint="http://stub/events",
        requests=hold_measured,
        rate=rate,
        transport=hold,
        max_in_flight=2,
        include_sync_warmup=False,
    )
    await releaser
    lower = min(
        hold_result.latencies_ms[0] - 2 * delta_s * 1000.0,
        hold_result.latencies_ms[1] - delta_s * 1000.0,
    )
    assert hold_result.pre_dispatch_slip_ms[2] >= lower - b1.LEG_SUM_TOLERANCE_MS


def test_ut_ig19_summary_evaluator():
    """UT-IG-19 (3) [evaluator]: identity split ≠ per-leg p99s; tie → smallest index."""
    n = 100
    slip = [0.5] * n
    lag = [0.3] * n
    attempt = [0.2] * n
    latencies = [1.0] * n
    # Three-way tie at the p99 rank (sorted[98] = 100.0); smallest index wins.
    latencies[10] = latencies[50] = latencies[80] = 100.0
    slip[10], lag[10], attempt[10] = 11.0, 22.0, 67.0
    slip[50], lag[50], attempt[50] = 6.0, 8.0, 86.0
    slip[80], lag[80], attempt[80] = 7.0, 9.0, 84.0
    expected = {
        "p99_index": 10,
        "split": (11.0, 22.0, 67.0),
        "leg_p99s": (7.0, 9.0, 84.0),
    }
    values = (
        expected["split"] + expected["leg_p99s"] + (float(expected["p99_index"]),)
    )
    assert len(set(values)) == 7

    idx = b1.p99_index_of(latencies)
    split = b1.p99_leg_split_of(latencies, slip, lag, attempt)
    per_leg = b1.leg_p99s_of(slip, lag, attempt)
    assert idx == expected["p99_index"]
    assert split == expected["split"]
    assert per_leg == expected["leg_p99s"]
    assert split != per_leg


def _is_idx_range_guard(node: ast.AST) -> bool:
    """True iff ``node`` is the compare ``0 <= idx < n``."""
    if not isinstance(node, ast.Compare) or len(node.ops) != 2:
        return False
    return (
        isinstance(node.left, ast.Constant)
        and node.left.value == 0
        and isinstance(node.ops[0], ast.LtE)
        and isinstance(node.ops[1], ast.Lt)
        and isinstance(node.comparators[0], ast.Name)
        and node.comparators[0].id == "idx"
        and isinstance(node.comparators[1], ast.Name)
        and node.comparators[1].id == "n"
    )


def _is_attempt_at_idx_store(node: ast.AST) -> bool:
    """True iff ``node`` assigns to ``attempt_at[idx]``."""
    if not isinstance(node, ast.Assign):
        return False
    for target in node.targets:
        if (
            isinstance(target, ast.Subscript)
            and isinstance(target.value, ast.Name)
            and target.value.id == "attempt_at"
            and isinstance(target.slice, ast.Name)
            and target.slice.id == "idx"
        ):
            return True
    return False


def _one_records_c_i_behind_idx_guard(src: str) -> bool:
    """True iff nested ``_one`` stores ``attempt_at[idx]`` only under ``0 <= idx < n``.

    Every matching assignment must sit inside that guard's body; a matching
    compare anywhere in ``_one`` is not enough, and an unguarded store fails.
    """
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if not isinstance(node, ast.AsyncFunctionDef) or node.name != "_one":
            continue
        stores: list[ast.Assign] = []
        guards: list[ast.If] = []
        for child in ast.walk(node):
            if _is_attempt_at_idx_store(child):
                stores.append(child)
            if isinstance(child, ast.If) and _is_idx_range_guard(child.test):
                guards.append(child)
        if not stores:
            return False
        guarded_ids: set[int] = set()
        for guard in guards:
            for stmt in guard.body:
                for inner in ast.walk(stmt):
                    guarded_ids.add(id(inner))
        return all(id(store) in guarded_ids for store in stores)
    return False


def test_ut_ig19_idx_guard_rejects_assignment_outside_compare():
    """W2: a matching ``0 <= idx < n`` anywhere in ``_one`` is not enough."""
    unguarded = textwrap.dedent(
        """
        async def _one(idx, raw, headers):
            if 0 <= idx < n:
                pass
            attempt_at[idx] = time.perf_counter()
        """
    )
    guarded = textwrap.dedent(
        """
        async def _one(idx, raw, headers):
            if 0 <= idx < n:
                attempt_at[idx] = time.perf_counter()
        """
    )
    assert _one_records_c_i_behind_idx_guard(unguarded) is False
    assert _one_records_c_i_behind_idx_guard(guarded) is True


@pytest.mark.asyncio
async def test_ut_ig19_negative_index_guard():
    """UT-IG-19 (4) [live path]: warmup/prologue never write a measured slot."""
    src = _PROFILE_PATH.read_text(encoding="utf-8")
    assert _one_records_c_i_behind_idx_guard(src)
    assert "complete_at" not in src
    rate = 50
    n = 3
    measured = [_stub_payload(f"n{i}") for i in range(n)]
    warmup = _stub_payload("warm")
    prologue = [_stub_payload("p0"), _stub_payload("p1")]
    result = await b1.run_open_loop(
        endpoint="http://stub/events",
        requests=measured,
        rate=rate,
        transport=_QuantumTransport(1.0 / rate),
        max_in_flight=n,
        warmup=warmup,
        prologue=prologue,
        include_sync_warmup=True,
    )
    assert len(result.pre_dispatch_slip_ms) == n
    assert len(result.start_lag_ms) == n
    assert len(result.attempt_duration_ms) == n
    assert len(result.latencies_ms) == n
    for i in range(n):
        due_i = result.due0 + i / rate
        d_i = due_i + result.pre_dispatch_slip_ms[i] / 1000.0
        c_i = d_i + result.start_lag_ms[i] / 1000.0
        assert c_i >= d_i - 1e-12
        assert d_i >= result.t0 - 1e-12


def test_ut_ig19_serializer_round_trip():
    """UT-IG-19 (5) [consumer path]: :.3f width and the two-tolerance boundary."""
    assert b1.LEG_SUM_TOLERANCE_MS == 1e-6
    assert b1.LEG_LINE_TOLERANCE_MS == (
        3 * (10**-3) / 2 + (10**-1) / 2 + b1.LEG_SUM_TOLERANCE_MS
    )
    triple = (1.234567, 2.345678, 3.456789)
    rendered = b1.serialize_leg_triple(triple)
    assert rendered == f"{triple[0]:.3f}/{triple[1]:.3f}/{triple[2]:.3f}"
    parts = rendered.split("/")
    assert all(len(p.split(".")[1]) == 3 for p in parts)
    parsed = _parse_leg_triple(rendered)
    assert parsed == (float(f"{triple[0]:.3f}"), float(f"{triple[1]:.3f}"), float(f"{triple[2]:.3f}"))

    # Each raw leg sits just above the :.3f half-ulp so format rounds upward.
    raw_legs = (1.0005001, 2.0005001, 3.0005001)
    assert all(float(f"{leg:.3f}") > leg for leg in raw_legs)
    line_split = b1.serialize_leg_triple(raw_legs)
    parsed_split = _parse_leg_triple(line_split)
    raw_p99 = sum(raw_legs)
    parsed_p99 = float(f"{raw_p99:.1f}")
    parsed_sum = sum(parsed_split)
    assert abs(parsed_sum - parsed_p99) <= b1.LEG_LINE_TOLERANCE_MS
    assert abs(parsed_sum - parsed_p99) > b1.LEG_SUM_TOLERANCE_MS


# ---------------------------------------------------------------------------
# UT-IG-18 — per-worker established-socket census (no product server)
# ---------------------------------------------------------------------------


def _write_proc_tcp_fixture(
    tmp_path: Path, *, serve_port: int, rows: list[tuple[int, str, str, str]]
) -> tuple[Path, Path]:
    """Build tcp/tcp6 fixture files; each row is (inode, local, remote, state)."""
    serve_hex = f"{serve_port:04X}"
    lines = [
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"
    ]
    for inode, local, remote, state in rows:
        lines.append(
            f"   {inode}: {local} {remote} {state} "
            "00000000:00000000 00000000:00000000 00000000     0        0 "
            f"{inode} 1 0000000000000000 20 4 30 10 40"
        )
    tcp = tmp_path / "tcp"
    tcp6 = tmp_path / "tcp6"
    tcp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    tcp6.write_text("  sl  local_address rem_address st\n", encoding="utf-8")
    return tcp, tcp6


def _write_proc_fd_fixture(tmp_path: Path, pid: int, links: dict[str, str]) -> Path:
    fd_dir = tmp_path / f"proc_{pid}_fd"
    fd_dir.mkdir()
    for name, target in links.items():
        (fd_dir / name).symlink_to(target)
    return fd_dir


def test_per_worker_census_attributes_sockets_to_each_pid(tmp_path):
    """UT-IG-18: N held sockets on one pid, zero on another — not aggregate for both."""
    serve_port = 18080
    serve_hex = f"{serve_port:04X}"
    inode_a, inode_b = 101, 102
    tcp = tmp_path / "tcp"
    tcp6 = tmp_path / "tcp6"
    tcp.write_text(
        textwrap.dedent(
            f"""
              sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
               0: 0100007F:{serve_hex} 0100007F:EA60 01 00000000:00000000 00000000:00000000 00000000     0        0 {inode_a} 1 0000000000000000 20 4 30 10 40
               1: 0100007F:{serve_hex} 0100007F:EA61 01 00000000:00000000 00000000:00000000 00000000     0        0 {inode_b} 1 0000000000000000 20 4 30 10 40
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    tcp6.write_text("  sl  local_address rem_address st\n", encoding="utf-8")
    pid_with = 10001
    pid_without = 10002
    fd_with = _write_proc_fd_fixture(
        tmp_path,
        pid_with,
        {"3": f"socket:[{inode_a}]", "4": f"socket:[{inode_b}]", "5": "pipe:[999]"},
    )
    fd_without = _write_proc_fd_fixture(tmp_path, pid_without, {"3": "pipe:[888]"})

    def fd_for_pid(pid: int) -> Path:
        return fd_with if pid == pid_with else fd_without

    counts = b1.count_per_worker_established_to_serve_port(
        [pid_with, pid_without],
        serve_port,
        tcp_path=tcp,
        tcp6_path=tcp6,
        fd_dir_for_pid=fd_for_pid,
    )
    assert counts == [2, 0]


def test_per_worker_census_reads_proc_tcp_once_per_sample(tmp_path, monkeypatch):
    """UT-IG-18: one /proc/net/tcp[6] read per count_per_worker invocation, not per pid."""
    serve_port = 18081
    serve_hex = f"{serve_port:04X}"
    inode_a, inode_b = 201, 202
    tcp = tmp_path / "tcp"
    tcp6 = tmp_path / "tcp6"
    tcp.write_text(
        textwrap.dedent(
            f"""
              sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
               0: 0100007F:{serve_hex} 0100007F:EA60 01 00000000:00000000 00000000:00000000 00000000     0        0 {inode_a} 1 0000000000000000 20 4 30 10 40
               1: 0100007F:{serve_hex} 0100007F:EA61 01 00000000:00000000 00000000:00000000 00000000     0        0 {inode_b} 1 0000000000000000 20 4 30 10 40
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    tcp6.write_text("  sl  local_address rem_address st\n", encoding="utf-8")
    pid_with = 10003
    pid_without = 10004
    fd_with = _write_proc_fd_fixture(
        tmp_path,
        pid_with,
        {"3": f"socket:[{inode_a}]", "4": f"socket:[{inode_b}]"},
    )
    fd_without = _write_proc_fd_fixture(tmp_path, pid_without, {"3": "pipe:[888]"})

    def fd_for_pid(pid: int) -> Path:
        return fd_with if pid == pid_with else fd_without

    read_calls = 0
    real_read = b1.read_proc_net_tcp_tables

    def counting_read(**kwargs):
        nonlocal read_calls
        read_calls += 1
        return real_read(**kwargs)

    monkeypatch.setattr(b1, "read_proc_net_tcp_tables", counting_read)

    counts = b1.count_per_worker_established_to_serve_port(
        [pid_with, pid_without],
        serve_port,
        tcp_path=tcp,
        tcp6_path=tcp6,
        fd_dir_for_pid=fd_for_pid,
    )
    assert counts == [2, 0]
    assert read_calls == 1


@pytest.mark.asyncio
async def test_census_sampler_reads_proc_tcp_once_per_tick(tmp_path, monkeypatch):
    """UT-IG-18: production _census_sampler reads /proc/net/tcp[6] once per tick."""
    serve_port = 18082
    serve_hex = f"{serve_port:04X}"
    inode_client, inode_client2, inode_server = 111, 333, 222
    tcp = tmp_path / "tcp"
    tcp6 = tmp_path / "tcp6"
    tcp.write_text(
        textwrap.dedent(
            f"""
              sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
               0: 0100007F:EA60 0100007F:{serve_hex} 01 00000000:00000000 00000000:00000000 00000000     0        0 {inode_client} 1 0000000000000000 20 4 30 10 40
               1: 0100007F:{serve_hex} 0100007F:EA61 01 00000000:00000000 00000000:00000000 00000000     0        0 {inode_server} 1 0000000000000000 20 4 30 10 40
               2: 0100007F:EA62 0100007F:{serve_hex} 01 00000000:00000000 00000000:00000000 00000000     0        0 {inode_client2} 1 0000000000000000 20 4 30 10 40
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    tcp6.write_text("  sl  local_address rem_address st\n", encoding="utf-8")

    tcp_text = tcp.read_text(encoding="utf-8")
    tcp6_text = tcp6.read_text(encoding="utf-8")

    pid_with = 10005
    pid_without = 10006
    fd_with = _write_proc_fd_fixture(
        tmp_path, pid_with, {"3": f"socket:[{inode_server}]"}
    )
    fd_without = _write_proc_fd_fixture(tmp_path, pid_without, {"3": "pipe:[888]"})

    def fd_for_pid(pid: int) -> Path:
        return fd_with if pid == pid_with else fd_without

    # Same bytes, different measurands: remote-port aggregate vs local-port inode set.
    # Two client-side rows (remote = serve port) vs one server-side inode {222} — counts
    # must diverge so a silent merge onto len(inodes) cannot pass.
    assert b1.count_established_from_proc_tables(tcp_text, tcp6_text, serve_port) == 2
    assert b1.established_serve_port_inodes_from_proc_tables(
        tcp_text, tcp6_text, serve_port
    ) == {inode_server}
    assert b1.count_per_worker_established_to_serve_port(
        [pid_with, pid_without],
        serve_port,
        tcp_text=tcp_text,
        tcp6_text=tcp6_text,
        fd_dir_for_pid=fd_for_pid,
    ) == [1, 0]

    real_per_worker = b1.count_per_worker_established_to_serve_port

    def per_worker_with_fd(worker_pids, serve_port, **kwargs):
        kwargs.setdefault("fd_dir_for_pid", fd_for_pid)
        return real_per_worker(worker_pids, serve_port, **kwargs)

    monkeypatch.setattr(
        b1, "count_per_worker_established_to_serve_port", per_worker_with_fd
    )

    read_calls = 0
    real_read = b1.read_proc_net_tcp_tables

    def counting_read(**kwargs):
        nonlocal read_calls
        read_calls += 1
        kwargs.setdefault("tcp_path", tcp)
        kwargs.setdefault("tcp6_path", tcp6)
        return real_read(**kwargs)

    monkeypatch.setattr(b1, "read_proc_net_tcp_tables", counting_read)

    parser_ticks = 0
    real_aggregate = b1.count_established_to_serve_port

    def counting_aggregate(serve_port, **kwargs):
        nonlocal parser_ticks
        if kwargs.get("tcp_text") is not None:
            parser_ticks += 1
        return real_aggregate(serve_port, **kwargs)

    monkeypatch.setattr(b1, "count_established_to_serve_port", counting_aggregate)

    class SlowStubTransport:
        async def post(self, url, *, content, headers):
            await asyncio.sleep(0.25)
            return 202, b'{"status":"ok"}', None

    measured = [
        (b'{"event_id":"a"}', {"Content-Type": "application/json"}),
        (b'{"event_id":"b"}', {"Content-Type": "application/json"}),
    ]
    result = await b1.run_open_loop(
        endpoint="http://stub/events",
        requests=measured,
        rate=1000,
        transport=SlowStubTransport(),
        max_in_flight=2,
        include_sync_warmup=False,
        serve_port=serve_port,
        worker_pids=[pid_with, pid_without],
    )

    assert parser_ticks >= 1
    assert read_calls == parser_ticks
    assert result.peak_established_connections == 2
    assert result.worker_established_peaks == [1, 0]
    assert result.peak_worker_established == 1


def test_per_worker_census_skips_non_socket_and_vanished_fd(tmp_path):
    serve_port = 9000
    serve_hex = f"{serve_port:04X}"
    inode = 555
    tcp, tcp6 = _write_proc_tcp_fixture(
        tmp_path,
        serve_port=serve_port,
        rows=[(0, f"0100007F:{serve_hex}", "0100007F:EA60", "01")],
    )
    tcp.write_text(
        textwrap.dedent(
            f"""
              sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
               0: 0100007F:{serve_hex} 0100007F:EA60 01 00000000:00000000 00000000:00000000 00000000     0        0 {inode} 1 0000000000000000 20 4 30 10 40
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    fd_dir = tmp_path / "fd"
    fd_dir.mkdir()
    (fd_dir / "3").symlink_to(f"socket:[{inode}]")
    (fd_dir / "4").symlink_to("anon_inode:[eventfd]")
    (fd_dir / "5").symlink_to("socket:[99999]")  # foreign inode

    count = b1.count_worker_established_to_serve_port(
        42, serve_port, tcp_path=tcp, tcp6_path=tcp6, fd_dir=fd_dir
    )
    assert count == 1


def test_per_worker_census_vanished_fd_is_skipped_not_raised(tmp_path, monkeypatch):
    serve_port = 9001
    serve_hex = f"{serve_port:04X}"
    inode = 777
    tcp, tcp6 = _write_proc_tcp_fixture(
        tmp_path,
        serve_port=serve_port,
        rows=[(0, f"0100007F:{serve_hex}", "0100007F:EA60", "01")],
    )
    tcp.write_text(
        textwrap.dedent(
            f"""
              sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
               0: 0100007F:{serve_hex} 0100007F:EA60 01 00000000:00000000 00000000:00000000 00000000     0        0 {inode} 1 0000000000000000 20 4 30 10 40
            """
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    fd_dir = tmp_path / "fd"
    fd_dir.mkdir()
    (fd_dir / "3").symlink_to(f"socket:[{inode}]")
    ghost = fd_dir / "4"
    ghost.symlink_to(f"socket:[{inode}]")

    real_readlink = os.readlink

    def flaky_readlink(path):
        if Path(path).name == "4":
            raise OSError("vanished")
        return real_readlink(path)

    monkeypatch.setattr(os, "readlink", flaky_readlink)
    count = b1.count_worker_established_to_serve_port(
        42, serve_port, tcp_path=tcp, tcp6_path=tcp6, fd_dir=fd_dir
    )
    assert count == 1


def test_per_worker_census_returns_unavailable_on_malformed_proc(tmp_path):
    tcp = tmp_path / "tcp"
    tcp6 = tmp_path / "tcp6"
    tcp.write_text("broken\n", encoding="utf-8")
    tcp6.write_text("  sl  local rem st\n", encoding="utf-8")
    fd_dir = tmp_path / "fd"
    fd_dir.mkdir()
    assert (
        b1.count_worker_established_to_serve_port(
            1, 8080, tcp_path=tcp, tcp6_path=tcp6, fd_dir=fd_dir
        )
        == b1.UNAVAILABLE
    )


def test_per_worker_census_returns_unavailable_on_unreadable_proc(tmp_path):
    missing = tmp_path / "nonexistent_tcp"
    good = tmp_path / "tcp6"
    good.write_text("  sl  local rem st\n", encoding="utf-8")
    fd_dir = tmp_path / "fd"
    fd_dir.mkdir()
    assert (
        b1.count_worker_established_to_serve_port(
            1, 8080, tcp_path=missing, tcp6_path=good, fd_dir=fd_dir
        )
        == b1.UNAVAILABLE
    )


def test_serialize_worker_established_peaks_preserves_pid_order():
    peaks = [3, 1, 7]
    assert b1.serialize_worker_established_peaks(peaks) == "3+1+7"
    assert b1.serialize_worker_established_peaks([1, b1.UNAVAILABLE]) == b1.UNAVAILABLE


def test_worker_established_peaks_from_sample_matrix():
    samples = [
        [1, 4, 2],
        [3, 4, 5],
        [2, 6, 5],
    ]
    peaks = b1.worker_established_peaks_from_samples(samples)
    assert peaks == [3, 6, 5]
    assert b1.peak_worker_established_from_peaks(peaks) == 6
    assert b1.peak_worker_established_from_peaks([b1.UNAVAILABLE]) == b1.UNAVAILABLE
    assert (
        b1.peak_worker_established_from_peaks([1, b1.UNAVAILABLE])
        == b1.UNAVAILABLE
    )


def test_per_worker_census_discriminating_pair_against_live_sockets():
    """Two children: one holds N accepted loopback sockets, one holds none."""
    n_sockets = 3
    src = textwrap.dedent(
        """
        import socket, sys, time
        port = int(sys.argv[1])
        role = sys.argv[2]
        n = int(sys.argv[3])
        if role == "acceptor":
            listener = socket.socket()
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", port))
            listener.listen(n)
            sys.stdout.write("bound\\n")
            sys.stdout.flush()
            held = []
            for _ in range(n):
                conn, _addr = listener.accept()
                held.append(conn)
            sys.stdout.write("ready\\n")
            sys.stdout.flush()
            time.sleep(10)
        else:
            time.sleep(10)
        """
    )
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    acceptor = subprocess.Popen(
        [sys.executable, "-c", src, str(port), "acceptor", str(n_sockets)],
        stdout=subprocess.PIPE,
        text=True,
    )
    empty = subprocess.Popen(
        [sys.executable, "-c", src, str(port), "empty", "0"],
        stdout=subprocess.PIPE,
        text=True,
    )
    clients: list[socket.socket] = []
    try:
        assert acceptor.stdout.readline().strip() == "bound"
        clients = []
        for _ in range(n_sockets):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("127.0.0.1", port))
            clients.append(s)
        assert acceptor.stdout.readline().strip() == "ready"
        time.sleep(0.1)
        holder_count = b1.count_worker_established_to_serve_port(acceptor.pid, port)
        empty_count = b1.count_worker_established_to_serve_port(empty.pid, port)
        assert isinstance(holder_count, int) and holder_count == n_sockets, holder_count
        assert empty_count == 0, empty_count
    finally:
        for s in clients:
            s.close()
        acceptor.send_signal(signal.SIGTERM)
        empty.send_signal(signal.SIGTERM)
        acceptor.wait(timeout=5)
        empty.wait(timeout=5)


# ---------------------------------------------------------------------------
# UT-IG-17 — pool census reader (no product server)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pool_census_reader_opposite_directions_and_reducers():
    """UT-IG-17: sockets vs queued tasks, seen-union, fail-open."""
    pool_size = 2
    hold = asyncio.Event()
    release = asyncio.Event()

    async def handler(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        await reader.read(65536)
        hold.set()
        await release.wait()
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
        await writer.drain()
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    host, port = server.sockets[0].getsockname()[:2]
    url = f"http://{host}:{port}/"
    client = b1.build_httpx_client(max_connections=pool_size)
    try:
        slow = [
            asyncio.create_task(client.post(url, content=b"slow"))
            for _ in range(pool_size)
        ]
        deadline = time.time() + 5.0
        while time.time() < deadline:
            conn, queued, _seen, _requests = b1.read_pool_census_sample(client)
            if isinstance(conn, int) and conn >= pool_size:
                break
            await asyncio.sleep(0.01)
        else:
            raise AssertionError("pool never reached held-connection plateau")

        conn, queued, seen, requests_n = b1.read_pool_census_sample(client)
        assert conn == pool_size
        assert requests_n == pool_size
        assert queued == 0
        assert seen is not None and len(seen) == pool_size

        extra_dispatch = 3
        extra = [
            asyncio.create_task(client.post(url, content=b"extra"))
            for _ in range(extra_dispatch)
        ]
        deadline = time.time() + 5.0
        while time.time() < deadline:
            conn_after, queued_after, _, requests_after = b1.read_pool_census_sample(client)
            if isinstance(queued_after, int) and queued_after == extra_dispatch:
                break
            await asyncio.sleep(0.01)
        else:
            raise AssertionError(
                f"queued never reached {extra_dispatch} (last={queued_after!r})"
            )
        assert conn_after == pool_size
        assert queued_after == extra_dispatch
        assert requests_after == pool_size + extra_dispatch

        release.set()
        await asyncio.gather(*slow, *extra, return_exceptions=True)
        hold.clear()
        release.clear()
        await client.aclose()

        close_hold = asyncio.Event()
        close_release = asyncio.Event()

        async def close_handler(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            await reader.read(65536)
            close_hold.set()
            await close_release.wait()
            writer.write(
                b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
            )
            await writer.drain()
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

        close_server = await asyncio.start_server(close_handler, "127.0.0.1", 0)
        close_host, close_port = close_server.sockets[0].getsockname()[:2]
        close_url = f"http://{close_host}:{close_port}/"
        churn_client = b1.build_httpx_client(max_connections=1)
        identity_sets: list[set[int]] = []
        try:
            for payload in (b"churn-a", b"churn-b"):
                close_hold.clear()
                close_release.clear()
                task = asyncio.create_task(churn_client.post(close_url, content=payload))
                deadline = time.time() + 5.0
                while time.time() < deadline:
                    _c, _q, seen_i, _r = b1.read_pool_census_sample(churn_client)
                    if seen_i:
                        identity_sets.append(set(seen_i))
                        break
                    await asyncio.sleep(0.01)
                else:
                    raise AssertionError("no connection identity sampled")
                close_release.set()
                await task
                await asyncio.sleep(0.05)

            seen_total = b1.pool_connections_seen_from_identity_sets(identity_sets)
            assert seen_total == 2
            assert identity_sets[0].isdisjoint(identity_sets[1])
        finally:
            close_release.set()
            await churn_client.aclose()
            close_server.close()
            await close_server.wait_closed()

        class _NoPool:
            _transport = type("T", (), {"_pool": None})()

        bad_conn, bad_q, bad_seen, bad_requests = b1.read_pool_census_sample(_NoPool())  # type: ignore[arg-type]
        assert bad_conn == b1.UNAVAILABLE
        assert bad_q == b1.UNAVAILABLE
        assert bad_seen is None
        assert bad_requests == b1.UNAVAILABLE

        class _NoTransport:
            pass

        bad2 = b1.read_pool_census_sample(_NoTransport())  # type: ignore[arg-type]
        assert bad2 == (b1.UNAVAILABLE, b1.UNAVAILABLE, None, b1.UNAVAILABLE)
    finally:
        release.set()
        if not client.is_closed:
            await client.aclose()
        server.close()
        await server.wait_closed()


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


def _b1_gateway_warning_count(log_path: Path, prefix_bytes: int) -> int:
    """Count complete warning lines only in the saved spawn-to-window prefix."""
    count = 0
    pending = b""
    with log_path.open("rb") as reader:
        remaining = prefix_bytes
        while remaining:
            chunk = reader.read(min(65536, remaining))
            if not chunk:
                raise RuntimeError(f"gateway log shortened before snapshot read: {log_path}")
            remaining -= len(chunk)
            lines = (pending + chunk).split(b"\n")
            pending = lines.pop()
            for line in lines:
                if re.fullmatch(r"WARNING:\s+Exceeded concurrency limit\.",
                                line.decode("utf-8", errors="replace").rstrip("\r\n")):
                    count += 1
    return count


def _b1_gateway_log_tail(log_path: Path) -> str:
    tail = ""
    with log_path.open(encoding="utf-8", errors="replace", newline="") as reader:
        while chunk := reader.read(65536):
            tail = (tail + chunk)[-2000:]
    return tail


def _b1_gateway_group_alive(pgid: int) -> bool:
    """Linux reference harness: zombies have exited and cannot retain the sink."""
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
        except FileNotFoundError:
            continue  # Process exited during enumeration.
        if int(fields[2]) == pgid and fields[0] not in {"Z", "X"}:
            return True
    return False


def _b1_gateway_signal_group(pgid: int, sig: int) -> None:
    try:
        os.killpg(pgid, sig)
    except ProcessLookupError:
        pass


@contextmanager
def _b1_gateway_process(argv, *, env, log_path: Path):
    """Own the regular-file sink and the entire isolated gateway process group."""
    with log_path.open("xb") as writer:
        proc = subprocess.Popen(
            argv, env=env, stdout=writer, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            try:
                yield proc
            finally:
                if proc.poll() is None or _b1_gateway_group_alive(proc.pid):
                    _b1_gateway_signal_group(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    _b1_gateway_signal_group(proc.pid, signal.SIGKILL)
                    proc.wait(timeout=10)
                # A supervisor may exit while an inherited-output worker survives.
                if _b1_gateway_group_alive(proc.pid):
                    _b1_gateway_signal_group(proc.pid, signal.SIGKILL)
                    deadline = time.monotonic() + 10
                    while _b1_gateway_group_alive(proc.pid):
                        if time.monotonic() >= deadline:
                            raise RuntimeError(f"gateway process group {proc.pid} survived teardown")
                        time.sleep(0.01)
                if proc.poll() is None:
                    raise RuntimeError(f"gateway child {proc.pid} was not reaped")
        except Exception as exc:
            tail = _b1_gateway_log_tail(log_path)
            raise RuntimeError(f"{exc}; gateway log={log_path}; tail:\n{tail}") from exc


@pytest.fixture(scope="module")
def b1_reference_run(tmp_path_factory):
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

        env = os.environ.copy()
        env["DBAGENT_GATEWAY_CONFIG"] = cfg_path
        env["PYTHONPATH"] = os.pathsep.join(
            [
                str(_PROFILE_PATH.parent),
                str(REPO_ROOT / "services" / "gateway"),
                str(REPO_ROOT / "libs" / "py" / "rca_common"),
            ]
        )
        log_path = tmp_path_factory.mktemp("b1-gateway") / "gateway.log"
        print(f"B1 gateway log={log_path}", flush=True)
        endpoint = f"http://127.0.0.1:{port}/api/v1/events"
        health = f"http://127.0.0.1:{port}/healthz"
        try:
            with _b1_gateway_process(
                [sys.executable, str(_PROFILE_PATH), "--host", "127.0.0.1", "--port", str(port)],
                env=env, log_path=log_path,
            ) as proc:
                deadline = time.time() + 30
                while time.time() < deadline:
                    if proc.poll() is not None:
                        raise RuntimeError("gateway exited early")
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

                # FP-IG-22: wait for the classified serving tree before any CPU read.
                workers_pre: set[int]
                trackers_pre: set[int]
                trackers_pre, workers_pre = b1.wait_for_classified_workers(
                    proc.pid, workers=b1.INGEST_GATEWAY_WORKERS
                )

                warmup = _build_requests(1)[0]
                prologue = _build_requests(b1.PROLOGUE_REQUESTS)
                measured = _build_requests(b1.TOTAL_REQUESTS)
                import asyncio

                marks: dict = {}

                def _after_prologue() -> None:
                    # Snapshot AFTER unmeasured prologue so CPU/audit exclude it (C2).
                    marks["cpu_before"] = b1.tree_cpu_seconds(proc.pid)
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

                def _after_window() -> None:
                    # Close the gateway CPU interval at drain/census stop, before
                    # O(N) leg derivation. Meaning of cpu_after is unchanged: end
                    # of the measured window, not end of post-window arithmetic.
                    marks["cpu_after"] = b1.tree_cpu_seconds(proc.pid)
                    marks["log_prefix_bytes"] = log_path.stat().st_size

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
                        on_window_complete=_after_window,
                        serve_port=port,
                        worker_pids=sorted(workers_pre),
                    )
                )
                concurrency_limit_warnings = _b1_gateway_warning_count(
                    log_path, marks["log_prefix_bytes"]
                )
                cpu_after = float(marks["cpu_after"])
                trackers_post, workers_post = b1.classify_tree(proc.pid)
                shed_probe = asyncio.run(
                    b1.run_shed_probe("127.0.0.1", port)
                )
                cpu_before = float(marks.get("cpu_before", cpu_after))
                span = result.t_last_complete - result.due0
                cpu_ms = (
                    (cpu_after - cpu_before) * 1000.0 / result.served if result.served else float("inf")
                )
                cpu_cores_used = (cpu_after - cpu_before) / span if span > 0 else 0.0
                worker_set_ok = (
                    trackers_post == trackers_pre and workers_post == workers_pre
                )

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
                status_histogram = b1.serialize_status_histogram(result.status_codes)
                peak_est = result.peak_established_connections
                peak_est_str = (
                    str(peak_est) if isinstance(peak_est, int) else peak_est
                )
                peak_pool_conn = result.peak_pool_connections
                peak_pool_conn_str = (
                    str(peak_pool_conn) if isinstance(peak_pool_conn, int) else peak_pool_conn
                )
                peak_pool_q = result.peak_pool_queued
                peak_pool_q_str = (
                    str(peak_pool_q) if isinstance(peak_pool_q, int) else peak_pool_q
                )
                pool_seen = result.pool_connections_seen
                pool_seen_str = (
                    str(pool_seen) if isinstance(pool_seen, int) else pool_seen
                )
                worker_peaks = result.worker_established_peaks
                worker_peaks_str = b1.serialize_worker_established_peaks(worker_peaks)
                peak_worker_est = result.peak_worker_established
                peak_worker_est_str = (
                    str(peak_worker_est)
                    if isinstance(peak_worker_est, int)
                    else peak_worker_est
                )
                p99_leg_split_str = b1.serialize_leg_triple(result.p99_leg_split)
                leg_p99s_str = b1.serialize_leg_triple(result.leg_p99s)
                fingerprint_line = (
                    f"B1 env=cpus={fp['cpus']},cpu_model={fp['cpu_model']},image={fp['image']},"
                    f"tier=reference,workers={b1.INGEST_GATEWAY_WORKERS},"
                    f"max_lateness_ms={result.max_lateness_ms:.1f},"
                    f"p99_ms={result.p99:.1f},served_rate={result.served_rate:.1f},"
                    f"served={result.served},errors={result.errors},committed={int(committed)},"
                    f"platform_online={1 if platform_online else 0},"
                    f"workers_pre={b1.format_pid_list(workers_pre)},"
                    f"workers_post={b1.format_pid_list(workers_post)},"
                    f"median_lateness_a_ms={med_a:.1f},median_lateness_b_ms={med_b:.1f},"
                    f"lateness_drift_ms={result.lateness_drift_ms:.1f},"
                    f"cpu_ms_per_req={cpu_ms:.3f},cpu_cores_used={cpu_cores_used:.2f},"
                    f"basis_ms_per_req={basis},"
                    f"max_in_flight={result.max_in_flight},max_backlog={result.max_backlog},"
                    f"status_histogram={status_histogram},"
                    f"concurrency_limit_warnings={concurrency_limit_warnings},"
                    f"peak_established_connections={peak_est_str},"
                    f"shed_probe={shed_probe},"
                    f"peak_pool_connections={peak_pool_conn_str},"
                    f"peak_pool_requests={result.peak_pool_requests},"
                    f"peak_pool_queued={peak_pool_q_str},"
                    f"pool_connections_seen={pool_seen_str},"
                    f"worker_established_peaks={worker_peaks_str},"
                    f"peak_worker_established={peak_worker_est_str},"
                    f"p99_leg_split={p99_leg_split_str},"
                    f"leg_p99s={leg_p99s_str}"
                )
                print(fingerprint_line, flush=True)

                yield {
                    "result": result,
                    "committed": int(committed),
                    "cpu_ms_per_request": cpu_ms,
                    "cpu_cores_used": cpu_cores_used,
                    "alive": proc.poll() is None,
                    "worker_set_ok": worker_set_ok,
                    "workers_pre": workers_pre,
                    "workers_post": workers_post,
                    "fingerprint": fingerprint_line,
                    "status_histogram": status_histogram,
                    "concurrency_limit_warnings": concurrency_limit_warnings,
                    "gateway_log_path": log_path,
                    "peak_established_connections": peak_est,
                    "peak_pool_connections": peak_pool_conn,
                    "peak_pool_queued": peak_pool_q,
                    "pool_connections_seen": pool_seen,
                    "worker_established_peaks": worker_peaks,
                    "peak_worker_established": peak_worker_est,
                    "p99_leg_split": result.p99_leg_split,
                    "leg_p99s": result.leg_p99s,
                    "shed_probe": shed_probe,
                    "host": fp,
                    "platform_online": platform_online,
                    "basis_ms_per_req": basis,
                }
        finally:
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
    assert b1_reference_run["worker_set_ok"], (
        f"worker set changed or under-populated; "
        f"pre={sorted(b1_reference_run['workers_pre'])} "
        f"post={sorted(b1_reference_run['workers_post'])}"
    )


def test_measured_cpu_cost_does_not_exceed_the_recorded_sizing_basis(b1_reference_run):
    """FP-IG-18: cpu_ms_per_request <= chart basis."""
    values = yaml.safe_load(VALUES_YAML.read_text(encoding="utf-8"))
    basis = float(values["ingestGateway"]["sizingBasis"]["cpuMsPerRequest"])
    measured = b1_reference_run["cpu_ms_per_request"]
    assert measured <= basis, (
        f"cpu_ms_per_request={measured} exceeds basis={basis}; "
        f"{b1_reference_run['fingerprint']}"
    )


# ---------------------------------------------------------------------------
# UT-IG-9 / FP-IG-22 — process-tree CPU reader and classified integrity
# Against the unfixed single-pid four-field /proc read: red (grandchild burn
# is invisible; poll() is None accepts a respawned or under-populated tree).
# ---------------------------------------------------------------------------


def _spawn(src: str) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, "-c", src],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def test_cpu_accounting_sums_the_whole_process_tree():
    """FP-IG-22: tree sum sees a grandchild's burn; a single-pid read does not."""
    src = textwrap.dedent(
        """
        import os, time
        def burn():
            t = time.time() + 0.4
            x = 0
            while time.time() < t:
                x += 1
        if os.fork() == 0:
            burn()
            os._exit(0)
        time.sleep(2)
        """
    )
    proc = _spawn(src)
    try:
        time.sleep(0.15)
        single = b1.pid_cpu_seconds(proc.pid)
        tree = b1.tree_cpu_seconds(proc.pid)
        # Parent sleeps; grandchild burns. Tree must exceed the parent.
        assert tree > single + 0.05, (
            f"tree={tree:.3f}s single={single:.3f}s — unfixed single-pid "
            "reader cannot see the grandchild (UT-IG-9 discriminating pair)"
        )
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=5)


def test_worker_set_identity_changes_when_a_grandchild_is_replaced():
    """Identity: a replaced grandchild between reads changes the reported set."""
    src = textwrap.dedent(
        """
        import os, signal, time, sys
        kids = []
        for _ in range(2):
            pid = os.fork()
            if pid == 0:
                time.sleep(30)
                os._exit(0)
            kids.append(pid)
        sys.stdout.write("ready\\n")
        sys.stdout.flush()
        line = sys.stdin.readline()
        os.kill(kids[0], signal.SIGKILL)
        os.waitpid(kids[0], 0)
        pid = os.fork()
        if pid == 0:
            time.sleep(30)
            os._exit(0)
        sys.stdout.write("replaced\\n")
        sys.stdout.flush()
        time.sleep(30)
        """
    )
    proc = subprocess.Popen(
        [sys.executable, "-c", src],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        assert proc.stdout.readline().strip() == "ready"
        first = set(b1.iter_live_descendants(proc.pid))
        assert len(first) >= 2, first
        proc.stdin.write("go\n")
        proc.stdin.flush()
        assert proc.stdout.readline().strip() == "replaced"
        second = set(b1.iter_live_descendants(proc.pid))
        assert first != second, (
            f"replaced grandchild left the descendant set unchanged: {first}"
        )
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=5)


def test_cardinality_precondition_rejects_stable_underpopulated_tree():
    """A tree stable at W-1 grandchildren fails the pre-snapshot wait.

    Red only with the cardinality precondition present (errata pass 9, D3).
    """
    n = b1.INGEST_GATEWAY_WORKERS - 1
    src = textwrap.dedent(
        f"""
        import os, time
        for _ in range({n}):
            if os.fork() == 0:
                time.sleep(30)
                os._exit(0)
        time.sleep(30)
        """
    )
    proc = _spawn(src)
    try:
        time.sleep(0.2)
        try:
            b1.wait_for_classified_workers(
                proc.pid, workers=b1.INGEST_GATEWAY_WORKERS, timeout_s=0.6
            )
        except TimeoutError as exc:
            msg = str(exc)
            assert "workers" in msg
        else:
            raise AssertionError(
                "stable W-1 tree must fail the cardinality wait; "
                "pid-set equality alone would accept it"
            )
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=5)


def test_classification_rejects_tracker_shaped_helper_in_worker_count():
    """W-1 worker-shaped grandchildren + one tracker-shaped helper.

    Raw descendant count is W; classified worker count is W-1. Red only
    with cmdline classification present (errata pass 11, D1).
    """
    w = b1.INGEST_GATEWAY_WORKERS
    src = textwrap.dedent(
        f"""
        import os, sys, time
        # tracker-shaped helper
        if os.fork() == 0:
            sys.argv = ["python", "-c", "from multiprocessing.resource_tracker import main; main(0)"]
            time.sleep(30)
            os._exit(0)
        for _ in range({w - 1}):
            if os.fork() == 0:
                sys.argv = ["python", "-c", "from multiprocessing.spawn import spawn_main"]
                time.sleep(30)
                os._exit(0)
        time.sleep(30)
        """
    )
    # cmdline is what classify_tree reads, not sys.argv of the parent.
    # Rewrite: exec a dummy that puts the mark in /proc/pid/cmdline.
    src = textwrap.dedent(
        f"""
        import os, sys, time
        def child(mark):
            os.execv(sys.executable, [sys.executable, "-c",
                "import time; time.sleep(30)  # " + mark])
        if os.fork() == 0:
            child("multiprocessing.resource_tracker")
        for _ in range({w - 1}):
            if os.fork() == 0:
                child("multiprocessing.spawn")
        time.sleep(30)
        """
    )
    proc = _spawn(src)
    try:
        time.sleep(0.25)
        trackers, workers = b1.classify_tree(proc.pid)
        raw = len(b1.iter_live_descendants(proc.pid))
        assert len(trackers) == 1, trackers
        assert len(workers) == w - 1, workers
        assert raw == w, f"raw count {raw} want {w}"
        try:
            b1.wait_for_classified_workers(proc.pid, workers=w, timeout_s=0.5)
        except TimeoutError:
            pass
        else:
            raise AssertionError(
                "W-1 workers + tracker must fail classified wait; "
                "a raw count of W would accept it"
            )
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=5)


# BD: the instant acceptor runs outside the driver's event loop/process.

_E2E_PROFILE_PATH = REPO_ROOT / "tests/e2e/b1_e2e_profile.py"
_e2e_spec = importlib.util.spec_from_file_location("bd_e2e_profile", _E2E_PROFILE_PATH)
assert _e2e_spec and _e2e_spec.loader
bd_e2e = importlib.util.module_from_spec(_e2e_spec)
_sys.modules[_e2e_spec.name] = bd_e2e
_e2e_spec.loader.exec_module(bd_e2e)

_BD_SERVER = r'''
import asyncio, sys
async def main():
    stop = asyncio.Event()
    writers = set()
    tasks = set()
    async def handle(reader, writer):
        writers.add(writer)
        tasks.add(asyncio.current_task())
        try:
            while True:
                headers = await reader.readuntil(b"\r\n\r\n")
                length = next((int(line.split(b":", 1)[1]) for line in headers.split(b"\r\n") if line.lower().startswith(b"content-length:")), 0)
                await reader.readexactly(length)
                body = b'{"investigation_id":"bd"}'
                writer.write(b"HTTP/1.1 202 Accepted\r\nContent-Length: " + str(len(body)).encode() + b"\r\nContent-Type: application/json\r\n\r\n" + body)
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writers.discard(writer)
            tasks.discard(asyncio.current_task())
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass
    server = await asyncio.start_server(handle, "127.0.0.1", 0, backlog=2048)
    print(server.sockets[0].getsockname()[1], flush=True)
    asyncio.get_running_loop().add_reader(sys.stdin.fileno(), stop.set)
    await stop.wait()
    server.close()
    await server.wait_closed()
    for writer in list(writers):
        writer.close()
    for task in list(tasks):
        task.cancel()
    await asyncio.gather(*list(tasks), return_exceptions=True)
asyncio.run(main())
'''


@contextmanager
def _bd_instant_server():
    proc = subprocess.Popen(
        [sys.executable, "-u", "-c", _BD_SERVER],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert select.select([proc.stdout], [], [], 10)[0], "BD server readiness timeout"
        port = int(proc.stdout.readline())
        yield f"http://127.0.0.1:{port}/"
    finally:
        try:
            proc.communicate("stop\n", timeout=3)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate(timeout=3)
        assert proc.poll() is not None, "BD server was not reaped"


def _bd_pool_settings(pool):
    return dict(
        ssl_context=pool._ssl_context,
        max_connections=pool._max_connections,
        max_keepalive_connections=pool._max_keepalive_connections,
        keepalive_expiry=pool._keepalive_expiry,
        http1=pool._http1, http2=pool._http2, retries=pool._retries,
    )


def _bd_requests(n):
    return [(json.dumps({"event_id": f"bd-{i}"}).encode(), {}) for i in range(n)]


async def _bd_offer(driver, client, endpoint, n, *, rate=1000):
    run = driver.run_open_loop if driver is b1 else driver.run_open_loop_baseline
    return await run(
        endpoint=endpoint, requests=_bd_requests(n), rate=rate,
        max_in_flight=1000, client=client, include_sync_warmup=False, warmup=None,
    )


@pytest.mark.parametrize("driver", [b1, bd_e2e], ids=["reference", "e2e"])
@pytest.mark.asyncio
async def test_b1_pool_reserves_before_http11_activation(driver):
    arrived = asyncio.Event()
    release = asyncio.Event()

    class BarrierPool(driver.B1ReservationPool):
        armed = False
        arrivals = 0

        async def _close_connections(self, closing):
            await super()._close_connections(closing)
            if self.armed and self.arrivals < 128:
                self.arrivals += 1
                if self.arrivals == 128:
                    arrived.set()
                await release.wait()

    with _bd_instant_server() as endpoint:
        async with driver.build_httpx_client(max_connections=1000) as client:
            original = client._transport._pool
            assert not original.connections and not original._requests
            pool = BarrierPool(**_bd_pool_settings(original))
            client._transport._pool = pool
            response = await client.post(endpoint, content=b"warm")
            assert response.status_code == 202
            assert len(pool.connections) == 1 and pool.connections[0].is_idle()
            pool.armed = True
            task = asyncio.create_task(_bd_offer(driver, client, endpoint, 128))
            try:
                await asyncio.wait_for(arrived.wait(), 10)
                c, q, ids, r = b1.read_pool_census_sample(client)
                assigned = [id(req.connection) for req in pool._requests if req.connection is not None]
                print(f"BD barrier {driver.__name__}: R={r} Q={q} C={c} unique={len(set(assigned))}")
                assert (r, q, c) == (128, 0, 128)
                assert len(set(assigned)) == 128
                assert set(assigned) == ids
            finally:
                release.set()
                result = await asyncio.wait_for(task, 10)
            assert result.served == 128 and result.errors == 0
            assert not pool._requests


async def _bd_instant_measurement(driver, endpoint, n, *, rate=1000):
    async with driver.build_httpx_client(max_connections=1000) as client:
        samples = []
        task = asyncio.create_task(_bd_offer(driver, client, endpoint, n, rate=rate))
        try:
            while not task.done():
                sample = b1.read_pool_census_sample(client)
                c, q, _, r = sample
                assert isinstance(c, int) and isinstance(q, int) and isinstance(r, int)
                assert r - q <= c
                assigned = [id(req.connection) for req in client._transport._pool._requests if req.connection is not None]
                assert len(assigned) == len(set(assigned))
                samples.append(sample)
                await asyncio.sleep(0.01)
            result = await task
        finally:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        print(json.dumps({
            "driver": driver.__name__, "offered": n, "served": result.served,
            "errors": result.errors, "served_rate": result.served_rate,
            "elapsed_drain": result.t_last_complete - result.due0,
            "p99": result.p99, "max_in_flight": result.max_in_flight,
            "peak_requests": max(s[3] for s in samples),
            "peak_connections": max(s[0] for s in samples),
            "peak_queued": max(s[1] for s in samples),
        }), flush=True)
        assert result.served == n and result.errors == 0
        assert result.max_in_flight < 1000
        assert not client._transport._pool._requests
        return result


@pytest.mark.parametrize("driver", [b1, bd_e2e], ids=["reference", "e2e"])
@pytest.mark.asyncio
async def test_b1_instant_server_clears_open_loop_offer(driver):
    with _bd_instant_server() as endpoint:
        await _bd_instant_measurement(driver, endpoint, 2000)


def characterize_b1_instant_server():
    """Explicit supporting benchmark; never invoked during collection/import."""
    async def run():
        with _bd_instant_server() as endpoint:
            for driver in (b1, bd_e2e):
                await _bd_instant_measurement(driver, endpoint, 30000, rate=1000)
    asyncio.run(run())


@asynccontextmanager
async def _bd_held_body_server():
    release = asyncio.Event()
    writers = set()
    tasks = set()

    async def handler(reader, writer):
        writers.add(writer)
        tasks.add(asyncio.current_task())
        try:
            while True:
                headers = await reader.readuntil(b"\r\n\r\n")
                length = next((int(line.split(b":", 1)[1]) for line in headers.split(b"\r\n") if line.lower().startswith(b"content-length:")), 0)
                await reader.readexactly(length)
                writer.write(b"HTTP/1.1 202 Accepted\r\nContent-Length: 2\r\n\r\n")
                await writer.drain()
                await release.wait()
                writer.write(b"{}")
                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            writers.discard(writer)
            tasks.discard(asyncio.current_task())
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    server = await asyncio.start_server(handler, "127.0.0.1", 0, backlog=2048)
    try:
        yield f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}/", release
    finally:
        release.set()
        server.close()
        await server.wait_closed()
        for writer in list(writers):
            writer.close()
        remaining = list(tasks)
        for task in remaining:
            task.cancel()
        await asyncio.gather(*remaining, return_exceptions=True)


async def _bd_wait_census(client, expected):
    async with asyncio.timeout(10):
        while True:
            c, q, _, r = b1.read_pool_census_sample(client)
            if (r, q, c) == expected:
                return
            await asyncio.sleep(0.001)


@pytest.mark.parametrize("driver", [b1, bd_e2e], ids=["reference", "e2e"])
@pytest.mark.asyncio
async def test_b1_reservation_lifecycle(driver):
    async with _bd_held_body_server() as (endpoint, release):
        client = driver.build_httpx_client(max_connections=2)
        pool = client._transport._pool
        pending = []
        responses = []
        async def headers():
            response = await client.send(client.build_request("POST", endpoint, content=b"body"), stream=True)
            responses.append(response)
            return response
        try:
            first, second = await asyncio.gather(headers(), headers())
            await _bd_wait_census(client, (2, 0, 2))
            third = asyncio.create_task(headers())
            pending.append(third)
            await _bd_wait_census(client, (3, 1, 2))
            assert not third.done()
            await first.aclose()
            await asyncio.wait_for(third, 10)  # assign_to_connection must wake it.
            assert not pool._requests[0].is_queued()
            queued = asyncio.create_task(headers())
            pending.append(queued)
            await _bd_wait_census(client, (3, 1, 2))
            queued.cancel()
            with pytest.raises(asyncio.CancelledError):
                await queued
            await _bd_wait_census(client, (2, 0, 2))
            with pytest.raises(httpx.PoolTimeout):
                await client.post(endpoint, timeout=httpx.Timeout(1, pool=0.02))
            assert len(pool._requests) == 2
            await second.aclose()
            await third.result().aclose()
            assert not pool._requests

            at_body = asyncio.Event()
            async def assigned():
                async with client.stream("POST", endpoint, content=b"cancel") as response:
                    assert response.status_code == 202
                    at_body.set()
                    await response.aread()
            task = asyncio.create_task(assigned())
            pending.append(task)
            await asyncio.wait_for(at_body.wait(), 10)
            assert len(pool._requests) == 1
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert not pool._requests
            release.set()
            assert (await client.post(endpoint)).status_code == 202
            assert not pool._requests
        finally:
            release.set()
            for task in pending:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            for response in responses:
                await response.aclose()
            await client.aclose()
        assert not pool.connections and not pool._requests


@pytest.mark.parametrize("driver", [b1, bd_e2e], ids=["reference", "e2e"])
@pytest.mark.parametrize("capacity", [2, 1000])
@pytest.mark.asyncio
async def test_bd_capacity_boundaries(driver, capacity):
    async with _bd_held_body_server() as (endpoint, release):
        async with driver.build_httpx_client(max_connections=capacity) as client:
            responses = []
            tasks = []
            async def headers():
                response = await client.send(client.build_request("POST", endpoint), stream=True)
                responses.append(response)
                return response
            try:
                tasks = [asyncio.create_task(headers()) for _ in range(capacity - 1)]
                await asyncio.wait_for(asyncio.gather(*tasks), 10)
                await _bd_wait_census(client, (capacity - 1, 0, capacity - 1))
                tasks.append(asyncio.create_task(headers()))
                await asyncio.wait_for(tasks[-1], 10)
                await _bd_wait_census(client, (capacity, 0, capacity))
                tasks.append(asyncio.create_task(headers()))
                await _bd_wait_census(client, (capacity + 1, 1, capacity))
                await responses[0].aclose()
                await asyncio.wait_for(tasks[-1], 10)
            finally:
                release.set()
                for task in tasks:
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                for response in responses:
                    await response.aclose()
            assert not client._transport._pool._requests


@pytest.mark.parametrize("driver", [b1, bd_e2e], ids=["reference", "e2e"])
@pytest.mark.parametrize("capacity", [None, True, False, float("nan"), 0, -1, 1.5, "2"])
def test_bd_invalid_capacity_precedes_transport(driver, capacity, monkeypatch):
    def forbidden(**kwargs):
        pytest.fail("transport constructed before validation")
    monkeypatch.setattr(driver, "B1ReservationTransport", forbidden)
    with pytest.raises(ValueError, match="positive integer"):
        driver.build_httpx_client(max_connections=capacity)


@pytest.mark.parametrize("driver", [b1, bd_e2e], ids=["reference", "e2e"])
@pytest.mark.parametrize("failure,exception", [("connect", httpx.ConnectError), ("read", httpx.ReadError), ("unavailable", None)])
@pytest.mark.asyncio
async def test_bd_inherited_failures_release_reservations(driver, failure, exception):
    class ReadFailure(httpcore.AsyncMockStream):
        async def read(self, max_bytes, timeout=None):
            raise httpcore.ReadError("injected read failure")

    class Backend(httpcore.AsyncMockBackend):
        first = True
        async def connect_tcp(self, *args, **kwargs):
            if self.first:
                self.first = False
                if failure == "connect":
                    raise httpcore.ConnectError("injected connect failure")
                if failure == "read":
                    return ReadFailure([])
            return await super().connect_tcp(*args, **kwargs)

    class UnavailableConnection(httpcore.AsyncHTTPConnection):
        async def handle_async_request(self, request):
            self._connect_failed = True
            raise httpcore.ConnectionNotAvailable()

    class FaultPool(driver.B1ReservationPool):
        first = True
        def create_connection(self, origin):
            if failure == "unavailable" and self.first:
                self.first = False
                return UnavailableConnection(origin)
            return super().create_connection(origin)

    async with driver.build_httpx_client(max_connections=1) as client:
        pool = FaultPool(
            **_bd_pool_settings(client._transport._pool),
            network_backend=Backend([b"HTTP/1.1 202 Accepted\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"]),
        )
        client._transport._pool = pool
        if exception is not None:
            with pytest.raises(exception):
                await client.post("http://bd.invalid/")
        else:
            assert (await client.post("http://bd.invalid/")).status_code == 202
        assert not pool._requests
        assert (await client.post("http://bd.invalid/")).status_code == 202
        assert not pool._requests
    assert not pool.connections


def test_bd_assignment_and_census_parity():
    """Same ledger fixture, exact assignment/census outcomes in both copies."""
    from httpcore._async.connection_pool import AsyncPoolRequest
    from types import SimpleNamespace

    class Connection:
        def __init__(self, origin, *, closed=False, expired=False, idle=True):
            self.origin, self.closed, self.expired, self.idle = origin, closed, expired, idle
        def is_closed(self):
            return self.closed
        def has_expired(self):
            return self.expired
        def is_idle(self):
            return self.idle
        def is_available(self):
            return self.idle and not self.closed
        def can_handle_request(self, origin):
            return self.origin == origin

    def exercise(driver):
        class Pool(driver.B1ReservationPool):
            def create_connection(self, origin):
                return Connection(origin)
        origin = httpcore.URL("http://first/").origin
        pool = Pool(max_connections=2, max_keepalive_connections=2)
        a, b = Connection(origin), Connection(origin)
        pool._connections = [a, b]
        requests = [AsyncPoolRequest(httpcore.Request("GET", "http://first/")) for _ in range(3)]
        pool._requests = requests
        assert pool._assign_requests_to_connections() == []
        assert [r.connection for r in requests] == [a, b, None]
        client = SimpleNamespace(_transport=SimpleNamespace(_pool=pool))
        c, q, ids, r = b1.read_pool_census_sample(client)
        assert (c, q, r) == (2, 1, 3) and ids == {id(a), id(b)}
        # A second-origin waiter must not evict reserved idle-looking objects.
        other = AsyncPoolRequest(httpcore.Request("GET", "http://second/"))
        pool._requests = [requests[0], requests[1], other]
        assert pool._assign_requests_to_connections() == []
        assert other.connection is None and pool.connections == [a, b]
        # Removing one owner permits idle eviction for the other origin.
        pool._requests.remove(requests[0])
        assert pool._assign_requests_to_connections() == [a]
        assert other.connection.origin == other.request.url.origin
        # Closed/expired/surplus objects cannot be cleaned while reserved.
        b.closed = True
        other.connection.expired = True
        pool._max_keepalive_connections = 0
        assert pool._assign_requests_to_connections() == []
        assert len(pool.connections) == 2
        pool._requests.clear()
        assert pool._assign_requests_to_connections() == [other.connection]
        assert not pool.connections
        # Explicit unreserved expired and surplus-idle cleanup paths.
        expired, idle, active = Connection(origin, expired=True), Connection(origin), Connection(origin, idle=False)
        pool._connections = [expired, idle, active]
        assert pool._assign_requests_to_connections() == [expired, idle]
        assert pool.connections == [active]
        # A cleared assignment is freshly derived, never sticky ownership.
        pool._connections = [a := Connection(origin)]
        request = AsyncPoolRequest(httpcore.Request("GET", "http://first/"))
        request.assign_to_connection(a)
        pool._requests = [request]
        pool._max_keepalive_connections = 2
        request.clear_connection()
        assert pool._assign_requests_to_connections() == []
        assert request.connection is a
        return c, q, r, len(ids)
    assert exercise(b1) == exercise(bd_e2e) == (2, 1, 3, 2)


def test_bd_census_empty_malformed_and_same_sample_arithmetic():
    from types import SimpleNamespace
    from httpcore._async.connection_pool import AsyncPoolRequest
    def client(pool):
        return SimpleNamespace(_transport=SimpleNamespace(_pool=pool))
    empty = SimpleNamespace(connections=[], _requests=[])
    assert b1.read_pool_census_sample(client(empty)) == (0, 0, set(), 0)
    for pool in (None, SimpleNamespace(connections=[]), SimpleNamespace(connections=[], _requests=None)):
        assert b1.read_pool_census_sample(client(pool)) == (b1.UNAVAILABLE, b1.UNAVAILABLE, None, b1.UNAVAILABLE)
    connections = [object(), object()]
    requests = [AsyncPoolRequest(httpcore.Request("GET", "http://first/")) for _ in range(3)]
    for request, connection in zip(requests, connections):
        request.assign_to_connection(connection)
    samples = []
    for ledger in (requests[:2], requests):
        sample = b1.read_pool_census_sample(client(SimpleNamespace(connections=connections, _requests=ledger)))
        c, q, _, r = sample
        assert r - q <= c
        samples.append((c, q, r))
    assert samples == [(2, 0, 2), (2, 1, 3)]
    assert b1.peak_pool_metric_from_samples([b1.UNAVAILABLE, 3]) == 3
    assert b1.peak_pool_metric_from_samples([b1.UNAVAILABLE]) == b1.UNAVAILABLE


@pytest.mark.parametrize("values,expected", [([b1.UNAVAILABLE, 3], 3), ([b1.UNAVAILABLE], b1.UNAVAILABLE)])
@pytest.mark.asyncio
async def test_bd_request_peak_uses_sampler(values, expected, monkeypatch):
    samples = iter(values)
    def sample(client):
        value = next(samples, values[-1])
        return 0, 0, set(), value
    monkeypatch.setattr(b1, "read_pool_census_sample", sample)
    with _bd_instant_server() as endpoint:
        async with b1.build_httpx_client(max_connections=1000) as client:
            result = await _bd_offer(b1, client, endpoint, 250)
    assert result.peak_pool_requests == expected


@pytest.mark.parametrize("driver", [b1, bd_e2e], ids=["reference", "e2e"])
@pytest.mark.asyncio
async def test_bd_transport_effective_settings(driver):
    async with driver.build_httpx_client(max_connections=17) as client:
        assert type(client._transport) is driver.B1ReservationTransport
        pool = client._transport._pool
        assert type(pool) is driver.B1ReservationPool
        assert (pool._max_connections, pool._max_keepalive_connections, pool._keepalive_expiry) == (17, 17, 30.0)
        assert pool._http1 is True and pool._http2 is False and pool._retries == 0
        assert client.timeout.as_dict() == dict(connect=30.0, read=30.0, write=30.0, pool=30.0)
        assert not client.trust_env and not client.follow_redirects
        assert not pool.connections and not pool._requests


@pytest.mark.parametrize("quantity", [0, 3, b1.UNAVAILABLE])
def test_bd_fingerprint_request_field_renders_phase_value(quantity):
    """Execute the sole fingerprint template, then its named FP-IG-37 check."""
    tree = ast.parse(Path(__file__).read_text())
    template = next(n.value for n in ast.walk(tree) if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "fingerprint_line" for t in n.targets))
    result = b1.PhaseResult(0, 0, 0, [], 0.0, 1.0, 0.0, 5, 0,
                            peak_pool_connections=quantity,
                            peak_pool_requests=quantity,
                            peak_pool_queued=quantity,
                            pool_connections_seen=quantity)
    names = {n.id for n in ast.walk(template) if isinstance(n, ast.Name)}
    env = dict.fromkeys(names, 0)
    env.update(b1=b1, result=result, int=int, fp=dict(cpus=4, cpu_model="fixture", image="fixture"),
               workers_pre=[], workers_post=[], peak_pool_conn_str=str(quantity),
               peak_pool_q_str=str(quantity), pool_seen_str=str(quantity))
    line = eval(compile(ast.Expression(template), str(__file__), "eval"), env)
    assert f",peak_pool_connections={quantity},peak_pool_requests={quantity},peak_pool_queued={quantity}," in line
    test_b1_fingerprint_line_locates_the_in_flight_population({"fingerprint": line, "result": result})


@pytest.mark.parametrize("driver", [b1, bd_e2e], ids=["reference", "e2e"])
@pytest.mark.asyncio
async def test_bd_expired_idle_connection_is_replaced(driver):
    with _bd_instant_server() as endpoint:
        async with driver.build_httpx_client(max_connections=1) as client:
            settings = _bd_pool_settings(client._transport._pool)
            settings["keepalive_expiry"] = 0
            pool = driver.B1ReservationPool(**settings)
            client._transport._pool = pool
            response = await client.send(client.build_request("POST", endpoint), stream=True)
            connection = pool.connections[0]
            await response.aread()
            # Inherited stream close reassigns and expires the now-unowned idle object.
            assert connection.is_closed() and not pool._requests
            assert (await client.post(endpoint)).status_code == 202
            assert not pool._requests


if __name__ == "__main__":
    if sys.argv[1:] != ["--characterize-b1-client"]:
        raise SystemExit("usage: test_b1_ingest_burst.py --characterize-b1-client")
    characterize_b1_instant_server()


@pytest.mark.parametrize("payload_length", [65535, 65536, 65537, 2097152])
def test_b1_gateway_output_is_retained_without_pipe_backpressure(tmp_path, payload_length):
    log_path = tmp_path / "gateway.log"
    sentinel = tmp_path / "complete"
    marker = b"\nSTDERR-TAIL\n"
    script = (
        "import pathlib,sys; "
        f"sys.stdout.buffer.write(b'x'*{payload_length}); sys.stdout.flush(); "
        f"sys.stderr.buffer.write({marker!r}); sys.stderr.flush(); "
        f"pathlib.Path({str(sentinel)!r}).touch()"
    )
    with _b1_gateway_process([sys.executable, "-c", script],
                             env=os.environ.copy(), log_path=log_path) as proc:
        try:
            proc.wait(timeout=10)
            assert sentinel.exists()
            assert proc.returncode == 0
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)
    assert log_path.read_bytes() == b"x" * payload_length + marker


def test_b1_gateway_log_prefix_count_and_diagnostic_tail(tmp_path):
    log_path = tmp_path / "gateway.log"
    warning = b"WARNING:  Exceeded concurrency limit.\n"
    with _b1_gateway_process([sys.executable, "-c", "pass"],
                             env=os.environ.copy(), log_path=log_path) as proc:
        proc.wait(timeout=10)
        assert _b1_gateway_warning_count(log_path, 0) == 0
        assert _b1_gateway_log_tail(log_path) == ""
        # Independent append descriptor models the child's shared writer offset.
        with log_path.open("ab", buffering=0) as child_writer:
            child_writer.write(b"INITIAL\n" + warning)
            assert _b1_gateway_warning_count(log_path, log_path.stat().st_size) == 1
            child_writer.write(warning + b"unrelated Exceeded concurrency limit.\n" + warning[:-1])
            prefix = log_path.stat().st_size
            assert _b1_gateway_warning_count(log_path, prefix) == 2
            before = log_path.read_bytes()
            offset = child_writer.tell()
            _b1_gateway_log_tail(log_path)
            assert child_writer.tell() == offset
            child_writer.write(b"\n" + warning + b"\xffTAIL")
            assert _b1_gateway_warning_count(log_path, prefix) == 2
            assert _b1_gateway_warning_count(log_path, log_path.stat().st_size) == 4
            assert log_path.read_bytes().startswith(before)
            assert "\ufffdTAIL" in _b1_gateway_log_tail(log_path)
    for length in (1999, 2000, 2001):
        path = tmp_path / str(length)
        payload = "\u00e9" * length
        path.write_text(payload)
        assert _b1_gateway_log_tail(path) == payload[-2000:]
        assert path.read_text() == payload
    with pytest.raises(OSError):
        _b1_gateway_warning_count(tmp_path / "missing", 0)
    with pytest.raises(OSError):
        _b1_gateway_warning_count(tmp_path, 0)
    with pytest.raises(RuntimeError, match="shortened"):
        _b1_gateway_warning_count(log_path, log_path.stat().st_size + 1)

    # Keep the child's non-O_APPEND writer alive across the diagnostic read.
    # Seeking that shared descriptor would overwrite the initial output.
    live_log = tmp_path / "live.log"
    ready, resume = tmp_path / "ready", tmp_path / "resume"
    initial = b"INITIAL-MARKER\n" + b"x" * 70000 + b"\xff\n" + warning
    script = textwrap.dedent(f"""
        import pathlib, sys, time
        sys.stdout.buffer.write({initial!r})
        sys.stdout.flush()
        pathlib.Path({str(ready)!r}).touch()
        while not pathlib.Path({str(resume)!r}).exists(): time.sleep(0.01)
        sys.stdout.buffer.write(b'APPENDED-TAIL')
        sys.stdout.flush()
    """)
    with _b1_gateway_process([sys.executable, "-c", script],
                             env=os.environ.copy(), log_path=live_log) as proc:
        deadline = time.monotonic() + 10
        while not ready.exists():
            assert time.monotonic() < deadline
            time.sleep(0.01)
        assert _b1_gateway_log_tail(live_log) == initial.decode(errors="replace")[-2000:]
        assert _b1_gateway_warning_count(live_log, live_log.stat().st_size) == 1
        resume.touch()
        proc.wait(timeout=10)
        assert proc.returncode == 0
    assert live_log.read_bytes() == initial + b"APPENDED-TAIL"

    boundary_log = tmp_path / "chunk-boundaries.log"
    # A UTF-8 whitespace character and warning straddle the parser's chunk boundary.
    boundary_log.write_bytes(b"x" * 65525 + b"\nWARNING:\xc2\xa0Exceeded concurrency limit.\r\n")
    assert _b1_gateway_warning_count(boundary_log, boundary_log.stat().st_size) == 1


@pytest.mark.parametrize("branch", [
    "normal", "early", "startup_timeout", "assertion", "stubborn", "constructor",
    "fake_kill", "fake_orphan", "fake_survivor", "fake_unreapable",
])
def test_b1_gateway_process_reaps_on_failure(tmp_path, monkeypatch, branch):
    log_path = tmp_path / "gateway.log"
    writers = []
    original_popen = subprocess.Popen

    def spawn(*args, **kwargs):
        writers.append(kwargs["stdout"])
        if branch == "constructor":
            raise OSError("constructor failure")
        return original_popen(*args, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", spawn)
    if branch == "constructor":
        with pytest.raises(OSError, match="constructor failure"):
            with _b1_gateway_process([], env={}, log_path=log_path):
                pytest.fail("constructor unexpectedly succeeded")
        assert writers[0].closed
        assert log_path.exists()
        return
    if branch.startswith("fake_"):
        class LifecycleFake:
            pid = 987654321
            returncode = None
            waits = 0

            def poll(self):
                return self.returncode

            def wait(self, timeout):
                self.waits += 1
                if branch == "fake_unreapable" or (branch == "fake_kill" and self.waits == 1):
                    raise subprocess.TimeoutExpired("fake", timeout)
                self.returncode = -9
                return self.returncode

        fake = LifecycleFake()
        def fake_spawn(*args, **kwargs):
            writers.append(kwargs["stdout"])
            return fake
        signals = []
        monkeypatch.setattr(subprocess, "Popen", fake_spawn)
        def send(pid, sig):
            signals.append((pid, sig))
        monkeypatch.setattr(os, "killpg", send)
        if branch in {"fake_orphan", "fake_survivor"}:
            monkeypatch.setitem(globals(), "_b1_gateway_group_alive", lambda pid: (
                branch == "fake_survivor" or (pid, signal.SIGKILL) not in signals
            ))
        if branch == "fake_survivor":
            from types import SimpleNamespace
            ticks = iter((0, 11))
            monkeypatch.setitem(globals(), "time", SimpleNamespace(monotonic=lambda: next(ticks)))
        if branch in {"fake_survivor", "fake_unreapable"}:
            with pytest.raises(RuntimeError, match="gateway log="):
                with _b1_gateway_process([], env={}, log_path=log_path):
                    pass
            assert writers[0].closed
            assert signals[-1] == (fake.pid, signal.SIGKILL)
            return
        with _b1_gateway_process([], env={}, log_path=log_path):
            pass
        if branch == "fake_orphan":
            assert fake.waits == 1 and fake.poll() == -9
            assert signals[-1] == (fake.pid, signal.SIGKILL)
            assert writers[0].closed
            return
        assert fake.waits == 2 and fake.poll() == -9
        assert signals == [(fake.pid, signal.SIGTERM), (fake.pid, signal.SIGKILL)]
        assert writers[0].closed
        return

    ready = tmp_path / "ready"
    script = "import sys; print('RETAINED-TAIL', flush=True); sys.exit(7)"
    if branch in {"startup_timeout", "assertion"}:
        script = f"import time,pathlib; print('RETAINED-TAIL',flush=True); pathlib.Path({str(ready)!r}).touch(); time.sleep(60)"
    elif branch == "stubborn":
        script = textwrap.dedent(f"""
            import os, signal, time, pathlib
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            child = os.fork()
            if child == 0:
                while True: time.sleep(1)
            print('RETAINED-TAIL', flush=True)
            pathlib.Path({str(ready)!r}).write_text(str(child))
            while True: time.sleep(1)
        """)
    elif branch == "normal":
        script = "print('RETAINED-TAIL', flush=True)"

    def exercise():
        with _b1_gateway_process([sys.executable, "-c", script],
                                 env=os.environ.copy(), log_path=log_path) as proc:
            processes.append(proc)
            if branch in {"normal", "early"}:
                proc.wait(timeout=10)
                if branch == "early":
                    raise RuntimeError("gateway exited early")
            else:
                deadline = time.monotonic() + 10
                while not ready.exists():
                    assert time.monotonic() < deadline, "child did not become ready"
                    time.sleep(0.01)
                assert _b1_gateway_group_alive(proc.pid)
                if branch == "startup_timeout":
                    raise RuntimeError("gateway never became healthy")
                if branch == "assertion":
                    raise AssertionError("fixture assertion")
    processes = []
    try:
        if branch in {"early", "startup_timeout", "assertion"}:
            with pytest.raises(RuntimeError, match="RETAINED-TAIL") as error:
                exercise()
            assert str(log_path) in str(error.value)
            assert isinstance(error.value.__cause__, (RuntimeError, AssertionError))
        else:
            exercise()
        assert processes[0].poll() is not None
        assert not _b1_gateway_group_alive(processes[0].pid)
        assert writers[0].closed
        assert b"RETAINED-TAIL" in log_path.read_bytes()
    finally:
        for proc in processes:
            _b1_gateway_signal_group(proc.pid, signal.SIGKILL)
            proc.wait(timeout=10)
        deadline = time.monotonic() + 10
        while any(_b1_gateway_group_alive(p.pid) for p in processes):
            assert time.monotonic() < deadline, "test left live group members"
            time.sleep(0.01)


def test_b1_fingerprint_line_reports_scoped_concurrency_warnings(tmp_path, monkeypatch):
    """Execute the fixture's actual callback, serialization and yielded mapping."""
    from types import SimpleNamespace

    tree = ast.parse(Path(__file__).read_text())
    fixture = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "b1_reference_run")
    callback = next(n for n in ast.walk(fixture) if isinstance(n, ast.FunctionDef) and n.name == "_after_window")
    warning = b"WARNING:  Exceeded concurrency limit.\n"
    log_path = tmp_path / "gateway.log"
    log_path.write_bytes(warning * 2)
    marks = {}
    def cpu(pid):
        assert "log_prefix_bytes" not in marks
        return 1.0
    monkeypatch.setattr(b1, "tree_cpu_seconds", cpu)
    namespace = {"b1": b1, "marks": marks, "proc": SimpleNamespace(pid=1, poll=lambda: None), "log_path": log_path}
    exec(compile(ast.Module(body=[callback], type_ignores=[]), "fixture-callback", "exec"), namespace)
    namespace["_after_window"]()
    assert marks["cpu_after"] == 1.0
    with log_path.open("ab") as output:
        output.write(warning * 2)  # Later shed-probe phase must not enter the prefix.
    count_assignment = next(n for n in ast.walk(fixture) if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "concurrency_limit_warnings" for t in n.targets))
    namespace["_b1_gateway_warning_count"] = _b1_gateway_warning_count
    exec(compile(ast.Module(body=[count_assignment], type_ignores=[]), "fixture-count", "exec"), namespace)
    assert namespace["concurrency_limit_warnings"] == 2
    assert _b1_gateway_warning_count(log_path, log_path.stat().st_size) == 4
    assignment = next(n for n in ast.walk(fixture) if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "fingerprint_line" for t in n.targets))
    mapping = next(n.value for n in ast.walk(fixture) if isinstance(n, ast.Yield))
    # Supply unrelated fixture observations; execute its unchanged consumer expressions.
    names = {n.id for root in (assignment, mapping) for n in ast.walk(root) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
    for name in names - namespace.keys() - {"int", "float", "str"}:
        namespace[name] = 1
    namespace.update(fp={"cpus": 1, "cpu_model": "test", "image": "test"},
                     workers_pre={1}, workers_post={1}, status_histogram="200:3;503:1")
    attrs = {n.attr for root in (assignment, mapping) for n in ast.walk(root) if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "result"}
    namespace["result"] = SimpleNamespace(**dict.fromkeys(attrs, 1))
    exec(compile(ast.Module(body=[assignment], type_ignores=[]), "fixture-line", "exec"), namespace)
    yielded = eval(compile(ast.Expression(mapping), "fixture-mapping", "eval"), namespace)
    assert "status_histogram=200:3;503:1,concurrency_limit_warnings=2," in yielded["fingerprint"]
    assert yielded["concurrency_limit_warnings"] == 2
    assert yielded["gateway_log_path"] == log_path
    # Pin the real callback registration and its ordering before the probe.
    calls = [n for n in ast.walk(fixture) if isinstance(n, ast.Call)]
    run = next(n for n in calls if isinstance(n.func, ast.Attribute) and n.func.attr == "run_open_loop")
    assert any(k.arg == "on_window_complete" and isinstance(k.value, ast.Name) and k.value.id == "_after_window" for k in run.keywords)
    probe = next(n for n in calls if isinstance(n.func, ast.Attribute) and n.func.attr == "run_shed_probe")
    assert run.lineno < count_assignment.lineno < probe.lineno
    # A failed snapshot cannot yield a zero-valued count/fingerprint.
    log_path.unlink()
    marks.clear()
    with pytest.raises(OSError):
        namespace["_after_window"]()
    assert "log_prefix_bytes" not in marks
