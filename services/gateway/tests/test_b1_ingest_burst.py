"""FP-IG-7 / FP-IG-18 / UT-IG-5: B1 reference-tier burst measurement.

Run only from the CI ``benchmark`` job (excluded from unit-gateway/functional
via --ignore). Spawns the real gateway under uvicorn against testcontainers PG.
"""
from __future__ import annotations

import asyncio
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
    peak_pool_q_raw = _parse_b1_env_field(line, "peak_pool_queued")
    pool_seen_raw = _parse_b1_env_field(line, "pool_connections_seen")

    for raw, quantity in (
        (peak_pool_conn_raw, result.peak_pool_connections),
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
            conn, queued, _seen = b1.read_pool_census_sample(client)
            if isinstance(conn, int) and conn >= pool_size:
                break
            await asyncio.sleep(0.01)
        else:
            raise AssertionError("pool never reached held-connection plateau")

        conn, queued, seen = b1.read_pool_census_sample(client)
        assert conn == pool_size
        assert queued == 0
        assert seen is not None and len(seen) == pool_size

        extra_dispatch = 3
        extra = [
            asyncio.create_task(client.post(url, content=b"extra"))
            for _ in range(extra_dispatch)
        ]
        deadline = time.time() + 5.0
        while time.time() < deadline:
            conn_after, queued_after, _ = b1.read_pool_census_sample(client)
            if isinstance(queued_after, int) and queued_after == extra_dispatch:
                break
            await asyncio.sleep(0.01)
        else:
            raise AssertionError(
                f"queued never reached {extra_dispatch} (last={queued_after!r})"
            )
        assert conn_after == pool_size
        assert queued_after == extra_dispatch

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
                    _c, _q, seen_i = b1.read_pool_census_sample(churn_client)
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

        bad_conn, bad_q, bad_seen = b1.read_pool_census_sample(_NoPool())  # type: ignore[arg-type]
        assert bad_conn == b1.UNAVAILABLE
        assert bad_q == b1.UNAVAILABLE
        assert bad_seen is None

        class _NoTransport:
            pass

        bad2 = b1.read_pool_census_sample(_NoTransport())  # type: ignore[arg-type]
        assert bad2 == (b1.UNAVAILABLE, b1.UNAVAILABLE, None)
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

        env = os.environ.copy()
        env["DBAGENT_GATEWAY_CONFIG"] = cfg_path
        env["PYTHONPATH"] = os.pathsep.join(
            [
                str(_PROFILE_PATH.parent),
                str(REPO_ROOT / "services" / "gateway"),
                str(REPO_ROOT / "libs" / "py" / "rca_common"),
            ]
        )
        proc = subprocess.Popen(
            [sys.executable, str(_PROFILE_PATH), "--host", "127.0.0.1", "--port", str(port)],
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
                    serve_port=port,
                    worker_pids=sorted(workers_pre),
                )
            )
            cpu_after = b1.tree_cpu_seconds(proc.pid)
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
                f"peak_established_connections={peak_est_str},"
                f"shed_probe={shed_probe},"
                f"peak_pool_connections={peak_pool_conn_str},"
                f"peak_pool_queued={peak_pool_q_str},"
                f"pool_connections_seen={pool_seen_str},"
                f"worker_established_peaks={worker_peaks_str},"
                f"peak_worker_established={peak_worker_est_str}"
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
                "peak_established_connections": peak_est,
                "peak_pool_connections": peak_pool_conn,
                "peak_pool_queued": peak_pool_q,
                "pool_connections_seen": pool_seen,
                "worker_established_peaks": worker_peaks,
                "peak_worker_established": peak_worker_est,
                "shed_probe": shed_probe,
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
