"""B1 reference-tier open-loop generator and oracle (design.md §11.3.3 H/Q).

Not collected by pytest (name does not match python_files). Loaded by explicit
path from delivery tests and by the benchmark module.
"""
from __future__ import annotations

import asyncio
import json
import math
import os
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Protocol
from urllib.parse import urlsplit

# Profile constants — each bound exactly once at module scope (FP-IG-13).
BURST_RATE = 1000
BURST_SECONDS = 30
TOTAL_REQUESTS = BURST_RATE * BURST_SECONDS  # 30000
BASE_RATE = 200
P99_MS = 150.0
SUSTAINED_FLOOR = 200
MAX_IN_FLIGHT = BURST_RATE  # one second of offered load
PROLOGUE_REQUESTS = int(BURST_RATE * P99_MS / 1000)  # 150
KEEPALIVE_EXPIRY = float(BURST_SECONDS)
CLIENT_TIMEOUT = float(BURST_SECONDS)
INGEST_GATEWAY_WORKERS = 4
TRACKER_CMDLINE_MARK = "multiprocessing.resource_tracker"
WORKER_CMDLINE_MARK = "multiprocessing.spawn"

# Post-window shed probe slack (FP-IG-36 / §11.3.3 AK). Absorbs connect losses;
# never load-bearing — the pigeonhole minimum alone forces a shed.
PROBE_SLACK = 8
# Shipped probe size: INGEST_GATEWAY_WORKERS × (ceiling − 1) + 1 + PROBE_SLACK
# → 4 × 149 + 1 + 8 = 605; pigeonhole minimum 597.
UNAVAILABLE = "unavailable"

# Float-identity tolerance from double-precision ulps at the magnitudes
# involved, never a behavioural allowance. Binds PhaseResult's own vectors
# and LV-1's full-precision JSON; never values parsed back from the
# fingerprint line.
LEG_SUM_TOLERANCE_MS = 1e-6
# Formatting-quantization bound, never a behavioural allowance: the two
# pinned format widths' half-ulps plus the raw-vector tolerance. Three
# :.3f legs contribute 3*(10**-3)/2; the :.1f p99_ms contributes
# (10**-1)/2. An expression over the widths, never a re-typed literal.
LEG_LINE_TOLERANCE_MS = (
    3 * (10**-3) / 2 + (10**-1) / 2 + LEG_SUM_TOLERANCE_MS
)


class Transport(Protocol):
    async def post(
        self, url: str, *, content: bytes, headers: dict[str, str]
    ) -> tuple[int, bytes | None, BaseException | None]:
        """Return (status_code, body_or_None, error_or_None)."""


def classify_response(
    status_code: int | None,
    body: bytes | None = None,
    error: BaseException | None = None,
) -> str:
    """Classify a response as 'served' or 'error' (FP-IG-8).

    served ⟺ HTTP 202, or HTTP 200 with body status == "merged".
    error ⟺ not served (exhaustive).
    """
    if error is not None or status_code is None:
        return "error"
    if status_code == 202:
        return "served"
    if status_code == 200:
        if body is None:
            return "error"
        try:
            parsed = json.loads(body)
        except (TypeError, ValueError, json.JSONDecodeError):
            return "error"
        if isinstance(parsed, dict) and parsed.get("status") == "merged":
            return "served"
        return "error"
    return "error"


def is_served(
    status_code: int | None,
    body: bytes | None = None,
    error: BaseException | None = None,
) -> bool:
    return classify_response(status_code, body, error) == "served"


def nearest_rank_p99(samples: list[float]) -> float:
    """Nearest-rank 99th percentile: sorted[ceil(0.99 × N) − 1]."""
    if not samples:
        return float("inf")
    ordered = sorted(samples)
    idx = max(0, math.ceil(0.99 * len(ordered)) - 1)
    return ordered[min(idx, len(ordered) - 1)]


def p99_index_of(latencies: list[float]) -> int | None:
    """Smallest request index whose lateness equals the nearest-rank p99."""
    if not latencies:
        return None
    target = nearest_rank_p99(latencies)
    for i, value in enumerate(latencies):
        if value == target:
            return i
    return None


def p99_leg_split_of(
    latencies: list[float],
    pre_dispatch_slip_ms: list[float],
    start_lag_ms: list[float],
    attempt_duration_ms: list[float],
) -> tuple[float, float, float]:
    """Identity-aligned triple of the p99-index request (FP-IG-39)."""
    idx = p99_index_of(latencies)
    if (
        idx is None
        or idx >= len(pre_dispatch_slip_ms)
        or idx >= len(start_lag_ms)
        or idx >= len(attempt_duration_ms)
    ):
        inf = float("inf")
        return (inf, inf, inf)
    return (
        pre_dispatch_slip_ms[idx],
        start_lag_ms[idx],
        attempt_duration_ms[idx],
    )


def leg_p99s_of(
    pre_dispatch_slip_ms: list[float],
    start_lag_ms: list[float],
    attempt_duration_ms: list[float],
) -> tuple[float, float, float]:
    """Three separate nearest-rank p99s; never a decomposition."""
    return (
        nearest_rank_p99(pre_dispatch_slip_ms),
        nearest_rank_p99(start_lag_ms),
        nearest_rank_p99(attempt_duration_ms),
    )


def serialize_leg_triple(values: tuple[float, float, float]) -> str:
    """Pinned :.3f triple for p99_leg_split / leg_p99s (FP-IG-39)."""
    a, b, c = values
    return f"{a:.3f}/{b:.3f}/{c:.3f}"


def derive_leg_vectors(
    latencies_ms: list[float],
    dispatch_at: list[float],
    attempt_at: list[float],
    *,
    due0: float,
    rate: float,
) -> tuple[list[float], list[float], list[float]]:
    """Post-window three-leg derivation (FP-IG-39). Called only after the
    measurement window is closed — never inside a recorded CPU interval.
    """
    n = len(latencies_ms)
    pre_dispatch_slip_ms = [0.0] * n
    start_lag_ms = [0.0] * n
    attempt_duration_ms = [0.0] * n
    for i in range(n):
        due_i = due0 + i / rate
        pre_dispatch_slip_ms[i] = (dispatch_at[i] - due_i) * 1000.0
        start_lag_ms[i] = (attempt_at[i] - dispatch_at[i]) * 1000.0
        # t_resp lives in latencies[i] = (t_resp - due_i) * 1000; no third store.
        attempt_duration_ms[i] = latencies_ms[i] - (attempt_at[i] - due_i) * 1000.0
    return pre_dispatch_slip_ms, start_lag_ms, attempt_duration_ms


def half_window_medians(latencies: list[float]) -> tuple[float, float]:
    n = len(latencies)
    if n == 0:
        return float("inf"), float("inf")
    mid = n // 2
    a = sorted(latencies[:mid]) if mid else []
    b = sorted(latencies[mid:]) if n - mid else []

    def _med(xs: list[float]) -> float:
        if not xs:
            return float("inf")
        return xs[len(xs) // 2]

    return _med(a), _med(b)


@dataclass
class PhaseResult:
    offered: int
    served: int
    errors: int
    latencies_ms: list[float]
    t0: float
    t_last_complete: float
    due0: float
    max_in_flight: int
    max_backlog: int
    status_codes: list[int] = field(default_factory=list)
    peak_established_connections: int | str = UNAVAILABLE
    peak_pool_connections: int | str = UNAVAILABLE
    peak_pool_requests: int | str = UNAVAILABLE
    peak_pool_queued: int | str = UNAVAILABLE
    pool_connections_seen: int | str = UNAVAILABLE
    worker_established_peaks: list[int | str] = field(default_factory=list)
    peak_worker_established: int | str = UNAVAILABLE
    pre_dispatch_slip_ms: list[float] = field(default_factory=list)
    start_lag_ms: list[float] = field(default_factory=list)
    attempt_duration_ms: list[float] = field(default_factory=list)

    @property
    def p99(self) -> float:
        return nearest_rank_p99(self.latencies_ms)

    @property
    def p99_index(self) -> int | None:
        return p99_index_of(self.latencies_ms)

    @property
    def p99_leg_split(self) -> tuple[float, float, float]:
        return p99_leg_split_of(
            self.latencies_ms,
            self.pre_dispatch_slip_ms,
            self.start_lag_ms,
            self.attempt_duration_ms,
        )

    @property
    def leg_p99s(self) -> tuple[float, float, float]:
        return leg_p99s_of(
            self.pre_dispatch_slip_ms,
            self.start_lag_ms,
            self.attempt_duration_ms,
        )

    @property
    def served_rate(self) -> float:
        span = self.t_last_complete - self.due0
        if span <= 0:
            return 0.0
        return self.served / span

    @property
    def max_lateness_ms(self) -> float:
        return max(self.latencies_ms) if self.latencies_ms else 0.0

    @property
    def lateness_drift_ms(self) -> float:
        a, b = half_window_medians(self.latencies_ms)
        if math.isinf(a) or math.isinf(b):
            return float("inf")
        return b - a


def serialize_status_histogram(status_codes: list[int]) -> str:
    """Serialize status_codes as sorted code:count pairs (FP-IG-35)."""
    counts: dict[int, int] = {}
    for code in status_codes:
        counts[code] = counts.get(code, 0) + 1
    return ";".join(f"{code}:{counts[code]}" for code in sorted(counts))


def _remote_port_from_proc_address(address: str) -> int | None:
    if ":" not in address:
        return None
    port_hex = address.rsplit(":", 1)[-1]
    try:
        return int(port_hex, 16)
    except ValueError:
        return None


def _local_port_from_proc_address(address: str) -> int | None:
    if ":" not in address:
        return None
    port_hex = address.rsplit(":", 1)[-1]
    try:
        return int(port_hex, 16)
    except ValueError:
        return None


def _inode_from_socket_link(target: str) -> int | None:
    if not target.startswith("socket:[") or not target.endswith("]"):
        return None
    inner = target[len("socket:[") : -1]
    try:
        return int(inner)
    except ValueError:
        return None


def established_serve_port_inodes_from_proc_content(
    content: str, serve_port: int, *, server_side: bool = True
) -> set[int]:
    """Inodes of ESTABLISHED rows on serve_port (server-side: local port match)."""
    inodes: set[int] = set()
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.lower().startswith("sl"):
            continue
        parts = stripped.split()
        if len(parts) < 10:
            raise ValueError("malformed proc row")
        local_address = parts[1]
        state = parts[3]
        if state != "01":
            continue
        if server_side:
            port = _local_port_from_proc_address(local_address)
        else:
            port = _remote_port_from_proc_address(parts[2])
        if port != serve_port:
            continue
        try:
            inodes.add(int(parts[9]))
        except ValueError as exc:
            raise ValueError("malformed proc row") from exc
    return inodes


def read_proc_net_tcp_tables(
    *,
    tcp_path: Path | None = None,
    tcp6_path: Path | None = None,
) -> tuple[str, str] | str:
    """Read /proc/net/tcp and /proc/net/tcp6 once; unavailable on any OSError."""
    tcp_path = tcp_path or Path("/proc/net/tcp")
    tcp6_path = tcp6_path or Path("/proc/net/tcp6")
    try:
        return (
            tcp_path.read_text(encoding="utf-8"),
            tcp6_path.read_text(encoding="utf-8"),
        )
    except OSError:
        return UNAVAILABLE


def established_serve_port_inodes_from_proc_tables(
    tcp_text: str, tcp6_text: str, serve_port: int
) -> set[int] | str:
    """Server-side ESTABLISHED inodes from pre-read /proc/net/tcp[6] content."""
    try:
        inodes = established_serve_port_inodes_from_proc_content(
            tcp_text, serve_port
        )
        inodes |= established_serve_port_inodes_from_proc_content(
            tcp6_text, serve_port
        )
        return inodes
    except ValueError:
        return UNAVAILABLE


def established_serve_port_inodes(
    serve_port: int,
    *,
    tcp_path: Path | None = None,
    tcp6_path: Path | None = None,
) -> set[int] | str:
    """Server-side ESTABLISHED inodes on serve_port from /proc/net/tcp[6]."""
    tables = read_proc_net_tcp_tables(tcp_path=tcp_path, tcp6_path=tcp6_path)
    if tables == UNAVAILABLE:
        return UNAVAILABLE
    tcp_text, tcp6_text = tables
    return established_serve_port_inodes_from_proc_tables(
        tcp_text, tcp6_text, serve_port
    )


def count_worker_established_from_inodes(
    pid: int,
    inodes: set[int] | str,
    *,
    fd_dir: Path | None = None,
) -> int | str:
    """Per-pid fd walk against a pre-built serve-port inode set (FP-IG-38)."""
    if inodes == UNAVAILABLE:
        return UNAVAILABLE
    assert isinstance(inodes, set)
    proc_fd = fd_dir or Path(f"/proc/{pid}/fd")
    try:
        entries = list(proc_fd.iterdir())
    except OSError:
        return UNAVAILABLE
    matched = 0
    for entry in entries:
        try:
            target = os.readlink(entry)
        except OSError:
            continue
        inode = _inode_from_socket_link(target)
        if inode is not None and inode in inodes:
            matched += 1
    return matched


def count_worker_established_to_serve_port(
    pid: int,
    serve_port: int,
    *,
    tcp_path: Path | None = None,
    tcp6_path: Path | None = None,
    fd_dir: Path | None = None,
) -> int | str:
    """Per-pid server-side ESTABLISHED census via /proc/<pid>/fd join (FP-IG-38)."""
    inodes = established_serve_port_inodes(
        serve_port, tcp_path=tcp_path, tcp6_path=tcp6_path
    )
    return count_worker_established_from_inodes(pid, inodes, fd_dir=fd_dir)


def count_per_worker_established_to_serve_port(
    worker_pids: list[int],
    serve_port: int,
    *,
    tcp_path: Path | None = None,
    tcp6_path: Path | None = None,
    tcp_text: str | None = None,
    tcp6_text: str | None = None,
    fd_dir_for_pid: Callable[[int], Path] | None = None,
) -> list[int | str]:
    """One census sample per worker pid, in the given pid order."""
    if tcp_text is not None and tcp6_text is not None:
        inodes = established_serve_port_inodes_from_proc_tables(
            tcp_text, tcp6_text, serve_port
        )
    else:
        inodes = established_serve_port_inodes(
            serve_port, tcp_path=tcp_path, tcp6_path=tcp6_path
        )
    out: list[int | str] = []
    for pid in worker_pids:
        fd_dir = fd_dir_for_pid(pid) if fd_dir_for_pid is not None else None
        out.append(
            count_worker_established_from_inodes(pid, inodes, fd_dir=fd_dir)
        )
    return out


def serialize_worker_established_peaks(peaks: list[int | str]) -> str:
    """Plus-join per-worker peaks; unavailable if any entry is unavailable."""
    if not peaks:
        return UNAVAILABLE
    if any(not isinstance(p, int) for p in peaks):
        return UNAVAILABLE
    return "+".join(str(p) for p in peaks)


def peak_worker_established_from_peaks(peaks: list[int | str]) -> int | str:
    """Maximum of per-worker peaks; unavailable when any peak failed (FP-IG-38)."""
    if not peaks:
        return UNAVAILABLE
    if any(not isinstance(p, int) for p in peaks):
        return UNAVAILABLE
    return max(peaks)


def worker_established_peaks_from_samples(
    samples: list[list[int | str]],
) -> list[int | str]:
    """Per-worker peak across census ticks."""
    if not samples:
        return []
    n_workers = len(samples[0])
    peaks: list[int | str] = []
    for idx in range(n_workers):
        worker_samples = [row[idx] for row in samples if len(row) > idx]
        peaks.append(peak_established_from_samples(worker_samples))
    return peaks


def count_established_in_proc_content(content: str, serve_port: int) -> int:
    """Count ESTABLISHED (st 01) rows whose remote port matches serve_port."""
    total = 0
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.lower().startswith("sl"):
            continue
        parts = stripped.split()
        if len(parts) < 4:
            raise ValueError("malformed proc row")
        rem_address = parts[2]
        state = parts[3]
        if state != "01":
            continue
        remote_port = _remote_port_from_proc_address(rem_address)
        if remote_port == serve_port:
            total += 1
    return total


def count_established_from_proc_tables(
    tcp_text: str, tcp6_text: str, serve_port: int
) -> int | str:
    """Aggregate ESTABLISHED census from pre-read /proc/net/tcp[6] content."""
    try:
        return count_established_in_proc_content(
            tcp_text, serve_port
        ) + count_established_in_proc_content(tcp6_text, serve_port)
    except ValueError:
        return UNAVAILABLE


def count_established_to_serve_port(
    serve_port: int,
    *,
    tcp_path: Path | None = None,
    tcp6_path: Path | None = None,
    tcp_text: str | None = None,
    tcp6_text: str | None = None,
) -> int | str:
    """Kernel ESTABLISHED census toward serve_port via /proc file reads (FP-IG-35)."""
    if tcp_text is not None and tcp6_text is not None:
        return count_established_from_proc_tables(tcp_text, tcp6_text, serve_port)
    tables = read_proc_net_tcp_tables(tcp_path=tcp_path, tcp6_path=tcp6_path)
    if tables == UNAVAILABLE:
        return UNAVAILABLE
    tcp_text, tcp6_text = tables
    return count_established_from_proc_tables(tcp_text, tcp6_text, serve_port)


def peak_established_from_samples(samples: list[int | str]) -> int | str:
    """Peak census sample; unavailable when every sample failed (UT-IG-15)."""
    numeric = [s for s in samples if isinstance(s, int)]
    if not numeric:
        return UNAVAILABLE
    return max(numeric)


def pool_census_from_snapshot(
    snapshot: Any,
) -> tuple[int | str, int | str, set[int] | None, int | str]:
    """Map one immutable pool snapshot to the historical census four-tuple.

    Pure, so every consumer of a tick (run_open_loop, the instant-server
    helper, scripted tests) reads the *same* observation rather than taking
    two snapshots and comparing different ticks (FP-IG-37 / FP-B1DF-5).
    Missing or malformed snapshot support degrades to ``unavailable``; a
    readable empty pool stays numeric zero.
    """
    try:
        return (
            snapshot.held_connections,
            snapshot.queued_requests,
            set(snapshot.connection_identities),
            snapshot.requests,
        )
    except (AttributeError, TypeError):
        return UNAVAILABLE, UNAVAILABLE, None, UNAVAILABLE


def read_pool_census_sample(
    client: B1RawHttp11Client | None,
) -> tuple[int | str, int | str, set[int] | None, int | str]:
    """Read one client-pool census sample (FP-IG-37 / UT-IG-17).

    Returns (held_connections, queued_requests, connection_identities, requests).
    Every attribute failure degrades to ``unavailable`` (fail-open recording).
    """
    try:
        snapshot = client.pool_snapshot()
    except (AttributeError, TypeError):
        return UNAVAILABLE, UNAVAILABLE, None, UNAVAILABLE
    return pool_census_from_snapshot(snapshot)


def peak_pool_metric_from_samples(samples: list[int | str]) -> int | str:
    """Peak of pool census samples; unavailable when every sample failed."""
    return peak_established_from_samples(samples)


def pool_connections_seen_from_identity_sets(identity_sets: list[set[int]]) -> int | str:
    """Cardinality of the union of connection identities across samples."""
    if not identity_sets:
        return UNAVAILABLE
    union: set[int] = set()
    for identities in identity_sets:
        union.update(identities)
    return len(union)


def pigeonhole_minimum(*, workers: int, ceiling_per_worker: int) -> int:
    """Minimum held sockets that force at least one worker to its ceiling."""
    return workers * (ceiling_per_worker - 1) + 1


def probe_connection_count(
    *,
    workers: int,
    ceiling_per_worker: int,
    slack: int = PROBE_SLACK,
) -> int:
    """Probe socket count: pigeonhole minimum + slack (FP-IG-36)."""
    return pigeonhole_minimum(workers=workers, ceiling_per_worker=ceiling_per_worker) + slack


def classify_shed_probe_outcome(
    socket_results: list[tuple[int | None, bool]],
    *,
    established_count: int,
    pigeonhole_minimum_count: int,
) -> str:
    """Classify post-window shed probe results (UT-IG-16 / FP-IG-36)."""
    if established_count < pigeonhole_minimum_count:
        return UNAVAILABLE
    statuses = [code for code, _timed_out in socket_results if code is not None]
    has_503 = any(code == 503 for code in statuses)
    if has_503:
        return "fired"
    has_timeout = any(timed_out for _code, timed_out in socket_results)
    if has_timeout:
        return "timeout"
    if statuses and len(statuses) == len(socket_results):
        return "absent"
    return UNAVAILABLE


def _parse_http_status_from_bytes(data: bytes) -> int | None:
    if not data:
        return None
    first = data.split(b"\r\n", 1)[0]
    parts = first.split()
    if len(parts) < 2:
        return None
    try:
        return int(parts[1])
    except ValueError:
        return None


async def run_shed_probe(
    host: str,
    port: int,
    *,
    workers: int = INGEST_GATEWAY_WORKERS,
    ceiling_per_worker: int | None = None,
    path: str = "/healthz",
) -> str:
    """Post-window enforcement witness (FP-IG-36). Raw asyncio sockets only."""
    from gateway.main import DEFAULT_MAX_CONNECTIONS_PER_WORKER

    if ceiling_per_worker is None:
        ceiling_per_worker = DEFAULT_MAX_CONNECTIONS_PER_WORKER
    min_established = pigeonhole_minimum(
        workers=workers, ceiling_per_worker=ceiling_per_worker
    )
    target = probe_connection_count(
        workers=workers, ceiling_per_worker=ceiling_per_worker
    )

    readers: list[asyncio.StreamReader] = []
    writers: list[asyncio.StreamWriter] = []
    established = 0
    try:
        for _ in range(target):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=CLIENT_TIMEOUT,
                )
            except (asyncio.TimeoutError, OSError):
                continue
            readers.append(reader)
            writers.append(writer)
            established += 1

        if established < min_established:
            return UNAVAILABLE

        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Connection: keep-alive\r\n"
            "\r\n"
        ).encode("ascii")

        async def _one_probe(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> tuple[int | None, bool]:
            timed_out = False
            status: int | None = None
            try:
                writer.write(req)
                await writer.drain()
                data = await asyncio.wait_for(reader.read(4096), timeout=CLIENT_TIMEOUT)
                status = _parse_http_status_from_bytes(data)
            except asyncio.TimeoutError:
                timed_out = True
            except OSError:
                pass
            return status, timed_out

        results = await asyncio.gather(
            *(_one_probe(r, w) for r, w in zip(readers, writers))
        )
        results_list = list(results)

        return classify_shed_probe_outcome(
            results_list,
            established_count=established,
            pigeonhole_minimum_count=min_established,
        )
    finally:
        for writer in writers:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass


# B1-RAW-CLIENT:BEGIN
# FP-B1DF-1/2/3 — B1's own HTTP/1.1 client. Every connection-ownership
# transition is O(1) in the connection/request population: no request-path
# helper iterates the held, idle, request or waiter collections. Work scales
# with payload bytes, never with MAX_IN_FLIGHT. The bytes between these two
# markers are identical in both driver copies — edit both, never one.
_B1_HEADER_NAME_FORBIDDEN = frozenset(' \t"(),/:;<=>?@[\\]{}\r\n\x00')
_B1_HEADER_VALUE_FORBIDDEN = frozenset("\r\n\x00")
# Framing is the client's own: a caller may not restate or contradict it.
_B1_RESERVED_HEADERS = frozenset(
    ("host", "content-length", "transfer-encoding", "connection")
)
_B1_TARGET_FORBIDDEN = frozenset(" \r\n\x00")
_B1_HEX_DIGITS = frozenset(b"0123456789abcdefABCDEF")
_B1_BODYLESS_STATUS = frozenset((204, 304))


@dataclass(frozen=True)
class B1HttpResponse:
    """The only response surface the B1 generators consume (FP-IG-8)."""

    status_code: int
    content: bytes


class B1ProtocolError(RuntimeError):
    """Malformed, conflicting or indeterminate HTTP/1.1 response framing."""


@dataclass(frozen=True)
class B1PoolSnapshot:
    """One coherent event-loop observation of the client's own ledgers."""

    held_connections: int
    queued_requests: int
    connection_identities: frozenset[int]
    assigned_connection_identities: tuple[int, ...]
    requests: int


class _B1Connection:
    """One reserved connection record, addressed by a stable connection id.

    A record exists from the moment its reservation is granted, so a record
    whose socket open is still in progress is already held and already owned.
    """

    __slots__ = ("cid", "reader", "writer", "idle_token", "expiry_handle")

    def __init__(self, cid: int) -> None:
        self.cid = cid
        self.reader = None
        self.writer = None
        self.idle_token = 0
        self.expiry_handle = None


def _b1_check_header_field(name: str, value: str) -> None:
    """Reject caller headers that could make the request framing ambiguous."""
    if not isinstance(name, str) or not isinstance(value, str):
        raise ValueError("header names and values must be str")
    if not name or _B1_HEADER_NAME_FORBIDDEN.intersection(name):
        raise ValueError(f"not a header name token: {name!r}")
    if name.lower() in _B1_RESERVED_HEADERS:
        raise ValueError(f"header {name!r} is framing the client owns")
    if _B1_HEADER_VALUE_FORBIDDEN.intersection(value):
        raise ValueError(f"header {name!r} value carries CR, LF or NUL")


def _b1_parse_head(head: bytes) -> tuple[bytes, int, list[tuple[bytes, bytes]]]:
    """Parse one response head into (version, status, lowercased headers)."""
    lines = head[:-4].split(b"\r\n")
    parts = lines[0].split(b" ", 2)
    if len(parts) < 2:
        raise B1ProtocolError(f"malformed status line: {lines[0]!r}")
    version = parts[0]
    if version not in (b"HTTP/1.1", b"HTTP/1.0"):
        raise B1ProtocolError(f"unsupported HTTP version: {version!r}")
    if not parts[1].isdigit():
        raise B1ProtocolError(f"malformed status code: {lines[0]!r}")
    status_code = int(parts[1])
    if not 100 <= status_code <= 599:
        raise B1ProtocolError(f"status code out of range: {status_code}")
    headers: list[tuple[bytes, bytes]] = []
    for line in lines[1:]:
        if not line:
            raise B1ProtocolError("empty header line before the head terminator")
        if line[:1] in (b" ", b"\t"):
            raise B1ProtocolError(f"obsolete header line folding: {line!r}")
        name, sep, value = line.partition(b":")
        if not sep or not name or name.strip() != name:
            raise B1ProtocolError(f"malformed header line: {line!r}")
        headers.append((name.lower(), value.strip()))
    return version, status_code, headers


def _b1_response_framing(
    version: bytes, status_code: int, headers: list[tuple[bytes, bytes]]
) -> tuple[str, int, bool]:
    """Decide (body mode, length, reusable) for one response head.

    Ambiguity is never resolved by preference: conflicting lengths, transfer
    coding beside a length, an unsupported coding and an unbounded body with
    no close signal are all protocol errors.
    """
    lengths: set[int] = set()
    codings: list[bytes] = []
    close = False
    keep_alive = False
    for name, value in headers:
        if name == b"content-length":
            if not value.isdigit():
                raise B1ProtocolError(f"malformed content-length: {value!r}")
            lengths.add(int(value))
        elif name == b"transfer-encoding":
            codings.extend(token.strip().lower() for token in value.split(b","))
        elif name == b"connection":
            for token in value.split(b","):
                token = token.strip().lower()
                if token == b"close":
                    close = True
                elif token == b"keep-alive":
                    keep_alive = True
    if len(lengths) > 1:
        raise B1ProtocolError(f"conflicting content-length values: {sorted(lengths)}")
    if codings and lengths:
        raise B1ProtocolError("transfer-encoding beside content-length is ambiguous")
    if codings and codings != [b"chunked"]:
        raise B1ProtocolError(f"unsupported transfer coding: {codings!r}")
    reusable = not close and (version == b"HTTP/1.1" or keep_alive)
    if status_code in _B1_BODYLESS_STATUS:
        return "empty", 0, reusable
    if codings:
        return "chunked", 0, reusable
    if lengths:
        return "length", lengths.pop(), reusable
    if close or version == b"HTTP/1.0":
        return "eof", 0, False
    raise B1ProtocolError("indeterminate response body boundary")


class B1RawHttp11Client:
    """Single-origin HTTP/1.1 client, one reserved connection per request.

    Deliberately not thread-safe: every caller is an asyncio phase inside one
    driver process, so the four ledgers are plain event-loop state and every
    ownership transition is a single dictionary operation.
    """

    def __init__(
        self,
        *,
        max_connections: int,
        timeout: float,
        keepalive_expiry: float,
        http_version: str,
        retries: int,
        follow_redirects: bool,
        trust_env: bool,
    ) -> None:
        if (
            isinstance(max_connections, bool)
            or not isinstance(max_connections, int)
            or max_connections <= 0
        ):
            raise ValueError("max_connections must be a positive integer")
        if http_version != "HTTP/1.1":
            raise ValueError("only HTTP/1.1 is supported")
        if retries != 0:
            raise ValueError("retries must be 0: a B1 request is never retried")
        if follow_redirects:
            raise ValueError("redirects are never followed")
        if trust_env:
            raise ValueError("the client reads no environment configuration")
        self._max_connections = max_connections
        self._timeout = float(timeout)
        self._keepalive_expiry = float(keepalive_expiry)
        self._origin: tuple[str, str, int] | None = None
        self._host_header: str | None = None
        self._closed = False
        self._next_request_id = 0
        self._next_connection_id = 0
        # The four populations. No request-path helper iterates any of them.
        self._connections: dict[int, _B1Connection] = {}
        self._idle: OrderedDict[int, _B1Connection] = OrderedDict()
        self._requests: dict[int, int | None] = {}
        self._waiters: OrderedDict[int, asyncio.Future] = OrderedDict()

    @property
    def is_closed(self) -> bool:
        return self._closed

    async def __aenter__(self) -> "B1RawHttp11Client":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    # -- public request path -------------------------------------------------

    async def post(
        self, url: str, *, content: bytes, headers: dict[str, str]
    ) -> B1HttpResponse:
        """One POST on one reserved connection. Never retried, never redirected."""
        if self._closed:
            raise RuntimeError("client is closed")
        target = self._bind_origin(url)
        head = self._render_head(target, content, headers)
        request_id, conn = await self._checkout()
        try:
            if conn.writer is None:
                await self._open(conn)
            await self._send(conn, head, content)
            status_code, body, reusable = await self._receive(conn)
        except BaseException:
            # One reservation, one retirement: every failure path frees exactly
            # this connection and exactly this ledger entry, and hands the
            # freed capacity to at most one waiter.
            self._retire(conn)
            self._requests.pop(request_id, None)
            raise
        self._requests.pop(request_id, None)
        if reusable:
            self._recycle(conn)
        else:
            self._retire(conn)
        return B1HttpResponse(status_code, body)

    def pool_snapshot(self) -> B1PoolSnapshot:
        """One coherent diagnostic observation (FP-IG-37 / FP-B1DF-5).

        Deliberately O(C + R) and deliberately off the request path: it is
        taken by the 100 ms census sampler, never by checkout or release.
        """
        assigned = tuple(cid for cid in self._requests.values() if cid is not None)
        return B1PoolSnapshot(
            held_connections=len(self._connections),
            queued_requests=len(self._requests) - len(assigned),
            connection_identities=frozenset(self._connections),
            assigned_connection_identities=assigned,
            requests=len(self._requests),
        )

    async def aclose(self) -> None:
        """Shutdown is once per phase, so O(C + Q) here is deliberate."""
        self._closed = True
        while self._waiters:
            request_id, waiter = self._waiters.popitem(last=False)
            self._requests.pop(request_id, None)
            if not waiter.done():
                waiter.set_exception(RuntimeError("client is closing"))
                waiter.exception()
        writers = []
        while self._connections:
            _cid, conn = self._connections.popitem()
            writer = self._detach(conn)
            if writer is not None:
                writers.append(writer)
        self._idle.clear()
        self._requests.clear()
        if writers:
            # Bounded and concurrent: shutdown must terminate even when a peer
            # has stopped reading a half-written request, and must leave the
            # four snapshot counts at zero either way.
            try:
                async with asyncio.timeout(self._timeout):
                    await asyncio.gather(
                        *(writer.wait_closed() for writer in writers),
                        return_exceptions=True,
                    )
            except TimeoutError:
                pass

    # -- origin and request serialization ------------------------------------

    def _bind_origin(self, url: str) -> str:
        """Bind (or re-check) the single origin and return the request target.

        Runs before any reservation exists, so invalid input never occupies
        capacity, and a single origin means release never scans for a victim.
        """
        parts = urlsplit(url)
        if parts.scheme != "http":
            raise ValueError(f"only http:// is supported: {url!r}")
        if parts.fragment:
            raise ValueError(f"a fragment is not a request target: {url!r}")
        if parts.username is not None or parts.password is not None:
            raise ValueError(f"userinfo is not accepted: {url!r}")
        host = parts.hostname
        if not host:
            raise ValueError(f"missing host: {url!r}")
        origin = (parts.scheme, host, parts.port or 80)
        if self._origin is None:
            self._origin = origin
            self._host_header = parts.netloc
        elif origin != self._origin:
            raise ValueError(f"client is bound to {self._origin}, got {origin}")
        target = parts.path or "/"
        if parts.query:
            target = f"{target}?{parts.query}"
        if _B1_TARGET_FORBIDDEN.intersection(target):
            raise ValueError(f"not a request target: {target!r}")
        return target

    def _render_head(
        self, target: str, content: bytes, headers: dict[str, str]
    ) -> bytes:
        """Serialize the request head. O(header bytes), never O(population)."""
        if not isinstance(content, (bytes, bytearray)):
            raise ValueError("content must be bytes")
        lines = [
            f"POST {target} HTTP/1.1",
            f"Host: {self._host_header}",
            f"Content-Length: {len(content)}",
            "Connection: keep-alive",
        ]
        for name, value in (headers or {}).items():
            _b1_check_header_field(name, value)
            lines.append(f"{name}: {value}")
        try:
            return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
        except UnicodeEncodeError as exc:
            raise ValueError(f"header bytes are not latin-1: {exc}") from exc

    # -- constant-time connection ownership (FP-B1DF-1) ----------------------

    async def _checkout(self) -> tuple[int, _B1Connection]:
        """Reserve exactly one connection for one request, in constant time."""
        request_id = self._next_request_id
        self._next_request_id += 1
        if self._idle:
            _cid, conn = self._idle.popitem(last=False)
            self._disarm(conn)
            if conn.writer.is_closing() or conn.reader.at_eof():
                # The peer retired it while parked. Replacing an unused socket
                # is not a retry: no request byte was ever written to it.
                self._drop(conn)
                conn = self._new_connection()
            self._requests[request_id] = conn.cid
            return request_id, conn
        if len(self._connections) < self._max_connections:
            conn = self._new_connection()
            self._requests[request_id] = conn.cid
            return request_id, conn
        waiter = asyncio.get_running_loop().create_future()
        self._requests[request_id] = None
        self._waiters[request_id] = waiter
        try:
            async with asyncio.timeout(self._timeout):
                conn = await waiter
        except BaseException:
            self._waiters.pop(request_id, None)
            if waiter.done() and not waiter.cancelled() and waiter.exception() is None:
                # Handed a connection in the same tick the wait ended: return
                # it rather than leaking one unit of capacity.
                self._retire(waiter.result())
            self._requests.pop(request_id, None)
            raise
        return request_id, conn

    def _new_connection(self) -> _B1Connection:
        """Allocate one held record, in `opening` state, with a stable id."""
        cid = self._next_connection_id
        self._next_connection_id += 1
        conn = _B1Connection(cid)
        self._connections[cid] = conn
        return conn

    def _disarm(self, conn: _B1Connection) -> None:
        """Cancel this record's keep-alive timer and void its idle generation."""
        handle = conn.expiry_handle
        if handle is not None:
            handle.cancel()
            conn.expiry_handle = None
        conn.idle_token += 1

    def _detach(self, conn: _B1Connection):
        """Unparent one record's socket and return its writer, if any."""
        self._disarm(conn)
        writer = conn.writer
        conn.writer = None
        conn.reader = None
        if writer is not None:
            try:
                writer.close()
            except OSError:
                pass
        return writer

    def _drop(self, conn: _B1Connection) -> None:
        """Remove and close exactly this connection. No ledger is scanned."""
        self._connections.pop(conn.cid, None)
        self._idle.pop(conn.cid, None)
        self._detach(conn)

    def _retire(self, conn: _B1Connection) -> None:
        """Close one connection and pass its freed capacity to one waiter."""
        self._drop(conn)
        if not self._closed:
            self._give_to_waiter(None)

    def _recycle(self, conn: _B1Connection) -> None:
        """Hand one reusable connection on, or park it with its own timer."""
        if self._closed:
            self._drop(conn)
            return
        if self._give_to_waiter(conn):
            return
        self._idle[conn.cid] = conn
        conn.idle_token += 1
        conn.expiry_handle = asyncio.get_running_loop().call_later(
            self._keepalive_expiry, self._expire_idle, conn.cid, conn.idle_token
        )

    def _give_to_waiter(self, conn: _B1Connection | None) -> bool:
        """Transfer one connection, or one unit of capacity, to the oldest waiter.

        The loop only discards waiters that are already dead, and each turn
        removes one entry permanently: the cost is amortized O(1) per request
        and no live waiter, request or connection is ever scanned.
        """
        while self._waiters:
            request_id, waiter = self._waiters.popitem(last=False)
            if waiter.done():
                self._requests.pop(request_id, None)
                continue
            if conn is None:
                conn = self._new_connection()
            self._requests[request_id] = conn.cid
            waiter.set_result(conn)
            return True
        return False

    def _expire_idle(self, cid: int, token: int) -> None:
        """Keep-alive expiry for exactly one id and one idle generation."""
        conn = self._idle.get(cid)
        if conn is None or conn.idle_token != token:
            return
        conn.expiry_handle = None
        self._drop(conn)

    # -- HTTP/1.1 exchange ---------------------------------------------------

    async def _open(self, conn: _B1Connection) -> None:
        _scheme, host, port = self._origin
        async with asyncio.timeout(self._timeout):
            conn.reader, conn.writer = await asyncio.open_connection(host, port)

    async def _send(self, conn: _B1Connection, head: bytes, content: bytes) -> None:
        conn.writer.write(head)
        if content:
            conn.writer.write(content)
        async with asyncio.timeout(self._timeout):
            await conn.writer.drain()

    async def _receive(self, conn: _B1Connection) -> tuple[int, bytes, bool]:
        version, status_code, headers = _b1_parse_head(
            await self._read_until(conn, b"\r\n\r\n")
        )
        if status_code < 200:
            raise B1ProtocolError(
                f"unexpected informational response: {status_code}"
            )
        mode, length, reusable = _b1_response_framing(version, status_code, headers)
        if mode == "length":
            body = await self._read_exactly(conn, length) if length else b""
        elif mode == "chunked":
            body = await self._read_chunked(conn)
        elif mode == "eof":
            body = await self._read_to_eof(conn)
        else:
            body = b""
        return status_code, body, reusable

    async def _read_until(self, conn: _B1Connection, separator: bytes) -> bytes:
        try:
            async with asyncio.timeout(self._timeout):
                return await conn.reader.readuntil(separator)
        except asyncio.IncompleteReadError as exc:
            raise B1ProtocolError("response truncated before its framing") from exc
        except asyncio.LimitOverrunError as exc:
            raise B1ProtocolError("response framing exceeds the stream limit") from exc

    async def _read_exactly(self, conn: _B1Connection, count: int) -> bytes:
        try:
            async with asyncio.timeout(self._timeout):
                return await conn.reader.readexactly(count)
        except asyncio.IncompleteReadError as exc:
            raise B1ProtocolError("response body truncated") from exc

    async def _read_to_eof(self, conn: _B1Connection) -> bytes:
        async with asyncio.timeout(self._timeout):
            return await conn.reader.read()

    async def _read_chunked(self, conn: _B1Connection) -> bytes:
        pieces = []
        while True:
            line = await self._read_until(conn, b"\r\n")
            size_field = line[:-2].split(b";", 1)[0].strip()
            if not size_field or not set(size_field).issubset(_B1_HEX_DIGITS):
                raise B1ProtocolError(f"malformed chunk size: {line!r}")
            size = int(size_field, 16)
            if size == 0:
                break
            piece = await self._read_exactly(conn, size + 2)
            if piece[-2:] != b"\r\n":
                raise B1ProtocolError("chunk not terminated by CRLF")
            pieces.append(piece[:-2])
        while await self._read_until(conn, b"\r\n") != b"\r\n":
            pass
        return b"".join(pieces)


def build_httpx_client(*, max_connections: int) -> B1RawHttp11Client:
    """Pinned B1 HTTP/1.1 client (FP-B1DF-2/3; compatibility factory name).

    The name is retained for its callers; the returned object is B1's own raw
    client. Capacity is validated before any state is allocated, and nothing
    here reads the environment, a proxy, a certificate or a socket option.
    """
    if (
        isinstance(max_connections, bool)
        or not isinstance(max_connections, int)
        or max_connections <= 0
    ):
        raise ValueError("max_connections must be a positive integer")
    return B1RawHttp11Client(
        max_connections=max_connections,
        timeout=CLIENT_TIMEOUT,
        keepalive_expiry=KEEPALIVE_EXPIRY,
        http_version="HTTP/1.1",
        retries=0,
        follow_redirects=False,
        trust_env=False,
    )
# B1-RAW-CLIENT:END


async def run_open_loop(
    *,
    endpoint: str,
    requests: list[tuple[bytes, dict[str, str]]],
    rate: int,
    transport: Transport | None = None,
    client: B1RawHttp11Client | None = None,
    max_in_flight: int = MAX_IN_FLIGHT,
    prologue: list[tuple[bytes, dict[str, str]]] | None = None,
    warmup: tuple[bytes, dict[str, str]] | None = None,
    include_sync_warmup: bool = True,
    on_prologue_complete: Callable[[], None] | None = None,
    on_window_complete: Callable[[], None] | None = None,
    serve_port: int | None = None,
    worker_pids: list[int] | None = None,
) -> PhaseResult:
    """Open-loop generator with due-time latency and unmeasured prologue.

    ``requests`` is the **measured** window only. Warmup and prologue payloads
    must be supplied separately (or omitted) so event_ids are never reused
    across unmeasured and measured phases (FP-IG-7 / C2).

    Request *i* is dispatched at or after due[i] = t0 + i / rate.
    latency_ms(i) = (t_response(i) − due[i]) × 1000 for every offered request.
    """
    n = len(requests)
    if n == 0:
        return PhaseResult(0, 0, 0, [], 0.0, 0.0, 0.0, 0, 0)

    own_client = client is None and transport is None
    if own_client:
        client = build_httpx_client(max_connections=max_in_flight)

    # Per-request stations (FP-IG-39). Preallocated length-n; stores guarded
    # so warmup (idx = -1) and prologue (idx <= -2) never write a measured slot.
    # AW licenses two timestamp reads and two list stores; t_resp is already
    # represented by latencies[idx], so the third leg is derived after drain.
    dispatch_at = [0.0] * n
    attempt_at = [0.0] * n

    async def _one(
        idx: int, raw: bytes, headers: dict[str, str]
    ) -> tuple[int, int | None, bytes | None, BaseException | None, float]:
        try:
            if 0 <= idx < n:
                attempt_at[idx] = time.perf_counter()
            if transport is not None:
                code, body, err = await transport.post(
                    endpoint, content=raw, headers=headers
                )
                return idx, code, body, err, time.perf_counter()
            assert client is not None
            r = await client.post(endpoint, content=raw, headers=headers)
            return idx, r.status_code, r.content, None, time.perf_counter()
        except BaseException as exc:  # noqa: BLE001
            return idx, None, None, exc, time.perf_counter()

    try:
        # --- unmeasured prologue (disjoint payloads only) ---
        if include_sync_warmup:
            if warmup is None:
                raise ValueError(
                    "include_sync_warmup=True requires a disjoint warmup payload"
                )
            await _one(-1, warmup[0], warmup[1])

        pro_list = list(prologue or ())
        if pro_list:
            t_pro_start = time.perf_counter()
            pro_tasks: list[asyncio.Task] = []
            for i, (raw, headers) in enumerate(pro_list):
                due = t_pro_start + i / rate
                now = time.perf_counter()
                if now < due:
                    await asyncio.sleep(due - now)
                pro_tasks.append(asyncio.create_task(_one(-(i + 2), raw, headers)))
            if pro_tasks:
                await asyncio.gather(*pro_tasks)

        if on_prologue_complete is not None:
            on_prologue_complete()

        census_samples: list[int | str] = []
        pool_conn_samples: list[int | str] = []
        pool_queued_samples: list[int | str] = []
        pool_request_samples: list[int | str] = []
        pool_identity_samples: list[set[int]] = []
        worker_census_samples: list[list[int | str]] = []
        census_stop = asyncio.Event()

        async def _census_sampler() -> None:
            while not census_stop.is_set():
                if serve_port is not None:
                    tables = read_proc_net_tcp_tables()
                    if tables == UNAVAILABLE:
                        census_samples.append(UNAVAILABLE)
                        if worker_pids:
                            worker_census_samples.append(
                                [UNAVAILABLE] * len(worker_pids)
                            )
                    else:
                        tcp_text, tcp6_text = tables
                        census_samples.append(
                            count_established_to_serve_port(
                                serve_port,
                                tcp_text=tcp_text,
                                tcp6_text=tcp6_text,
                            )
                        )
                        if worker_pids:
                            worker_census_samples.append(
                                count_per_worker_established_to_serve_port(
                                    worker_pids,
                                    serve_port,
                                    tcp_text=tcp_text,
                                    tcp6_text=tcp6_text,
                                )
                            )
                if client is not None and transport is None:
                    conn_n, queued_n, seen, requests_n = read_pool_census_sample(client)
                    pool_conn_samples.append(conn_n)
                    pool_request_samples.append(requests_n)
                    pool_queued_samples.append(queued_n)
                    if seen is not None:
                        pool_identity_samples.append(seen)
                try:
                    await asyncio.wait_for(census_stop.wait(), timeout=0.1)
                except asyncio.TimeoutError:
                    pass

        census_task: asyncio.Task | None = None

        # --- measured window ---
        latencies = [0.0] * n
        outcomes: list[str] = [""] * n
        codes: list[int] = [0] * n
        t0 = time.perf_counter()
        due0 = t0
        if serve_port is not None or (client is not None and transport is None):
            census_task = asyncio.create_task(_census_sampler())
        in_flight = 0
        max_if = 0
        max_backlog = 0
        pending: set[asyncio.Task] = set()
        t_last = t0

        async def _on_done(task: asyncio.Task) -> None:
            nonlocal in_flight, t_last
            idx, code, body, err, t_resp = task.result()
            in_flight -= 1
            t_last = max(t_last, t_resp)
            due_i = due0 + idx / rate
            latencies[idx] = (t_resp - due_i) * 1000.0
            outcomes[idx] = classify_response(code, body, err)
            codes[idx] = code if code is not None else 599

        for i in range(n):
            due = due0 + i / rate
            now = time.perf_counter()
            if now < due:
                await asyncio.sleep(due - now)
            # backlog = requests whose due has passed but not yet dispatched
            backlog = max(0, int((time.perf_counter() - due0) * rate) - i)
            if backlog > max_backlog:
                max_backlog = backlog
            while in_flight >= max_in_flight:
                done, pending = await asyncio.wait(
                    pending, return_when=asyncio.FIRST_COMPLETED
                )
                for t in done:
                    await _on_done(t)
            raw, headers = requests[i]
            if 0 <= i < n:
                dispatch_at[i] = time.perf_counter()
            task = asyncio.create_task(_one(i, raw, headers))
            pending.add(task)
            # Dispatch peak: incremented at create_task, before pool/socket
            # acquisition — an upper bound on on-wire concurrency, not a measure.
            in_flight += 1
            if in_flight > max_if:
                max_if = in_flight
            # Drain completed without blocking dispatch
            finished = {t for t in pending if t.done()}
            for t in finished:
                pending.discard(t)
                await _on_done(t)

        while pending:
            done, pending = await asyncio.wait(
                pending, return_when=asyncio.FIRST_COMPLETED
            )
            for t in done:
                await _on_done(t)

        if census_task is not None:
            census_stop.set()
            await census_task
        # Window is closed. Any recorded quantity of the measured interval
        # (CPU included) must be sampled here, before O(N) leg arithmetic.
        if on_window_complete is not None:
            on_window_complete()
        peak_census = (
            peak_established_from_samples(census_samples)
            if serve_port is not None
            else UNAVAILABLE
        )
        peak_pool_conn = (
            peak_pool_metric_from_samples(pool_conn_samples)
            if pool_conn_samples
            else UNAVAILABLE
        )
        peak_pool_q = (
            peak_pool_metric_from_samples(pool_queued_samples)
            if pool_queued_samples
            else UNAVAILABLE
        )
        pool_seen = pool_connections_seen_from_identity_sets(pool_identity_samples)
        worker_peaks = (
            worker_established_peaks_from_samples(worker_census_samples)
            if worker_pids
            else []
        )
        peak_worker_est = (
            peak_worker_established_from_peaks(worker_peaks)
            if worker_peaks
            else UNAVAILABLE
        )

        served = sum(1 for o in outcomes if o == "served")
        errors = n - served
        pre_dispatch_slip_ms, start_lag_ms, attempt_duration_ms = derive_leg_vectors(
            latencies,
            dispatch_at,
            attempt_at,
            due0=due0,
            rate=rate,
        )
        return PhaseResult(
            offered=n,
            served=served,
            errors=errors,
            latencies_ms=latencies,
            t0=t0,
            t_last_complete=t_last,
            due0=due0,
            max_in_flight=max_if,
            max_backlog=max_backlog,
            status_codes=codes,
            peak_established_connections=peak_census,
            peak_pool_connections=peak_pool_conn,
            peak_pool_requests=peak_pool_metric_from_samples(pool_request_samples),
            peak_pool_queued=peak_pool_q,
            pool_connections_seen=pool_seen,
            worker_established_peaks=worker_peaks,
            peak_worker_established=peak_worker_est,
            pre_dispatch_slip_ms=pre_dispatch_slip_ms,
            start_lag_ms=start_lag_ms,
            attempt_duration_ms=attempt_duration_ms,
        )
    finally:
        if own_client and client is not None:
            await client.aclose()


def evaluate_b1_clauses(result: PhaseResult) -> list[str]:
    """Return list of failed clause names; empty means all pass (final oracle)."""
    fails: list[str] = []
    if result.served + result.errors != result.offered:
        fails.append("served+errors==offered")
    if result.errors != 0:
        fails.append("errors==0")
    if result.served != result.offered:
        fails.append("served==offered")
    if not (result.p99 < P99_MS):
        fails.append("p99<P99_MS")
    if not (result.served_rate >= SUSTAINED_FLOOR):
        fails.append("served_rate>=SUSTAINED_FLOOR")
    return fails


def evaluate_superseded_form1(result: PhaseResult) -> list[str]:
    """Errata pass 1: completion clauses without the rate floor."""
    fails: list[str] = []
    if result.served + result.errors != result.offered:
        fails.append("served+errors==offered")
    if result.errors != 0:
        fails.append("errors==0")
    if result.served != result.offered:
        fails.append("served==offered")
    if not (result.p99 < P99_MS):
        fails.append("p99<P99_MS")
    return fails


def evaluate_superseded_form2(result: PhaseResult) -> list[str]:
    """Errata pass 2: p99-discounted ratio >= BURST_RATE."""
    fails = evaluate_superseded_form1(result)
    span = result.t_last_complete - result.due0 - (result.p99 / 1000.0)
    ratio = result.served / span if span > 0 else 0.0
    if not (ratio >= BURST_RATE):
        fails.append("discounted_ratio>=BURST_RATE")
    return fails


def evaluate_superseded_form3(result: PhaseResult) -> list[str]:
    """Errata pass 3: p100 + half-window lateness drift pair.

    Both must hold. The drift bound is intentionally tight enough that
    round3_997 (half-medians ~24 vs ~68) and round5_constant_995
    (~37 vs ~112) fail while healthy_1000 / round4_repeated_ramp pass —
    matching design.md §11.3.5's acceptance matrix.
    """
    fails = evaluate_superseded_form1(result)
    if not (result.max_lateness_ms < P99_MS):
        fails.append("p100<P99_MS")
    a, b = half_window_medians(result.latencies_ms)
    drift = (b - a) if not (math.isinf(a) or math.isinf(b)) else float("inf")
    if not (abs(drift) < 40.0):
        fails.append("lateness_drift")
    return fails


def evaluate_superseded_form4(result: PhaseResult) -> list[str]:
    """Errata pass 4: p100 alone (max lateness < P99_MS)."""
    fails = evaluate_superseded_form1(result)
    if not (result.max_lateness_ms < P99_MS):
        fails.append("p100<P99_MS")
    return fails


# Expected verdicts under the four superseded formulations (design.md §11.3.5).
ACCEPTANCE_SUPERSEDED: dict[str, tuple[str, str, str, str]] = {
    "healthy_1000": ("pass", "pass", "pass", "pass"),
    "round2_tail": ("pass", "fail", "fail", "fail"),
    "late_first_completion": ("pass", "pass", "fail", "fail"),
    "sustained_deficit_990": ("fail", "fail", "fail", "fail"),
    "sustained_deficit_400": ("fail", "fail", "fail", "fail"),
    "round3_997": ("pass", "pass", "fail", "pass"),
    "round4_repeated_ramp": ("pass", "pass", "pass", "pass"),
    "round5_constant_995": ("pass", "fail", "fail", "pass"),
    "round5_burst_credits": ("pass", "pass", "pass", "pass"),
    "round6_dispatch_hold": ("pass", "fail", "fail", "fail"),
}


# Acceptance-case synthetic schedules (FP-IG-7 §11.3.5). Deterministic.
def _acceptance_schedule(name: str) -> PhaseResult:
    n = TOTAL_REQUESTS
    rate = BURST_RATE
    due0 = 0.0
    latencies = [0.0] * n
    t_last = 0.0

    if name == "healthy_1000":
        for i in range(n):
            latencies[i] = 5.0 + (i % 36)  # 5–40 ms, no trend
        t_last = (n - 1) / rate + latencies[-1] / 1000.0
    elif name == "round2_tail":
        for i in range(n):
            latencies[i] = 149.0 if i < 29700 else 4000.0
        t_last = (n - 1) / rate + 4.0
    elif name == "late_first_completion":
        for i in range(n):
            latencies[i] = 5000.0 if i == 0 else 20.0
        t_last = (n - 1) / rate + 0.02
    elif name == "sustained_deficit_990":
        # lag ramps to ~303 ms: lateness_ms(i) = i * (1/S − 1/R) * 1000
        for i in range(n):
            latencies[i] = i * (1.0 / 990.0 - 1.0 / rate) * 1000.0
        t_last = (n - 1) / rate + latencies[-1] / 1000.0
    elif name == "sustained_deficit_400":
        for i in range(n):
            latencies[i] = i * (1.0 / 400.0 - 1.0 / rate) * 1000.0
        t_last = (n - 1) / rate + latencies[-1] / 1000.0
        # Timeouts on the tail become errors
        errors = max(0, n - int(400 * BURST_SECONDS))
        served = n - errors
        return PhaseResult(
            offered=n,
            served=served,
            errors=errors,
            latencies_ms=latencies,
            t0=0.0,
            t_last_complete=t_last,
            due0=due0,
            max_in_flight=0,
            max_backlog=0,
        )
    elif name == "round3_997":
        for i in range(n):
            if i < 301:
                latencies[i] = 149.0
            else:
                latencies[i] = min(91.0, 1.0 + i * 90.0 / n)
        t_last = (n - 1) / rate + latencies[-1] / 1000.0
    elif name == "round4_repeated_ramp":
        for i in range(n):
            if i < 14700:
                latencies[i] = 90.0 * i / 14700
            elif i < 15000:
                latencies[i] = 90.0 * (1.0 - (i - 14700) / 300)
            else:
                latencies[i] = 90.0 * (i - 15000) / 15000
        t_last = (n - 1) / rate + latencies[-1] / 1000.0
    elif name == "round5_constant_995":
        for i in range(n):
            latencies[i] = i * (1.0 / 995.1 - 1.0 / rate) * 1000.0
        t_last = (n - 1) / rate + latencies[-1] / 1000.0
    elif name == "round5_burst_credits":
        for i in range(n):
            latencies[i] = 20.0
        t_last = (n - 1) / rate + 0.02
    elif name == "round6_dispatch_hold":
        for i in range(n):
            if i < 29700:
                latencies[i] = 149.0
            else:
                # dispatch held ~200 s past due; completes promptly after
                latencies[i] = 200_000.0 + 20.0
        t_last = (n - 1) / rate + 200.02
    else:
        raise ValueError(name)

    return PhaseResult(
        offered=n,
        served=n,
        errors=0,
        latencies_ms=latencies,
        t0=0.0,
        t_last_complete=t_last,
        due0=due0,
        max_in_flight=0,
        max_backlog=0,
    )


# Expected final verdicts for the ten acceptance cases.
ACCEPTANCE_EXPECTED: dict[str, str] = {
    "healthy_1000": "pass",
    "round2_tail": "pass",
    "late_first_completion": "pass",
    "sustained_deficit_990": "fail",
    "sustained_deficit_400": "fail",
    "round3_997": "pass",
    "round4_repeated_ramp": "pass",
    "round5_constant_995": "pass",
    "round5_burst_credits": "pass",
    "round6_dispatch_hold": "fail",
}


def run_acceptance_case(name: str) -> tuple[str, list[str]]:
    """Return (verdict, failed_clauses) under the final oracle."""
    result = _acceptance_schedule(name)
    fails = evaluate_b1_clauses(result)
    return ("pass" if not fails else "fail"), fails


def run_acceptance_matrix(name: str) -> dict[str, str]:
    """Return final + four superseded verdicts for one acceptance case."""
    result = _acceptance_schedule(name)
    forms = {
        "final": evaluate_b1_clauses,
        "form1": evaluate_superseded_form1,
        "form2": evaluate_superseded_form2,
        "form3": evaluate_superseded_form3,
        "form4": evaluate_superseded_form4,
    }
    out: dict[str, str] = {}
    for key, fn in forms.items():
        fails = fn(result)
        out[key] = "pass" if not fails else "fail"
    return out


def _proc_cmdline(pid: int) -> str:
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return ""
    return raw.replace(b"\x00", b" ").decode("utf-8", "replace")


def iter_live_descendants(root_pid: int) -> list[int]:
    """AA: enumerate live descendants via /proc/<pid>/task/*/children."""
    seen: set[int] = set()
    out: list[int] = []
    queue = [root_pid]
    while queue:
        pid = queue.pop(0)
        if pid in seen:
            continue
        seen.add(pid)
        if pid != root_pid:
            out.append(pid)
        task = Path(f"/proc/{pid}/task")
        if not task.is_dir():
            continue
        for tdir in task.iterdir():
            children_file = tdir / "children"
            try:
                text = children_file.read_text().strip()
            except OSError:
                continue
            if text:
                queue.extend(int(tok) for tok in text.split())
    return out


def classify_tree(root_pid: int) -> tuple[set[int], set[int]]:
    """Return (tracker_pids, worker_pids) classified by cmdline."""
    trackers: set[int] = set()
    workers: set[int] = set()
    for pid in iter_live_descendants(root_pid):
        cmd = _proc_cmdline(pid)
        if TRACKER_CMDLINE_MARK in cmd:
            trackers.add(pid)
        elif WORKER_CMDLINE_MARK in cmd:
            workers.add(pid)
    return trackers, workers


def pid_cpu_seconds(pid: int) -> float:
    """utime + stime only — cutime/cstime are not used (AA)."""
    clk = os.sysconf("SC_CLK_TCK")
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8") as f:
            fields = f.read().split()
    except OSError:
        return 0.0
    return (int(fields[13]) + int(fields[14])) / clk


def tree_cpu_seconds(root_pid: int) -> float:
    total = pid_cpu_seconds(root_pid)
    for pid in iter_live_descendants(root_pid):
        total += pid_cpu_seconds(pid)
    return total


def wait_for_classified_workers(
    root_pid: int,
    *,
    workers: int = INGEST_GATEWAY_WORKERS,
    timeout_s: float = 30.0,
) -> tuple[set[int], set[int]]:
    """Bounded wait until the tree holds one tracker and exactly ``workers`` pids."""
    deadline = time.time() + timeout_s
    last: tuple[set[int], set[int]] = (set(), set())
    while time.time() < deadline:
        trackers, worker_pids = classify_tree(root_pid)
        last = (trackers, worker_pids)
        if len(trackers) == 1 and len(worker_pids) == workers:
            return trackers, worker_pids
        time.sleep(0.05)
    raise TimeoutError(
        f"classified tree never reached 1 tracker + {workers} workers; "
        f"last trackers={sorted(last[0])} workers={sorted(last[1])}"
    )


def format_pid_list(pids: set[int] | list[int]) -> str:
    return "+".join(str(p) for p in sorted(set(pids)))


def create_benchmark_app():
    """Import-string factory for the multi-worker B1 child (AA / FP-IG-22).

    Calls the shipped ``build_app()`` and attaches the recording Temporal stub
    in a startup handler. Config path comes from the child env set by the
    harness (gateway.main reads it; this file does not).
    """
    from gateway.main import build_app

    app, _config, service = build_app()

    class Stub:
        async def start_investigation(self, event, investigation_id):
            return f"investigation-{investigation_id}"

    @app.on_event("startup")
    async def _attach_stub() -> None:
        service._workflow_starter = Stub()

    return app


def serve_benchmark(*, host: str, port: int) -> None:
    import uvicorn

    from gateway.main import (
        BACKLOG,
        DEFAULT_MAX_CONNECTIONS_PER_WORKER,
        DEFAULT_TIMEOUT_KEEP_ALIVE_S,
    )

    uvicorn.run(
        "b1_reference_profile:create_benchmark_app",
        factory=True,
        workers=INGEST_GATEWAY_WORKERS,
        host=host,
        port=port,
        log_level="warning",
        limit_concurrency=DEFAULT_MAX_CONNECTIONS_PER_WORKER,
        timeout_keep_alive=DEFAULT_TIMEOUT_KEEP_ALIVE_S,
        backlog=BACKLOG,
    )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    ns = parser.parse_args()
    serve_benchmark(host=ns.host, port=ns.port)
