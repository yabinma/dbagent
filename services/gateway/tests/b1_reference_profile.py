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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Protocol

import httpx

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
    peak_pool_queued: int | str = UNAVAILABLE
    pool_connections_seen: int | str = UNAVAILABLE
    worker_established_peaks: list[int | str] = field(default_factory=list)
    peak_worker_established: int | str = UNAVAILABLE

    @property
    def p99(self) -> float:
        return nearest_rank_p99(self.latencies_ms)

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


def read_pool_census_sample(
    client: httpx.AsyncClient,
) -> tuple[int | str, int | str, set[int] | None]:
    """Read one client-pool census sample (FP-IG-37 / UT-IG-17).

    Returns (held_connections, queued_requests, connection_identities).
    Every attribute failure degrades to ``unavailable`` (fail-open recording).
    """
    try:
        pool = client._transport._pool
        connections = len(pool.connections)
        queued = sum(1 for req in pool._requests if req.is_queued())
        seen = {id(c) for c in pool.connections}
        return connections, queued, seen
    except (AttributeError, TypeError):
        return UNAVAILABLE, UNAVAILABLE, None


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


def build_httpx_client(*, max_connections: int) -> httpx.AsyncClient:
    """Pinned HTTPX client (FP-IG-13 / §11.3.3 H)."""
    return httpx.AsyncClient(
        limits=httpx.Limits(
            max_connections=max_connections,
            max_keepalive_connections=max_connections,
            keepalive_expiry=KEEPALIVE_EXPIRY,
        ),
        timeout=httpx.Timeout(
            connect=CLIENT_TIMEOUT,
            read=CLIENT_TIMEOUT,
            write=CLIENT_TIMEOUT,
            pool=CLIENT_TIMEOUT,
        ),
        trust_env=False,
        http2=False,
        http1=True,
        follow_redirects=False,
    )


async def run_open_loop(
    *,
    endpoint: str,
    requests: list[tuple[bytes, dict[str, str]]],
    rate: int,
    transport: Transport | None = None,
    client: httpx.AsyncClient | None = None,
    max_in_flight: int = MAX_IN_FLIGHT,
    prologue: list[tuple[bytes, dict[str, str]]] | None = None,
    warmup: tuple[bytes, dict[str, str]] | None = None,
    include_sync_warmup: bool = True,
    on_prologue_complete: Callable[[], None] | None = None,
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

    async def _one(
        idx: int, raw: bytes, headers: dict[str, str]
    ) -> tuple[int, int | None, bytes | None, BaseException | None, float]:
        try:
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
                    conn_n, queued_n, seen = read_pool_census_sample(client)
                    pool_conn_samples.append(conn_n)
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
            peak_pool_queued=peak_pool_q,
            pool_connections_seen=pool_seen,
            worker_established_peaks=worker_peaks,
            peak_worker_established=peak_worker_est,
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
