"""B1 e2e two-phase generator and oracle (design.md §11.3.3 H/Q, FP-IG-9/15).

Not collected by pytest. Open-loop baseline at BASE_RATE + closed-loop
saturation of SATURATION_CLIENTS for BURST_SECONDS.
"""
from __future__ import annotations

import asyncio
import json
import math
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Callable, Protocol
from urllib.parse import urlsplit

# FP-E2EB1D-1 — the three shipped reference helpers this carrier needs while
# building and querying PhaseResult. Direct pure imports: no copy, no
# re-export, no dynamic import, and no live reader is imported (design §3.1).
from services.gateway.tests.b1_reference_profile import (
    derive_leg_vectors,
    leg_p99s_of,
    p99_leg_split_of,
)

# Profile constants — each bound exactly once at module scope (FP-IG-13).
BURST_RATE = 1000
BURST_SECONDS = 30
BASE_RATE = 200
BASE_SECONDS = 30
BASE_TOTAL = BASE_RATE * BASE_SECONDS  # 6000
P99_MS = 150.0
SUSTAINED_FLOOR = 200
MAX_IN_FLIGHT = BURST_RATE
SATURATION_CLIENTS = int(5 * BASE_RATE * P99_MS / 1000)  # 150
PROLOGUE_REQUESTS = int(BASE_RATE * P99_MS / 1000)  # 30
KEEPALIVE_EXPIRY = float(BURST_SECONDS)
CLIENT_TIMEOUT = float(BURST_SECONDS)
INGEST_AUDIT_ACTIONS = ("event_received", "event_merged")


class Transport(Protocol):
    async def post(
        self, url: str, *, content: bytes, headers: dict[str, str]
    ) -> tuple[int, bytes | None, BaseException | None]:
        ...


def classify_response(
    status_code: int | None,
    body: bytes | None = None,
    error: BaseException | None = None,
) -> str:
    """Identical classifier to the reference tier (FP-IG-8)."""
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
    phase: str = "baseline"
    status_codes: list[int] = field(default_factory=list)
    # FP-E2EB1D-1 — trailing diagnostic carriers. Defaulting to empty keeps
    # every saturation and synthetic constructor byte-identical; only the
    # baseline return supplies populated vectors.
    pre_dispatch_slip_ms: list[float] = field(default_factory=list)
    start_lag_ms: list[float] = field(default_factory=list)
    attempt_duration_ms: list[float] = field(default_factory=list)

    @property
    def p99(self) -> float:
        return nearest_rank_p99(self.latencies_ms)

    @property
    def p99_leg_split(self) -> tuple[float, float, float]:
        """Identity-aligned triple of the p99-index request (reference FP-IG-39)."""
        return p99_leg_split_of(
            self.latencies_ms,
            self.pre_dispatch_slip_ms,
            self.start_lag_ms,
            self.attempt_duration_ms,
        )

    @property
    def leg_p99s(self) -> tuple[float, float, float]:
        """Three independent nearest-rank statistics; never a decomposition."""
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


async def run_open_loop_baseline(
    *,
    endpoint: str,
    requests: list[tuple[bytes, dict[str, str]]],
    transport: Transport | None = None,
    client: B1RawHttp11Client | None = None,
    rate: int = BASE_RATE,
    prologue: list[tuple[bytes, dict[str, str]]] | None = None,
    warmup: tuple[bytes, dict[str, str]] | None = None,
    max_in_flight: int = MAX_IN_FLIGHT,
    include_sync_warmup: bool = True,
    on_prologue_complete: Callable[[], None] | None = None,
    on_window_open: Callable[[], None] | None = None,
    on_window_complete: Callable[[], None] | None = None,
) -> PhaseResult:
    """Open-loop baseline at BASE_RATE with due-time latency.

    ``requests`` is the measured window only. Warmup/prologue must be disjoint
    payloads so event_ids are never reused (FP-IG-9 / C2).
    """
    n = len(requests)
    own_client = client is None and transport is None
    if own_client:
        client = build_httpx_client(max_connections=max_in_flight)

    # FP-E2EB1D-1/7 — per-request stations, in the shipped reference's shape.
    # Preallocated length-n HERE, before `_one` is defined and before any
    # warmup/prologue call can occur, and stored under bounds guards, so
    # warmup (idx = -1) and prologue (idx <= -2) cross only the guard, still
    # execute the unchanged transport/client branch, and can never index a
    # measured slot.
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
        if include_sync_warmup:
            if warmup is None:
                raise ValueError(
                    "include_sync_warmup=True requires a disjoint warmup payload"
                )
            await _one(-1, warmup[0], warmup[1])

        pro_list = list(prologue or ())
        if pro_list:
            t_pro = time.perf_counter()
            tasks = []
            for i, (raw, headers) in enumerate(pro_list):
                due = t_pro + i / rate
                now = time.perf_counter()
                if now < due:
                    await asyncio.sleep(due - now)
                tasks.append(asyncio.create_task(_one(-(i + 2), raw, headers)))
            if tasks:
                await asyncio.gather(*tasks)

        if on_prologue_complete is not None:
            on_prologue_complete()

        latencies = [0.0] * n
        outcomes = [""] * n
        codes = [0] * n
        # FP-E2EB1D-7 — the LAST operation before the window opens, so every
        # external boundary read finishes before `t0` exists.
        if on_window_open is not None:
            on_window_open()
        t0 = time.perf_counter()
        due0 = t0
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
            backlog = max(0, int((time.perf_counter() - due0) * rate) - i)
            if backlog > max_backlog:
                max_backlog = backlog
            while in_flight >= max_in_flight:
                done, pending = await asyncio.wait(
                    pending, return_when=asyncio.FIRST_COMPLETED
                )
                for t in done:
                    await _on_done(t)
            if 0 <= i < n:
                dispatch_at[i] = time.perf_counter()
            task = asyncio.create_task(_one(i, *requests[i]))
            pending.add(task)
            in_flight += 1
            if in_flight > max_if:
                max_if = in_flight
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

        # FP-E2EB1D-7 — the window is closed and `t_last` is fixed; the first
        # diagnostic operation after drain, before any O(N) leg arithmetic.
        if on_window_complete is not None:
            on_window_complete()

        served = sum(1 for o in outcomes if o == "served")
        # FP-E2EB1D-1 — fail-soft boundary 1: the shipped helper is total for
        # these internally guaranteed inputs, but future drift must not abort
        # the baseline. On an exception the three diagnostic vectors are empty
        # and every core value below is unchanged, so the same p99 assertion
        # is reached. KeyboardInterrupt / SystemExit are not caught.
        try:
            pre_dispatch_slip_ms, start_lag_ms, attempt_duration_ms = derive_leg_vectors(
                latencies,
                dispatch_at,
                attempt_at,
                due0=due0,
                rate=rate,
            )
        except Exception:  # noqa: BLE001 -- diagnostic only, never the oracle
            pre_dispatch_slip_ms, start_lag_ms, attempt_duration_ms = [], [], []
        return PhaseResult(
            offered=n,
            served=served,
            errors=n - served,
            latencies_ms=latencies,
            t0=t0,
            t_last_complete=t_last,
            due0=due0,
            max_in_flight=max_if,
            max_backlog=max_backlog,
            phase="baseline",
            status_codes=codes,
            pre_dispatch_slip_ms=pre_dispatch_slip_ms,
            start_lag_ms=start_lag_ms,
            attempt_duration_ms=attempt_duration_ms,
        )
    finally:
        if own_client and client is not None:
            await client.aclose()


async def run_closed_loop_saturation(
    *,
    endpoint: str,
    request_factory: Callable[[], tuple[bytes, dict[str, str]]],
    clients: int = SATURATION_CLIENTS,
    duration_s: float = BURST_SECONDS,
    transport: Transport | None = None,
    client: B1RawHttp11Client | None = None,
) -> PhaseResult:
    """Closed-loop saturation: clients issue back-to-back for duration_s.

    Latency is measured from request start (not due time). No rate asserted.
    """
    own_client = client is None and transport is None
    if own_client:
        client = build_httpx_client(max_connections=clients)

    latencies: list[float] = []
    outcomes: list[str] = []
    codes: list[int] = []
    lock = asyncio.Lock()
    t0 = time.perf_counter()
    deadline = t0 + duration_s
    max_if = 0
    in_flight = 0
    if_lock = asyncio.Lock()

    async def _worker() -> None:
        nonlocal max_if, in_flight
        while time.perf_counter() < deadline:
            raw, headers = request_factory()
            async with if_lock:
                in_flight += 1
                if in_flight > max_if:
                    max_if = in_flight
            t_start = time.perf_counter()
            try:
                if transport is not None:
                    code, body, err = await transport.post(
                        endpoint, content=raw, headers=headers
                    )
                else:
                    assert client is not None
                    r = await client.post(endpoint, content=raw, headers=headers)
                    code, body, err = r.status_code, r.content, None
            except BaseException as exc:  # noqa: BLE001
                code, body, err = None, None, exc
            t_end = time.perf_counter()
            async with if_lock:
                in_flight -= 1
            async with lock:
                latencies.append((t_end - t_start) * 1000.0)
                outcomes.append(classify_response(code, body, err))
                codes.append(code if code is not None else 599)

    try:
        await asyncio.gather(*[_worker() for _ in range(clients)])
        t_last = time.perf_counter()
        served = sum(1 for o in outcomes if o == "served")
        n = len(outcomes)
        return PhaseResult(
            offered=n,
            served=served,
            errors=n - served,
            latencies_ms=latencies,
            t0=t0,
            t_last_complete=t_last,
            due0=t0,
            max_in_flight=max_if,
            max_backlog=0,
            phase="saturation",
            status_codes=codes,
        )
    finally:
        if own_client and client is not None:
            await client.aclose()


def evaluate_baseline_correctness_clauses(result: PhaseResult) -> list[str]:
    """Baseline correctness clauses — no rate and no p99 comparison.

    FP-IG-9 minus its clause 5: the e2e-b1-kind-policy slice makes the nested
    kind due-time p99 observational, so the final oracle and every superseded
    form share this correctness-only base. Forms 2-4 add their own historical
    latency clauses on top; none of them reaches the removed p99 gate through
    this call.
    """
    fails: list[str] = []
    if result.served + result.errors != result.offered:
        fails.append("served+errors==offered")
    if result.errors != 0:
        fails.append("errors==0")
    if result.served != result.offered:
        fails.append("served==offered")
    return fails


def evaluate_saturation_clauses(result: PhaseResult) -> list[str]:
    fails: list[str] = []
    if result.served + result.errors != result.offered:
        fails.append("served+errors==issued")
    if result.errors != 0:
        fails.append("errors==0")
    return fails


# ---------------------------------------------------------------------------
# FP-IG-9 acceptance matrix — same ten schedules as FP-IG-7, at BASE_RATE.
# Case 10's required e2e verdict is **pass** (no rate floor at the nested tier).
# ---------------------------------------------------------------------------

def evaluate_superseded_form1(result: PhaseResult) -> list[str]:
    """Errata pass 1: completion clauses without a rate floor."""
    return evaluate_baseline_correctness_clauses(result)


def evaluate_superseded_form2(result: PhaseResult) -> list[str]:
    """Errata pass 2: p99-discounted ratio >= BASE_RATE."""
    fails = evaluate_baseline_correctness_clauses(result)
    span = result.t_last_complete - result.due0 - (result.p99 / 1000.0)
    ratio = result.served / span if span > 0 else 0.0
    if not (ratio >= BASE_RATE):
        fails.append("discounted_ratio>=BASE_RATE")
    return fails


def evaluate_superseded_form3(result: PhaseResult) -> list[str]:
    """Errata pass 3: p100 + half-window lateness drift pair."""
    fails = evaluate_baseline_correctness_clauses(result)
    if not (result.max_lateness_ms < P99_MS):
        fails.append("p100<P99_MS")
    a, b = half_window_medians(result.latencies_ms)
    drift = (b - a) if not (math.isinf(a) or math.isinf(b)) else float("inf")
    if not (abs(drift) < 40.0):
        fails.append("lateness_drift")
    return fails


def evaluate_superseded_form4(result: PhaseResult) -> list[str]:
    """Errata pass 4: p100 alone."""
    fails = evaluate_baseline_correctness_clauses(result)
    if not (result.max_lateness_ms < P99_MS):
        fails.append("p100<P99_MS")
    return fails


# Final e2e baseline oracle = form1 (no rate floor). Superseded forms 2–4
# scale the reference-tier formulations to BASE_RATE.
ACCEPTANCE_SUPERSEDED: dict[str, tuple[str, str, str, str]] = {
    "healthy_1000": ("pass", "pass", "pass", "pass"),
    "round2_tail": ("pass", "fail", "fail", "fail"),
    "late_first_completion": ("pass", "pass", "fail", "fail"),
    "sustained_deficit_990": ("pass", "pass", "fail", "fail"),
    "sustained_deficit_400": ("fail", "fail", "fail", "fail"),
    "round3_997": ("pass", "pass", "fail", "pass"),
    "round4_repeated_ramp": ("pass", "pass", "pass", "pass"),
    # form2 at BASE_RATE: the proportional 0.5 % deficit no longer undercuts
    # the discounted-ratio bar the way it did at BURST_RATE (reference form2
    # fails at ≈999.98 < 1000; here ratio ≥ 200). Final / form1 / form3 / form4
    # match the reference row.
    "round5_constant_995": ("pass", "pass", "fail", "pass"),
    "round5_burst_credits": ("pass", "pass", "pass", "pass"),
    # Case 10: dispatch hold fails the reference rate floor but **passes** e2e
    # (design.md FP-IG-9: baseline asserts no rate comparison).
    "round6_dispatch_hold": ("pass", "fail", "fail", "fail"),
}


def _acceptance_schedule(name: str) -> PhaseResult:
    """Deterministic synthetic schedules at BASE_RATE / BASE_TOTAL (FP-IG-9).

    Index fractions match the reference-tier cases so p99 / lateness behaviour
    is comparable; absolute times scale with the 200 req/s offer.
    """
    n = BASE_TOTAL  # 6000
    rate = BASE_RATE  # 200
    due0 = 0.0
    latencies = [0.0] * n
    t_last = 0.0
    # Map reference 30 000-index landmarks onto the 6 000-point baseline.
    i_29700 = int(29700 * n / 30000)  # 5940
    i_301 = int(301 * n / 30000)  # 60
    i_14700 = int(14700 * n / 30000)  # 2940
    i_15000 = int(15000 * n / 30000)  # 3000

    if name == "healthy_1000":
        for i in range(n):
            latencies[i] = 5.0 + (i % 36)  # 5–40 ms, no trend
        t_last = (n - 1) / rate + latencies[-1] / 1000.0
    elif name == "round2_tail":
        for i in range(n):
            latencies[i] = 149.0 if i < i_29700 else 4000.0
        t_last = (n - 1) / rate + 4.0
    elif name == "late_first_completion":
        for i in range(n):
            latencies[i] = 5000.0 if i == 0 else 20.0
        t_last = (n - 1) / rate + 0.02
    elif name == "sustained_deficit_990":
        # Scale the 1 % deficit relative to offer: service = 0.99 * BASE_RATE.
        service = rate * 0.99
        for i in range(n):
            latencies[i] = i * (1.0 / service - 1.0 / rate) * 1000.0
        t_last = (n - 1) / rate + latencies[-1] / 1000.0
    elif name == "sustained_deficit_400":
        # Unfixed-code shape: ~0.4 of offer capacity.
        service = rate * 0.4
        for i in range(n):
            latencies[i] = i * (1.0 / service - 1.0 / rate) * 1000.0
        t_last = (n - 1) / rate + latencies[-1] / 1000.0
        errors = max(0, n - int(service * BASE_SECONDS))
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
            phase="baseline",
        )
    elif name == "round3_997":
        for i in range(n):
            if i < i_301:
                latencies[i] = 149.0
            else:
                latencies[i] = min(91.0, 1.0 + i * 90.0 / n)
        t_last = (n - 1) / rate + latencies[-1] / 1000.0
    elif name == "round4_repeated_ramp":
        for i in range(n):
            if i < i_14700:
                latencies[i] = 90.0 * i / max(i_14700, 1)
            elif i < i_15000:
                latencies[i] = 90.0 * (1.0 - (i - i_14700) / max(i_15000 - i_14700, 1))
            else:
                latencies[i] = 90.0 * (i - i_15000) / max(n - i_15000, 1)
        t_last = (n - 1) / rate + latencies[-1] / 1000.0
    elif name == "round5_constant_995":
        service = rate * 0.9951
        for i in range(n):
            latencies[i] = i * (1.0 / service - 1.0 / rate) * 1000.0
        t_last = (n - 1) / rate + latencies[-1] / 1000.0
    elif name == "round5_burst_credits":
        for i in range(n):
            latencies[i] = 20.0
        t_last = (n - 1) / rate + 0.02
    elif name == "round6_dispatch_hold":
        for i in range(n):
            if i < i_29700:
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
        phase="baseline",
    )


# Final e2e verdicts: case 10 PASSES (no rate floor); others follow the
# correctness-only base evaluator at BASE_RATE. sustained_deficit_990 is the
# latency-only miss the kind tier now observes instead of failing on.
ACCEPTANCE_EXPECTED: dict[str, str] = {
    "healthy_1000": "pass",
    "round2_tail": "pass",
    "late_first_completion": "pass",
    "sustained_deficit_990": "pass",  # latency-only miss: observational at the kind tier
    "sustained_deficit_400": "fail",
    "round3_997": "pass",
    "round4_repeated_ramp": "pass",
    "round5_constant_995": "pass",
    "round5_burst_credits": "pass",
    "round6_dispatch_hold": "pass",  # e2e divergence from reference (fail there)
}


def run_acceptance_case(name: str) -> tuple[str, list[str]]:
    """Return (verdict, failed_clauses) under the e2e baseline oracle."""
    result = _acceptance_schedule(name)
    fails = evaluate_baseline_correctness_clauses(result)
    return ("pass" if not fails else "fail"), fails


def run_acceptance_matrix(name: str) -> dict[str, str]:
    """Return final + four superseded verdicts for one acceptance case."""
    result = _acceptance_schedule(name)
    forms = {
        "final": evaluate_baseline_correctness_clauses,
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
