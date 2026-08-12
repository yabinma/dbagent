"""B1 e2e two-phase generator and oracle (design.md §11.3.3 H/Q, FP-IG-9/15).

Not collected by pytest. Open-loop baseline at BASE_RATE + closed-loop
saturation of SATURATION_CLIENTS for BURST_SECONDS.
"""
from __future__ import annotations

import asyncio
import json
import math
import time
from dataclasses import dataclass, field
from typing import Callable, Protocol

import httpx

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


def build_httpx_client(*, max_connections: int) -> httpx.AsyncClient:
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


async def run_open_loop_baseline(
    *,
    endpoint: str,
    requests: list[tuple[bytes, dict[str, str]]],
    transport: Transport | None = None,
    client: httpx.AsyncClient | None = None,
    rate: int = BASE_RATE,
    prologue: list[tuple[bytes, dict[str, str]]] | None = None,
    warmup: tuple[bytes, dict[str, str]] | None = None,
    max_in_flight: int = MAX_IN_FLIGHT,
    include_sync_warmup: bool = True,
    on_prologue_complete: Callable[[], None] | None = None,
) -> PhaseResult:
    """Open-loop baseline at BASE_RATE with due-time latency.

    ``requests`` is the measured window only. Warmup/prologue must be disjoint
    payloads so event_ids are never reused (FP-IG-9 / C2).
    """
    n = len(requests)
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

        served = sum(1 for o in outcomes if o == "served")
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
    client: httpx.AsyncClient | None = None,
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


def evaluate_baseline_clauses(result: PhaseResult) -> list[str]:
    """Baseline clauses — no rate comparison (FP-IG-9)."""
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
    return evaluate_baseline_clauses(result)


def evaluate_superseded_form2(result: PhaseResult) -> list[str]:
    """Errata pass 2: p99-discounted ratio >= BASE_RATE."""
    fails = evaluate_baseline_clauses(result)
    span = result.t_last_complete - result.due0 - (result.p99 / 1000.0)
    ratio = result.served / span if span > 0 else 0.0
    if not (ratio >= BASE_RATE):
        fails.append("discounted_ratio>=BASE_RATE")
    return fails


def evaluate_superseded_form3(result: PhaseResult) -> list[str]:
    """Errata pass 3: p100 + half-window lateness drift pair."""
    fails = evaluate_baseline_clauses(result)
    if not (result.max_lateness_ms < P99_MS):
        fails.append("p100<P99_MS")
    a, b = half_window_medians(result.latencies_ms)
    drift = (b - a) if not (math.isinf(a) or math.isinf(b)) else float("inf")
    if not (abs(drift) < 40.0):
        fails.append("lateness_drift")
    return fails


def evaluate_superseded_form4(result: PhaseResult) -> list[str]:
    """Errata pass 4: p100 alone."""
    fails = evaluate_baseline_clauses(result)
    if not (result.max_lateness_ms < P99_MS):
        fails.append("p100<P99_MS")
    return fails


# Final e2e baseline oracle = form1 (no rate floor). Superseded forms 2–4
# scale the reference-tier formulations to BASE_RATE.
ACCEPTANCE_SUPERSEDED: dict[str, tuple[str, str, str, str]] = {
    "healthy_1000": ("pass", "pass", "pass", "pass"),
    "round2_tail": ("pass", "fail", "fail", "fail"),
    "late_first_completion": ("pass", "pass", "fail", "fail"),
    "sustained_deficit_990": ("fail", "fail", "fail", "fail"),
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


# Final e2e verdicts: case 10 PASSES (no rate floor); others match reference
# form1 / completion+p99 behaviour at BASE_RATE.
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
    "round6_dispatch_hold": "pass",  # e2e divergence from reference (fail there)
}


def run_acceptance_case(name: str) -> tuple[str, list[str]]:
    """Return (verdict, failed_clauses) under the e2e baseline oracle."""
    result = _acceptance_schedule(name)
    fails = evaluate_baseline_clauses(result)
    return ("pass" if not fails else "fail"), fails


def run_acceptance_matrix(name: str) -> dict[str, str]:
    """Return final + four superseded verdicts for one acceptance case."""
    result = _acceptance_schedule(name)
    forms = {
        "final": evaluate_baseline_clauses,
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
