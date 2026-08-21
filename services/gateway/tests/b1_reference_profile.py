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

        # --- measured window ---
        latencies = [0.0] * n
        outcomes: list[str] = [""] * n
        codes: list[int] = [0] * n
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
