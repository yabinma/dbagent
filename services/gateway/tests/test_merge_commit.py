"""GC-5 (FP-GC5-1/4/5): the per-worker merge coalescer, in isolation.

Deterministic on purpose. The batch shape and the collection budget are fixed
source constants with no override, so the tests drive the two module-level
seams the coalescer reads instead -- a fake monotonic clock and a fake arrival
wait -- and never a constructor knob. The callback is an ordinary Python
function: this module contains no database object at all.
"""
from __future__ import annotations

import asyncio
import textwrap
import threading
import uuid

import pytest

from gateway import merge_commit
from gateway.merge_commit import (
    MERGE_COMMIT_BATCH_SIZE,
    MERGE_COMMIT_MAX_WAIT_SECONDS,
    MergeCommitClosed,
    MergeCommitCoalescer,
    MergeCommitLoopError,
    MergeHit,
    MergeMiss,
)


def _event(index: int) -> dict:
    return {"event_id": f"event-{index}", "fingerprint": "fp"}


class _FakeClock:
    """A monotonic clock the test advances by hand."""

    def __init__(self, start: float = 1000.0):
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class _RecordingWait:
    """Stands in for the arrival wait; records every requested timeout."""

    def __init__(self, clock: _FakeClock, *, arrive: bool = False):
        self.clock = clock
        self.arrive = arrive
        self.timeouts: list[float] = []

    async def __call__(self, arrival, timeout):
        self.timeouts.append(timeout)
        # Let the loop run the other submitters, then expire the budget.
        await asyncio.sleep(0)
        if self.arrive and arrival.is_set():
            return True
        self.clock.advance(timeout)
        return False


@pytest.fixture
def deterministic(monkeypatch):
    clock = _FakeClock()
    waiter = _RecordingWait(clock)
    # The real wait is kept for the sub-case that exercises it unfaked.
    waiter.real = merge_commit._wait_for_arrival  # noqa: SLF001
    monkeypatch.setattr(merge_commit, "_monotonic", clock)
    monkeypatch.setattr(merge_commit, "_wait_for_arrival", waiter)
    return clock, waiter


def _batches_recorder():
    batches: list[list[str]] = []

    def execute(events):
        batches.append([event["event_id"] for event in events])
        return [MergeMiss() for _ in events]

    return batches, execute


@pytest.mark.asyncio
async def test_gc5_fifo_fills_at_eight_or_oldest_deadline(deterministic):
    """FP-GC5-1: exact FIFO groups, a full group immediately, one 10 ms budget."""
    clock, waiter = deterministic
    batches, execute = _batches_recorder()
    coalescer = MergeCommitCoalescer(execute)

    # (a) Constants are the fixed shape, and they are literals in the one
    # production carrier -- not a constructor argument of this object.
    assert MERGE_COMMIT_BATCH_SIZE == 8
    assert MERGE_COMMIT_MAX_WAIT_SECONDS == 0.010

    # (b) Nine simultaneous candidates: the first eight form one full group
    # without ANY wait, and the ninth is left for the next group.
    results = await asyncio.gather(
        *[coalescer.submit(_event(index)) for index in range(9)]
    )
    assert len(results) == 9
    assert all(isinstance(result, MergeMiss) for result in results)
    assert batches[0] == [f"event-{index}" for index in range(8)], batches
    assert batches[1] == ["event-8"], batches
    # The full group waited for nothing; only the remainder consumed a budget.
    assert waiter.timeouts == [pytest.approx(MERGE_COMMIT_MAX_WAIT_SECONDS)], (
        waiter.timeouts
    )

    # (c) A partial group waits exactly the oldest candidate's remaining
    # budget, measured from ITS enqueue time, not from the newest arrival.
    waiter.timeouts.clear()
    batches.clear()
    first = asyncio.ensure_future(coalescer.submit(_event(100)))
    await asyncio.sleep(0)
    clock.advance(0.004)
    second = asyncio.ensure_future(coalescer.submit(_event(101)))
    await asyncio.gather(first, second)
    assert batches == [["event-100", "event-101"]], batches
    # 0.006, not 0.010: the budget is measured from the OLDEST candidate's
    # enqueue time, so four milliseconds of it were already spent.
    assert waiter.timeouts == [pytest.approx(0.006)], waiter.timeouts

    # (d) An arrival that lands while the previous group is in the database
    # finds its own deadline already past and is taken immediately: the budget
    # bounds intentional collection delay, never time behind a group.
    waiter.timeouts.clear()
    batches.clear()
    gate = threading.Event()

    def gated_execute(events):
        batches.append([event["event_id"] for event in events])
        if len(batches) == 1:
            # Hold the first group inside its worker thread, so the loop is
            # free to accept an arrival behind it.
            assert gate.wait(10), "the first group was never released"
        return [MergeMiss() for _ in events]

    behind = MergeCommitCoalescer(gated_execute)
    full_group = [
        asyncio.ensure_future(behind.submit(_event(300 + index))) for index in range(8)
    ]
    while not batches:
        await asyncio.sleep(0.001)
    late = asyncio.ensure_future(behind.submit(_event(399)))
    await asyncio.sleep(0)
    assert behind.pending == 1, "the late arrival was not queued behind the group"
    clock.advance(0.050)  # its 10 ms budget expires while the group is running
    gate.set()
    await asyncio.gather(*full_group, late)
    assert batches == [[f"event-{300 + index}" for index in range(8)], ["event-399"]], (
        batches
    )
    # Neither group requested a wait: the first was full, and the second's
    # oldest deadline had already passed.
    assert waiter.timeouts == [], waiter.timeouts

    # (e) A group that FILLS while the drainer is waiting is taken at once,
    # without serving out the rest of its budget.
    waiter.timeouts.clear()
    batches.clear()
    waiter.arrive = True
    filling = MergeCommitCoalescer(execute)
    started_at = clock.now
    head = asyncio.ensure_future(filling.submit(_event(400)))
    await asyncio.sleep(0)
    rest = [
        asyncio.ensure_future(filling.submit(_event(400 + index)))
        for index in range(1, 8)
    ]
    await asyncio.gather(head, *rest)
    assert batches == [[f"event-{400 + index}" for index in range(8)]], batches
    # Exactly ONE wait was requested -- the head's whole budget -- and it was
    # not served out. The fake wait advances the fake clock only when a budget
    # expires, so an unmoved clock is the witness that the group was taken as
    # soon as the eighth candidate arrived; a drainer that waited on after that
    # arrival would show a second request and an advanced clock.
    assert waiter.timeouts == [pytest.approx(MERGE_COMMIT_MAX_WAIT_SECONDS)], (
        waiter.timeouts
    )
    assert clock.now == started_at, (
        f"the budget was served out after the group filled: the clock advanced "
        f"by {clock.now - started_at}"
    )
    waiter.arrive = False
    await filling.close()

    # (f) The real arrival wait, unfaked: True when an arrival lands inside
    # the budget, False when the budget expires first.
    arrival = asyncio.Event()
    assert await waiter.real(arrival, 0.001) is False
    arrival.set()
    assert await waiter.real(arrival, 0.001) is True

    await coalescer.close()
    await behind.close()


@pytest.mark.asyncio
async def test_gc5_submit_is_shielded_and_drainer_exit_cannot_strand_queue(
    deterministic,
):
    """FP-GC5-4/5: one drainer, strongly held; a crash fans out and refuses."""
    _clock, _waiter = deterministic

    # (a) One drainer task, strongly referenced while work is queued, and set
    # back to None under the same lock when the queue empties.
    started: list[int] = []

    def execute(events):
        started.append(len(events))
        return [MergeMiss() for _ in events]

    coalescer = MergeCommitCoalescer(execute)
    pending = [
        asyncio.ensure_future(coalescer.submit(_event(index))) for index in range(3)
    ]
    await asyncio.sleep(0)
    drainer = coalescer.drainer
    assert drainer is not None and not drainer.done()
    await asyncio.gather(*pending)
    assert started == [3]
    assert coalescer.drainer is None, "the drainer slot was not cleared"
    # ...and a later arrival gets a NEW drainer rather than an orphaned queue.
    assert isinstance(await coalescer.submit(_event(9)), MergeMiss)
    assert started == [3, 1]
    assert coalescer.pending == 0
    await coalescer.close()

    # (a2) The teardown window itself: the empty-queue check and the clearing
    # of the drainer slot happen under ONE hold of the same lock, with no
    # suspension point between them. An arrival can therefore only be seen by
    # this drainer (queue non-empty) or by the next one (slot already None),
    # never stranded between the two. This is asserted structurally because
    # the window a mutation opens is exactly one `await` wide: a behavioural
    # test would have to win a scheduling race to observe it.
    import ast
    import inspect

    loop_source = inspect.getsource(MergeCommitCoalescer._drain_loop)  # noqa: SLF001
    loop_tree = ast.parse(textwrap.dedent(loop_source)).body[0]
    guards = [
        node for node in ast.walk(loop_tree)
        if isinstance(node, ast.AsyncWith)
        and "self._lock" in ast.unparse(node.items[0].context_expr)
        and any(
            isinstance(inner, ast.Assign)
            and "self._drainer" in ast.unparse(inner.targets[0])
            for inner in ast.walk(node)
        )
    ]
    assert len(guards) == 1, "the drainer slot is not cleared under the lock"
    guard = guards[0]
    rendered = ast.unparse(guard)
    assert "if not self._queue" in rendered, (
        "the empty-queue check left the lock that clears the drainer slot"
    )
    assert "self._drainer = None" in rendered
    awaits = [node for node in ast.walk(guard) if isinstance(node, (ast.Await, ast.Yield))]
    assert awaits == [], (
        "a suspension point sits between the empty-queue check and the teardown"
    )

    # (b) An unexpected drainer exit fails every queued waiter with the cause
    # and permanently refuses admission for this service instance.
    boom = RuntimeError("drainer died")

    def exploding(events):
        raise boom

    crashing = MergeCommitCoalescer(exploding)
    first = asyncio.ensure_future(crashing.submit(_event(1)))
    with pytest.raises(RuntimeError, match="drainer died"):
        await first
    # A per-group failure is not a drainer crash: admission still works.
    assert crashing.closing is False
    with pytest.raises(RuntimeError, match="drainer died"):
        await crashing.submit(_event(2))

    # ...but a drainer that cannot even run its loop fails every waiter and
    # refuses everything afterwards.
    async def broken_loop(self):
        raise boom

    fatal = MergeCommitCoalescer(lambda events: [MergeMiss() for _ in events])
    queued = asyncio.ensure_future(fatal.submit(_event(3)))
    await asyncio.sleep(0)
    fatal._drain_loop = broken_loop.__get__(fatal, MergeCommitCoalescer)  # noqa: SLF001
    later = asyncio.ensure_future(fatal.submit(_event(4)))
    results = await asyncio.gather(queued, later, return_exceptions=True)
    assert any(isinstance(result, BaseException) for result in results)
    with pytest.raises(MergeCommitClosed):
        await fatal.submit(_event(5))
    assert fatal.pending == 0, "a waiter was stranded on an orphaned queue"
    await fatal.close()

    # (c) A cancelled drainer strands nothing either: the members it had
    # already taken off the queue fail with it, admission is refused
    # afterwards, and `close()` still returns.
    gate = threading.Event()
    entered = threading.Event()

    def held_execute(events):
        entered.set()
        assert gate.wait(10), "the held group was never released"
        return [MergeMiss() for _ in events]

    cancelled = MergeCommitCoalescer(held_execute)
    taken = [
        asyncio.ensure_future(cancelled.submit(_event(600 + index)))
        for index in range(8)
    ]
    while not entered.is_set():
        await asyncio.sleep(0.001)
    assert cancelled.pending == 0, "the group was not taken off the queue"
    drainer = cancelled.drainer
    assert drainer is not None
    drainer.cancel()
    outcomes = await asyncio.gather(*taken, return_exceptions=True)
    for outcome in outcomes:
        assert isinstance(outcome, MergeCommitClosed), outcome
    gate.set()
    with pytest.raises(MergeCommitClosed):
        await cancelled.submit(_event(699))
    await cancelled.close()

    # (d) A callback that answers a group with the wrong number of outcomes --
    # or with no sequence at all -- fails EVERY member of that group. Silently
    # zipping a short answer would leave the group's tail pending for ever,
    # which is the one thing FP-GC5-5 forbids: no accepted item may be left
    # waiting on an outcome that never comes. Each wait is bounded so a
    # stranded waiter is a failure here rather than a hung suite.
    for label, broken in (
        ("one outcome short", lambda events: [MergeMiss() for _ in events][:-1]),
        ("one outcome too many", lambda events: [MergeMiss() for _ in events] + [MergeMiss()]),
        ("not a sequence at all", lambda events: None),
    ):
        mismatched = MergeCommitCoalescer(broken)
        group = [
            asyncio.ensure_future(mismatched.submit(_event(700 + index)))
            for index in range(3)
        ]
        resolved = await asyncio.wait_for(
            asyncio.gather(*group, return_exceptions=True), 10
        )
        assert len(resolved) == 3, (label, resolved)
        for outcome in resolved:
            assert isinstance(outcome, RuntimeError), (label, outcome)
            assert "for 3 accepted items" in str(outcome), (label, outcome)
        assert mismatched.pending == 0, label
        await mismatched.close()


@pytest.mark.asyncio
async def test_gc5_cancellation_detaches_without_cancelling_accepted_work(
    deterministic,
):
    """FP-GC5-4: a cancelled waiter detaches; its accepted item still runs.

    Also the capacity claim: waiting for a group holds no database connection
    and no threadpool token -- the callback is entered once per group, and
    only while a group is being executed.
    """
    _clock, _waiter = deterministic
    seen: list[list[str]] = []
    concurrent = {"now": 0, "peak": 0}

    def execute(events):
        concurrent["now"] += 1
        concurrent["peak"] = max(concurrent["peak"], concurrent["now"])
        seen.append([event["event_id"] for event in events])
        try:
            return [MergeHit(uuid.uuid4()) for _ in events]
        finally:
            concurrent["now"] -= 1

    coalescer = MergeCommitCoalescer(execute)
    detached = asyncio.ensure_future(coalescer.submit(_event(1)))
    await asyncio.sleep(0)
    assert coalescer.pending == 1, "queueing did not accept the item"
    accepted = coalescer._queue[0].future  # noqa: SLF001 — the pinned invariant
    detached.cancel()
    with pytest.raises(asyncio.CancelledError):
        await detached
    # The waiter's cancellation did NOT cancel the accepted database item:
    # that is what the shielded await is for.
    assert not accepted.cancelled(), (
        "cancelling the HTTP waiter cancelled the accepted merge item"
    )
    # ...and the item reaches the database callback in its own group.
    kept = await coalescer.submit(_event(2))
    assert isinstance(kept, MergeHit)
    assert ["event-1"] in seen, seen
    assert accepted.done() and isinstance(accepted.result(), MergeHit)
    assert concurrent["peak"] == 1, "more than one group was active at a time"

    # A detached item whose group fails leaks no unobserved failure: its
    # outcome is retrieved, so the loop's exception handler never hears about
    # it when the future is collected.
    import gc

    loop = asyncio.get_running_loop()
    reported: list[dict] = []
    previous_handler = loop.get_exception_handler()
    loop.set_exception_handler(lambda _loop, context: reported.append(context))
    try:
        failing = MergeCommitCoalescer(
            lambda events: [RuntimeError("item failed") for _ in events]
        )
        lost = asyncio.ensure_future(failing.submit(_event(3)))
        await asyncio.sleep(0)
        lost_future = failing._queue[0].future  # noqa: SLF001
        lost.cancel()
        with pytest.raises(asyncio.CancelledError):
            await lost
        await failing.close()
        assert failing.pending == 0
        assert lost_future.done() and isinstance(
            lost_future.exception(), RuntimeError
        )
        del lost_future
        gc.collect()
        await asyncio.sleep(0)
    finally:
        loop.set_exception_handler(previous_handler)
    assert not [
        context for context in reported
        if "never retrieved" in str(context.get("message", ""))
    ], reported
    await coalescer.close()


@pytest.mark.asyncio
async def test_gc5_graceful_close_resolves_every_accepted_item_and_refuses_admission(
    deterministic,
):
    """FP-GC5-5: close drains accepted work, then refuses; loops stay separate."""
    _clock, _waiter = deterministic
    executed: list[str] = []

    def execute(events):
        executed.extend(event["event_id"] for event in events)
        return [MergeMiss() for _ in events]

    coalescer = MergeCommitCoalescer(execute)
    accepted = [
        asyncio.ensure_future(coalescer.submit(_event(index))) for index in range(4)
    ]
    await asyncio.sleep(0)
    assert coalescer.pending == 4

    # (a) Close waits for every accepted item and resolves all of them.
    await coalescer.close()
    assert coalescer.closing is True
    assert executed == [f"event-{index}" for index in range(4)], executed
    for future in accepted:
        assert isinstance(await future, MergeMiss)
    assert coalescer.pending == 0
    assert coalescer.drainer is None

    # (b) Admission after close is refused, not silently queued.
    with pytest.raises(MergeCommitClosed):
        await coalescer.submit(_event(99))
    assert coalescer.pending == 0

    # (c) Closing twice is idempotent and never raises.
    await coalescer.close()

    # (d) A second event loop is refused rather than served: one coalescer
    # belongs to exactly one worker loop.
    other = MergeCommitCoalescer(execute)
    await other.submit(_event(500))

    async def _from_another_loop():
        with pytest.raises(MergeCommitLoopError):
            await other.submit(_event(501))

    await asyncio.to_thread(asyncio.run, _from_another_loop())
    await other.close()
