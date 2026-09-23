"""Per-worker commit coalescer for the committed-existing-case merge (GC-5).

FP-GC5-1: one gateway worker owns exactly one FIFO coalescer. Starting from
the oldest queued event it takes at most ``MERGE_COMMIT_BATCH_SIZE``
candidates and waits no longer than ``MERGE_COMMIT_MAX_WAIT_SECONDS`` from
that event's enqueue time for the group to fill. The group is then handed, as
one list, to the callback the service bound at construction time -- which runs
the unchanged fused statement once per candidate inside its own savepoint and
performs at most one stock-durability outer commit.

FP-GC5-4/5: waiting for a group occupies neither a database connection nor a
threadpool token; request cancellation detaches the waiter without cancelling
the accepted database item; graceful close drains every accepted item and then
permanently refuses admission.

This module owns queueing and lifecycle only. It imports no database driver,
opens no Session, reads no configuration, and holds no process-shared object:
the two constants below are fixed implementation constants with no
environment, chart, YAML, query-string or caller override.
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections import deque
from dataclasses import dataclass
from typing import Any, Callable, Sequence

from starlette.concurrency import run_in_threadpool

logger = logging.getLogger(__name__)

#: Candidates per shared outer transaction. Eight is the batch shape whose
#: diagnostic control raised local merge throughput 2.91x (design/rca.md).
MERGE_COMMIT_BATCH_SIZE = 8
#: Collection budget measured from the OLDEST queued candidate, in seconds.
#: Small relative to the unchanged 150 ms client-lateness bound.
MERGE_COMMIT_MAX_WAIT_SECONDS = 0.010


@dataclass(frozen=True)
class MergeHit:
    """The fused statement merged this event into a committed case."""

    investigation_id: uuid.UUID


@dataclass(frozen=True)
class MergeMiss:
    """The fused statement found no committed case and wrote nothing."""


class MergeCommitClosed(RuntimeError):
    """Admission is refused: the coalescer is closing, closed, or failed."""


class MergeCommitLoopError(RuntimeError):
    """The coalescer was reached from a second event loop."""


@dataclass
class _PendingMerge:
    """One accepted candidate: its event, its enqueue instant, its future."""

    event: dict[str, Any]
    enqueued_at: float
    future: "asyncio.Future[Any]"


# Test seams, deliberately module-level names rather than constructor
# arguments: a caller-facing parameter would be an override of the fixed batch
# shape, which FP-GC5-1 forbids. Neither is read from configuration.
_monotonic = time.monotonic


async def _wait_for_arrival(arrival: asyncio.Event, timeout: float) -> bool:
    """Wait up to ``timeout`` for the next arrival; True if one happened."""
    try:
        await asyncio.wait_for(arrival.wait(), timeout)
    except (asyncio.TimeoutError, TimeoutError):
        return False
    return True


def _absorb(future: "asyncio.Future[Any]") -> None:
    """Retrieve a detached future's outcome so nothing is reported unobserved."""
    if not future.cancelled():
        future.exception()


class MergeCommitCoalescer:
    """One FIFO merge-batch queue, one drainer task, one bound executor."""

    def __init__(
        self,
        execute_batch: Callable[[Sequence[dict[str, Any]]], Sequence[Any]],
    ) -> None:
        self._execute_batch = execute_batch
        self._queue: "deque[_PendingMerge]" = deque()
        self._lock = asyncio.Lock()
        self._arrival = asyncio.Event()
        self._drainer: "asyncio.Task[None] | None" = None
        self._inflight: "list[_PendingMerge]" = []
        self._loop: "asyncio.AbstractEventLoop | None" = None
        self._closing = False
        self._failure: BaseException | None = None

    # -- admission ---------------------------------------------------------

    async def submit(self, event: dict[str, Any]) -> Any:
        """Queue one candidate and await its own outcome.

        Returns ``MergeHit`` or ``MergeMiss``; an item-local or batch-fatal
        failure is delivered as the exception itself. Cancellation of the
        caller detaches the waiter and leaves the accepted item to finish.
        """
        loop = asyncio.get_running_loop()
        if self._loop is None:
            self._loop = loop
        elif self._loop is not loop:
            raise MergeCommitLoopError(
                "the merge coalescer is bound to one worker event loop"
            )
        future: "asyncio.Future[Any]" = loop.create_future()
        async with self._lock:
            self._refuse_if_closed()
            self._queue.append(_PendingMerge(event, _monotonic(), future))
            self._arrival.set()
            if self._drainer is None:
                self._drainer = loop.create_task(self._drain())
        try:
            return await asyncio.shield(future)
        except asyncio.CancelledError:
            if not future.done():
                # The accepted item stays queued and still reaches the
                # database; nobody is waiting for its outcome any more, so
                # this coalescer consumes it.
                future.add_done_callback(_absorb)
            raise

    def _refuse_if_closed(self) -> None:
        if self._failure is not None:
            raise MergeCommitClosed(
                "the merge coalescer stopped after an unexpected drainer exit"
            ) from self._failure
        if self._closing:
            raise MergeCommitClosed("the merge coalescer is closing")

    # -- drainer -----------------------------------------------------------

    async def _drain(self) -> None:
        try:
            await self._drain_loop()
        except asyncio.CancelledError:
            self._fail_everything(
                MergeCommitClosed("the merge coalescer drainer was cancelled")
            )
            raise
        except BaseException as exc:  # noqa: BLE001 -- fan out, never strand
            logger.exception("merge coalescer drainer exited unexpectedly")
            self._fail_everything(exc)

    async def _drain_loop(self) -> None:
        while True:
            async with self._lock:
                if not self._queue:
                    # Under the same lock an arrival cannot be stranded
                    # between this check and the task's teardown.
                    self._drainer = None
                    return
                deadline = self._queue[0].enqueued_at + MERGE_COMMIT_MAX_WAIT_SECONDS
                full = len(self._queue) >= MERGE_COMMIT_BATCH_SIZE
            if not full:
                await self._await_group(deadline)
            async with self._lock:
                size = min(len(self._queue), MERGE_COMMIT_BATCH_SIZE)
                batch = [self._queue.popleft() for _ in range(size)]
            if batch:
                await self._run_batch(batch)

    async def _await_group(self, deadline: float) -> None:
        """Wait for eight candidates or for the oldest one's deadline.

        An arrival that lands while the previous group was in the database
        finds its deadline already past and is taken immediately: the budget
        bounds intentional collection delay, never time behind a batch.
        """
        while True:
            remaining = deadline - _monotonic()
            if remaining <= 0:
                return
            self._arrival.clear()
            async with self._lock:
                if len(self._queue) >= MERGE_COMMIT_BATCH_SIZE:
                    return
            if not await _wait_for_arrival(self._arrival, remaining):
                return

    async def _run_batch(self, batch: "list[_PendingMerge]") -> None:
        events = [item.event for item in batch]
        # Held so a drainer that dies mid-group still resolves the members it
        # already took off the queue, rather than stranding their waiters.
        self._inflight = list(batch)
        try:
            outcomes = await asyncio.shield(
                run_in_threadpool(self._execute_batch, events)
            )
        except asyncio.CancelledError:
            # Deliberately NOT cleared: the members are still unresolved, and
            # the drainer's own handler is what fails them.
            raise
        except BaseException as exc:  # noqa: BLE001 -- the whole group fails
            self._inflight = []
            for item in batch:
                _resolve_exception(item.future, exc)
            return
        self._inflight = []
        try:
            resolved = list(outcomes)
        except TypeError:
            resolved = None
        if resolved is None or len(resolved) != len(batch):
            # One outcome per accepted item, or the whole group fails: zipping a
            # short answer would leave this group's tail waiting for an outcome
            # that never comes, which FP-GC5-5 forbids outright.
            answered = type(outcomes).__name__ if resolved is None else len(resolved)
            for item in batch:
                _resolve_exception(
                    item.future,
                    RuntimeError(
                        f"the merge group callback answered {answered} "
                        f"for {len(batch)} accepted items"
                    ),
                )
            return
        for item, outcome in zip(batch, resolved):
            if isinstance(outcome, BaseException):
                _resolve_exception(item.future, outcome)
            else:
                _resolve_result(item.future, outcome)

    def _fail_everything(self, exc: BaseException) -> None:
        """Fail every accepted item and refuse admission from now on."""
        self._failure = exc
        self._closing = True
        self._drainer = None
        stranded, self._inflight = self._inflight, []
        for item in stranded:
            _resolve_exception(item.future, exc)
        while self._queue:
            _resolve_exception(self._queue.popleft().future, exc)

    # -- lifecycle ---------------------------------------------------------

    async def close(self) -> None:
        """Stop admission, then wait for every accepted item to resolve."""
        async with self._lock:
            self._closing = True
            drainer = self._drainer
        self._arrival.set()
        if drainer is None:
            return
        try:
            await asyncio.shield(drainer)
        except asyncio.CancelledError:
            # A cancelled DRAINER has already failed every accepted item, so
            # close has nothing left to wait for; a cancelled CALLER is never
            # masked.
            if not drainer.cancelled():
                raise
            logger.warning("merge coalescer drainer was cancelled during close")
        except BaseException:  # noqa: BLE001 -- already fanned out to waiters
            logger.exception("merge coalescer drainer failed during close")

    @property
    def closing(self) -> bool:
        return self._closing

    @property
    def pending(self) -> int:
        return len(self._queue)

    @property
    def drainer(self) -> "asyncio.Task[None] | None":
        return self._drainer


def _resolve_result(future: "asyncio.Future[Any]", outcome: Any) -> None:
    if not future.done():
        future.set_result(outcome)


def _resolve_exception(future: "asyncio.Future[Any]", exc: BaseException) -> None:
    if not future.done():
        future.set_exception(exc)
