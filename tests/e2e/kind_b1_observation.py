"""Kind B1 burst p99 observation (kind-deploy-tuning FP-KDT-2/3).

Not collected by pytest (the name does not match ``test_*``). The live kind
burst ``tests/e2e/test_e2e_load.py::test_b1_ingest_burst_profile`` calls
:func:`emit_kind_b1_p99` once, right after its open-loop baseline returns, to
REPORT the baseline's nearest-rank due-time p99 against the 150 ms figure.

The comparison is an observation, never a verdict: nothing here asserts,
raises, returns early, skips or retries on the comparison's result. The only
failures this module produces are observation-integrity errors -- a
non-finite p99 (there is no real measurement to report) or a failed write of
the line -- and a finite p99 at or above the threshold is not one of them.

The line is written to ``output_path`` (``/tmp/rca-e2e/b1-kind-p99.txt`` in
the live test, which ``tests/e2e/run.sh`` prints after a passing
``pytest_e2e`` phase and the failure artifact carries otherwise) and printed
with ``flush=True``. Its grammar is exactly::

    B1 kind p99_ms=<Python float repr>,threshold_ms=150.0,under_150=<true|false>
"""
from __future__ import annotations

import math
from pathlib import Path
from typing import Callable

#: The pytest property that carries the comparison's Boolean.
KIND_B1_P99_PROPERTY = "b1_kind_p99_lt_150_ms"
#: The live test's output file; run.sh's two named functions default to it.
KIND_B1_P99_PATH = Path("/tmp/rca-e2e/b1-kind-p99.txt")


class KindB1ObservationError(ValueError):
    """The p99 cannot be reported honestly (measurement integrity, not a miss)."""


def emit_kind_b1_p99(
    p99_ms: float,
    threshold_ms: float,
    record_property: Callable[[str, object], None],
    output_path: Path,
) -> str:
    """Record, write and print one kind p99 observation line; return it.

    ``under_150`` is ``p99_ms < threshold_ms``, computed exactly once; a p99
    of exactly the threshold is ``false``. Raises
    :class:`KindB1ObservationError` for a non-finite p99 before anything is
    recorded, written or printed, and removes any earlier line at
    ``output_path``, so no misleading line exists.
    """
    p99 = float(p99_ms)
    threshold = float(threshold_ms)
    output = Path(output_path)
    if not math.isfinite(p99):
        # A line left by an earlier run must not stand in for this one.
        output.unlink(missing_ok=True)
        raise KindB1ObservationError(
            f"kind B1 p99 is not a finite measurement ({p99!r}); "
            "no observation line is written"
        )
    under = p99 < threshold
    record_property(KIND_B1_P99_PROPERTY, under)
    line = (
        f"B1 kind p99_ms={p99!r},threshold_ms={threshold!r},"
        f"under_150={'true' if under else 'false'}"
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(line + "\n", encoding="utf-8")
    print(line, flush=True)
    return line
