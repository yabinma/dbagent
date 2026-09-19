"""Minimal Activity used by `PingWorkflow` (design.md Section 12 M1
acceptance: "An empty workflow runs end to end"). Deliberately has no
dependency on `rca_common` so it can be exercised without any external
infrastructure at all.
"""
from __future__ import annotations

from temporalio import activity


@activity.defn
async def echo(message: str) -> str:
    return f"pong:{message}"
