"""`PingWorkflow` — a minimal Temporal round-trip proof standing in for
M1's "empty workflow" acceptance criterion (design.md Section 12: "An
empty workflow runs end to end"). The full `InvestigationWorkflow`
(Section 5) is explicitly M3 scope; this workflow exists only to prove the
worker/Temporal plumbing (registration, task queue dispatch, Activity
execution, result return) works end to end.
"""
from __future__ import annotations

from datetime import timedelta

from temporalio import workflow

with workflow.unsafe.imports_passed_through():
    from worker.activities.echo import echo


@workflow.defn
class PingWorkflow:
    @workflow.run
    async def run(self, message: str = "ping") -> str:
        return await workflow.execute_activity(
            echo,
            message,
            start_to_close_timeout=timedelta(seconds=10),
        )
