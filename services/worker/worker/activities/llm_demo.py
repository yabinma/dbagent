"""Demo Activity that proves `LLMClient` works end to end inside a real
Temporal Activity (design.md Section 12 M1 acceptance: "one model call
produces an `llm_calls` row + S3 objects"). This is a standalone Activity
built for M1's acceptance proof only -- it is distinct from the four
production agent Activities (planner/collector/rca/remediation), which are
M3 scope (Section 5.2/5.3).

Bound to a concrete `LLMClient` at worker start-up (see `worker_main.py`)
so the Activity body stays a thin call-through, consistent with Section
7/D5: the `llmclient` wrapper is the sole call path for every model call.
"""
from __future__ import annotations

from dataclasses import dataclass

from temporalio import activity

from rca_common.llmclient import LLMClient


@dataclass
class LLMDemoInput:
    agent_role: str
    model: str
    prompt: str
    max_tokens: int = 200
    investigation_id: str | None = None


@dataclass
class LLMDemoOutput:
    call_id: str
    content: str
    cost_usd: float | None
    input_tokens: int | None
    output_tokens: int | None


class LLMDemoActivities:
    def __init__(self, llm_client: LLMClient):
        self._llm_client = llm_client

    @activity.defn(name="llm_demo_generate")
    async def generate(self, input: LLMDemoInput) -> LLMDemoOutput:
        result = await self._llm_client.generate(
            agent_role=input.agent_role,
            model=input.model,
            max_tokens=input.max_tokens,
            messages=[{"role": "user", "content": input.prompt}],
            investigation_id=input.investigation_id,
        )
        return LLMDemoOutput(
            call_id=str(result.call_id),
            content=result.content,
            cost_usd=result.cost_usd,
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
        )
