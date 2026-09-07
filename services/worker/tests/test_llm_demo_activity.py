import pytest
from temporalio.testing import ActivityEnvironment

from rca_common.llmclient import LLMClient
from rca_common.llmclient.backend import ChatCompletionResponse
from rca_common.llmclient.objectstore import FakeObjectStore
from rca_common.llmclient.tracestore import FakeTraceStore

from worker.activities.llm_demo import LLMDemoActivities, LLMDemoInput


class _FakeBackend:
    async def chat_completion(self, **kwargs):
        return ChatCompletionResponse(
            content="demo response",
            input_tokens=7,
            output_tokens=3,
            cost_usd=0.0011,
            provider="mock",
            raw={"choices": [{"message": {"content": "demo response"}}]},
        )


@pytest.mark.asyncio
async def test_llm_demo_activity_invokes_llm_client_once_and_writes_trace():
    object_store = FakeObjectStore()
    trace_store = FakeTraceStore()
    llm_client = LLMClient(
        backend=_FakeBackend(),
        object_store=object_store,
        trace_store=trace_store,
        tracing_backend="builtin",
    )
    activities = LLMDemoActivities(llm_client)

    env = ActivityEnvironment()
    result = await env.run(
        activities.generate,
        LLMDemoInput(agent_role="planner", model="ollama/qwen2.5:14b", prompt="say hi"),
    )

    assert result.content == "demo response"
    assert result.cost_usd == pytest.approx(0.0011)
    assert result.input_tokens == 7
    assert result.output_tokens == 3
    assert len(trace_store.records) == 1
    assert trace_store.records[0].agent_role == "planner"
