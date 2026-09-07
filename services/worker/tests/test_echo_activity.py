import pytest
from temporalio.testing import ActivityEnvironment

from worker.activities.echo import echo


@pytest.mark.asyncio
async def test_echo_returns_pong_prefixed_message():
    env = ActivityEnvironment()
    result = await env.run(echo, "hello")
    assert result == "pong:hello"
