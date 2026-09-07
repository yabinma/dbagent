"""Unit-tier workflow test (design.md Section 14.2: "All Activities mocked;
Temporal's time-skipping `WorkflowEnvironment`"). Runs `PingWorkflow`
against the real workflow engine (no live Temporal server needed) with the
real `echo` Activity -- there is nothing to mock since M1's `PingWorkflow`
has no external dependency.
"""
import uuid

import pytest
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from worker.activities.echo import echo
from worker.workflows.ping import PingWorkflow


@pytest.mark.asyncio
async def test_ping_workflow_round_trip():
    async with await WorkflowEnvironment.start_time_skipping() as env:
        async with Worker(
            env.client,
            task_queue="test-ping-queue",
            workflows=[PingWorkflow],
            activities=[echo],
        ):
            result = await env.client.execute_workflow(
                PingWorkflow.run,
                "hello",
                id=f"ping-{uuid.uuid4()}",
                task_queue="test-ping-queue",
            )
    assert result == "pong:hello"


@pytest.mark.asyncio
async def test_ping_workflow_default_message():
    async with await WorkflowEnvironment.start_time_skipping() as env:
        async with Worker(
            env.client,
            task_queue="test-ping-queue-2",
            workflows=[PingWorkflow],
            activities=[echo],
        ):
            result = await env.client.execute_workflow(
                PingWorkflow.run,
                id=f"ping-{uuid.uuid4()}",
                task_queue="test-ping-queue-2",
            )
    assert result == "pong:ping"
