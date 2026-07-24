"""Unit tests for FakeProbeGatewayClient + HTTP client shape."""
import pytest
import respx
import httpx

from worker.probeclient import FakeProbeGatewayClient, HTTPProbeGatewayClient


@pytest.mark.asyncio
async def test_fake_records_calls():
    client = FakeProbeGatewayClient({"presto_nodes": {"exit_code": 0, "data": {"n": 1}}})
    r = await client.execute_tool("pk", tool="presto_nodes", args={})
    assert r.exit_code == 0
    assert client.calls[0]["tool"] == "presto_nodes"


@pytest.mark.asyncio
@respx.mock
async def test_http_client_execute_tool():
    respx.post("http://pgw/internal/v1/execute").mock(
        return_value=httpx.Response(
            200,
            json={
                "task_id": "t1",
                "exit_code": 0,
                "data": {"ok": True},
                "redacted": False,
                "truncated": False,
                "probe_id": "p1",
            },
        )
    )
    client = HTTPProbeGatewayClient("http://pgw")
    r = await client.execute_tool("presto-us1", tool="presto_cluster_info", args={})
    assert r.exit_code == 0
    assert r.data["ok"] is True
    await client.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_http_client_raw_command():
    respx.post("http://pgw/internal/v1/execute").mock(
        return_value=httpx.Response(
            200,
            json={"task_id": "t2", "exit_code": 0, "data": "out", "redacted": False, "truncated": False},
        )
    )
    client = HTTPProbeGatewayClient("http://pgw")
    r = await client.execute_raw_command("presto-us1", command="cat /x")
    assert r.exit_code == 0
    await client.aclose()
