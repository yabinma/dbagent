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
async def test_http_client_dispatch_timeout_502_returns_error_envelope():
    respx.post("http://pgw/internal/v1/execute").mock(
        return_value=httpx.Response(502, text="gwserver: task dispatch timed out")
    )
    client = HTTPProbeGatewayClient("http://pgw")
    r = await client.execute_tool("presto-us1", tool="presto_list_queries", args={})
    assert r.exit_code == 1
    assert "task dispatch timed out" in (r.error or "")
    await client.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_http_client_probe_not_connected_502_raises():
    respx.post("http://pgw/internal/v1/execute").mock(
        return_value=httpx.Response(502, text="gwserver: no active session for platform")
    )
    client = HTTPProbeGatewayClient("http://pgw")
    with pytest.raises(httpx.HTTPStatusError):
        await client.execute_tool("presto-us1", tool="presto_list_queries", args={})
    await client.aclose()


@pytest.mark.asyncio
@respx.mock
async def test_http_client_context_deadline_502_returns_error_envelope():
    respx.post("http://pgw/internal/v1/execute").mock(
        return_value=httpx.Response(502, text="context deadline exceeded")
    )
    client = HTTPProbeGatewayClient("http://pgw")
    r = await client.execute_tool("presto-us1", tool="presto_list_queries", args={})
    assert r.exit_code == 1
    assert "context deadline exceeded" in (r.error or "")
    await client.aclose()


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


import base64
import respx
import httpx
import pytest


@pytest.mark.asyncio
async def test_fake_execute_write_records_signature():
    client = FakeProbeGatewayClient({"write": {"ok": True, "exit_code": 0}})
    r = await client.execute_write(
        "p1",
        playbook_id="presto.kill_query",
        step_index=0,
        op="presto_kill_query",
        params={"query_id": "q"},
        execution_id="e1",
        signature_b64=base64.b64encode(b"x" * 64).decode(),
    )
    assert r.exit_code == 0
    assert client.calls[0]["kind"] == "write"
    assert client.calls[0]["op"] == "presto_kill_query"


@pytest.mark.asyncio
async def test_http_execute_write_body_shape():
    async with httpx.AsyncClient() as http:
        # Use respx if available, else ASGI transport not needed — mock transport.
        pass


@pytest.mark.asyncio
async def test_http_execute_write_posts_kind_write(monkeypatch):
    captured = {}

    class FakeResp:
        status_code = 200
        content = b'{"exit_code":0,"data":{"ok":true}}'

        def raise_for_status(self):
            return None

        def json(self):
            return {"exit_code": 0, "data": {"ok": True}}

    class FakeHTTP:
        async def post(self, url, json=None):
            captured["url"] = url
            captured["json"] = json
            return FakeResp()

        async def aclose(self):
            return None

    client = HTTPProbeGatewayClient("http://gateway:8080", client=None)
    client._client = FakeHTTP()  # type: ignore[assignment]
    r = await client.execute_write(
        "p1",
        playbook_id="presto.kill_query",
        step_index=0,
        op="presto_kill_query",
        params={"query_id": "q"},
        execution_id="e1",
        signature_b64="YWJj",
    )
    assert r.exit_code == 0
    assert captured["json"]["kind"] == "write"
    assert captured["json"]["op"] == "presto_kill_query"
    assert captured["json"]["control_plane_signature"] == "YWJj"
