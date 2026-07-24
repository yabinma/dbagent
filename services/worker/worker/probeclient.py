"""HTTP client for probe-gateway's internal ExecuteTool API (Section 3.2).

M2 exposed ``gwserver.Server.Dispatch`` in-process only. M3 wires a
cross-language HTTP surface (``POST /internal/v1/execute``) so Python
Activities can dispatch ToolCall / RawCommand tasks. Unit/functional
tests inject a ``FakeProbeGatewayClient`` instead of hitting the network.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Protocol

import httpx


@dataclass
class ToolExecutionResult:
    task_id: str
    exit_code: int
    data: dict[str, Any] | list | str | None
    raw_bytes: bytes
    redacted: bool
    truncated: bool
    error: str | None = None
    probe_id: str | None = None


class ProbeGatewayClient(Protocol):
    async def execute_tool(
        self,
        platform_key: str,
        *,
        tool: str,
        args: dict[str, Any] | None = None,
        timeout_seconds: int = 60,
        task_id: str | None = None,
    ) -> ToolExecutionResult: ...

    async def execute_raw_command(
        self,
        platform_key: str,
        *,
        command: str,
        timeout_seconds: int = 60,
        task_id: str | None = None,
    ) -> ToolExecutionResult: ...


class HTTPProbeGatewayClient:
    """Production client against probe-gateway's internal HTTP dispatch API."""

    def __init__(
        self,
        base_url: str,
        *,
        client: httpx.AsyncClient | None = None,
        timeout_seconds: int = 120,
    ):
        self._base_url = base_url.rstrip("/")
        self._client = client
        self._timeout = timeout_seconds
        self._owns_client = client is None

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout)
        return self._client

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def execute_tool(
        self,
        platform_key: str,
        *,
        tool: str,
        args: dict[str, Any] | None = None,
        timeout_seconds: int = 60,
        task_id: str | None = None,
    ) -> ToolExecutionResult:
        return await self._execute(
            platform_key,
            kind="tool",
            tool=tool,
            args=args or {},
            timeout_seconds=timeout_seconds,
            task_id=task_id,
        )

    async def execute_raw_command(
        self,
        platform_key: str,
        *,
        command: str,
        timeout_seconds: int = 60,
        task_id: str | None = None,
    ) -> ToolExecutionResult:
        return await self._execute(
            platform_key,
            kind="raw_command",
            command=command,
            timeout_seconds=timeout_seconds,
            task_id=task_id,
        )

    async def _execute(
        self,
        platform_key: str,
        *,
        kind: str,
        tool: str | None = None,
        args: dict[str, Any] | None = None,
        command: str | None = None,
        timeout_seconds: int = 60,
        task_id: str | None = None,
    ) -> ToolExecutionResult:
        tid = task_id or str(uuid.uuid4())
        body: dict[str, Any] = {
            "platform_key": platform_key,
            "task_id": tid,
            "kind": kind,
            "timeout_seconds": timeout_seconds,
        }
        if kind == "tool":
            body["tool"] = tool
            body["args"] = args or {}
        else:
            body["command"] = command
        resp = await self._http().post(f"{self._base_url}/internal/v1/execute", json=body)
        resp.raise_for_status()
        payload = resp.json()
        data = payload.get("data")
        raw = resp.content
        return ToolExecutionResult(
            task_id=tid,
            exit_code=int(payload.get("exit_code", 0)),
            data=data,
            raw_bytes=raw if isinstance(raw, (bytes, bytearray)) else str(data).encode(),
            redacted=bool(payload.get("redacted", False)),
            truncated=bool(payload.get("truncated", False)),
            error=payload.get("error"),
            probe_id=payload.get("probe_id"),
        )


class FakeProbeGatewayClient:
    """Scripted fake for unit/functional tests (Section 14.1 isolation)."""

    def __init__(self, script: dict[str, Any] | None = None):
        # script maps tool name -> envelope data (or list of sequential results)
        self.script = script or {}
        self.calls: list[dict[str, Any]] = []
        self._counters: dict[str, int] = {}

    def _next(self, key: str) -> Any:
        value = self.script.get(key, {"ok": True})
        if isinstance(value, list):
            idx = self._counters.get(key, 0)
            self._counters[key] = idx + 1
            return value[min(idx, len(value) - 1)]
        return value

    async def execute_tool(
        self,
        platform_key: str,
        *,
        tool: str,
        args: dict[str, Any] | None = None,
        timeout_seconds: int = 60,
        task_id: str | None = None,
    ) -> ToolExecutionResult:
        self.calls.append(
            {"kind": "tool", "platform_key": platform_key, "tool": tool, "args": args or {}}
        )
        data = self._next(tool)
        if isinstance(data, Exception):
            raise data
        import json

        raw = json.dumps(data).encode()
        return ToolExecutionResult(
            task_id=task_id or str(uuid.uuid4()),
            exit_code=int(data.get("exit_code", 0)) if isinstance(data, dict) else 0,
            data=data,
            raw_bytes=raw,
            redacted=bool(data.get("redacted", False)) if isinstance(data, dict) else False,
            truncated=bool(data.get("truncated", False)) if isinstance(data, dict) else False,
            probe_id="fake-probe",
        )

    async def execute_raw_command(
        self,
        platform_key: str,
        *,
        command: str,
        timeout_seconds: int = 60,
        task_id: str | None = None,
    ) -> ToolExecutionResult:
        self.calls.append(
            {"kind": "raw_command", "platform_key": platform_key, "command": command}
        )
        data = self._next("raw_command")
        import json

        raw = json.dumps(data).encode()
        return ToolExecutionResult(
            task_id=task_id or str(uuid.uuid4()),
            exit_code=0,
            data=data,
            raw_bytes=raw,
            redacted=False,
            truncated=False,
            probe_id="fake-probe",
        )
