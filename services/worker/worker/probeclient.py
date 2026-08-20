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

    async def execute_write(
        self,
        platform_key: str,
        *,
        playbook_id: str,
        step_index: int,
        op: str,
        params: dict[str, Any],
        execution_id: str,
        signature_b64: str,
        timeout_seconds: int = 60,
        task_id: str | None = None,
    ) -> ToolExecutionResult: ...

    async def execute_health(
        self,
        platform_key: str,
        *,
        builtin: bool = True,
        custom_query: str = "",
        wait_seconds: int = 0,
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

    async def execute_write(
        self,
        platform_key: str,
        *,
        playbook_id: str,
        step_index: int,
        op: str,
        params: dict[str, Any],
        execution_id: str,
        signature_b64: str,
        timeout_seconds: int = 60,
        task_id: str | None = None,
    ) -> ToolExecutionResult:
        return await self._execute(
            platform_key,
            kind="write",
            playbook_id=playbook_id,
            step_index=step_index,
            op=op,
            params=params or {},
            execution_id=execution_id,
            signature_b64=signature_b64,
            timeout_seconds=timeout_seconds,
            task_id=task_id,
        )

    async def execute_health(
        self,
        platform_key: str,
        *,
        builtin: bool = True,
        custom_query: str = "",
        wait_seconds: int = 0,
        timeout_seconds: int = 60,
        task_id: str | None = None,
    ) -> ToolExecutionResult:
        return await self._execute(
            platform_key,
            kind="health",
            builtin=builtin,
            custom_query=custom_query,
            wait_seconds=wait_seconds,
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
        playbook_id: str | None = None,
        step_index: int | None = None,
        op: str | None = None,
        params: dict[str, Any] | None = None,
        execution_id: str | None = None,
        signature_b64: str | None = None,
        builtin: bool | None = None,
        custom_query: str | None = None,
        wait_seconds: int | None = None,
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
        elif kind == "raw_command":
            body["command"] = command
        elif kind == "write":
            body["playbook_id"] = playbook_id
            body["step_index"] = step_index
            body["op"] = op
            body["params"] = params or {}
            body["execution_id"] = execution_id
            body["control_plane_signature"] = signature_b64
        elif kind == "health":
            body["builtin"] = True if builtin is None else builtin
            body["custom_query"] = custom_query or ""
            body["wait_seconds"] = wait_seconds or 0
        resp = await self._http().post(f"{self._base_url}/internal/v1/execute", json=body)
        if resp.status_code == 502 and (
            "task dispatch timed out" in resp.text
            or "context deadline exceeded" in resp.text
        ):
            return ToolExecutionResult(
                task_id=tid,
                exit_code=1,
                data=None,
                raw_bytes=resp.content,
                redacted=False,
                truncated=False,
                error=resp.text.strip(),
            )
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
        # query_ids removed by successful presto_kill_query writes (M5 closed loop)
        self._killed_queries: set[str] = set()

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
        import copy

        if isinstance(data, dict) and tool == "presto_list_queries" and self._killed_queries:
            data = copy.deepcopy(data)
            # Filter killed queries from common envelope shapes.
            for key in ("queries",):
                if isinstance(data.get(key), list):
                    data[key] = [
                        q
                        for q in data[key]
                        if not (
                            isinstance(q, dict)
                            and (
                                q.get("queryId") in self._killed_queries
                                or q.get("query_id") in self._killed_queries
                                or q.get("id") in self._killed_queries
                            )
                        )
                        and q not in self._killed_queries
                    ]
            inner = data.get("data")
            if isinstance(inner, dict) and isinstance(inner.get("queries"), list):
                inner["queries"] = [
                    q
                    for q in inner["queries"]
                    if not (
                        isinstance(q, dict)
                        and (
                            q.get("queryId") in self._killed_queries
                            or q.get("query_id") in self._killed_queries
                            or q.get("id") in self._killed_queries
                        )
                    )
                    and q not in self._killed_queries
                ]

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

    async def execute_write(
        self,
        platform_key: str,
        *,
        playbook_id: str,
        step_index: int,
        op: str,
        params: dict[str, Any],
        execution_id: str,
        signature_b64: str,
        timeout_seconds: int = 60,
        task_id: str | None = None,
    ) -> ToolExecutionResult:
        rec = {
            "kind": "write",
            "platform_key": platform_key,
            "playbook_id": playbook_id,
            "step_index": step_index,
            "op": op,
            "params": params or {},
            "execution_id": execution_id,
            "signature_b64": signature_b64,
        }
        self.calls.append(rec)
        import json

        data = self._next(f"write:{op}")
        if data == {"ok": True} and f"write:{op}" not in self.script:
            data = self._next("write")
        if isinstance(data, Exception):
            raise data
        if isinstance(data, dict):
            exit_code = int(data.get("exit_code", 0 if data.get("ok", True) else 1))
            err = data.get("error")
            if not data.get("ok", True) and exit_code == 0:
                exit_code = 1
        else:
            exit_code = 0
            err = None
        if exit_code == 0 and op == "presto_kill_query":
            qid = (params or {}).get("query_id")
            if qid:
                self._killed_queries.add(str(qid))
        raw = json.dumps(data).encode()
        return ToolExecutionResult(
            task_id=task_id or str(uuid.uuid4()),
            exit_code=exit_code,
            data=data,
            raw_bytes=raw,
            redacted=False,
            truncated=False,
            error=err,
            probe_id="fake-probe",
        )

    async def execute_health(
        self,
        platform_key: str,
        *,
        builtin: bool = True,
        custom_query: str = "",
        wait_seconds: int = 0,
        timeout_seconds: int = 60,
        task_id: str | None = None,
    ) -> ToolExecutionResult:
        self.calls.append(
            {
                "kind": "health",
                "platform_key": platform_key,
                "builtin": builtin,
                "custom_query": custom_query,
                "wait_seconds": wait_seconds,
            }
        )
        import json

        data = self._next("health")
        if isinstance(data, Exception):
            raise data
        if isinstance(data, dict):
            exit_code = int(data.get("exit_code", 0 if data.get("ok", True) else 1))
            err = data.get("error")
        else:
            exit_code = 0
            err = None
            data = {"ok": True}
        raw = json.dumps(data).encode()
        return ToolExecutionResult(
            task_id=task_id or str(uuid.uuid4()),
            exit_code=exit_code,
            data=data,
            raw_bytes=raw,
            redacted=False,
            truncated=False,
            error=err,
            probe_id="fake-probe",
        )
