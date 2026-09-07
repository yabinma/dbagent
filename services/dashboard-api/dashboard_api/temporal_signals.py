"""Temporal signal helpers for dashboard-api (string signal names; no worker import)."""
from __future__ import annotations

from typing import Any, Protocol


class TemporalClientProto(Protocol):
    def get_workflow_handle(self, workflow_id: str) -> Any: ...


class WorkflowNotRunning(Exception):
    """Raised when a signal targets a closed/unknown workflow."""


async def signal_workflow(
    client: Any,
    workflow_id: str,
    signal_name: str,
    arg: Any = None,
) -> None:
    """Send a named Temporal Signal. Maps closed-workflow RPC errors to WorkflowNotRunning."""
    if client is None:
        raise WorkflowNotRunning("no temporal client configured")
    handle = client.get_workflow_handle(workflow_id)
    try:
        if arg is None:
            await handle.signal(signal_name)
        else:
            await handle.signal(signal_name, arg)
    except Exception as exc:  # noqa: BLE001 — Temporal RPC surface varies by version
        msg = str(exc).lower()
        name = type(exc).__name__
        if any(
            s in msg
            for s in (
                "not found",
                "not running",
                "completed",
                "terminated",
                "canceled",
                "failed",
                "workflow execution already completed",
                "no running",
            )
        ) or "WorkflowNotFound" in name or "RPCError" in name and "not found" in msg:
            raise WorkflowNotRunning(str(exc)) from exc
        # Some Temporal versions raise ApplicationError / RPCError with status.
        status = getattr(exc, "status", None) or getattr(exc, "grpc_status", None)
        if status is not None and str(status) in ("5", "NOT_FOUND", "Status.NOT_FOUND"):
            raise WorkflowNotRunning(str(exc)) from exc
        raise
