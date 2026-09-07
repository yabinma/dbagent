"""Control-plane tools executed without the probe (design.md Section 8.5).

``read_evidence``, ``fetch_source``, ``diff_versions``, ``search_commits``.
External GitHub access is injected so unit/functional tests never hit the
network (Section 14.1).
"""
from __future__ import annotations

import uuid
from typing import Any, Protocol


class SourceStore(Protocol):
    def fetch_source(self, file_path: str, ref: str) -> str: ...
    def diff_versions(self, path_or_symbol: str, from_tag: str, to_tag: str) -> str: ...
    def search_commits(self, keyword: str, from_tag: str, limit: int = 10) -> list[dict[str, str]]: ...


class FakeSourceStore:
    """Deterministic in-memory source store for tests."""

    def __init__(self, files: dict[str, str] | None = None, commits: list[dict[str, str]] | None = None):
        self.files = files or {}
        self.commits = commits or []

    def fetch_source(self, file_path: str, ref: str) -> str:
        key = f"{ref}:{file_path}"
        return self.files.get(key, self.files.get(file_path, f"// source for {file_path}@{ref}\n"))

    def diff_versions(self, path_or_symbol: str, from_tag: str, to_tag: str) -> str:
        return f"--- {path_or_symbol} {from_tag}\n+++ {path_or_symbol} {to_tag}\n"

    def search_commits(self, keyword: str, from_tag: str, limit: int = 10) -> list[dict[str, str]]:
        hits = [c for c in self.commits if keyword.lower() in c.get("message", "").lower()]
        return hits[:limit]


class ObjectStoreReader(Protocol):
    def get_bytes(self, key: str) -> bytes: ...


async def run_control_tool(
    tool: str,
    args: dict[str, Any],
    *,
    source_store: SourceStore,
    evidence_lookup,
    object_store: ObjectStoreReader | None = None,
) -> dict[str, Any]:
    """Dispatch a control tool; returns a tool-result-shaped dict."""
    if tool == "read_evidence":
        evidence_id = args.get("evidence_id")
        byte_range = args.get("byte_range")  # optional [start, end]
        row = evidence_lookup(evidence_id)
        if row is None:
            return {"tool": tool, "exit_code": 1, "data": {"error": "not_found"}}
        payload = b""
        if object_store is not None and getattr(row, "payload_ref", None):
            payload = object_store.get_bytes(row.payload_ref)
        elif isinstance(row, dict):
            payload = (row.get("payload") or "").encode() if isinstance(row.get("payload"), str) else b""
            if isinstance(row.get("payload"), (bytes, bytearray)):
                payload = bytes(row.get("payload"))
            elif row.get("payload") is not None and not isinstance(row.get("payload"), str):
                import json

                payload = json.dumps(row.get("payload")).encode()
        if byte_range and isinstance(byte_range, (list, tuple)) and len(byte_range) == 2:
            start, end = int(byte_range[0]), int(byte_range[1])
            payload = payload[start:end]
        return {
            "tool": tool,
            "exit_code": 0,
            "data": {
                "evidence_id": str(evidence_id),
                "bytes": payload.decode("utf-8", errors="replace"),
                "byte_length": len(payload),
            },
        }
    if tool == "fetch_source":
        content = source_store.fetch_source(args.get("file_path", ""), args.get("ref", "HEAD"))
        return {"tool": tool, "exit_code": 0, "data": {"content": content}}
    if tool == "diff_versions":
        diff = source_store.diff_versions(
            args.get("path_or_symbol", ""),
            args.get("from_tag", ""),
            args.get("to_tag", ""),
        )
        return {"tool": tool, "exit_code": 0, "data": {"diff": diff}}
    if tool == "search_commits":
        commits = source_store.search_commits(
            args.get("keyword", ""),
            args.get("from_tag", ""),
            int(args.get("limit", 10)),
        )
        return {"tool": tool, "exit_code": 0, "data": {"commits": commits}}
    return {"tool": tool, "exit_code": 1, "data": {"error": f"unknown control tool {tool}"}}
