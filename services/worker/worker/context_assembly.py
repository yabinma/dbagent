"""RCA context assembly (design.md Section 5.3 / B14).

The RCA prompt injects: all evidence **summaries** + the **latest round's
full payloads** + compact versions of previous RCA reports. Keeps context
cost bounded while preserving full-detail reachability via ``read_evidence``.
"""
from __future__ import annotations

import json
import time
from typing import Any


def compact_report(report: dict[str, Any]) -> dict[str, Any]:
    """Reduce a prior RCA report to the fields useful for follow-up rounds."""
    return {
        "status": report.get("status"),
        "confidence": report.get("confidence"),
        "root_cause": report.get("root_cause"),
        "rca_compact": report.get("rca_compact"),
        "missing_info": report.get("missing_info"),
    }


def assemble_rca_context(
    *,
    event: dict[str, Any],
    evidence: list[dict[str, Any]],
    reports: list[dict[str, Any]],
    round_num: int,
    max_rounds: int,
    spent_usd: float,
    platform_type: str = "presto",
    engine_version: str = "0.298",
    model_context_budget_chars: int = 200_000,
) -> dict[str, Any]:
    """Build the template variables for the RCA prompt.

    Returns a dict with prompt variables plus ``metrics`` (build latency,
    whether latest-round payloads were truncated — must be False for B14).
    """
    t0 = time.perf_counter()
    latest_round = round_num
    summaries = []
    latest_full: list[dict[str, Any]] = []
    for ev in evidence:
        summaries.append(
            {
                "evidence_id": ev.get("evidence_id"),
                "tool_name": ev.get("tool_name"),
                "round": ev.get("round"),
                "summary": ev.get("summary") or "",
            }
        )
        if int(ev.get("round") or 0) == latest_round:
            latest_full.append(
                {
                    "evidence_id": ev.get("evidence_id"),
                    "tool_name": ev.get("tool_name"),
                    "args": ev.get("args"),
                    "payload": ev.get("payload"),
                    "exit_code": ev.get("exit_code"),
                }
            )

    # `reports` is already prior-only: analyze is invoked with ctx["reports"]
    # *before* the current round's report is appended (workflows/investigation.py).
    # Do not slice with [:-1] — that incorrectly drops the most recent prior report.
    previous = [compact_report(r) for r in reports] if reports else []
    variables = {
        "platform_type": platform_type,
        "engine_version": engine_version,
        "alert_event": json.dumps(event, default=str),
        "round": str(round_num),
        "max_rounds": str(max_rounds),
        "spent": f"{spent_usd:.4f}",
        "evidence_summaries": json.dumps(summaries, default=str),
        "latest_evidence_full": json.dumps(latest_full, default=str),
        "previous_reports_compact": json.dumps(previous, default=str),
    }
    assembled_size = sum(len(v) for v in variables.values())
    # Never truncate the latest round's full payloads (Section 5.3 / B14).
    latest_truncated = False
    if assembled_size > model_context_budget_chars:
        # Trim older evidence summaries only, keep latest_full intact.
        while assembled_size > model_context_budget_chars and len(summaries) > len(latest_full):
            summaries.pop(0)
            variables["evidence_summaries"] = json.dumps(summaries, default=str)
            assembled_size = sum(len(v) for v in variables.values())
        # If still over budget, we still do NOT truncate latest_full.
        latest_truncated = False

    elapsed_ms = (time.perf_counter() - t0) * 1000
    return {
        "variables": variables,
        "metrics": {
            "build_ms": elapsed_ms,
            "assembled_chars": assembled_size,
            "latest_round_truncated": latest_truncated,
        },
    }
