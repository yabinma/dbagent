"""JSON Schemas used for structured agent outputs (Section 6).

Loaded from the monorepo ``schemas/`` directory when present; otherwise a
minimal inline schema matching the generated pydantic models is used so
unit tests can run without the repo-root path.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

_REPO_SCHEMAS = Path(__file__).resolve().parents[4] / "schemas"


@lru_cache(maxsize=8)
def load_schema(name: str) -> dict:
    """Load ``schemas/{name}.schema.json`` (plan, rca_report, ...)."""
    path = _REPO_SCHEMAS / f"{name}.schema.json"
    if path.is_file():
        return json.loads(path.read_text(encoding="utf-8"))
    # Minimal fallbacks for isolated test environments.
    if name == "plan":
        return {
            "type": "object",
            "required": ["tool_calls", "unresolvable"],
            "properties": {
                "tool_calls": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["tool", "args", "purpose"],
                        "properties": {
                            "tool": {"type": "string"},
                            "args": {"type": "object"},
                            "purpose": {"type": "string"},
                        },
                    },
                },
                "unresolvable": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": ["what", "reason"],
                        "properties": {
                            "what": {"type": "string"},
                            "reason": {"type": "string"},
                        },
                    },
                },
            },
        }
    if name == "rca_report":
        return {
            "type": "object",
            "required": ["status", "confidence"],
            "properties": {
                "status": {"enum": ["concluded", "need_more_data", "inconclusive"]},
                "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            },
        }
    if name == "evidence_summary":
        return {
            "type": "object",
            "required": ["summary"],
            "properties": {
                "summary": {"type": "string"},
                "notable_lines": {"type": "array", "items": {"type": "string"}},
                "anomaly_detected": {"type": "boolean"},
            },
        }
    if name == "remediation":
        return {
            "type": "object",
            "required": ["proposed_actions"],
            "properties": {
                "proposed_actions": {"type": "array"},
                "rca_compact": {"type": "string"},
            },
        }
    raise FileNotFoundError(f"schema {name} not found at {path}")


# Default Presto tool catalog names (Section 8.5) for the planner prompt.
DEFAULT_TOOL_CATALOG = [
    "presto_cluster_info",
    "presto_nodes",
    "presto_list_queries",
    "presto_query_detail",
    "presto_query_json_section",
    "presto_config",
    "presto_session_properties",
    "presto_jmx",
    "pod_logs",
    "container_logs",
    "k8s_pods",
    "swarm_tasks",
    "k8s_describe",
    "docker_inspect",
    "k8s_events",
    "docker_events",
    "resource_usage",
    "jvm_thread_dump",
    "jvm_heap_histo",
    "fetch_source",
    "diff_versions",
    "search_commits",
    "read_evidence",
]

MVP_PLAYBOOKS = [
    {
        "playbook_id": "presto.kill_query",
        "risk_level": "R1",
        "params_schema": {"type": "object", "properties": {"query_id": {"type": "string"}}},
    },
    {
        "playbook_id": "presto.update_config_restart_workers",
        "risk_level": "R2",
        "params_schema": {"type": "object"},
    },
    {
        "playbook_id": "presto.restart_coordinator",
        "risk_level": "R2",
        "params_schema": {"type": "object"},
    },
    {
        "playbook_id": "presto.restart_worker",
        "risk_level": "R2",
        "params_schema": {"type": "object", "properties": {"worker_id": {"type": "string"}}},
    },
    {
        "playbook_id": "presto.adjust_memory_config",
        "risk_level": "R2",
        "params_schema": {"type": "object"},
    },
]

RISK_DEFS = (
    "R0 no-op/read-only; R1 reversible low impact; R2 service-interrupting; "
    "R3 destructive/irreversible"
)

CONTROL_TOOLS = frozenset(
    {"fetch_source", "diff_versions", "search_commits", "read_evidence"}
)
