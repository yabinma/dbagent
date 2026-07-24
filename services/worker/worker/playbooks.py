"""MVP playbook step registry (design.md Section 9.2 / 9.5.3).

``PLAYBOOK_STEPS[playbook_id](deployment, params, locators)`` returns the
ordered list of write-op primitives for a deployment (``k8s`` | ``swarm``).
Resource locators come from ``platforms.config.remediation_targets`` — never
from the LLM. The LLM supplies only semantic params (``query_id``,
``worker_id``, config key/values).
"""
from __future__ import annotations

from typing import Any, Callable

# Appendix B.5 memory-config whitelist (also enforced probe-side).
MEMORY_CONFIG_WHITELIST = frozenset(
    {
        "query.max-memory",
        "query.max-memory-per-node",
        "query.max-total-memory-per-node",
        "memory.heap-headroom-per-node",
    }
)

# Per-playbook default settle window (seconds). Overridable via
# platforms.config.remediation.settle_seconds.
DEFAULT_SETTLE_SECONDS: dict[str, int] = {
    "presto.kill_query": 0,
    "presto.update_config_restart_workers": 120,
    "presto.restart_coordinator": 120,
    "presto.restart_worker": 120,
    "presto.adjust_memory_config": 120,
}

# Catalog rows for seed_playbooks (FP-M5-11) — steps/verification are
# descriptive JSON; the executable step sequence is PLAYBOOK_STEPS.
PLAYBOOK_CATALOG: list[dict[str, Any]] = [
    {
        "playbook_id": "presto.kill_query",
        "platform_type": "presto",
        "risk_level": "R1",
        "params_schema": {
            "type": "object",
            "required": ["query_id"],
            "properties": {"query_id": {"type": "string"}},
        },
        "steps": [{"op": "presto_kill_query", "params_from": ["query_id"]}],
        "verification": {
            "checks": ["query_absent", "canary"],
            "description": "query gone; queued count decreases; canary",
        },
    },
    {
        "playbook_id": "presto.update_config_restart_workers",
        "platform_type": "presto",
        "risk_level": "R2",
        "params_schema": {
            "type": "object",
            "properties": {
                "config_key": {"type": "string"},
                "config_value": {"type": "string"},
                "patches": {"type": "array"},
            },
        },
        "steps": [
            {"op": "k8s_patch_configmap|swarm_update_service_env"},
            {"op": "k8s_rollout_restart|swarm_restart_service"},
        ],
        "verification": {
            "checks": ["workers_active_count", "config_key_equals", "canary"],
        },
    },
    {
        "playbook_id": "presto.restart_coordinator",
        "platform_type": "presto",
        "risk_level": "R2",
        "params_schema": {"type": "object", "properties": {}},
        "steps": [
            {"op": "k8s_rollout_restart|swarm_restart_service", "target": "coordinator"},
        ],
        "verification": {"checks": ["coordinator_up", "workers_active_count", "canary"]},
    },
    {
        "playbook_id": "presto.restart_worker",
        "platform_type": "presto",
        "risk_level": "R2",
        "params_schema": {
            "type": "object",
            "properties": {"worker_id": {"type": "string"}},
        },
        "steps": [
            {"op": "k8s_delete_pod|swarm_restart_service", "target": "worker"},
        ],
        "verification": {"checks": ["node_active", "canary"]},
    },
    {
        "playbook_id": "presto.adjust_memory_config",
        "platform_type": "presto",
        "risk_level": "R2",
        "params_schema": {
            "type": "object",
            "properties": {
                "patches": {"type": "array"},
                "memory_params": {"type": "object"},
            },
        },
        "steps": [
            {"op": "k8s_patch_configmap|swarm_update_service_env"},
            {"op": "k8s_rollout_restart|swarm_restart_service"},
        ],
        "verification": {
            "checks": [
                "workers_active_count",
                "config_key_equals",
                "jmx_memory_pool_ok",
                "canary",
            ],
        },
    },
]


def default_locators(deployment: str) -> dict[str, Any]:
    """Sensible defaults when platforms.config.remediation_targets is absent."""
    if deployment == "swarm":
        return {
            "worker_service": "presto-worker",
            "coordinator_service": "presto-coordinator",
            "config_file": "config",
        }
    return {
        "namespace": "presto",
        "worker_configmap": "presto-worker-config",
        "coordinator_configmap": "presto-coordinator-config",
        "worker_workload_kind": "deployment",
        "worker_workload_name": "presto-worker",
        "coordinator_workload_kind": "deployment",
        "coordinator_workload_name": "presto-coordinator",
        "config_file_key": "config.properties",
    }


def resolve_locators(deployment: str, platform_config: dict[str, Any] | None) -> dict[str, Any]:
    cfg = platform_config or {}
    base = default_locators(deployment)
    targets = cfg.get("remediation_targets") or {}
    base.update(targets)
    return base


def settle_seconds(playbook_id: str, platform_config: dict[str, Any] | None = None) -> int:
    cfg = platform_config or {}
    rem = cfg.get("remediation") or {}
    if "settle_seconds" in rem:
        return int(rem["settle_seconds"])
    # Optional per-playbook override map.
    per = rem.get("settle_seconds_by_playbook") or {}
    if playbook_id in per:
        return int(per[playbook_id])
    return int(DEFAULT_SETTLE_SECONDS.get(playbook_id, 120))


def resolve_action_settle_seconds(
    action: dict[str, Any],
    *,
    remediation_config: dict[str, Any] | None = None,
    input_override: int | None = None,
) -> int:
    """Resolve the settle window for one remediation action (FP-M5-8).

    Precedence: action.settle_seconds → workflow-input override →
    ``settle_seconds(playbook_id, platform_config)`` (platform remediation
    block + per-playbook defaults).
    """
    if action.get("settle_seconds") is not None:
        return int(action["settle_seconds"])
    if input_override is not None:
        return int(input_override)
    pid = str(action.get("playbook_id") or "")
    return settle_seconds(pid, {"remediation": remediation_config or {}})


def _memory_patches(params: dict[str, Any]) -> list[dict[str, str]]:
    """Build whitelist-constrained patches from playbook_params.

    Raises ValueError if any explicitly provided key is off-whitelist
    (FP-M5-4 worker-side enforcement).
    """
    if params.get("patches"):
        out = []
        for p in params["patches"]:
            k = p.get("key") if isinstance(p, dict) else None
            v = p.get("value") if isinstance(p, dict) else None
            if not k:
                continue
            if k not in MEMORY_CONFIG_WHITELIST:
                raise ValueError(f"memory config key {k!r} is not in the whitelist")
            out.append({"key": k, "value": str(v)})
        return out
    mem = params.get("memory_params") or {}
    out = []
    for k, v in mem.items():
        if k not in MEMORY_CONFIG_WHITELIST:
            raise ValueError(f"memory config key {k!r} is not in the whitelist")
        out.append({"key": k, "value": str(v)})
    # Also accept top-level whitelist keys.
    for k in MEMORY_CONFIG_WHITELIST:
        if k in params and k not in {p["key"] for p in out}:
            out.append({"key": k, "value": str(params[k])})
    return out


def _config_patches(params: dict[str, Any], locators: dict[str, Any]) -> list[dict[str, str]]:
    if params.get("patches"):
        return [
            {"key": p["key"], "value": str(p["value"])}
            for p in params["patches"]
            if isinstance(p, dict) and p.get("key") is not None
        ]
    key = params.get("config_key")
    value = params.get("config_value")
    if key is not None:
        # Full-file content with a single property for Appendix B.5 shape.
        file_key = locators.get("config_file_key") or "config.properties"
        return [{"key": file_key, "value": f"{key}={value}\n"}]
    return []


def steps_kill_query(
    deployment: str, params: dict[str, Any], locators: dict[str, Any]
) -> list[dict[str, Any]]:
    qid = params.get("query_id")
    if not qid:
        raise ValueError("presto.kill_query requires query_id")
    return [{"op": "presto_kill_query", "params": {"query_id": str(qid)}}]


def steps_update_config_restart_workers(
    deployment: str, params: dict[str, Any], locators: dict[str, Any]
) -> list[dict[str, Any]]:
    if deployment == "swarm":
        env_patches = []
        for p in _config_patches(params, locators):
            # For swarm, env keys are property names when adjust-style;
            # for update_config use key as env var name.
            env_patches.append({"key": p["key"], "value": p["value"]})
        if not env_patches and params.get("config_key"):
            env_patches = [
                {"key": str(params["config_key"]), "value": str(params.get("config_value", ""))}
            ]
        return [
            {
                "op": "swarm_update_service_env",
                "params": {
                    "service": locators.get("worker_service") or "presto-worker",
                    "env": env_patches,
                },
            },
            {
                "op": "swarm_restart_service",
                "params": {"service": locators.get("worker_service") or "presto-worker"},
            },
        ]
    patches = _config_patches(params, locators)
    return [
        {
            "op": "k8s_patch_configmap",
            "params": {
                "name": locators.get("worker_configmap") or "presto-worker-config",
                "namespace": locators.get("namespace") or "presto",
                "patches": patches,
            },
        },
        {
            "op": "k8s_rollout_restart",
            "params": {
                "kind": locators.get("worker_workload_kind") or "deployment",
                "name": locators.get("worker_workload_name") or "presto-worker",
                "namespace": locators.get("namespace") or "presto",
            },
        },
    ]


def steps_restart_coordinator(
    deployment: str, params: dict[str, Any], locators: dict[str, Any]
) -> list[dict[str, Any]]:
    if deployment == "swarm":
        return [
            {
                "op": "swarm_restart_service",
                "params": {
                    "service": locators.get("coordinator_service") or "presto-coordinator"
                },
            }
        ]
    return [
        {
            "op": "k8s_rollout_restart",
            "params": {
                "kind": locators.get("coordinator_workload_kind") or "deployment",
                "name": locators.get("coordinator_workload_name") or "presto-coordinator",
                "namespace": locators.get("namespace") or "presto",
            },
        }
    ]


def steps_restart_worker(
    deployment: str, params: dict[str, Any], locators: dict[str, Any]
) -> list[dict[str, Any]]:
    worker_id = (
        params.get("worker_id")
        or params.get("pod")
        or params.get("task")
        or locators.get("default_worker_pod")
        or "presto-worker-0"
    )
    if deployment == "swarm":
        # Swarm: force-restart the whole worker service (or a named service).
        return [
            {
                "op": "swarm_restart_service",
                "params": {
                    "service": locators.get("worker_service") or "presto-worker"
                },
            }
        ]
    return [
        {
            "op": "k8s_delete_pod",
            "params": {
                "name": str(worker_id),
                "namespace": locators.get("namespace") or "presto",
            },
        }
    ]


def steps_adjust_memory_config(
    deployment: str, params: dict[str, Any], locators: dict[str, Any]
) -> list[dict[str, Any]]:
    patches = _memory_patches(params)
    if not patches:
        # Fail closed: never fabricate an unrequested memory mutation
        # (review C1). Sibling builders (e.g. kill_query) raise on missing
        # semantic params; execute_playbook maps this to status=failed →
        # NEEDS_HUMAN.
        raise ValueError("adjust_memory_config requires memory params")
    # Worker-side whitelist enforcement (defense in depth; probe also checks).
    for p in patches:
        if p["key"] not in MEMORY_CONFIG_WHITELIST:
            raise ValueError(f"memory config key {p['key']!r} is not in the whitelist")
    if deployment == "swarm":
        return [
            {
                "op": "swarm_update_service_env",
                "params": {
                    "service": locators.get("worker_service") or "presto-worker",
                    "env": patches,
                },
            },
            {
                "op": "swarm_restart_service",
                "params": {"service": locators.get("worker_service") or "presto-worker"},
            },
        ]
    return [
        {
            "op": "k8s_patch_configmap",
            "params": {
                "name": locators.get("worker_configmap") or "presto-worker-config",
                "namespace": locators.get("namespace") or "presto",
                "patches": patches,
            },
        },
        {
            "op": "k8s_rollout_restart",
            "params": {
                "kind": locators.get("worker_workload_kind") or "deployment",
                "name": locators.get("worker_workload_name") or "presto-worker",
                "namespace": locators.get("namespace") or "presto",
            },
        },
    ]


PLAYBOOK_STEPS: dict[str, Callable[[str, dict[str, Any], dict[str, Any]], list[dict[str, Any]]]] = {
    "presto.kill_query": steps_kill_query,
    "presto.update_config_restart_workers": steps_update_config_restart_workers,
    "presto.restart_coordinator": steps_restart_coordinator,
    "presto.restart_worker": steps_restart_worker,
    "presto.adjust_memory_config": steps_adjust_memory_config,
}


# Pre-snapshot tool lists per playbook (Section 9.5.3 table).
PRE_SNAPSHOT_TOOLS: dict[str, list[dict[str, Any]]] = {
    "presto.kill_query": [
        {"tool": "presto_query_detail", "args_from": ["query_id"]},
        {"tool": "presto_list_queries", "args": {"state": "QUEUED"}},
    ],
    "presto.update_config_restart_workers": [
        {"tool": "presto_config", "args": {"component": "worker", "file": "config"}},
        {"tool": "k8s_pods|swarm_tasks", "args": {}},
        {"tool": "presto_nodes", "args": {}},
    ],
    "presto.adjust_memory_config": [
        {"tool": "presto_config", "args": {"component": "worker", "file": "config"}},
        {"tool": "k8s_pods|swarm_tasks", "args": {}},
        {"tool": "presto_jmx", "args": {"object": "heap"}},
    ],
    "presto.restart_coordinator": [
        {"tool": "presto_cluster_info", "args": {}},
        {"tool": "presto_nodes", "args": {}},
        {"tool": "k8s_pods|swarm_tasks", "args": {}},
    ],
    "presto.restart_worker": [
        {"tool": "k8s_pods|swarm_tasks", "args": {}},
        {"tool": "presto_nodes", "args": {}},
    ],
}


def resolve_runtime_tool(name: str, deployment: str) -> str:
    """Pick k8s vs swarm tool when the registry uses ``a|b`` form."""
    if "|" not in name:
        return name
    left, right = name.split("|", 1)
    return right if deployment == "swarm" else left
