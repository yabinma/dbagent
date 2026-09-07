"""Playbook default verification checks (design.md Section 9.2 / 9.5.3).

``PLAYBOOK_VERIFICATIONS[playbook_id]`` is a list of named check callables.
Each runs against the real probe via ``probe_client.execute_tool`` /
``execute_health`` and returns ``{name, ok, detail}``.
"""
from __future__ import annotations

from typing import Any, Awaitable, Callable


CheckFn = Callable[..., Awaitable[dict[str, Any]]]


def _unwrap_data(result_data: Any) -> Any:
    """Normalize ToolExecutionResult.data shapes from real/fake probes."""
    if isinstance(result_data, list):
        return result_data
    if not isinstance(result_data, dict):
        return {}
    # FakeProbe often returns {"exit_code":0,"data":{...}} as the whole data blob.
    inner = result_data.get("data")
    if isinstance(inner, dict) and (
        "queries" in inner
        or "nodes" in inner
        or "active" in inner
        or "content" in inner
        or "text" in inner
    ):
        return inner
    if isinstance(inner, list):
        return inner
    return result_data


async def check_query_absent(
    probe, platform_key: str, *, params: dict[str, Any], **_: Any
) -> dict[str, Any]:
    qid = params.get("query_id")
    result = await probe.execute_tool(
        platform_key, tool="presto_list_queries", args={"state": "RUNNING"}
    )
    data = _unwrap_data(result.data)
    if isinstance(data, list):
        queries = data
    else:
        queries = data.get("queries") or []
    if isinstance(queries, dict):
        queries = list(queries.values())
    present = False
    if isinstance(queries, list):
        for q in queries:
            if isinstance(q, dict) and (
                q.get("queryId") == qid or q.get("query_id") == qid or q.get("id") == qid
            ):
                present = True
                break
            if q == qid:
                present = True
                break
    # Also treat exit_code!=0 as soft-fail only if explicitly marked.
    ok = (not present) and result.exit_code == 0
    return {"name": "query_absent", "ok": ok, "detail": f"query_id={qid} present={present}"}


async def check_workers_active_count(
    probe, platform_key: str, *, params: dict[str, Any], **_: Any
) -> dict[str, Any]:
    result = await probe.execute_tool(platform_key, tool="presto_nodes", args={})
    data = _unwrap_data(result.data)
    if isinstance(data, dict):
        nodes = data.get("active") or data.get("nodes") or data.get("activeWorkers") or []
    else:
        nodes = []
    if isinstance(nodes, int):
        count = nodes
    elif isinstance(nodes, list):
        count = len(nodes)
    else:
        count = int((data.get("activeWorkers") if isinstance(data, dict) else 0) or 0)
    min_workers = int(params.get("min_workers") or 1)
    ok = result.exit_code == 0 and count >= min_workers
    return {
        "name": "workers_active_count",
        "ok": ok,
        "detail": f"active={count} min={min_workers}",
    }


async def check_config_key_equals(
    probe, platform_key: str, *, params: dict[str, Any], **_: Any
) -> dict[str, Any]:
    key = params.get("config_key") or params.get("key")
    expect = params.get("config_value") or params.get("value")
    # For memory playbooks, first whitelist key/value.
    if not key:
        mem = params.get("memory_params") or {}
        if mem:
            key, expect = next(iter(mem.items()))
        elif params.get("patches"):
            p0 = params["patches"][0]
            key, expect = p0.get("key"), p0.get("value")
    result = await probe.execute_tool(
        platform_key,
        tool="presto_config",
        args={"component": "worker", "file": "config"},
    )
    data = _unwrap_data(result.data)
    if isinstance(data, dict):
        content = data.get("content") or data.get("text") or ""
    else:
        content = ""
    if not content and isinstance(result.data, dict):
        content = result.data.get("content") or result.data.get("text") or result.data.get("data") or ""
    if isinstance(content, dict):
        content = "\n".join(f"{k}={v}" for k, v in content.items())
    content = str(content)
    ok = result.exit_code == 0
    if key is not None and expect is not None:
        ok = ok and (f"{key}={expect}" in content or str(expect) in content)
    return {
        "name": "config_key_equals",
        "ok": ok,
        "detail": f"key={key} expect={expect}",
    }


async def check_coordinator_up(
    probe, platform_key: str, *, params: dict[str, Any], **_: Any
) -> dict[str, Any]:
    result = await probe.execute_tool(platform_key, tool="presto_cluster_info", args={})
    ok = result.exit_code == 0 and result.error is None
    return {"name": "coordinator_up", "ok": ok, "detail": result.error or "ok"}


async def check_node_active(
    probe, platform_key: str, *, params: dict[str, Any], **_: Any
) -> dict[str, Any]:
    worker_id = params.get("worker_id")
    result = await probe.execute_tool(platform_key, tool="presto_nodes", args={})
    data = _unwrap_data(result.data)
    if isinstance(data, list):
        nodes = data
    elif isinstance(data, dict):
        nodes = data.get("active") or data.get("nodes") or data.get("activeWorkers") or []
    else:
        nodes = []
    ok = result.exit_code == 0
    if worker_id and isinstance(nodes, list):
        ok = ok and any(
            (
                isinstance(n, dict)
                and (
                    n.get("node_id") == worker_id
                    or n.get("nodeId") == worker_id
                    or n.get("uri") == worker_id
                )
            )
            or n == worker_id
            for n in nodes
        )
    return {"name": "node_active", "ok": ok, "detail": f"worker_id={worker_id}"}


async def check_jmx_memory_pool_ok(
    probe, platform_key: str, *, params: dict[str, Any], **_: Any
) -> dict[str, Any]:
    result = await probe.execute_tool(
        platform_key, tool="presto_jmx", args={"mbean": "heap"}
    )
    ok = result.exit_code == 0
    return {"name": "jmx_memory_pool_ok", "ok": ok, "detail": result.error or "ok"}


async def run_canary(
    probe, platform_key: str, *, health_query: str | None = None, **_: Any
) -> dict[str, Any]:
    """Built-in SELECT 1 + configured health_query via HealthCheck task."""
    if hasattr(probe, "execute_health"):
        result = await probe.execute_health(
            platform_key,
            builtin=True,
            custom_query=health_query or "",
            wait_seconds=0,
        )
        ok = result.exit_code == 0 and not result.error
        # Fake may return data.ok
        if isinstance(result.data, dict) and "ok" in result.data:
            ok = bool(result.data["ok"]) and result.exit_code == 0
        return {"name": "canary", "ok": ok, "detail": result.error or "ok"}
    # Fallback: tool-based SELECT 1
    result = await probe.execute_tool(
        platform_key, tool="presto_cluster_info", args={}
    )
    ok = result.exit_code == 0
    return {"name": "canary", "ok": ok, "detail": result.error or "fallback-cluster-info"}


PLAYBOOK_VERIFICATIONS: dict[str, list[CheckFn]] = {
    "presto.kill_query": [check_query_absent],
    "presto.update_config_restart_workers": [
        check_workers_active_count,
        check_config_key_equals,
    ],
    "presto.restart_coordinator": [check_coordinator_up, check_workers_active_count],
    "presto.restart_worker": [check_node_active],
    "presto.adjust_memory_config": [
        check_workers_active_count,
        check_config_key_equals,
        check_jmx_memory_pool_ok,
    ],
}


async def run_verification(
    probe,
    platform_key: str,
    *,
    playbook_id: str,
    params: dict[str, Any],
    verification_plan: list[Any] | None = None,
    health_query: str | None = None,
) -> dict[str, Any]:
    """Run playbook defaults ∪ RCA plan ∪ canary. Returns {ok, checks}."""
    checks: list[dict[str, Any]] = []
    for fn in PLAYBOOK_VERIFICATIONS.get(playbook_id, []):
        checks.append(await fn(probe, platform_key, params=params or {}))

    for entry in verification_plan or []:
        if isinstance(entry, str):
            tool, args = entry, {}
        elif isinstance(entry, dict):
            tool = entry.get("tool") or entry.get("name") or ""
            args = entry.get("args") or {}
        else:
            continue
        if not tool:
            continue
        result = await probe.execute_tool(platform_key, tool=tool, args=args)
        checks.append(
            {
                "name": f"rca:{tool}",
                "ok": result.exit_code == 0 and not result.error,
                "detail": result.error or "ok",
            }
        )

    checks.append(await run_canary(probe, platform_key, health_query=health_query))
    ok = all(c.get("ok") for c in checks)
    return {"ok": ok, "checks": checks}
