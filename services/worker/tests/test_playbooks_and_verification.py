"""Unit tests for playbook step registry + verification (FP-M5-3/5/7/9)."""
from __future__ import annotations

import base64
import uuid

import pytest

from rca_common.signing.signer import bootstrap_signing_key, canonical_step_hash
from worker.playbooks import (
    MEMORY_CONFIG_WHITELIST,
    PLAYBOOK_STEPS,
    resolve_action_settle_seconds,
    settle_seconds,
    steps_adjust_memory_config,
)
from worker.probeclient import FakeProbeGatewayClient
from worker.verification import run_verification


def test_five_playbooks_have_steps_for_k8s_and_swarm():
    params = {
        "query_id": "q1",
        "worker_id": "worker-1",
        "config_key": "query.max-memory",
        "config_value": "50GB",
        "patches": [{"key": "query.max-memory", "value": "50GB"}],
        "memory_params": {"query.max-memory": "50GB"},
    }
    for pid, builder in PLAYBOOK_STEPS.items():
        for dep in ("k8s", "swarm"):
            steps = builder(dep, params, {})
            assert steps, f"{pid}/{dep} empty"
            assert all("op" in s and "params" in s for s in steps)


def test_adjust_memory_whitelist_rejects_offlist():
    with pytest.raises(ValueError, match="whitelist"):
        steps_adjust_memory_config(
            "k8s",
            {"patches": [{"key": "evil.key", "value": "1"}]},
            {},
        )


def test_adjust_memory_empty_params_raises():
    """C1: empty params must not fabricate a hardcoded memory write."""
    with pytest.raises(ValueError, match="requires memory params"):
        steps_adjust_memory_config("k8s", {}, {})
    with pytest.raises(ValueError, match="requires memory params"):
        steps_adjust_memory_config("swarm", {"patches": []}, {})


def test_settle_seconds_defaults_and_override():
    assert settle_seconds("presto.kill_query") == 0
    assert settle_seconds("presto.restart_worker") == 120
    assert settle_seconds("presto.restart_coordinator") == 120
    assert settle_seconds("presto.adjust_memory_config") == 120
    assert settle_seconds("presto.update_config_restart_workers") == 120
    assert settle_seconds("presto.kill_query", {"remediation": {"settle_seconds": 5}}) == 5


def test_resolve_action_settle_seconds_default_path():
    """C2 / FP-M5-8: default path (no action or input override) is nonzero for restart playbooks."""
    # No explicit settle_seconds on action → playbook default.
    assert (
        resolve_action_settle_seconds(
            {"playbook_id": "presto.restart_worker"},
            remediation_config={},
            input_override=None,
        )
        == 120
    )
    assert (
        resolve_action_settle_seconds(
            {"playbook_id": "presto.kill_query"},
            remediation_config={},
            input_override=None,
        )
        == 0
    )
    assert (
        resolve_action_settle_seconds(
            {"playbook_id": "presto.adjust_memory_config"},
            remediation_config={},
            input_override=None,
        )
        == 120
    )
    # Action override wins.
    assert (
        resolve_action_settle_seconds(
            {"playbook_id": "presto.restart_worker", "settle_seconds": 2},
            remediation_config={},
            input_override=None,
        )
        == 2
    )
    # Workflow-input override when action omits settle_seconds.
    assert (
        resolve_action_settle_seconds(
            {"playbook_id": "presto.restart_worker"},
            remediation_config={},
            input_override=7,
        )
        == 7
    )
    # Platform remediation.settle_seconds overrides playbook default.
    assert (
        resolve_action_settle_seconds(
            {"playbook_id": "presto.restart_worker"},
            remediation_config={"settle_seconds": 0},
            input_override=None,
        )
        == 0
    )


@pytest.mark.asyncio
async def test_verify_union_and_canary():
    probe = FakeProbeGatewayClient(
        {
            "presto_list_queries": [[]],
            "presto_nodes": {"active": [{"node_id": "n1"}]},
            "health": {"ok": True, "exit_code": 0},
            "presto_cluster_info": {"exit_code": 0, "data": {}},
        }
    )
    result = await run_verification(
        probe,
        "p1",
        playbook_id="presto.kill_query",
        params={"query_id": "q1"},
        verification_plan=["presto_cluster_info"],
        health_query="SELECT 1",
    )
    assert result["ok"] is True
    names = [c["name"] for c in result["checks"]]
    assert "query_absent" in names
    assert "canary" in names
    assert "rca:presto_cluster_info" in names


def _acts(tmp_path):
    from unittest.mock import MagicMock
    from rca_common.llmclient.objectstore import FakeObjectStore
    from rca_common.signing.signer import bootstrap_signing_key
    from worker.activities.investigation import InvestigationActivities
    from helpers import ScriptedLLM

    class _SessionCtx:
        def __init__(self, session):
            self._session = session

        def __enter__(self):
            return self._session

        def __exit__(self, *args):
            return False

    inv_row = MagicMock()
    inv_row.investigation_id = uuid.uuid4()
    inv_row.status = "OPEN"
    inv_row.platform_key = "p1"
    session = MagicMock()
    # get() returns None for Playbook/RemediationExecution; Investigation via scalars.
    session.get = MagicMock(return_value=None)
    session.scalars = MagicMock(return_value=MagicMock(first=MagicMock(return_value=inv_row)))
    # update_investigation_status uses session.get(Investigation, id) in some paths
    def _get(model, key):
        name = getattr(model, "__name__", str(model))
        if "Investigation" in name:
            return inv_row
        return None

    session.get = MagicMock(side_effect=_get)
    probe = FakeProbeGatewayClient(
        {
            "presto_list_queries": {"exit_code": 0, "data": {"queries": []}},
            "presto_query_detail": {"exit_code": 0, "data": {"queryId": "q"}},
            "write": {"ok": True, "exit_code": 0},
            "health": {"ok": True, "exit_code": 0},
        }
    )
    acts = InvestigationActivities(
        session_factory=lambda: _SessionCtx(session),
        llm_client=ScriptedLLM({}),
        probe_client=probe,
        object_store=FakeObjectStore(),
        signer=bootstrap_signing_key(str(tmp_path / "k")),
    )
    return acts, probe


@pytest.mark.asyncio
async def test_execute_playbook_signs_and_dispatches(tmp_path):
    activities, probe = _acts(tmp_path)
    inv = str(uuid.uuid4())
    r = await activities.execute_playbook(
        {
            "investigation_id": inv,
            "platform_key": "p1",
            "deployment": "k8s",
            "action": {
                "playbook_id": "presto.kill_query",
                "playbook_params": {"query_id": "2024_q"},
                "rollback_note": "re-run query",
            },
        }
    )
    assert r["ok"] is True
    assert r["execution_id"]
    writes = [c for c in probe.calls if c["kind"] == "write"]
    assert len(writes) == 1
    w = writes[0]
    assert w["op"] == "presto_kill_query"
    digest = canonical_step_hash(
        w["execution_id"], w["playbook_id"], w["step_index"], w["op"], w["params"]
    )
    sig = base64.b64decode(w["signature_b64"])
    import nacl.signing

    vk = nacl.signing.VerifyKey(activities._signer.public_key_bytes())
    vk.verify(digest, sig)


@pytest.mark.asyncio
async def test_execute_playbook_halts_on_step_failure(tmp_path):
    activities, probe = _acts(tmp_path)
    probe.script["write"] = {"ok": False, "exit_code": 1, "error": "boom"}
    inv = str(uuid.uuid4())
    r = await activities.execute_playbook(
        {
            "investigation_id": inv,
            "platform_key": "p1",
            "deployment": "k8s",
            "action": {
                "playbook_id": "presto.kill_query",
                "playbook_params": {"query_id": "q"},
                "rollback_note": "manual undo",
            },
        }
    )
    assert r["ok"] is False
    assert r.get("rollback_note") == "manual undo"
    assert r.get("failed_step") == 0


@pytest.mark.asyncio
async def test_execute_playbook_empty_memory_params_fails_closed(tmp_path):
    """C1: adjust_memory_config with empty params fails before any write."""
    activities, probe = _acts(tmp_path)
    inv = str(uuid.uuid4())
    r = await activities.execute_playbook(
        {
            "investigation_id": inv,
            "platform_key": "p1",
            "deployment": "k8s",
            "action": {
                "playbook_id": "presto.adjust_memory_config",
                "playbook_params": {},
                "rollback_note": "restore prior memory",
            },
        }
    )
    assert r["ok"] is False
    assert "memory params" in (r.get("error") or "").lower()
    assert not [c for c in probe.calls if c.get("kind") == "write"]


@pytest.mark.asyncio
async def test_pre_snapshot_captured(tmp_path):
    activities, probe = _acts(tmp_path)
    inv = str(uuid.uuid4())
    r = await activities.execute_playbook(
        {
            "investigation_id": inv,
            "platform_key": "p1",
            "deployment": "k8s",
            "action": {
                "playbook_id": "presto.kill_query",
                "playbook_params": {"query_id": "q"},
            },
        }
    )
    assert "presto_query_detail" in r["pre_snapshot"] or "presto_list_queries" in r["pre_snapshot"]
    tools = [c["tool"] for c in probe.calls if c["kind"] == "tool"]
    assert "presto_query_detail" in tools
    assert "presto_list_queries" in tools


@pytest.mark.asyncio
async def test_verification_helpers_pass_and_fail():
    from worker.verification import (
        check_query_absent,
        check_workers_active_count,
        check_config_key_equals,
        check_coordinator_up,
        check_node_active,
        check_jmx_memory_pool_ok,
        run_canary,
        run_verification,
    )

    probe = FakeProbeGatewayClient(
        {
            "presto_list_queries": [[{"query_id": "gone", "state": "RUNNING"}]],
            "presto_nodes": {"active": [{"node_id": "w1"}]},
            "presto_config": {"exit_code": 0, "data": {"content": "query.max-memory=50GB\n"}},
            "presto_cluster_info": {"exit_code": 0, "data": {}},
            "presto_jmx": {"exit_code": 0, "data": {}},
            "health": {"ok": True, "exit_code": 0},
        }
    )
    # query still present → fail
    r = await check_query_absent(probe, "p", params={"query_id": "gone"})
    assert r["ok"] is False
    # absent
    probe.script["presto_list_queries"] = [[]]
    r = await check_query_absent(probe, "p", params={"query_id": "gone"})
    assert r["ok"] is True

    r = await check_workers_active_count(probe, "p", params={"min_workers": 1})
    assert r["ok"] is True
    r = await check_config_key_equals(
        probe, "p", params={"config_key": "query.max-memory", "config_value": "50GB"}
    )
    assert r["ok"] is True
    r = await check_coordinator_up(probe, "p", params={})
    assert r["ok"] is True
    r = await check_node_active(probe, "p", params={"worker_id": "w1"})
    assert r["ok"] is True
    r = await check_jmx_memory_pool_ok(probe, "p", params={})
    assert r["ok"] is True
    r = await run_canary(probe, "p", health_query="SELECT 1")
    assert r["ok"] is True

    # canary fail
    probe.script["health"] = {"ok": False, "exit_code": 1, "error": "down"}
    r = await run_canary(probe, "p")
    assert r["ok"] is False

    # full adjust_memory verification
    probe.script["health"] = {"ok": True, "exit_code": 0}
    result = await run_verification(
        probe,
        "p",
        playbook_id="presto.adjust_memory_config",
        params={"memory_params": {"query.max-memory": "50GB"}},
        verification_plan=[{"tool": "presto_cluster_info", "args": {}}],
    )
    assert result["ok"] is True

    # string verification plan entry + dict without tool skipped
    result = await run_verification(
        probe,
        "p",
        playbook_id="presto.restart_coordinator",
        params={},
        verification_plan=["presto_cluster_info", {"args": {}}, 123],
    )
    assert "rca:presto_cluster_info" in [c["name"] for c in result["checks"]]


@pytest.mark.asyncio
async def test_workers_active_count_appendix_b_active_key():
    """Real probe returns {'active': [...]} — not 'nodes' / 'activeWorkers'."""
    from worker.verification import check_workers_active_count

    probe = FakeProbeGatewayClient(
        {
            "presto_nodes": {"active": [{"node_id": "w1"}]},
        }
    )
    r = await check_workers_active_count(probe, "p", params={"min_workers": 1})
    assert r["ok"] is True
    assert r["detail"] == "active=1 min=1"


@pytest.mark.asyncio
async def test_jmx_memory_pool_ok_uses_mbean_arg():
    """Appendix B presto_jmx requires 'mbean', not 'object'."""
    from worker.playbooks import PRE_SNAPSHOT_TOOLS
    from worker.verification import check_jmx_memory_pool_ok

    probe = FakeProbeGatewayClient({"presto_jmx": {"exit_code": 0, "data": {}}})
    await check_jmx_memory_pool_ok(probe, "p", params={})
    jmx_calls = [c for c in probe.calls if c["tool"] == "presto_jmx"]
    assert jmx_calls[-1]["args"] == {"mbean": "heap"}

    jmx = [e for e in PRE_SNAPSHOT_TOOLS["presto.adjust_memory_config"] if e.get("tool") == "presto_jmx"]
    assert jmx and jmx[0]["args"] == {"mbean": "heap"}


@pytest.mark.asyncio
async def test_query_absent_fails_on_appendix_b_bare_list():
    """Real probe returns a bare query list, not {'queries': [...]}."""
    from worker.verification import check_query_absent

    # FakeProbe treats a top-level list as sequential responses; wrap so _next
    # returns the Appendix B bare list payload the real probe emits.
    probe = FakeProbeGatewayClient(
        {
            "presto_list_queries": [[{"query_id": "q1", "state": "RUNNING"}]],
        }
    )
    r = await check_query_absent(probe, "p", params={"query_id": "q1"})
    assert r["ok"] is False
    assert "present=True" in r["detail"]


@pytest.mark.asyncio
async def test_query_absent_passes_on_appendix_b_empty_list():
    """Appendix B empty query list means the target query is absent."""
    from worker.verification import check_query_absent

    probe = FakeProbeGatewayClient({"presto_list_queries": [[]]})
    r = await check_query_absent(probe, "p", params={"query_id": "q1"})
    assert r["ok"] is True
    assert "present=False" in r["detail"]


@pytest.mark.asyncio
async def test_node_active_appendix_b_active_key():
    """Real probe returns {'active': [...]} with node_id — not nodes/nodeId."""
    from worker.verification import check_node_active

    probe = FakeProbeGatewayClient(
        {
            "presto_nodes": {"active": [{"node_id": "w1"}]},
        }
    )
    r = await check_node_active(probe, "p", params={"worker_id": "w1"})
    assert r["ok"] is True


@pytest.mark.asyncio
async def test_node_active_nodes_key_fallback():
    """Legacy nodes/nodeId envelope still matches when present."""
    from worker.verification import check_node_active

    probe = FakeProbeGatewayClient(
        {
            "presto_nodes": {"nodes": [{"nodeId": "w1"}]},
        }
    )
    r = await check_node_active(probe, "p", params={"worker_id": "w1"})
    assert r["ok"] is True


@pytest.mark.asyncio
async def test_workers_active_count_nodes_key_fallback():
    """Legacy nodes/nodeId envelope still counts workers when present."""
    from worker.verification import check_workers_active_count

    probe = FakeProbeGatewayClient(
        {
            "presto_nodes": {"nodes": [{"nodeId": "w1"}]},
        }
    )
    r = await check_workers_active_count(probe, "p", params={"min_workers": 1})
    assert r["ok"] is True
    assert r["detail"] == "active=1 min=1"


@pytest.mark.asyncio
async def test_workers_active_count_active_workers_int():
    """Legacy integer activeWorkers count uses the int branch, not len(list)."""
    from worker.verification import check_workers_active_count

    probe = FakeProbeGatewayClient(
        {
            "presto_nodes": {"active": 3},
        }
    )
    r = await check_workers_active_count(probe, "p", params={"min_workers": 2})
    assert r["ok"] is True
    assert r["detail"] == "active=3 min=2"


@pytest.mark.asyncio
async def test_query_absent_queries_key_fallback():
    """Legacy {queries:[...]} envelope still detects a present query."""
    from worker.verification import check_query_absent

    probe = FakeProbeGatewayClient(
        {
            "presto_list_queries": {"exit_code": 0, "data": {"queries": [{"query_id": "q1"}]}},
        }
    )
    r = await check_query_absent(probe, "p", params={"query_id": "q1"})
    assert r["ok"] is False
    assert "present=True" in r["detail"]


@pytest.mark.asyncio
async def test_query_absent_unwrap_data_inner_list():
    """FakeProbe nested data:[{...}] unwraps to the bare Appendix B list."""
    from worker.verification import check_query_absent

    probe = FakeProbeGatewayClient(
        {
            "presto_list_queries": {"exit_code": 0, "data": [{"query_id": "q1"}]},
        }
    )
    r = await check_query_absent(probe, "p", params={"query_id": "q1"})
    assert r["ok"] is False
    assert "present=True" in r["detail"]


def test_playbook_helpers_coverage():
    from worker.playbooks import (
        default_locators,
        resolve_locators,
        resolve_runtime_tool,
        steps_update_config_restart_workers,
        steps_restart_coordinator,
        steps_kill_query,
        _config_patches,
        _memory_patches,
    )
    assert default_locators("swarm")["worker_service"] == "presto-worker"
    assert default_locators("k8s")["namespace"] == "presto"
    locs = resolve_locators("k8s", {"remediation_targets": {"namespace": "ns2"}})
    assert locs["namespace"] == "ns2"
    assert resolve_runtime_tool("k8s_pods|swarm_tasks", "swarm") == "swarm_tasks"
    assert resolve_runtime_tool("k8s_pods|swarm_tasks", "k8s") == "k8s_pods"
    assert resolve_runtime_tool("x", "k8s") == "x"

    with pytest.raises(ValueError):
        steps_kill_query("k8s", {}, {})

    steps = steps_update_config_restart_workers(
        "swarm",
        {"config_key": "A", "config_value": "1"},
        {},
    )
    assert steps[0]["op"] == "swarm_update_service_env"
    steps = steps_update_config_restart_workers(
        "k8s",
        {"patches": [{"key": "config.properties", "value": "a=1\n"}]},
        {},
    )
    assert steps[0]["op"] == "k8s_patch_configmap"
    steps = steps_restart_coordinator("swarm", {}, {})
    assert steps[0]["op"] == "swarm_restart_service"
    steps = steps_restart_coordinator("k8s", {}, {})
    assert steps[0]["op"] == "k8s_rollout_restart"

    patches = _config_patches({"config_key": "k", "config_value": "v"}, {"config_file_key": "f"})
    assert patches[0]["key"] == "f"
    patches = _memory_patches({"query.max-memory": "10GB"})
    assert patches[0]["key"] == "query.max-memory"
    patches = _memory_patches({"memory_params": {"query.max-memory": "10GB"}})
    assert patches[0]["value"] == "10GB"


@pytest.mark.asyncio
async def test_canary_fallback_without_execute_health():
    class NoHealth:
        async def execute_tool(self, platform_key, *, tool, args=None, **kw):
            from worker.probeclient import ToolExecutionResult
            import json
            return ToolExecutionResult(
                task_id="t", exit_code=0, data={}, raw_bytes=b"{}", redacted=False, truncated=False
            )

    from worker.verification import run_canary

    r = await run_canary(NoHealth(), "p")
    assert r["ok"] is True
    assert "fallback" in r["detail"] or r["ok"]
