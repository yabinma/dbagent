"""Coverage for main entrypoint, temporal signal errors, bootstrap helpers."""
from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from dashboard_api.bootstrap_admin import bootstrap_admin, main as bootstrap_main
from dashboard_api.temporal_signals import WorkflowNotRunning, signal_workflow
from dashboard_api import services as svc
from dashboard_helpers import seed_user


@pytest.mark.asyncio
async def test_signal_workflow_none_client():
    with pytest.raises(WorkflowNotRunning):
        await signal_workflow(None, "wf-1", "pause")


@pytest.mark.asyncio
async def test_signal_workflow_not_found_maps():
    class H:
        async def signal(self, name, arg=None):
            raise RuntimeError("workflow execution already completed")

    class C:
        def get_workflow_handle(self, wid):
            return H()

    with pytest.raises(WorkflowNotRunning):
        await signal_workflow(C(), "wf-1", "pause")


@pytest.mark.asyncio
async def test_signal_workflow_success():
    called = {}

    class H:
        async def signal(self, name, arg=None):
            called["name"] = name
            called["arg"] = arg

    class C:
        def get_workflow_handle(self, wid):
            return H()

    await signal_workflow(C(), "wf-1", "adjust_budget", {"max_rounds": 3})
    assert called["name"] == "adjust_budget"
    assert called["arg"]["max_rounds"] == 3


def test_ca_fingerprint_from_pem(tmp_path):
    # minimal fake PEM body (not a real cert, but exercise the parser path)
    import base64

    der = b"\x30\x82\x01\x00" + b"\x00" * 20
    b64 = base64.b64encode(der).decode()
    pem = f"-----BEGIN CERTIFICATE-----\n{b64}\n-----END CERTIFICATE-----\n"
    p = tmp_path / "ca.crt"
    p.write_text(pem)
    fp = svc.ca_fingerprint(str(p))
    assert fp and fp.startswith("sha256:")


def test_ca_fingerprint_empty():
    assert svc.ca_fingerprint("") is None


def test_bootstrap_admin_skipped_empty(session_factory):
    assert bootstrap_admin(session_factory, username="", password="") == "skipped"


def test_bootstrap_main_missing_env(monkeypatch):
    monkeypatch.delenv("ADMIN_USERNAME", raising=False)
    monkeypatch.delenv("ADMIN_INITIAL_PASSWORD", raising=False)
    assert bootstrap_main([]) == 2


def test_bootstrap_main_happy(monkeypatch, session_factory, tmp_path):
    # Write a minimal config file pointing at the test PG via env.
    monkeypatch.setenv("ADMIN_USERNAME", "rootadmin")
    monkeypatch.setenv("ADMIN_INITIAL_PASSWORD", "root-password-12")
    cfg = tmp_path / "cfg.yaml"
    # bootstrap_main loads config for DSN — patch make_engine path instead.
    with patch("dashboard_api.bootstrap_admin.load_config") as lc, patch(
        "dashboard_api.bootstrap_admin.make_engine"
    ) as me, patch(
        "dashboard_api.bootstrap_admin.make_session_factory", return_value=session_factory
    ):
        lc.return_value = MagicMock(storage=MagicMock(postgres_dsn="postgresql://x"))
        me.return_value = MagicMock()
        rc = bootstrap_main([])
        assert rc == 0


def test_build_app_requires_secret(tmp_path, monkeypatch):
    from dashboard_api import main as main_mod

    cfg = tmp_path / "c.yaml"
    cfg.write_text(
        "dashboard:\n  jwt_secret: ''\nstorage:\n  postgres_dsn: postgresql://x\n  s3:\n    endpoint: http://minio:9000\n    bucket: b\n    access_key: a\n    secret_key: s\n"
    )
    monkeypatch.setenv("DBAGENT_DASHBOARD_CONFIG", str(cfg))
    with pytest.raises(SystemExit):
        main_mod.build_app(str(cfg))


def test_build_app_ok(tmp_path, monkeypatch):
    from dashboard_api import main as main_mod

    cfg = tmp_path / "c.yaml"
    cfg.write_text(
        "dashboard:\n  jwt_secret: 'secret-value-here'\n"
        "storage:\n  postgres_dsn: postgresql://x\n  s3:\n    endpoint: http://minio:9000\n"
        "    bucket: b\n    access_key: a\n    secret_key: s\n"
        "temporal:\n  address: localhost:7233\n  namespace: default\n"
    )
    with patch("dashboard_api.main.make_engine") as me, patch(
        "dashboard_api.main.make_session_factory"
    ) as msf, patch("dashboard_api.main.boto3") as boto:
        me.return_value = MagicMock()
        msf.return_value = MagicMock()
        boto.client.return_value = MagicMock()
        app, config = main_mod.build_app(str(cfg))
        assert app is not None
        assert config.dashboard.jwt_secret == "secret-value-here"


@pytest.mark.asyncio
async def test_async_main_wires_temporal_and_serves(tmp_path, monkeypatch):
    """Mirror gateway: drive _async_main with connect + uvicorn.Server mocked."""
    from dashboard_api import main as main_mod

    cfg = tmp_path / "c.yaml"
    cfg.write_text(
        "dashboard:\n  jwt_secret: 'secret-value-here'\n"
        "storage:\n  postgres_dsn: postgresql://x\n  s3:\n    endpoint: http://minio:9000\n"
        "    bucket: b\n    access_key: a\n    secret_key: s\n"
        "temporal:\n  address: localhost:7233\n  namespace: default\n"
    )
    monkeypatch.setenv("DBAGENT_DASHBOARD_CONFIG", str(cfg))
    monkeypatch.setenv("DBAGENT_DASHBOARD_PORT", "0")
    monkeypatch.setenv("DBAGENT_DASHBOARD_HOST", "127.0.0.1")

    class FakeClient:
        pass

    async def fake_connect(*a, **k):
        return FakeClient()

    served = {}

    class FakeServer:
        async def serve(self):
            served["ok"] = True

    class FakeConfig:
        def __init__(self, app, host, port, log_level="info"):
            self.app = app
            self.host = host
            self.port = port

    with patch("dashboard_api.main.make_engine") as me, patch(
        "dashboard_api.main.make_session_factory"
    ) as msf, patch("dashboard_api.main.boto3") as boto:
        me.return_value = MagicMock()
        msf.return_value = MagicMock()
        boto.client.return_value = MagicMock()
        monkeypatch.setattr("dashboard_api.main.Client.connect", fake_connect)
        monkeypatch.setattr("dashboard_api.main.uvicorn.Config", FakeConfig)
        monkeypatch.setattr(
            "dashboard_api.main.uvicorn.Server", lambda cfg: FakeServer()
        )
        await main_mod._async_main()
    assert served["ok"] is True


def test_main_starts_async(monkeypatch):
    from dashboard_api import main as main_mod

    called = {}

    async def fake_async_main():
        called["ok"] = True

    monkeypatch.setattr(main_mod, "_async_main", fake_async_main)
    main_mod.main()
    assert called["ok"] is True


@pytest.mark.asyncio
async def test_list_llm_calls_and_audit_cursor(client, session_factory, object_store):
    """Exercise list_llm_calls filters + audit cursor pagination paths."""
    from datetime import datetime, timezone
    import uuid
    from rca_common.db.models import AuditLog, LLMCall, Platform
    from dashboard_helpers import login

    seed_user(session_factory, username="ad", password="admin-pass-123", role="admin")
    inv = uuid.uuid4()
    with session_factory() as s:
        s.add(
            Platform(
                platform_key="p-llm",
                platform_type="presto",
                deployment="k8s",
                display_name="p",
                status="online",
                config={},
                created_at=datetime.now(timezone.utc),
            )
        )
        for i in range(3):
            s.add(
                LLMCall(
                    call_id=uuid.uuid4(),
                    created_at=datetime.now(timezone.utc),
                    investigation_id=inv,
                    round=1,
                    agent_role="rca",
                    model="m",
                    provider="p",
                    prompt_ref=f"pr/{i}",
                    response_ref=f"rs/{i}",
                    cost_usd=0.01,
                    latency_ms=1,
                )
            )
            s.add(
                AuditLog(
                    investigation_id=inv,
                    actor="system",
                    action="case_opened",
                    detail={},
                    at=datetime.now(timezone.utc),
                )
            )
        s.commit()
    object_store.put("pr/0", b"x")
    tok = await login(client, "ad", "admin-pass-123")
    h = {"Authorization": f"Bearer {tok}"}
    r = await client.get(
        "/api/v1/llm-calls",
        headers=h,
        params={"investigation_id": str(inv), "round": 1, "agent_role": "rca", "limit": 2},
    )
    assert r.status_code == 200
    assert len(r.json()["items"]) == 2
    assert r.json()["next_cursor"] is not None
    r2 = await client.get(
        "/api/v1/llm-calls",
        headers=h,
        params={"investigation_id": str(inv), "cursor": r.json()["next_cursor"]},
    )
    assert r2.status_code == 200

    r = await client.get("/api/v1/audit", headers=h, params={"limit": 2})
    assert r.status_code == 200
    assert r.json()["next_cursor"] is not None


@pytest.mark.asyncio
async def test_unknown_approval_and_investigation_404(client, session_factory):
    from dashboard_helpers import login
    import uuid

    seed_user(session_factory, username="a", password="approver-pass12", role="approver")
    tok = await login(client, "a", "approver-pass12")
    h = {"Authorization": f"Bearer {tok}"}
    r = await client.get(
        f"/api/v1/investigations/{uuid.uuid4()}",
        headers=h,
    )
    assert r.status_code == 404
    r = await client.post(
        f"/api/v1/approvals/{uuid.uuid4()}/decision",
        headers=h,
        json={"decision": "approved"},
    )
    assert r.status_code == 404


@pytest.mark.asyncio
async def test_workflow_closed_on_decision_returns_409(
    client, session_factory, temporal_client
):
    """Signal RPC reports closed workflow → 409 case_terminal after decision."""
    from datetime import datetime, timezone
    import uuid
    from rca_common.db.models import Approval, Investigation, Platform
    from dashboard_helpers import login

    seed_user(session_factory, username="a", password="approver-pass12", role="approver")
    inv_id = uuid.uuid4()
    aid = uuid.uuid4()
    wf = f"investigation-{inv_id}"
    with session_factory() as s:
        s.add(
            Platform(
                platform_key="p-closed",
                platform_type="presto",
                deployment="k8s",
                display_name="p",
                status="online",
                config={},
                created_at=datetime.now(timezone.utc),
            )
        )
        s.flush()
        s.add(
            Investigation(
                investigation_id=inv_id,
                created_at=datetime.now(timezone.utc),
                platform_key="p-closed",
                status="AWAITING_APPROVAL",
                trigger_event=None,
                workflow_id=wf,
                budget={"max_rounds": 15, "max_cost_usd": 10.0, "max_wall_seconds": 1800},
                spent={"rounds": 1, "cost_usd": 0},
                rca_report=None,
            )
        )
        s.add(
            Approval(
                approval_id=aid,
                investigation_id=inv_id,
                kind="raw_command",
                subject={},
                decision=None,
                created_at=datetime.now(timezone.utc),
            )
        )
        s.commit()
    temporal_client.closed.add(wf)
    tok = await login(client, "a", "approver-pass12")
    r = await client.post(
        f"/api/v1/approvals/{aid}/decision",
        headers={"Authorization": f"Bearer {tok}"},
        json={"decision": "approved"},
    )
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "case_terminal"
