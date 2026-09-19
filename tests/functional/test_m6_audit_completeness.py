"""FP-M6-25 / F16: every AUDIT_ACTIONS value is emitted at its trigger point.

Non-credentials actions are produced by calling the production functions that
own them (ingest, investigation_repo, activities, dashboard signal endpoints).
credentials_* are produced by real probe-gateway Session registration and
mid-session re-register (ManifestRefresh), never by a Transitions/Write hand
loop or a Python self-insert (code review round 7, C6).
"""
from __future__ import annotations

import json
import os
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
import pytest
from sqlalchemy import text

from rca_common.db.models import AUDIT_ACTIONS, Approval, Platform, User
from rca_common.db.session import make_engine, make_session_factory
from rca_common.investigation_repo import open_case_from_event
from rca_common.userauth import hash_password

REPO = Path(__file__).resolve().parents[2]


def _seed_platform(session, key: str = "f16-plat") -> None:
    if session.get(Platform, key) is None:
        session.add(
            Platform(
                platform_key=key,
                platform_type="presto",
                deployment="k8s",
                display_name=key,
                status="online",
                config={},
                created_at=datetime.now(timezone.utc),
            )
        )


def _seed_admin(session) -> uuid.UUID:
    uid = uuid.uuid4()
    session.add(
        User(
            user_id=uid,
            username=f"f16admin-{uid.hex[:8]}",
            password_hash=hash_password("f16-admin-pass-12"),
            role="admin",
            created_at=datetime.now(timezone.utc),
            disabled=False,
            must_change_password=False,
        )
    )
    return uid


def _emit_ingest_and_case(session_factory) -> uuid.UUID:
    """event_rejected / case_opened via real APIs; event_received/merged via M3."""
    from gateway.ingest import IngestService

    inv_id = uuid.uuid4()
    event_id = uuid.uuid4()

    with session_factory() as session:
        _seed_platform(session)
        session.commit()

    # event_rejected via IngestService._reject
    svc = IngestService(
        session_factory,
        budget_defaults={"max_rounds": 5, "max_cost_usd": 1.0, "max_wall_seconds": 600},
        known_sources={"grafana": "secret"},
        workflow_starter=None,
    )
    with session_factory() as session:
        svc._reject(  # noqa: SLF001 — production reject path
            session,
            {
                "event_id": str(uuid.uuid4()),
                "fingerprint": "fp-reject",
                "source": "grafana",
                "platform_key": "f16-plat",
                "severity": "low",
            },
            "f16-reject",
        )
        session.commit()

    # case_opened via open_case_from_event (ingest/workflow path)
    with session_factory() as session:
        open_case_from_event(
            session,
            event={
                "event_id": str(event_id),
                "platform_key": "f16-plat",
                "fingerprint": "fp-f16",
            },
            workflow_id=f"investigation-{inv_id}",
            budget={"max_rounds": 5, "max_cost_usd": 1.0, "max_wall_seconds": 600},
            investigation_id=inv_id,
        )
        session.commit()
    # event_received / event_merged: call-site presence only. Real emission at
    # the ingest trigger is proven by M3's test_f16_audit_actions_emitted (W2).
    ingest_src = (REPO / "services/gateway/gateway/ingest.py").read_text(encoding="utf-8")
    assert 'action="event_received"' in ingest_src
    assert 'action="event_merged"' in ingest_src
    return inv_id


# Activity actions already exercised at their Temporal triggers by
# test_m3_investigation_loop.py::test_f16_audit_actions_emitted. M6 only
# greps call sites for these — no self-insert (review W2).
_M3_TRIGGER_COVERED_ACTIONS = frozenset(
    {
        "event_received",
        "event_merged",
        "event_rejected",
        "case_opened",
        "round_started",
        "task_dispatched",
        "tool_executed",
        "raw_cmd_requested",
        "raw_cmd_approved",
        "raw_cmd_denied",
        "rca_produced",
        "budget_exceeded",
        "remediation_proposed",
        "approval_requested",
        "approval_decided",
        "remediation_started",
        "remediation_finished",
        "verification_run",
        "case_closed",
    }
)


def _emit_activity_actions(
    session_factory, inv_id: uuid.UUID, baseline_seq: int
) -> None:
    """Worker-owned actions: live call-site grep for M3-covered set; real
    ``send_notifications`` Activity for ``notification_sent`` (round 7, C6).

    credentials_* are handled separately through the Go probe-gateway Session path.
    """
    import asyncio
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from threading import Thread

    from worker.activities import investigation as inv_src
    from worker.activities.investigation import InvestigationActivities

    src = Path(inv_src.__file__).read_text(encoding="utf-8")
    activity_actions = [
        "round_started",
        "task_dispatched",
        "tool_executed",
        "raw_cmd_requested",
        "rca_produced",
        "budget_exceeded",
        "remediation_proposed",
        "approval_requested",
        "remediation_started",
        "remediation_finished",
        "verification_run",
        "case_closed",
        "notification_sent",
    ]
    for action in activity_actions:
        assert f'action="{action}"' in src or f"action='{action}'" in src, (
            f"{action} missing from investigation activities (trigger deleted?)"
        )

    # Drive the real send_notifications Activity so notification_sent is
    # produced by production code, not a self-insert (round 7, C6).
    class _OK(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            length = int(self.headers.get("Content-Length", 0))
            if length:
                self.rfile.read(length)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args):  # silence
            return

    server = HTTPServer(("127.0.0.1", 0), _OK)
    port = server.server_address[1]
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        acts = InvestigationActivities(
            session_factory=session_factory,
            llm_client=None,
            probe_client=None,
            config=None,
            dashboard_base_url="http://dash.test",
        )
        results = asyncio.run(
            acts.send_notifications(
                {
                    "event": "case_resolved",
                    "payload": {
                        "investigation_id": str(inv_id),
                        "platform_key": "f16-plat",
                        "severity": "high",
                        "summary": "f16 notification",
                    },
                    "webhooks": [
                        {
                            "name": "f16-hook",
                            "url": f"http://127.0.0.1:{port}/hook",
                            "format": "generic",
                            "events": ["case_resolved"],
                            "min_severity": "low",
                        }
                    ],
                }
            )
        )
        assert results.get("ok") is True, results
        assert any(r.get("ok") for r in (results.get("results") or [])), results
    finally:
        server.shutdown()

    with session_factory() as session:
        # Scope to this test's investigation *and* post-baseline rows so
        # earlier functional tests (or concurrent writers) cannot satisfy
        # the assertion (review C2/C3).
        exists = session.execute(
            text(
                "SELECT 1 FROM audit_log WHERE action = 'notification_sent' "
                "AND investigation_id = :id AND seq > :base LIMIT 1"
            ),
            {"id": str(inv_id), "base": baseline_seq},
        ).first()
        assert exists, "send_notifications did not write notification_sent"


def _emit_dashboard_actions(
    session_factory, inv_id: uuid.UUID, baseline_seq: int
) -> None:
    """Dashboard-owned: approval_decided, raw_cmd_*, signals, admin_config_changed.

    Signals go through the real FastAPI ``POST .../signal`` endpoint so deleting
    the write_audit call sites in app.py cannot leave F16 green (round 7, C6).
    """
    import asyncio

    from dashboard_api import app as dash_app
    from dashboard_api import services as dash
    from dashboard_api.app import DashboardAppConfig, create_app
    from httpx import ASGITransport, AsyncClient

    admin_password = "f16-admin-pass-12"
    with session_factory() as session:
        user_id = _seed_admin(session)
        admin = session.get(User, user_id)
        assert admin is not None
        admin_username = admin.username
        # Ensure the investigation is non-terminal so signals are accepted.
        # Composite PK (investigation_id, created_at) — query, don't session.get.
        inv = session.execute(
            text(
                "SELECT investigation_id FROM investigations "
                "WHERE investigation_id = :id LIMIT 1"
            ),
            {"id": str(inv_id)},
        ).first()
        if inv is not None:
            session.execute(
                text(
                    "UPDATE investigations SET status = 'INVESTIGATING', "
                    "workflow_id = COALESCE(NULLIF(workflow_id, ''), :wf) "
                    "WHERE investigation_id = :id"
                ),
                {"id": str(inv_id), "wf": f"investigation-{inv_id}"},
            )
        appr_ok = uuid.uuid4()
        appr_deny = uuid.uuid4()
        session.add(
            Approval(
                approval_id=appr_ok,
                investigation_id=inv_id,
                kind="raw_command",
                subject={"command": "echo ok"},
                created_at=datetime.now(timezone.utc),
            )
        )
        session.add(
            Approval(
                approval_id=appr_deny,
                investigation_id=inv_id,
                kind="raw_command",
                subject={"command": "echo no"},
                created_at=datetime.now(timezone.utc),
            )
        )
        session.commit()

    with session_factory() as session:
        dash.decide_approval_atomic(
            session,
            appr_ok,
            decision="approved",
            decided_by=user_id,
            comment="f16",
        )
        dash.decide_approval_atomic(
            session,
            appr_deny,
            decision="denied",
            decided_by=user_id,
            comment="f16",
        )
        dash.patch_platform(
            session, "f16-plat", {"display_name": "f16-renamed"}, user_id
        )
        session.commit()

    assert dash_app.SIGNAL_AUDIT["pause"] == "case_paused"
    assert dash_app.SIGNAL_AUDIT["resume"] == "case_resumed"
    assert dash_app.SIGNAL_AUDIT["abort"] == "case_aborted"
    assert dash_app.SIGNAL_AUDIT["adjust_budget"] == "budget_adjusted"

    class _FakeHandle:
        def __init__(self, workflow_id: str, parent: "_FakeTemporal"):
            self.workflow_id = workflow_id
            self._parent = parent

        async def signal(self, name, arg=None):
            self._parent.signals.append(
                {"workflow_id": self.workflow_id, "name": name, "arg": arg}
            )

    class _FakeTemporal:
        def __init__(self):
            self.signals: list[dict] = []

        def get_workflow_handle(self, workflow_id: str):
            return _FakeHandle(workflow_id, self)

    temporal = _FakeTemporal()
    app = create_app(
        session_factory=session_factory,
        temporal_client=temporal,
        object_store=None,
        config=DashboardAppConfig(
            jwt_secret="f16-test-jwt-secret-key-32bytes!",
            token_ttl_seconds=3600,
            password_min_length=12,
        ),
    )

    async def _drive_signals() -> None:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            lr = await client.post(
                "/api/v1/auth/login",
                json={"username": admin_username, "password": admin_password},
            )
            assert lr.status_code == 200, lr.text
            token = lr.json().get("token") or lr.json().get("access_token")
            assert token, lr.text
            headers = {"Authorization": f"Bearer {token}"}
            for action, extra in [
                ("pause", {}),
                ("resume", {}),
                ("adjust_budget", {"budget": {"max_rounds": 9}}),
                ("abort", {}),
            ]:
                r = await client.post(
                    f"/api/v1/investigations/{inv_id}/signal",
                    headers=headers,
                    json={"action": action, **extra},
                )
                assert r.status_code == 200, f"{action}: {r.status_code} {r.text}"

    asyncio.run(_drive_signals())
    assert {s["name"] for s in temporal.signals} >= {
        "pause",
        "resume",
        "adjust_budget",
        "abort",
    }

    with session_factory() as session:
        for action in (
            "case_paused",
            "case_resumed",
            "budget_adjusted",
            "case_aborted",
        ):
            # Scope to this test's investigation and post-baseline rows
            # (review C2/C3).
            exists = session.execute(
                text(
                    "SELECT 1 FROM audit_log WHERE action = :a "
                    "AND investigation_id = :id AND seq > :base LIMIT 1"
                ),
                {"a": action, "id": str(inv_id), "base": baseline_seq},
            ).first()
            assert exists, f"signal endpoint did not emit {action}"


def _run_go_f16_test(postgres_dsn: str, test_name: str, *, audit: bool, refresh: bool) -> None:
    """Invoke a single F16 Go integration test against the shared Postgres DSN."""
    dsn = postgres_dsn
    if dsn.startswith("postgresql+psycopg2://"):
        dsn = "postgres://" + dsn[len("postgresql+psycopg2://") :]
    elif dsn.startswith("postgresql://"):
        dsn = "postgres://" + dsn[len("postgresql://") :]

    env = os.environ.copy()
    if audit:
        env["F16_AUDIT_DSN"] = dsn
    if refresh:
        env["F16_REFRESH_DSN"] = dsn
    env["GOCACHE"] = env.get("GOCACHE", "/tmp/go-cache")
    env["GOMODCACHE"] = env.get("GOMODCACHE", "/tmp/go-mod")
    proc = subprocess.run(
        [
            "go",
            "test",
            "./services/probe-gateway/internal/gwserver/",
            "-run",
            f"^{test_name}$",
            "-count=1",
            "-v",
        ],
        cwd=str(REPO),
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode == 0, (
        f"Go F16 test {test_name} failed:\n{proc.stdout}\n{proc.stderr}"
    )


def test_f16_every_audit_action_emitted_at_its_trigger(postgres_dsn):
    engine = make_engine(postgres_dsn)
    factory = make_session_factory(engine)

    # Capture baseline before any emit so session-scoped DSN rows from earlier
    # functional tests cannot satisfy missing production emissions (review C3).
    with factory() as session:
        baseline_seq = session.execute(
            text("SELECT COALESCE(MAX(seq), 0) FROM audit_log")
        ).scalar()

    inv_id = _emit_ingest_and_case(factory)
    _emit_activity_actions(factory, inv_id, baseline_seq)
    _emit_dashboard_actions(factory, inv_id, baseline_seq)
    # Fake-probe path only — real-session-client is a separate function test
    # (review C4) so its f16-refresh-plat rows cannot poison this assertion.
    _run_go_f16_test(
        postgres_dsn,
        "TestF16_CredentialsEmittedAtRegistrationAndRefresh",
        audit=True,
        refresh=False,
    )

    with factory() as session:
        # Post-baseline rows scoped to this investigation or f16-plat.
        # event_rejected / admin_config_changed carry no investigation_id and
        # no detail.platform_key (platform lives under detail.entity_id for
        # admin_config_changed); they remain the explicit baseline-only
        # exceptions so they are not dropped by inv/platform filters
        # (review C2).
        rows = session.execute(
            text(
                "SELECT DISTINCT action FROM audit_log "
                "WHERE seq > :base AND ("
                "  investigation_id = :inv"
                "  OR detail->>'platform_key' = :plat"
                "  OR action IN ('event_rejected', 'admin_config_changed')"
                ")"
            ),
            {
                "base": baseline_seq,
                "inv": str(inv_id),
                "plat": "f16-plat",
            },
        ).fetchall()
        emitted = {r[0] for r in rows}
        # M3 trigger-covered activity actions are grepped above and proven in
        # test_m3_investigation_loop::test_f16_audit_actions_emitted — not
        # re-inserted here. Require every *other* enum value in this DB.
        required_here = set(AUDIT_ACTIONS) - _M3_TRIGGER_COVERED_ACTIONS
        # Re-add enums this test *does* emit via real production paths.
        required_here |= {
            "event_rejected",
            "case_opened",
            "approval_decided",
            "raw_cmd_approved",
            "raw_cmd_denied",
            "admin_config_changed",
            "notification_sent",
            "case_paused",
            "case_resumed",
            "case_aborted",
            "budget_adjusted",
            "credentials_detected",
            "credentials_verified",
            "credentials_test_failed",
        }
        missing = required_here - emitted
        assert not missing, f"missing audit actions: {sorted(missing)}"

        # Call-site presence for the M3-covered activity set still holds.
        from worker.activities import investigation as inv_src

        src = Path(inv_src.__file__).read_text(encoding="utf-8")
        for action in _M3_TRIGGER_COVERED_ACTIONS:
            if action.startswith("credentials_") or action in {
                "event_received",
                "event_merged",
                "event_rejected",
                "case_opened",
                "approval_decided",
                "raw_cmd_approved",
                "raw_cmd_denied",
                "admin_config_changed",
            }:
                continue
            assert f'action="{action}"' in src or f"action='{action}'" in src, action

        # Filter to this test's own post-baseline f16-plat rows only (review C3/C4).
        cred_rows = session.execute(
            text(
                "SELECT action, actor, detail FROM audit_log "
                "WHERE action LIKE 'credentials_%' "
                "AND detail->>'platform_key' = 'f16-plat' "
                "AND seq > :base"
            ),
            {"base": baseline_seq},
        ).fetchall()
        seen_cred = {r[0] for r in cred_rows}
        for need in (
            "credentials_detected",
            "credentials_verified",
            "credentials_test_failed",
        ):
            assert need in seen_cred, seen_cred
        for action, actor, detail in cred_rows:
            assert str(actor).startswith("probe:"), (action, actor)
            if isinstance(detail, str):
                detail = json.loads(detail)
            assert detail.get("platform_key") == "f16-plat", (action, detail)


def test_f16_manifest_refresh_through_the_real_session_client(postgres_dsn):
    """FP-M6-25 / F16: real probe binary + sessionclient.ManifestRefresh path.

    Invokes only the real-client Go integration test (review C4) — not the
    fakeProbe path — so audit rows prove the production edge independently.
    """
    _run_go_f16_test(
        postgres_dsn,
        "TestF16_ManifestRefreshThroughTheRealSessionClientEmitsAudit",
        audit=False,
        refresh=True,
    )
