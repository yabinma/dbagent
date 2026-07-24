"""FastAPI app for dashboard-api (design.md Section 10.2 / Appendix D).

Factory pattern mirrors ``gateway.app.create_app``.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from fastapi import Depends, FastAPI, Query, Request
from fastapi.middleware.cors import CORSMiddleware

from dashboard_api.auth import (
    AuthUser,
    authenticate_user,
    issue_token,
    require_role,
)
from dashboard_api.errors import APIError, api_error_handler
from dashboard_api import services as svc
from dashboard_api.temporal_signals import WorkflowNotRunning, signal_workflow
from rca_common.audit import actor_user, write_audit
from rca_common.investigation_repo import TERMINAL_STATUSES
from rca_common.userauth import hash_password, verify_password


@dataclass
class DashboardAppConfig:
    jwt_secret: str
    token_ttl_seconds: int = 43200
    password_min_length: int = 12
    cors_origins: list[str] = field(default_factory=list)
    bootstrap_ca_cert_path: str = ""
    notification_webhooks: list[dict[str, Any]] = field(default_factory=list)


SIGNAL_AUDIT = {
    "pause": "case_paused",
    "resume": "case_resumed",
    "abort": "case_aborted",
    "adjust_budget": "budget_adjusted",
}


def create_app(
    *,
    session_factory,
    temporal_client=None,
    object_store=None,
    config: DashboardAppConfig,
) -> FastAPI:
    if not config.jwt_secret:
        raise ValueError("dashboard.jwt_secret is required; dashboard-api refuses to start with an empty secret")

    app = FastAPI(title="rca-dashboard-api", version="0.1.0")
    app.state.session_factory = session_factory
    app.state.temporal_client = temporal_client
    app.state.object_store = object_store
    app.state.config = config

    ca_fp = svc.ca_fingerprint(config.bootstrap_ca_cert_path) if config.bootstrap_ca_cert_path else None
    app.state.ca_fingerprint = ca_fp

    if config.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=config.cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    app.add_exception_handler(APIError, api_error_handler)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    # ---- D.1 Auth --------------------------------------------------------
    @app.post("/api/v1/auth/login")
    async def login(request: Request) -> dict[str, Any]:
        body = await request.json()
        username = (body.get("username") or "").strip()
        password = body.get("password") or ""
        with session_factory() as session:
            user = authenticate_user(session, username, password)
            if user is None:
                raise APIError(401, "invalid_credentials", "bad credentials or disabled user")
            token, exp = issue_token(
                user_id=user.user_id,
                username=user.username,
                role=user.role,
                jwt_secret=config.jwt_secret,
                ttl_seconds=config.token_ttl_seconds,
            )
            return {
                "token": token,
                "role": user.role,
                "expires_at": exp.isoformat(),
                "must_change_password": bool(getattr(user, "must_change_password", False)),
            }

    @app.post("/api/v1/auth/change-password", status_code=204)
    async def change_password(
        request: Request,
        user: AuthUser = Depends(require_role("viewer")),
    ) -> None:
        body = await request.json()
        old_password = body.get("old_password") or ""
        new_password = body.get("new_password") or ""
        if len(new_password) < config.password_min_length:
            raise APIError(
                400,
                "password_too_short",
                f"new_password must be at least {config.password_min_length} characters",
            )
        from rca_common.db.models import User

        with session_factory() as session:
            row = session.get(User, user.user_id)
            if row is None:
                raise APIError(401, "unauthorized", "user not found")
            if not verify_password(row.password_hash, old_password):
                raise APIError(401, "invalid_credentials", "old_password is wrong")
            row.password_hash = hash_password(new_password)
            row.must_change_password = False
            write_audit(
                session,
                action="admin_config_changed",
                actor=actor_user(user.user_id),
                detail={
                    "entity": "user",
                    "entity_id": str(user.user_id),
                    "change": "password_change",
                },
            )
            session.commit()

    # ---- D.2 Investigations ----------------------------------------------
    @app.get("/api/v1/investigations")
    async def get_investigations(
        status: list[str] | None = Query(default=None),
        platform_key: str | None = None,
        category: str | None = None,
        cursor: str | None = None,
        limit: int = 50,
        user: AuthUser = Depends(require_role("viewer")),
    ) -> dict[str, Any]:
        with session_factory() as session:
            return svc.list_investigations(
                session,
                status=status,
                platform_key=platform_key,
                category=category,
                cursor=cursor,
                limit=limit,
            )

    @app.get("/api/v1/investigations/{investigation_id}")
    async def get_investigation(
        investigation_id: uuid.UUID,
        user: AuthUser = Depends(require_role("viewer")),
    ) -> dict[str, Any]:
        with session_factory() as session:
            return svc.get_investigation_detail(session, investigation_id)

    @app.get("/api/v1/investigations/{investigation_id}/iterations")
    async def get_iterations(
        investigation_id: uuid.UUID,
        user: AuthUser = Depends(require_role("viewer")),
    ) -> dict[str, Any]:
        with session_factory() as session:
            return svc.list_iterations(session, investigation_id)

    @app.post("/api/v1/investigations/{investigation_id}/signal")
    async def post_signal(
        investigation_id: uuid.UUID,
        request: Request,
        user: AuthUser = Depends(require_role("approver")),
    ) -> dict[str, Any]:
        body = await request.json()
        action = body.get("action")
        if action not in ("pause", "resume", "abort", "adjust_budget"):
            raise APIError(400, "invalid_action", f"unknown signal action {action!r}")
        with session_factory() as session:
            inv = svc.latest_investigation(session, investigation_id)
            if inv is None:
                raise APIError(404, "not_found", f"investigation {investigation_id} not found")
            if inv.status in TERMINAL_STATUSES:
                raise APIError(409, "case_terminal", "case is terminal")
            workflow_id = inv.workflow_id
            try:
                if action == "adjust_budget":
                    await signal_workflow(
                        app.state.temporal_client,
                        workflow_id,
                        "adjust_budget",
                        body.get("budget") or {},
                    )
                else:
                    await signal_workflow(app.state.temporal_client, workflow_id, action)
            except WorkflowNotRunning as exc:
                raise APIError(409, "case_terminal", "workflow is not running") from exc
            write_audit(
                session,
                action=SIGNAL_AUDIT[action],
                actor=actor_user(user.user_id),
                investigation_id=investigation_id,
                detail={"action": action, "budget": body.get("budget")},
            )
            session.commit()
        return {"ok": True, "action": action}

    # ---- D.3 Evidence / Traces -------------------------------------------
    @app.get("/api/v1/evidence/{evidence_id}")
    async def get_evidence(
        evidence_id: uuid.UUID,
        full: bool = False,
        user: AuthUser = Depends(require_role("viewer")),
    ) -> dict[str, Any]:
        with session_factory() as session:
            return svc.get_evidence(
                session,
                evidence_id,
                full=full,
                object_store=app.state.object_store,
            )

    @app.get("/api/v1/llm-calls")
    async def get_llm_calls(
        investigation_id: str | None = None,
        round: int | None = None,
        agent_role: str | None = None,
        cursor: str | None = None,
        limit: int = 50,
        user: AuthUser = Depends(require_role("viewer")),
    ) -> dict[str, Any]:
        with session_factory() as session:
            return svc.list_llm_calls(
                session,
                investigation_id=investigation_id,
                round_num=round,
                agent_role=agent_role,
                cursor=cursor,
                limit=limit,
                object_store=app.state.object_store,
            )

    # ---- D.4 Approvals ---------------------------------------------------
    @app.get("/api/v1/approvals")
    async def get_approvals(
        pending: bool = True,
        limit: int = 50,
        user: AuthUser = Depends(require_role("approver")),
    ) -> dict[str, Any]:
        with session_factory() as session:
            return svc.list_approvals(session, pending=pending, limit=limit)

    @app.post("/api/v1/approvals/{approval_id}/decision")
    async def post_decision(
        approval_id: uuid.UUID,
        request: Request,
        user: AuthUser = Depends(require_role("approver")),
    ) -> dict[str, Any]:
        body = await request.json()
        decision = body.get("decision")
        comment = body.get("comment")
        with session_factory() as session:
            row, inv = svc.decide_approval_atomic(
                session,
                approval_id,
                decision=decision,
                decided_by=user.user_id,
                comment=comment,
            )
            session.commit()
            workflow_id = inv.workflow_id
            try:
                await signal_workflow(
                    app.state.temporal_client,
                    workflow_id,
                    "approval_decided",
                    {
                        "approval_id": str(approval_id),
                        "decision": decision,
                        "comment": comment,
                    },
                )
            except WorkflowNotRunning as exc:
                # Decision stays recorded (Section 10.2.3 benign terminal race).
                raise APIError(409, "case_terminal", "workflow is not running") from exc
        return {
            "approval_id": str(approval_id),
            "decision": decision,
            "ok": True,
        }

    # ---- D.5 Administration ----------------------------------------------
    @app.get("/api/v1/platforms")
    async def get_platforms(
        user: AuthUser = Depends(require_role("viewer")),
    ) -> dict[str, Any]:
        with session_factory() as session:
            return svc.list_platforms(session, ca_fp=app.state.ca_fingerprint)

    @app.post("/api/v1/platforms", status_code=201)
    async def post_platform(
        request: Request,
        user: AuthUser = Depends(require_role("admin")),
    ) -> dict[str, Any]:
        body = await request.json()
        with session_factory() as session:
            out = svc.create_platform(session, body, user.user_id)
            session.commit()
            return out

    @app.patch("/api/v1/platforms/{key}")
    async def patch_platform(
        key: str,
        request: Request,
        user: AuthUser = Depends(require_role("admin")),
    ) -> dict[str, Any]:
        body = await request.json()
        with session_factory() as session:
            out = svc.patch_platform(session, key, body, user.user_id)
            session.commit()
            return out

    @app.post("/api/v1/platforms/{key}/bootstrap-token")
    async def post_bootstrap_token(
        key: str,
        user: AuthUser = Depends(require_role("admin")),
    ) -> dict[str, Any]:
        with session_factory() as session:
            out = svc.issue_bootstrap_token(session, key, user.user_id)
            session.commit()
            return out

    @app.get("/api/v1/probes")
    async def get_probes(
        user: AuthUser = Depends(require_role("admin")),
    ) -> dict[str, Any]:
        with session_factory() as session:
            return svc.list_probes(session, ca_fp=app.state.ca_fingerprint)

    @app.get("/api/v1/playbooks")
    async def get_playbooks(
        user: AuthUser = Depends(require_role("viewer")),
    ) -> dict[str, Any]:
        with session_factory() as session:
            return svc.list_playbooks(session)

    @app.get("/api/v1/playbooks/{playbook_id}")
    async def get_playbook(
        playbook_id: str,
        user: AuthUser = Depends(require_role("viewer")),
    ) -> dict[str, Any]:
        with session_factory() as session:
            return svc.get_playbook(session, playbook_id)

    @app.put("/api/v1/playbooks/{playbook_id}")
    async def put_playbook(
        playbook_id: str,
        request: Request,
        user: AuthUser = Depends(require_role("admin")),
    ) -> dict[str, Any]:
        body = await request.json()
        with session_factory() as session:
            return svc.put_playbook_auto_eligible(session, playbook_id, body, user.user_id)

    @app.get("/api/v1/users")
    async def get_users(
        user: AuthUser = Depends(require_role("admin")),
    ) -> dict[str, Any]:
        with session_factory() as session:
            return svc.list_users(session)

    @app.post("/api/v1/users", status_code=201)
    async def post_user(
        request: Request,
        user: AuthUser = Depends(require_role("admin")),
    ) -> dict[str, Any]:
        body = await request.json()
        if body.get("password") and len(body["password"]) < config.password_min_length:
            raise APIError(
                400,
                "password_too_short",
                f"password must be at least {config.password_min_length} characters",
            )
        with session_factory() as session:
            out = svc.create_user(session, body, user.user_id)
            session.commit()
            return out

    @app.patch("/api/v1/users/{user_id}")
    async def patch_user(
        user_id: uuid.UUID,
        request: Request,
        user: AuthUser = Depends(require_role("admin")),
    ) -> dict[str, Any]:
        body = await request.json()
        with session_factory() as session:
            out = svc.patch_user(session, user_id, body, user.user_id)
            session.commit()
            return out

    @app.post("/api/v1/admin/notifications/test")
    async def post_notification_test(
        user: AuthUser = Depends(require_role("admin")),
    ) -> dict[str, Any]:
        with session_factory() as session:
            out = await svc.test_notifications(
                config.notification_webhooks, user.user_id, session
            )
            session.commit()
            return out

    @app.get("/api/v1/audit")
    async def get_audit(
        investigation_id: str | None = None,
        actor: str | None = None,
        action: str | None = None,
        from_: str | None = Query(default=None, alias="from"),
        to: str | None = None,
        cursor: str | None = None,
        limit: int = 50,
        user: AuthUser = Depends(require_role("admin")),
    ) -> dict[str, Any]:
        with session_factory() as session:
            return svc.list_audit(
                session,
                investigation_id=investigation_id,
                actor=actor,
                action=action,
                from_ts=from_,
                to_ts=to,
                cursor=cursor,
                limit=limit,
            )

    @app.get("/api/v1/metrics/summary")
    async def get_metrics(
        window: str = "7d",
        user: AuthUser = Depends(require_role("viewer")),
    ) -> dict[str, Any]:
        with session_factory() as session:
            return svc.metrics_summary(session, window=window)

    return app
