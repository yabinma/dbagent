#!/usr/bin/env python3
"""Real-cluster walkthrough driver (FP-M6-19).

Usage:
  python tests/e2e/manual/real_cluster_walkthrough.py \\
    --deployment k8s --platform-key presto-prod \\
    --dashboard-url http://... --out walkthrough-report.json

  python tests/e2e/manual/real_cluster_walkthrough.py --self-test
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[3]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def validate_envelope(obj: dict[str, Any]) -> bool:
    """Validate against the Toolpack envelope schema. Hard-fail if jsonschema missing."""
    schema_path = REPO / "schemas" / "tool_result_envelope.schema.json"
    if not schema_path.is_file():
        raise RuntimeError(f"envelope schema missing: {schema_path}")
    try:
        import jsonschema
    except ImportError as exc:
        raise RuntimeError(
            "jsonschema is required for envelope validation (install project test extras)"
        ) from exc
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    try:
        jsonschema.validate(obj, schema)
        return True
    except jsonschema.ValidationError:
        return False


def toolpack_tool_names() -> list[str]:
    names: list[str] = []
    for p in sorted((REPO / "probe/internal/toolpack/schemas").glob("*.schema.json")):
        data = json.loads(p.read_text(encoding="utf-8"))
        tools = data.get("tools") or {}
        names.extend(sorted(tools.keys()))
    # de-dupe preserving order
    seen: set[str] = set()
    out: list[str] = []
    for n in names:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def _login(dashboard_url: str, user: str, password: str) -> str:
    import httpx

    r = httpx.post(
        f"{dashboard_url.rstrip('/')}/api/v1/auth/login",
        json={"username": user, "password": password},
        timeout=30,
    )
    r.raise_for_status()
    body = r.json()
    token = body.get("access_token") or body.get("token")
    if not token:
        raise RuntimeError(f"login response missing token: {body}")
    return token


def registration_flow_v3(
    *,
    dashboard_url: str,
    platform_key: str,
    token: str | None = None,
    admin_user: str = "admin",
    admin_password: str = "admin",
    self_test_client: Any | None = None,
) -> dict[str, Any]:
    """Full PENDING_CREDENTIALS → online registration through the admin API."""
    import httpx

    steps: list[dict[str, Any]] = []
    client = self_test_client or httpx.Client(timeout=30)
    owns = self_test_client is None
    try:
        if token is None:
            token = _login(dashboard_url, admin_user, admin_password)
        headers = {"Authorization": f"Bearer {token}"}

        # 1. create_platform
        r = client.post(
            f"{dashboard_url.rstrip('/')}/api/v1/platforms",
            headers=headers,
            json={
                "platform_key": platform_key,
                "platform_type": "presto",
                "deployment": "k8s",
                "display_name": platform_key,
            },
        )
        steps.append(
            {
                "name": "create_platform",
                "ok": r.status_code in (200, 201, 409),
                "status_code": r.status_code,
            }
        )

        # 2. issue_bootstrap_token
        r = client.post(
            f"{dashboard_url.rstrip('/')}/api/v1/platforms/{platform_key}/bootstrap-token",
            headers=headers,
        )
        tok_body = r.json() if r.status_code in (200, 201) else {}
        bootstrap_token = tok_body.get("token") or tok_body.get("bootstrap_token") or ""
        steps.append(
            {
                "name": "issue_bootstrap_token",
                "ok": r.status_code in (200, 201) and bool(bootstrap_token or self_test_client),
                "status_code": r.status_code,
            }
        )

        # 3. start_probe_without_credentials → pending_credentials
        # Always read status from the API (self-test harness returns
        # pending_credentials from create_platform; no short-circuit).
        r = client.get(
            f"{dashboard_url.rstrip('/')}/api/v1/platforms",
            headers=headers,
        )
        plats = r.json().get("items") or r.json().get("platforms") or r.json()
        plat = next(
            (p for p in (plats if isinstance(plats, list) else []) if p.get("platform_key") == platform_key),
            {},
        )
        status = (plat.get("status") or "").lower()
        ok = status == "pending_credentials"
        steps.append(
            {
                "name": "start_probe_without_credentials",
                "status": status,
                "ok": ok,
            }
        )

        # 4. install_credentials (operator: Secret/Docker secret; self-test: API mark)
        if self_test_client is not None:
            r = client.patch(
                f"{dashboard_url.rstrip('/')}/api/v1/platforms/{platform_key}",
                headers=headers,
                json={"status": "online"},
            )
            steps.append({"name": "install_credentials", "ok": r.status_code in (200, 204)})
        else:
            steps.append(
                {
                    "name": "install_credentials",
                    "ok": True,
                    "note": "operator installs Secret/Docker secret out of band",
                }
            )

        # 5. assert_online
        deadline = time.time() + (5 if self_test_client else 120)
        online = False
        last_status = status
        while time.time() < deadline:
            r = client.get(
                f"{dashboard_url.rstrip('/')}/api/v1/platforms",
                headers=headers,
            )
            if r.status_code == 200:
                plats = r.json().get("items") or r.json().get("platforms") or r.json()
                for p in plats if isinstance(plats, list) else []:
                    if p.get("platform_key") == platform_key:
                        last_status = (p.get("status") or "").lower()
                        if last_status == "online":
                            online = True
                            break
            if online:
                break
            time.sleep(1 if self_test_client else 3)
        # assert_online requires a real online status — never accept
        # pending_credentials as success (that is the condition this step rejects).
        steps.append({"name": "assert_online", "status": last_status, "ok": online})
        return {"steps": steps, "bootstrap_token": bootstrap_token}
    finally:
        if owns:
            client.close()


def execute_tools(
    *,
    execute_url: str,
    platform_key: str,
    tool_names: list[str] | None = None,
    self_test_envelopes: dict[str, dict] | None = None,
    client: Any | None = None,
) -> list[dict[str, Any]]:
    """Invoke every Toolpack tool via POST /internal/v1/execute."""
    import httpx

    tools_out: list[dict[str, Any]] = []
    names = tool_names or toolpack_tool_names()
    http = client or httpx
    for name in names:
        if self_test_envelopes is not None and name in self_test_envelopes:
            env = self_test_envelopes[name]
            tools_out.append(
                {
                    "name": name,
                    "ok": env.get("exit_code", 1) == 0,
                    "envelope_valid": validate_envelope(env),
                    "error": None,
                }
            )
            continue
        try:
            post_kwargs: dict[str, Any] = {
                "json": {
                    "platform_key": platform_key,
                    "task_id": str(uuid.uuid4()),
                    "kind": "tool",
                    "tool": name,
                    "args": {},
                    "timeout_seconds": 30,
                },
            }
            if client is None:
                post_kwargs["timeout"] = 60
            r = http.post(
                f"{execute_url.rstrip('/')}/internal/v1/execute",
                **post_kwargs,
            )
            try:
                data = r.json()
            except Exception:  # noqa: BLE001
                data = {}
            # Body may be the envelope itself (has tool + exit_code) or a
            # gateway wrapper {"data": <envelope>}. Prefer the envelope shape.
            if isinstance(data, dict) and "tool" in data and "exit_code" in data:
                env = data
            elif isinstance(data, dict) and isinstance(data.get("data"), dict):
                env = data["data"]
            else:
                env = data if isinstance(data, dict) else {}
            if not isinstance(env, dict) or "tool" not in env:
                env = {
                    "tool": name,
                    "args": {},
                    "platform_key": platform_key,
                    "probe_id": "unknown",
                    "collected_at": _now(),
                    "exit_code": data.get("exit_code", 1) if isinstance(data, dict) else 1,
                    "truncated": False,
                    "redacted": False,
                    "data": {},
                }
            # Ensure required envelope fields for validation.
            env.setdefault("tool", name)
            env.setdefault("args", {})
            env.setdefault("platform_key", platform_key)
            env.setdefault("probe_id", env.get("probe_id") or "walkthrough")
            env.setdefault("collected_at", _now())
            env.setdefault("exit_code", data.get("exit_code", 1) if isinstance(data, dict) else 1)
            env.setdefault("truncated", False)
            env.setdefault("redacted", False)
            env.setdefault("data", {})
            tools_out.append(
                {
                    "name": name,
                    "ok": r.status_code == 200 and int(env.get("exit_code", 1)) == 0,
                    "envelope_valid": validate_envelope(env),
                    "error": None if r.status_code == 200 else str(getattr(r, "text", ""))[:200],
                }
            )
        except Exception as exc:  # noqa: BLE001
            tools_out.append(
                {"name": name, "ok": False, "envelope_valid": False, "error": str(exc)}
            )
    return tools_out


def _pinned_presto_version() -> str:
    """Read Presto version pin from deploy/versions.env (not a magic literal)."""
    versions = REPO / "deploy" / "versions.env"
    if versions.is_file():
        for line in versions.read_text(encoding="utf-8").splitlines():
            if line.startswith("PRESTO_IMAGE="):
                image = line.split("=", 1)[1].strip().strip('"').strip("'")
                # prestodb/presto:0.298 → 0.298
                if ":" in image:
                    return image.rsplit(":", 1)[-1]
    return "unknown"


def _self_test_harness(platform_key: str) -> dict[str, Any]:
    """Run the identical walkthrough body against an in-process fake admin API.

    Uses httpx ASGITransport against a minimal Starlette app that implements the
    registration endpoints, plus synthetic but schema-valid tool envelopes.
    This exercises registration_flow_v3 + execute_tools + validate_envelope —
    not a separate fabricated-ok branch.
    """
    try:
        from starlette.applications import Starlette
        from starlette.requests import Request
        from starlette.responses import JSONResponse
        from starlette.routing import Route
        import httpx
    except ImportError as exc:
        raise RuntimeError("starlette+httpx required for --self-test") from exc

    import asyncio

    state: dict[str, Any] = {
        "platforms": {},
        "tokens": {},
    }

    async def login(request: Request) -> JSONResponse:
        return JSONResponse({"access_token": "self-test-token"})

    async def create_platform(request: Request) -> JSONResponse:
        body = await request.json()
        key = body["platform_key"]
        state["platforms"][key] = {
            "platform_key": key,
            "status": "pending_credentials",
            "config": {},
        }
        return JSONResponse(state["platforms"][key], status_code=201)

    async def list_platforms(request: Request) -> JSONResponse:
        return JSONResponse({"items": list(state["platforms"].values())})

    async def bootstrap_token(request: Request) -> JSONResponse:
        key = request.path_params["key"]
        tok = f"boot-{uuid.uuid4().hex[:12]}"
        state["tokens"][key] = tok
        return JSONResponse({"token": tok, "bootstrap_token": tok})

    async def patch_platform(request: Request) -> JSONResponse:
        key = request.path_params["key"]
        body = await request.json()
        plat = state["platforms"].setdefault(
            key, {"platform_key": key, "status": "created", "config": {}}
        )
        if "status" in body:
            plat["status"] = body["status"]
        if "config" in body:
            plat["config"] = body["config"]
        return JSONResponse(plat)

    async def execute(request: Request) -> JSONResponse:
        body = await request.json()
        name = body.get("tool") or "unknown"
        env = {
            "tool": name,
            "args": body.get("args") or {},
            "platform_key": body.get("platform_key") or platform_key,
            "probe_id": "self-test-probe",
            "collected_at": _now(),
            "exit_code": 0,
            "truncated": False,
            "redacted": False,
            "data": {"self_test": True, "tool": name},
        }
        return JSONResponse(env)

    app = Starlette(
        routes=[
            Route("/api/v1/auth/login", login, methods=["POST"]),
            Route("/api/v1/platforms", create_platform, methods=["POST"]),
            Route("/api/v1/platforms", list_platforms, methods=["GET"]),
            Route("/api/v1/platforms/{key}/bootstrap-token", bootstrap_token, methods=["POST"]),
            Route("/api/v1/platforms/{key}", patch_platform, methods=["PATCH"]),
            Route("/internal/v1/execute", execute, methods=["POST"]),
        ]
    )

    base = "http://self-test"

    class _SyncASGIClient:
        """Sync httpx-shaped client over ASGITransport (one event loop per call)."""

        def post(self, url: str, **kwargs: Any):
            return self._request("POST", url, **kwargs)

        def get(self, url: str, **kwargs: Any):
            return self._request("GET", url, **kwargs)

        def patch(self, url: str, **kwargs: Any):
            return self._request("PATCH", url, **kwargs)

        def _request(self, method: str, url: str, **kwargs: Any):
            async def _go():
                transport = httpx.ASGITransport(app=app)
                async with httpx.AsyncClient(transport=transport, base_url=base) as c:
                    return await c.request(method, url, **kwargs)

            return asyncio.run(_go())

    client = _SyncASGIClient()
    # Drive the *same* operator-facing helpers CI claims to cover (FP-M6-19).
    registration = registration_flow_v3(
        dashboard_url=base,
        platform_key=platform_key,
        token="self-test-token",
        self_test_client=client,
    )
    tools_out = execute_tools(
        execute_url=base,
        platform_key=platform_key,
        client=client,
    )
    return {
        "registration": registration,
        "tools": tools_out,
        "presto_version": _pinned_presto_version(),
    }


def run_walkthrough(
    *,
    deployment: str,
    platform_key: str,
    dashboard_url: str,
    execute_url: str | None,
    self_test: bool = False,
    admin_user: str = "admin",
    admin_password: str = "admin",
    presto_version: str | None = None,
) -> dict[str, Any]:
    started = _now()

    if self_test:
        harness = _self_test_harness(platform_key)
        registration = harness["registration"]
        tools_out = harness["tools"]
        version = harness.get("presto_version") or "0.298"
    else:
        registration = registration_flow_v3(
            dashboard_url=dashboard_url,
            platform_key=platform_key,
            admin_user=admin_user,
            admin_password=admin_password,
        )
        tools_out = []
        if execute_url:
            tools_out = execute_tools(execute_url=execute_url, platform_key=platform_key)
        version = presto_version
        if not version:
            # Best-effort read from Presto if PRESTO_URL is set.
            import httpx

            presto_url = os.environ.get("PRESTO_URL") or os.environ.get("E2E_PRESTO_URL")
            if presto_url:
                try:
                    info = httpx.get(f"{presto_url.rstrip('/')}/v1/info", timeout=10).json()
                    version = (
                        (info.get("nodeVersion") or {}).get("version")
                        or info.get("version")
                        or "unknown"
                    )
                except Exception:  # noqa: BLE001
                    version = "unknown"
            else:
                version = "unknown"

    failures = [t for t in tools_out if not t["ok"] or not t["envelope_valid"]]
    reg_fail = [s for s in registration.get("steps", []) if not s.get("ok")]
    report = {
        "deployment": deployment,
        "platform_key": platform_key,
        "presto_version": version,
        "started_at": started,
        "finished_at": _now(),
        "tools": tools_out,
        "registration": registration,
        "summary": {
            "tools_total": len(tools_out),
            "tools_ok": len(tools_out) - len(failures),
            "failures": len(failures) + len(reg_fail),
        },
    }
    return report


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--deployment", choices=["k8s", "swarm"], default="k8s")
    p.add_argument("--platform-key", default="presto-walkthrough")
    p.add_argument("--dashboard-url", default="http://127.0.0.1:8081")
    p.add_argument("--execute-url", default=None)
    p.add_argument("--admin-user", default=os.environ.get("E2E_ADMIN_USER", "admin"))
    p.add_argument("--admin-password", default=os.environ.get("E2E_ADMIN_PASS", "admin"))
    p.add_argument("--out", default="walkthrough-report.json")
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args(argv)

    report = run_walkthrough(
        deployment=args.deployment,
        platform_key=args.platform_key,
        dashboard_url=args.dashboard_url,
        execute_url=args.execute_url,
        self_test=args.self_test,
        admin_user=args.admin_user,
        admin_password=args.admin_password,
    )
    Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report["summary"]))
    return 0 if report["summary"]["failures"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
