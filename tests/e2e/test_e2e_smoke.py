"""E0 install smoke (FP-M6-15/16/8 runtime half)."""
from __future__ import annotations

import os
import subprocess

import httpx
import pytest

ADMIN_USER = os.environ.get("E2E_ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("E2E_ADMIN_PASS", "admin-e2e-password")
DASHBOARD_WEB_URL = os.environ.get("E2E_DASHBOARD_WEB_URL", "http://127.0.0.1:30083")


@pytest.mark.e2e
def test_e0_install_smoke_all_services_healthy(ingest_url, dashboard_url, probe_gw_url):
    """Four healthz endpoints: ingest, dashboard-api, probe-gateway, dashboard-web."""
    urls = [
        f"{ingest_url.rstrip('/')}/healthz",
        f"{dashboard_url.rstrip('/')}/healthz",
        f"{probe_gw_url.rstrip('/')}/healthz",
        f"{DASHBOARD_WEB_URL.rstrip('/')}/healthz",
    ]
    for url in urls:
        r = httpx.get(url, timeout=10)
        assert r.status_code == 200, url


@pytest.mark.e2e
def test_e0_presto_0298_cluster_ready_and_probe_online(presto_url, dashboard_url):
    r = httpx.get(f"{presto_url.rstrip('/')}/v1/info", timeout=10)
    assert r.status_code == 200
    body = r.json()
    ver = (body.get("nodeVersion") or {}).get("version") or body.get("version") or ""
    # FP-M6-16 pins Presto 0.298 exactly — a 0.29 prefix accepted 0.297/0.299
    # (code review round 7, W2).
    assert str(ver).strip() == "0.298", f"expected Presto 0.298 exactly, got {ver!r}"

    # Auth required for platforms — login and assert at least one online platform.
    lr = httpx.post(
        f"{dashboard_url.rstrip('/')}/api/v1/auth/login",
        json={"username": ADMIN_USER, "password": ADMIN_PASS},
        timeout=30,
    )
    assert lr.status_code == 200, lr.text
    body = lr.json()
    token = body.get("access_token") or body.get("token")
    if body.get("must_change_password"):
        cr = httpx.post(
            f"{dashboard_url.rstrip('/')}/api/v1/auth/change-password",
            headers={"Authorization": f"Bearer {token}"},
            json={"old_password": ADMIN_PASS, "new_password": ADMIN_PASS},
            timeout=30,
        )
        assert cr.status_code in (200, 204), cr.text
        lr = httpx.post(
            f"{dashboard_url.rstrip('/')}/api/v1/auth/login",
            json={"username": ADMIN_USER, "password": ADMIN_PASS},
            timeout=30,
        )
        assert lr.status_code == 200, lr.text
        token = lr.json().get("access_token") or lr.json().get("token")
    pr = httpx.get(
        f"{dashboard_url.rstrip('/')}/api/v1/platforms",
        headers={"Authorization": f"Bearer {token}"},
        timeout=30,
    )
    assert pr.status_code == 200, pr.text
    plats = pr.json().get("items") or pr.json().get("platforms") or pr.json()
    assert isinstance(plats, list) and len(plats) >= 1, plats
    assert any((p.get("status") or "").lower() == "online" for p in plats), plats


@pytest.mark.e2e
def test_e0_helm_upgrade_is_idempotent():
    """FP-M6-8: signing key, alembic version_num, playbooks maturity stable across upgrade."""
    def _secret_key() -> str:
        p = subprocess.run(
            [
                "kubectl",
                "-n",
                "rca",
                "get",
                "secret",
                "rca-agent-signing-key",
                "-o",
                "jsonpath={.data.ed25519\\.key}",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        return p.stdout.strip()

    def _alembic_version() -> str:
        p = subprocess.run(
            [
                "kubectl",
                "-n",
                "rca",
                "exec",
                "deploy/rca-agent-dashboard-api",
                "--",
                "python",
                "-c",
                "import os; from sqlalchemy import create_engine,text; "
                "e=create_engine(os.environ['RCA_PG_DSN']); "
                "print(e.connect().execute(text('select version_num from alembic_version')).scalar())",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        out = (p.stdout or "").strip()
        assert out, f"empty alembic version_num from cluster: stderr={p.stderr!r}"
        return out

    def _playbooks_snapshot() -> list:
        import json as _json

        p = subprocess.run(
            [
                "kubectl",
                "-n",
                "rca",
                "exec",
                "deploy/rca-agent-dashboard-api",
                "--",
                "python",
                "-c",
                "import os,json; from sqlalchemy import create_engine,text; "
                "e=create_engine(os.environ['RCA_PG_DSN']); "
                "rows=e.connect().execute(text("
                "'select playbook_id, auto_eligible, maturity from playbooks order by playbook_id'"
                ")).fetchall(); "
                "print(json.dumps([[r[0], r[1], dict(r[2]) if r[2] is not None else {}] for r in rows]))",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        out = (p.stdout or "").strip()
        assert out, f"empty playbooks snapshot: stderr={p.stderr!r}"
        rows = _json.loads(out)
        assert isinstance(rows, list) and len(rows) == 5, (
            f"expected 5 MVP playbook rows, got {rows!r}"
        )
        return rows

    key_before = _secret_key()
    assert key_before
    alembic_before = _alembic_version()
    playbooks_before = _playbooks_snapshot()

    subprocess.run(
        [
            "helm",
            "upgrade",
            "rca-agent",
            "deploy/charts/rca-agent",
            "-n",
            "rca",
            "-f",
            "tests/e2e/values-rca-agent.yaml",
            "--wait",
            "--timeout",
            "5m",
        ],
        check=True,
    )

    assert _secret_key() == key_before, "signing key rotated on helm upgrade"
    alembic_after = _alembic_version()
    assert alembic_after == alembic_before, (alembic_before, alembic_after)
    playbooks_after = _playbooks_snapshot()
    assert playbooks_after == playbooks_before, (
        f"playbooks maturity/auto_eligible changed: "
        f"before={playbooks_before!r} after={playbooks_after!r}"
    )
