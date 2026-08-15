"""FP-IG-30/31 static leg + UT-IG-13 (design.md §11.3.3 AH / §11.3.5).

Against the unfixed chart this file is red three ways: probe-gateway's
ConfigMap has no max_db_conns, temporal-dev declares no SQL_MAX_CONNS, and
with ceilings declared 145 + RESERVE > 100. Weak forms this file refuses:
log-grep for 'too many clients'; rendering chart defaults (bundled PG
absent); a hardcoded demand literal; a static leg that skips unknown
workloads.
"""
from __future__ import annotations

import re
from typing import Any

import pytest

from connection_budget import (
    ENGINES_PER_PROCESS,
    RESERVE,
    BudgetError,
    count_make_engine_calls,
    evaluate,
    stock_engine_capacity,
)
from delivery_helpers import CHARTS, REPO_ROOT, helm_template, parse_manifests

DBAGENT = CHARTS / "dbagent"
BUNDLED_OVERLAYS = [
    DBAGENT / "values-dev.yaml",
    REPO_ROOT / "tests" / "e2e" / "values-dbagent.yaml",
]

AH_DEMAND = {
    "ingest-gateway": 60,
    "temporal-worker": 30,
    "dashboard-api": 15,
    "probe-gateway": 10,
    "temporal": 30,
}


def _secret(name: str = "t-app", *, pg_dsn: bool = True, extra: dict[str, str] | None = None) -> dict[str, Any]:
    data = dict(extra or {})
    if pg_dsn:
        data["PG_DSN"] = "postgresql://dbagent:dbagent@postgresql:5432/dbagent"
    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": name},
        "stringData": data,
    }


def _deploy(
    name: str,
    container: dict[str, Any],
    *,
    replicas: int = 1,
    volumes: list[dict[str, Any]] | None = None,
    kind: str = "Deployment",
) -> dict[str, Any]:
    spec: dict[str, Any] = {
        "replicas": replicas,
        "template": {
            "spec": {
                "containers": [container],
                "volumes": volumes or [],
            }
        },
    }
    return {
        "apiVersion": "apps/v1",
        "kind": kind,
        "metadata": {"name": name},
        "spec": spec,
    }


def _job(name: str, container: dict[str, Any]) -> dict[str, Any]:
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {"name": name},
        "spec": {
            "template": {
                "spec": {
                    "containers": [container],
                    "restartPolicy": "Never",
                }
            }
        },
    }


def _envfrom_container(name: str, secret: str = "t-app", extra_env: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    env = list(extra_env or [])
    return {
        "name": name,
        "envFrom": [{"secretRef": {"name": secret}}],
        "env": env,
    }


def _probe_cm(max_db_conns: int | None = 10, name: str = "t-probe-gateway-config") -> dict[str, Any]:
    lines = [
        'postgres_dsn: "${PG_DSN}"',
        'session_listen_addr: ":8443"',
    ]
    if max_db_conns is not None:
        lines.append(f"max_db_conns: {max_db_conns}")
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": name},
        "data": {"config.yaml": "\n".join(lines) + "\n"},
    }


def _probe_container(cm_name: str = "t-probe-gateway-config") -> dict[str, Any]:
    return {
        "name": "probe-gateway",
        "envFrom": [{"secretRef": {"name": "t-app"}}],
        "volumeMounts": [{"name": "config", "mountPath": "/etc/dbagent/probe-gateway"}],
    }


def _probe_volumes(cm_name: str = "t-probe-gateway-config") -> list[dict[str, Any]]:
    return [{"name": "config", "configMap": {"name": cm_name}}]


def _ingest_container(workers: int = 4) -> dict[str, Any]:
    return {
        "name": "ingest-gateway",
        "envFrom": [{"secretRef": {"name": "t-app"}}],
        "env": [{"name": "DBAGENT_GATEWAY_WORKERS", "value": str(workers)}],
    }


def _worker_container() -> dict[str, Any]:
    return _envfrom_container("temporal-worker")


def _dashboard_container() -> dict[str, Any]:
    return _envfrom_container("dashboard-api")


def _temporal_container(*, max_conns: str | None = "20", vis: str | None = "10") -> dict[str, Any]:
    env = [
        {"name": "DB", "value": "postgres12"},
        {"name": "POSTGRES_SEEDS", "value": "t-postgresql"},
    ]
    if max_conns is not None:
        env.append({"name": "SQL_MAX_CONNS", "value": max_conns})
    if vis is not None:
        env.append({"name": "SQL_VIS_MAX_CONNS", "value": vis})
    return {"name": "temporal", "env": env}


def _model_gateway_container(*, database_url: bool = False) -> dict[str, Any]:
    env = []
    if database_url:
        env.append({"name": "DATABASE_URL", "value": "postgresql://x"})
    return _envfrom_container("model-gateway", extra_env=env)


def _postgres_container(*, max_connections: int | None = 160) -> dict[str, Any]:
    c: dict[str, Any] = {
        "name": "postgresql",
        "env": [
            {"name": "POSTGRES_USER", "value": "dbagent"},
            {"name": "POSTGRES_PASSWORD", "value": "dbagent"},
            {"name": "POSTGRES_DB", "value": "dbagent"},
        ],
    }
    if max_connections is not None:
        c["args"] = ["-c", f"max_connections={max_connections}"]
    return c


def _ah_fixture(*, postgres_max: int | None = 160) -> list[dict[str, Any]]:
    """Synthetic rendered set matching AH's demand table (145) + model-gateway."""
    return [
        _secret(),
        _probe_cm(10),
        _deploy("t-ingest-gateway", _ingest_container(4)),
        _deploy("t-temporal-worker", _worker_container()),
        _deploy("t-dashboard-api", _dashboard_container()),
        _deploy(
            "t-probe-gateway",
            _probe_container(),
            volumes=_probe_volumes(),
        ),
        _deploy("t-temporal", _temporal_container()),
        _deploy("t-model-gateway", _model_gateway_container()),
        _deploy("t-postgresql", _postgres_container(max_connections=postgres_max)),
        _deploy(
            "t-dashboard-web",
            {"name": "dashboard-web", "env": [{"name": "DBAGENT_API_BASE_URL", "value": "/api"}]},
        ),
        _deploy(
            "t-minio",
            {
                "name": "minio",
                "env": [
                    {"name": "MINIO_ROOT_USER", "value": "minioadmin"},
                    {"name": "MINIO_ROOT_PASSWORD", "value": "minioadmin"},
                ],
            },
        ),
    ]


# ---------------------------------------------------------------------------
# UT-IG-13 — synthetic fixtures, no helm
# ---------------------------------------------------------------------------


def test_fixture_with_all_ceilings_declared_matches_ah_arithmetic():
    """Complete fixture computes exactly the AH table (145).

    Against a hardcoded-demand calculator this still passes — the live-chart
    tests (and workers: 5) are what kill that weak form.
    """
    result = evaluate(_ah_fixture())
    assert result.per_consumer == AH_DEMAND, result.per_consumer
    assert result.demand == 145
    assert result.max_connections == 160
    assert result.demand + RESERVE <= result.max_connections
    assert "model-gateway" in result.allowlisted
    assert "model-gateway" not in result.per_consumer


def test_undeclared_consumer_fails_by_name():
    """Potential consumer with no ceiling carrier → undeclared consumer.

    Weak form: silently skip unknown workloads — this fixture would pass.
    """
    docs = _ah_fixture()
    docs.append(
        _deploy(
            "t-mystery",
            {
                "name": "mystery",
                "env": [{"name": "PG_DSN", "value": "postgresql://x"}],
            },
        )
    )
    with pytest.raises(BudgetError, match="undeclared consumer: mystery"):
        evaluate(docs)


def test_postgres_without_max_connections_arg_fails():
    """Compiled default is not a declaration."""
    with pytest.raises(BudgetError, match="compiled default is not a declaration"):
        evaluate(_ah_fixture(postgres_max=None))


def test_envfrom_only_consumer_is_classified():
    """Workload receiving PG_DSN solely through envFrom is a potential consumer.

    Red against a direct-env-var-only reader (the D1 defect shape): that
    reader would skip this container and the test would not raise.
    """
    docs = _ah_fixture()
    docs.append(_deploy("t-envfrom-only", _envfrom_container("envfrom-consumer")))
    with pytest.raises(BudgetError, match="undeclared consumer: envfrom-consumer"):
        evaluate(docs)


def test_allowlisted_workload_with_database_url_fails_predicate():
    """Allowlist is not a name list: DATABASE_URL on model-gateway fails the predicate.

    Weak form: name-only allowlist — this fixture would pass.
    """
    docs = _ah_fixture()
    for i, doc in enumerate(docs):
        if doc.get("kind") == "Deployment" and (doc.get("metadata") or {}).get("name") == "t-model-gateway":
            docs[i] = _deploy("t-model-gateway", _model_gateway_container(database_url=True))
            break
    with pytest.raises(BudgetError, match="allowlist reason predicate failed: model-gateway"):
        evaluate(docs)


def test_valueFrom_pg_dsn_consumer_is_classified():
    """Workload receiving PG_DSN via valueFrom.secretKeyRef is a potential consumer.

    Kills a literal-value-only env reader: that reader drops valueFrom entries
    and this fixture would pass (demand still 145, no undeclared consumer).
    The chart already injects DBAGENT_PG_DSN this way (jobs.yaml).
    """
    docs = _ah_fixture()
    docs.append(
        _deploy(
            "t-valuefrom",
            {
                "name": "valuefrom-consumer",
                "env": [
                    {
                        "name": "PG_DSN",
                        "valueFrom": {
                            "secretKeyRef": {"name": "t-app", "key": "PG_DSN"}
                        },
                    }
                ],
            },
        )
    )
    with pytest.raises(BudgetError, match="undeclared consumer: valuefrom-consumer"):
        evaluate(docs)


def test_allowlisted_workload_with_valueFrom_database_url_fails_predicate():
    """Allowlist predicate sees DATABASE_URL supplied via valueFrom.

    Kills a literal-value-only env reader inside the reason predicate:
    that reader would skip this spelling and the fixture would pass.
    This is how one actually wires litellm to a database.
    """
    docs = _ah_fixture()
    for i, doc in enumerate(docs):
        if doc.get("kind") == "Deployment" and (doc.get("metadata") or {}).get("name") == "t-model-gateway":
            docs[i] = _deploy(
                "t-model-gateway",
                _envfrom_container(
                    "model-gateway",
                    extra_env=[
                        {
                            "name": "DATABASE_URL",
                            "valueFrom": {
                                "secretKeyRef": {
                                    "name": "t-app",
                                    "key": "DATABASE_URL",
                                }
                            },
                        }
                    ],
                ),
            )
            break
    with pytest.raises(BudgetError, match="allowlist reason predicate failed: model-gateway"):
        evaluate(docs)


def test_stale_allowlist_entry_fails():
    """Allowlist entry naming a container absent from the potential-consumer set.

    Kills a classification-only check (rendered ⊆ declared ∪ allowlist) that
    never walks the allowlist back to the render. A declared⊆rendered check
    *does* raise here and is not what this fixture kills.
    """
    docs = [d for d in _ah_fixture() if not (
        d.get("kind") == "Deployment"
        and (d.get("metadata") or {}).get("name") == "t-model-gateway"
    )]
    with pytest.raises(BudgetError, match="stale allowlist entry: model-gateway"):
        evaluate(docs)


def test_unknown_workload_kind_fails():
    """PodSpec kind outside the enumeration partition.

    Weak form: silently ignore unknown kinds — this fixture would pass.
    """
    docs = _ah_fixture()
    docs.append(
        {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "stray"},
            "spec": {
                "containers": [
                    {"name": "stray", "env": [{"name": "PG_DSN", "value": "postgresql://x"}]}
                ]
            },
        }
    )
    with pytest.raises(BudgetError, match="unknown workload kind: Pod"):
        evaluate(docs)


def test_job_kind_consumer_is_accepted_without_ceiling():
    """Job-kind containers are RESERVE — no ceiling required.

    Kills a Job-inclusive classifier, which on the corrected tree would
    raise undeclared consumer against migrate/bootstrap-admin/seed-playbooks
    (three shipped Jobs receive PG_DSN via envFrom).
    """
    docs = _ah_fixture()
    docs.append(_job("t-migrate", _envfrom_container("migrate")))
    docs.append(_job("t-bootstrap-admin", _envfrom_container("bootstrap-admin")))
    docs.append(_job("t-seed-playbooks", _envfrom_container("seed-playbooks")))
    result = evaluate(docs)
    assert result.demand == 145
    assert "migrate" not in result.per_consumer
    assert "migrate" not in result.potential_consumers


def test_per_engine_read_returns_stock_queue_capacity():
    """Lazy QueuePool (no server) is 5 + 10 = 15. A default-change moves demand."""
    assert stock_engine_capacity() == 15


def test_declared_engines_per_process_matches_ast_count():
    """Declared table equals AST count of make_engine over production modules.

    Capable of failing: a gained/lost call in worker_main.py diverges from
    the declared 2. Exclusions: tests/, scripts/seed_playbooks.py,
    dashboard_api/bootstrap_admin.py, rca_common's definition.
    """
    for service, declared in ENGINES_PER_PROCESS.items():
        counted = count_make_engine_calls(service)
        assert counted == declared, (
            f"{service}: declared engines-per-process {declared} != "
            f"AST make_engine count {counted}"
        )
    assert ENGINES_PER_PROCESS == {
        "ingest-gateway": 1,
        "temporal-worker": 2,
        "dashboard-api": 1,
    }


def test_allowlist_predicate_fails_closed_when_secret_is_external():
    """envFrom of a Secret not in the render makes the key set unknowable."""
    docs = [d for d in _ah_fixture() if d.get("kind") != "Secret"]
    with pytest.raises(BudgetError, match="allowlist reason predicate failed: model-gateway"):
        evaluate(docs)


# ---------------------------------------------------------------------------
# FP-IG-30 / FP-IG-31 — live chart, both bundled overlays
# ---------------------------------------------------------------------------


def _render_overlay(overlay) -> list[dict[str, Any]]:
    return parse_manifests(helm_template(DBAGENT, values=[str(overlay)]))


def test_every_pg_consumer_declares_a_finite_ceiling():
    """FP-IG-30: every rendered potential consumer is declared or allowlisted.

    Red against the unfixed tree on probe-gateway's ConfigMap lacking
    max_db_conns and the Temporal dev server's undeclared limits.
    model-gateway is allowlisted (receives PG_DSN via envFrom; no DATABASE_URL).
    """
    for overlay in BUNDLED_OVERLAYS:
        docs = _render_overlay(overlay)
        result = evaluate(docs)
        assert result.per_consumer.keys() == AH_DEMAND.keys(), (
            f"{overlay}: consumers {sorted(result.per_consumer)}"
        )
        assert "model-gateway" in result.allowlisted
        # Trap 1: max_db_conns must be a bare !!int, never a ${} placeholder
        # (envexpand re-tags placeholder scalars !!str; yaml.v3 cannot decode
        # !!str into the int field).
        cms = [
            d
            for d in docs
            if d.get("kind") == "ConfigMap"
            and "probe-gateway" in (d.get("metadata") or {}).get("name", "")
        ]
        assert cms, overlay
        raw = (cms[0].get("data") or {}).get("config.yaml") or ""
        assert re.search(r"(?m)^max_db_conns: 10$", raw), (
            f"{overlay}: max_db_conns must render as a bare unquoted int; got:\n{raw}"
        )


def test_rendered_connection_demand_fits_rendered_supply():
    """FP-IG-31 static leg: demand recomputed from the render + engine read.

    Red against 13830d9 three ways (no max_db_conns, no SQL_MAX_CONNS, and
    145 + 13 > 100). Weak forms: log-grep, defaults render, hardcoded demand.
    """
    assert RESERVE == 13
    for overlay in BUNDLED_OVERLAYS:
        result = evaluate(_render_overlay(overlay))
        assert result.per_consumer == AH_DEMAND, (
            f"{overlay}: {result.per_consumer} != {AH_DEMAND}"
        )
        assert result.demand == 145
        assert result.max_connections == 160
        assert result.demand + RESERVE <= result.max_connections, (
            f"{overlay}: {result.demand} + {RESERVE} > {result.max_connections}"
        )
