"""Connection-budget calculator (design.md §11.3.3 AH / FP-IG-29…31).

Importable, not collected. Both the delivery static leg and the e2e runtime
leg share this module. Demand is recomputed from rendered manifests under
AH's identification rule; supply is the postgres container's
``-c max_connections`` arg. A potential PG consumer whose ceiling carrier
is absent and which is not allowlisted fails by name (``undeclared
consumer``) — never skipped.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

REPO_ROOT = Path(__file__).resolve().parents[2]

# 3 superuser_reserved_connections + 10 transient (migrate alembic,
# signing-key / bootstrap-admin / seed-playbooks Jobs, temporal-sql-tool,
# operational psql). Bound once; FP-IG-31 asserts demand + RESERVE <= max.
RESERVE = 13

# Declared engines-per-process. Each entry is verified by AST count of
# make_engine call sites over the service's production modules (UT-IG-13).
# ingest-gateway: gateway.main.build_app
# temporal-worker: worker_main.build_llm_client + build_investigation_activities
# dashboard-api: dashboard_api.main.build_app (bootstrap_admin → RESERVE)
ENGINES_PER_PROCESS: dict[str, int] = {
    "ingest-gateway": 1,
    "temporal-worker": 2,
    "dashboard-api": 1,
}

SERVICE_SOURCE_DIRS: dict[str, Path] = {
    "ingest-gateway": REPO_ROOT / "services" / "gateway" / "gateway",
    "temporal-worker": REPO_ROOT / "services" / "worker" / "worker",
    "dashboard-api": REPO_ROOT / "services" / "dashboard-api" / "dashboard_api",
}

# Filenames inside a service package that are transient entrypoints (RESERVE),
# not the serving process. scripts/seed_playbooks.py and tests/ sit outside
# these package dirs; rca_common.db.session.make_engine is the definition.
EXCLUDED_ENGINE_FILES = frozenset({"bootstrap_admin.py"})

# Container names whose ceiling is a stock QueuePool × declared engines.
_PYTHON_SERVICES = frozenset(ENGINES_PER_PROCESS)

_CLASSIFY_KINDS = frozenset({"Deployment", "StatefulSet", "DaemonSet"})
_RESERVE_KINDS = frozenset({"Job", "CronJob"})

# Machine-checked non-consumer allowlist, keyed by container name.
# model-gateway receives PG_DSN via envFrom of the app secret; litellm
# reads DATABASE_URL, which this chart does not set.
NON_CONSUMER_ALLOWLIST: dict[str, str] = {
    "model-gateway": "litellm reads DATABASE_URL, which this chart does not set",
}


class BudgetError(Exception):
    """Fail-closed identification / ceiling / supply error."""


@dataclass(frozen=True)
class WorkloadContainer:
    kind: str
    workload_name: str
    container_name: str
    replicas: int
    container: dict[str, Any]
    pod_spec: dict[str, Any]
    is_init: bool = False


@dataclass
class BudgetResult:
    demand: int
    max_connections: int
    per_consumer: dict[str, int] = field(default_factory=dict)
    potential_consumers: frozenset[str] = field(default_factory=frozenset)
    allowlisted: frozenset[str] = field(default_factory=frozenset)


def stock_engine_capacity() -> int:
    """Per-engine QueuePool capacity: size() + _max_overflow.

    Pin: SQLAlchemy 2.0 QueuePool (rca_common ``SQLAlchemy>=2.0,<2.1``).
    ``pool.size`` is a bound method; ``_max_overflow`` is the overflow cap.
    A rename of either fails loudly — the correct direction. Engine
    construction is lazy and contacts no server.
    """
    from sqlalchemy import create_engine

    engine = create_engine("postgresql://budget:budget@127.0.0.1:1/budget")
    pool = engine.pool
    return pool.size() + pool._max_overflow  # noqa: SLF001 — pinned private read


def count_make_engine_calls(service: str) -> int:
    """AST count of ``make_engine(...)`` call sites in production modules."""
    root = SERVICE_SOURCE_DIRS[service]
    total = 0
    for path in sorted(root.rglob("*.py")):
        if path.name in EXCLUDED_ENGINE_FILES:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Name) and func.id == "make_engine":
                total += 1
            elif isinstance(func, ast.Attribute) and func.attr == "make_engine":
                total += 1
    return total


def evaluate(docs: list[Mapping[str, Any]]) -> BudgetResult:
    """Classify every rendered container and compute demand + supply.

    Raises BudgetError with a named phrase on any fail-closed condition.
    """
    workloads = list(_iter_workload_containers(docs))
    secrets = _index_secrets(docs)
    configmaps = _index_configmaps(docs)
    cm_keys = _index_configmap_keys(docs)

    potential: list[WorkloadContainer] = []
    for wl in workloads:
        if wl.kind in _RESERVE_KINDS:
            continue
        if _is_potential_consumer(wl, secrets, cm_keys):
            potential.append(wl)

    potential_names = [wl.container_name for wl in potential]
    _reject_duplicate_names(potential_names)
    potential_set = frozenset(potential_names)

    for name in NON_CONSUMER_ALLOWLIST:
        if name not in potential_set:
            raise BudgetError(f"stale allowlist entry: {name}")

    per_consumer: dict[str, int] = {}
    allowlisted: set[str] = set()
    pool_capacity = stock_engine_capacity()

    for wl in potential:
        name = wl.container_name
        in_allowlist = name in NON_CONSUMER_ALLOWLIST
        in_declared = name in _PYTHON_SERVICES or name in {
            "probe-gateway",
            "temporal",
        }
        if in_allowlist and in_declared:
            raise BudgetError(
                f"consumer {name} is in both the declared-ceiling table and the allowlist"
            )
        if in_allowlist:
            _assert_allowlist_predicate(wl, secrets, cm_keys)
            allowlisted.add(name)
            continue
        if name in _PYTHON_SERVICES:
            ceiling = _python_service_ceiling(wl, name, pool_capacity)
        elif name == "probe-gateway":
            ceiling = _probe_gateway_ceiling(wl, docs, configmaps)
        elif name == "temporal":
            ceiling = _temporal_dev_ceiling(wl)
        else:
            raise BudgetError(f"undeclared consumer: {name}")
        if ceiling is None:
            raise BudgetError(f"undeclared consumer: {name}")
        per_consumer[name] = ceiling

    demand = sum(per_consumer.values())
    max_conn = _parse_max_connections(workloads)
    return BudgetResult(
        demand=demand,
        max_connections=max_conn,
        per_consumer=per_consumer,
        potential_consumers=potential_set,
        allowlisted=frozenset(allowlisted),
    )


def _reject_duplicate_names(names: list[str]) -> None:
    seen: set[str] = set()
    for name in names:
        if name in seen:
            raise BudgetError(f"duplicate potential-consumer container name: {name}")
        seen.add(name)


def _iter_workload_containers(
    docs: Iterable[Mapping[str, Any]],
) -> Iterable[WorkloadContainer]:
    for doc in docs:
        kind = doc.get("kind") or ""
        if not _has_pod_spec(doc):
            continue
        if kind not in _CLASSIFY_KINDS and kind not in _RESERVE_KINDS:
            raise BudgetError(f"unknown workload kind: {kind}")
        pod_spec = _pod_spec(doc)
        replicas = _replicas(doc)
        workload_name = (doc.get("metadata") or {}).get("name") or ""
        for key, is_init in (("initContainers", True), ("containers", False)):
            for container in pod_spec.get(key) or []:
                yield WorkloadContainer(
                    kind=kind,
                    workload_name=workload_name,
                    container_name=container.get("name") or "",
                    replicas=replicas,
                    container=container,
                    pod_spec=pod_spec,
                    is_init=is_init,
                )


def _has_pod_spec(doc: Mapping[str, Any]) -> bool:
    kind = doc.get("kind") or ""
    spec = doc.get("spec") or {}
    if kind == "Pod":
        return bool(spec.get("containers") or spec.get("initContainers"))
    if kind == "CronJob":
        job_spec = ((spec.get("jobTemplate") or {}).get("spec") or {})
        tspec = ((job_spec.get("template") or {}).get("spec") or {})
        return bool(tspec.get("containers") or tspec.get("initContainers"))
    tspec = ((spec.get("template") or {}).get("spec") or {})
    return bool(tspec.get("containers") or tspec.get("initContainers"))


def _pod_spec(doc: Mapping[str, Any]) -> dict[str, Any]:
    kind = doc.get("kind") or ""
    spec = doc.get("spec") or {}
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        job_spec = ((spec.get("jobTemplate") or {}).get("spec") or {})
        return (job_spec.get("template") or {}).get("spec") or {}
    return (spec.get("template") or {}).get("spec") or {}


def _replicas(doc: Mapping[str, Any]) -> int:
    spec = doc.get("spec") or {}
    replicas = spec.get("replicas")
    if replicas is None:
        return 1
    return int(replicas)


def _index_secrets(docs: Iterable[Mapping[str, Any]]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for doc in docs:
        if doc.get("kind") != "Secret":
            continue
        name = (doc.get("metadata") or {}).get("name") or ""
        keys = set((doc.get("stringData") or {}).keys())
        keys |= set((doc.get("data") or {}).keys())
        out[name] = keys
    return out


def _index_configmaps(docs: Iterable[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for doc in docs:
        if doc.get("kind") != "ConfigMap":
            continue
        name = (doc.get("metadata") or {}).get("name") or ""
        out[name] = doc
    return out


def _index_configmap_keys(docs: Iterable[Mapping[str, Any]]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for doc in docs:
        if doc.get("kind") != "ConfigMap":
            continue
        name = (doc.get("metadata") or {}).get("name") or ""
        out[name] = set((doc.get("data") or {}).keys()) | set(
            (doc.get("binaryData") or {}).keys()
        )
    return out


def _env_map(container: Mapping[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for entry in container.get("env") or []:
        if "name" in entry and "value" in entry:
            out[entry["name"]] = str(entry["value"])
    return out


def _env_names(container: Mapping[str, Any]) -> set[str]:
    """Every declared env name, regardless of value form (value | valueFrom)."""
    return {e["name"] for e in (container.get("env") or []) if "name" in e}


def _envfrom_sources(container: Mapping[str, Any]) -> list[tuple[str, str]]:
    """Every envFrom source as (kind, name), total over the envFrom grammar."""
    out: list[tuple[str, str]] = []
    for src in container.get("envFrom") or []:
        for key, kind in (("secretRef", "Secret"), ("configMapRef", "ConfigMap")):
            ref = src.get(key) or {}
            if "name" in ref:
                out.append((kind, ref["name"]))
                break
        else:
            out.append(("unknown", ""))
    return out


def _envfrom_keys(
    kind: str,
    name: str,
    secrets: Mapping[str, set[str]],
    cm_keys: Mapping[str, set[str]],
) -> set[str] | None:
    """Reachable env-key set, or None when unknowable (⇒ caller fails closed)."""
    table = {"Secret": secrets, "ConfigMap": cm_keys}.get(kind)
    if table is None or name not in table:
        return None
    return table[name]


def _is_potential_consumer(
    wl: WorkloadContainer,
    secrets: Mapping[str, set[str]],
    cm_keys: Mapping[str, set[str]],
) -> bool:
    env = _env_map(wl.container)
    names = _env_names(wl.container)
    receives_pg_dsn = "PG_DSN" in names
    for kind, sname in _envfrom_sources(wl.container):
        keys = _envfrom_keys(kind, sname, secrets, cm_keys)
        if keys is None or "PG_DSN" in keys:
            receives_pg_dsn = True
    temporal_shape = env.get("DB") == "postgres12" and "POSTGRES_SEEDS" in names
    return receives_pg_dsn or temporal_shape


def _assert_allowlist_predicate(
    wl: WorkloadContainer,
    secrets: Mapping[str, set[str]],
    cm_keys: Mapping[str, set[str]],
) -> None:
    """model-gateway: rendered container has no DATABASE_URL env.

    Fail-closed when an envFrom names a Secret or ConfigMap not in the
    rendered output (key set unknowable).
    """
    if "DATABASE_URL" in _env_names(wl.container):
        raise BudgetError(
            f"allowlist reason predicate failed: {wl.container_name} "
            f"(DATABASE_URL is set)"
        )
    for kind, sname in _envfrom_sources(wl.container):
        keys = _envfrom_keys(kind, sname, secrets, cm_keys)
        if keys is None:
            label = "secret" if kind == "Secret" else kind
            raise BudgetError(
                f"allowlist reason predicate failed: {wl.container_name} "
                f"(envFrom {label} {sname!r} is not in the render)"
            )
        if "DATABASE_URL" in keys:
            raise BudgetError(
                f"allowlist reason predicate failed: {wl.container_name} "
                f"(DATABASE_URL reachable via envFrom)"
            )


def _python_service_ceiling(
    wl: WorkloadContainer, name: str, pool_capacity: int
) -> int | None:
    engines = ENGINES_PER_PROCESS[name]
    workers = 1
    if name == "ingest-gateway":
        env = _env_map(wl.container)
        raw = env.get("DBAGENT_GATEWAY_WORKERS")
        if raw is None or raw == "":
            return None
        workers = int(raw)
    return wl.replicas * workers * engines * pool_capacity


def _probe_gateway_ceiling(
    wl: WorkloadContainer,
    docs: list[Mapping[str, Any]],
    configmaps: Mapping[str, Mapping[str, Any]],
) -> int | None:
    import yaml

    cm_names = _mounted_configmap_names(wl)
    for cm_name in cm_names:
        cm = configmaps.get(cm_name)
        if cm is None:
            continue
        raw = (cm.get("data") or {}).get("config.yaml")
        if not raw:
            continue
        parsed = yaml.safe_load(raw) or {}
        if "max_db_conns" not in parsed:
            continue
        value = parsed["max_db_conns"]
        try:
            n = int(value)
        except (TypeError, ValueError):
            return None
        if n <= 0:
            return None
        return wl.replicas * n
    return None


def _mounted_configmap_names(wl: WorkloadContainer) -> list[str]:
    volumes = {v.get("name"): v for v in (wl.pod_spec.get("volumes") or [])}
    names: list[str] = []
    for mount in wl.container.get("volumeMounts") or []:
        vol = volumes.get(mount.get("name")) or {}
        cm = vol.get("configMap") or {}
        if "name" in cm:
            names.append(cm["name"])
    return names


def _temporal_dev_ceiling(wl: WorkloadContainer) -> int | None:
    env = _env_map(wl.container)
    raw_max = env.get("SQL_MAX_CONNS")
    raw_vis = env.get("SQL_VIS_MAX_CONNS")
    if raw_max is None or raw_vis is None or raw_max == "" or raw_vis == "":
        return None
    return wl.replicas * (int(raw_max) + int(raw_vis))


def _parse_max_connections(workloads: Iterable[WorkloadContainer]) -> int:
    for wl in workloads:
        if wl.container_name != "postgresql":
            continue
        parsed = _max_connections_from_args(wl.container.get("args") or [])
        if parsed is None:
            raise BudgetError(
                "postgres container has no -c max_connections arg; "
                "the compiled default is not a declaration"
            )
        return parsed
    raise BudgetError(
        "postgres container has no -c max_connections arg; "
        "the compiled default is not a declaration"
    )


def _max_connections_from_args(args: list[Any]) -> int | None:
    tokens = [str(a) for a in args]
    for i, tok in enumerate(tokens):
        if tok == "-c" and i + 1 < len(tokens):
            nxt = tokens[i + 1]
            if nxt.startswith("max_connections="):
                return int(nxt.split("=", 1)[1])
        stripped = tok[2:] if tok.startswith("-c") else tok
        if stripped.startswith("max_connections="):
            return int(stripped.split("=", 1)[1])
    return None
