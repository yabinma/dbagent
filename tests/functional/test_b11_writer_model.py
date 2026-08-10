"""FP-M6-31: B11's writer model enforced outside the benchmark tier.

Hermetic — no database, no benchmark execution.  design.md Section 11.1.3,
*B11's writer model*, consequence 4 (errata passes 1-9, rev 2.5).

Every rule is a module-level ``check_<ID>`` function taking **plain data** — a
filename plus source text, an object decoded from the manifest, a set of file
names, or a directory path — and raising ``AssertionError`` whose message
**begins with a stable rule ID followed by** ``": "``.  Twenty-nine IDs, one
checker function each:

    L0-L3   the loader layers (the width test's part (i))
    W2-W4   the width test's remaining parts
    A1, A2a-A2d, A3-A6, A7a-A7c, A8, A9, A10   the allowlist rules
    C1-C7   the call-site checks

The ID is matched as an **exact token**, never as a prefix: the fourth test
compares ``message.split(":", 1)[0]`` to the expected ID, so a fixture that
expects ``A2d`` cannot be satisfied by an ``A2a`` failure and an ``A10`` failure
cannot satisfy a fixture that expects ``A1``.

Every negative fixture in ``_fixtures()`` seeds a repository tree from the clean
baselines, applies one minimal mutation to a real file in that tree, and invokes
the **real** checker function against it.  No fixture reimplements checker logic
and none raises its own expected error: a fixture can only go green by making
production guard code reject the mutation.
"""
from __future__ import annotations

import ast
import json
import py_compile
import re
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Callable, NoReturn

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
BENCH_DIR = REPO_ROOT / "tests" / "benchmark"
CONFTEST = BENCH_DIR / "conftest.py"
BENCH = BENCH_DIR / "test_pg_scale.py"
THRESHOLDS = BENCH_DIR / "thresholds.yaml"
ROOT_CONFTEST_PATH = REPO_ROOT / "conftest.py"
CI_YML = REPO_ROOT / ".github" / "workflows" / "ci.yml"
GO_GUARD = "tests/functional/b11_writer_model/callsites_test.go"
GO_GUARD_FUNC = "func TestB11GoCallSitesAreRealCalls("

CONFTEST_NAME = "conftest.py"
BENCH_NAME = "test_pg_scale.py"
LOADER_NAME = "load_b11_writer_model"
B11_TEST_NAME = "test_b11_audit_llm_insert_throughput"
# The one function the executor may drive, and the two production writers its
# counted loop must call.  W2 pins the whole chain from this function to the
# asserted rate; see `_check_w2_measured_rate`.
WRITER_FUNC_NAME = "_run_writer"
WRITER_PRODUCTION_CALLS = ("write_audit", "insert_llm_call")
MANIFEST_KEY_PATH = "benchmarks[id=B11].concurrency_model"
SHARED_LIB_ROOT = "libs/py/rca_common/"

# --------------------------------------------------------------------------
# Guard literals.  Everything the guard trusts, beyond what a `python -I` child
# reports, is one of these.
# --------------------------------------------------------------------------

EXPECTED_CONCURRENCY_MODEL = {
    "writers": 4,
    "pool": "per-writer-independent",
    "pool_widening": "none",
    "durability": "stock",
    "writer_processes": [
        {
            "process": "ingest-gateway",
            "tables": ["audit_log"],
            "call_sites": [
                {
                    "file": "services/gateway/gateway/ingest.py",
                    "line": 113,
                    "in": "IngestService.ingest",
                    "symbol": "write_audit",
                    "expr": "write_audit(",
                }
            ],
        },
        {
            "process": "dashboard-api",
            "tables": ["audit_log"],
            "call_sites": [
                {
                    "file": "services/dashboard-api/dashboard_api/services.py",
                    "line": 467,
                    "in": "decide_approval_atomic",
                    "symbol": "write_audit",
                    "expr": "write_audit(",
                }
            ],
        },
        {
            "process": "probe-gateway",
            "tables": ["audit_log"],
            "call_sites": [
                {
                    "file": "services/probe-gateway/internal/gwserver/server.go",
                    "line": 507,
                    "in": "(*Server).emitCredentialAudits",
                    "symbol": "Write",
                    "expr": "audit.Write(ctx, s.AuditDB,",
                }
            ],
        },
        {
            "process": "temporal-worker",
            "tables": ["audit_log", "llm_calls"],
            "call_sites": [
                {
                    "file": "services/worker/worker/activities/investigation.py",
                    "line": 146,
                    "in": "InvestigationActivities.create_case",
                    "symbol": "write_audit",
                    "expr": "write_audit(",
                },
                {
                    "file": "libs/py/rca_common/rca_common/llmclient/client.py",
                    "line": 168,
                    "in": "LLMClient.generate",
                    "symbol": "insert_llm_call",
                    "expr": "self._trace_store.insert_llm_call(record)",
                    "via": {
                        "file": "services/worker/worker/activities/investigation.py",
                        "line": 245,
                        "in": "InvestigationActivities._plan",
                        "symbol": "generate",
                        "expr": "await self._llm.generate(",
                    },
                },
            ],
        },
    ],
}

PROCESS_SOURCE_ROOTS = {
    "ingest-gateway": "services/gateway/",
    "dashboard-api": "services/dashboard-api/",
    "probe-gateway": "services/probe-gateway/",
    "temporal-worker": "services/worker/",
}

WRITER_DEFINITION_FILES = {
    "libs/py/rca_common/rca_common/audit.py",
    "libs/py/rca_common/rca_common/llmclient/tracestore.py",
    "services/probe-gateway/internal/audit/audit.go",
}

# consequence 4(b), verbatim.  Modulo formatting, comments and an optional
# docstring — none of which `ast` sees — this is what conftest.py must contain.
LOADER_SOURCE = (
    "def load_b11_writer_model():\n"
    "    manifest = yaml.safe_load(\n"
    '        Path(__file__).with_name("thresholds.yaml").read_text(encoding="utf-8")\n'
    "    )\n"
    '    by_id = {entry["id"]: entry for entry in manifest["benchmarks"]}\n'
    '    return by_id["B11"]["concurrency_model"]["writer_processes"]\n'
)
LOADER_FREE_NAMES = {"yaml", "Path", "__file__"}
LOADER_ATTRIBUTES = {"safe_load", "with_name", "read_text"}

# consequence 3's four fixed diagnostic prefixes (the fourth added by errata
# pass 9).  Guard *data*, not a rule ID of their own: W4 asserts all four.
DIAGNOSTIC_PREFIXES = (
    "B11 writers=",
    "B11 writer_map=",
    "B11 single_writer_rate=",
    "B11 env=",
)

# A2a — the closed (module, name) import inventory of the benchmark tier.
# `name is None` means a plain `import <module>`.
ALLOWED_BENCHMARK_IMPORTS = {
    ("__future__", "annotations"),
    ("statistics", None),
    ("time", None),
    ("uuid", None),
    # `os` is imported for exactly one call, `os.cpu_count()`, which feeds the
    # `B11 env=cpus=` fingerprint consequence 3 requires (errata pass 9).  A7a
    # admits `cpu_count` and nothing else, so `os.environ` still fails.
    ("os", None),
    ("yaml", None),
    ("concurrent.futures", "ThreadPoolExecutor"),
    ("datetime", "datetime"),
    ("datetime", "timezone"),
    ("pathlib", "Path"),
    ("pytest", None),
    ("sqlalchemy", "text"),
    ("alembic", "command"),
    ("alembic.config", "Config"),
    ("testcontainers.postgres", "PostgresContainer"),
    ("rca_common.db.partitions", "ensure_month"),
    ("rca_common.db.session", "make_engine"),
    ("rca_common.db.session", "make_session_factory"),
    ("rca_common.audit", "actor_system"),
    ("rca_common.audit", "write_audit"),
    ("rca_common.investigation_repo", "find_open_by_fingerprint"),
    ("rca_common.llmclient.tracestore", "LLMCallRecord"),
    ("rca_common.llmclient.tracestore", "PGTraceStore"),
    ("dashboard_api", "services"),
    # The benchmark imports the pinned loader from its sibling conftest; that
    # import is what consequence 4(b) exists to make unavoidable.
    ("conftest", LOADER_NAME),
}

# A2b — module-scope binding inventory, exact and closed.  One binding each.
EXPECTED_MODULE_BINDINGS: dict[str, Counter] = {
    CONFTEST_NAME: Counter(
        {
            ("annotations", "import"): 1,
            ("datetime", "import"): 1,
            ("timezone", "import"): 1,
            ("Path", "import"): 1,
            ("yaml", "import"): 1,
            ("pytest", "import"): 1,
            ("command", "import"): 1,
            ("Config", "import"): 1,
            ("text", "import"): 1,
            ("PostgresContainer", "import"): 1,
            ("ensure_month", "import"): 1,
            ("make_engine", "import"): 1,
            ("make_session_factory", "import"): 1,
            ("REPO_ROOT", "assign"): 1,
            ("RCA_COMMON_DIR", "assign"): 1,
            ("_months_back", "def"): 1,
            ("_run_migrations", "def"): 1,
            ("scale_pg", "def"): 1,
            (LOADER_NAME, "def"): 1,
        }
    ),
    BENCH_NAME: Counter(
        {
            ("annotations", "import"): 1,
            ("statistics", "import"): 1,
            ("time", "import"): 1,
            ("uuid", "import"): 1,
            # see ALLOWED_BENCHMARK_IMPORTS for `os`
            ("os", "import"): 1,
            ("ThreadPoolExecutor", "import"): 1,
            ("datetime", "import"): 1,
            ("timezone", "import"): 1,
            ("pytest", "import"): 1,
            ("text", "import"): 1,
            ("actor_system", "import"): 1,
            ("write_audit", "import"): 1,
            ("find_open_by_fingerprint", "import"): 1,
            ("LLMCallRecord", "import"): 1,
            ("PGTraceStore", "import"): 1,
            # consequence 2's one independent engine per writer: the benchmark
            # builds them itself rather than sharing the fixture's engine.
            ("make_engine", "import"): 1,
            ("make_session_factory", "import"): 1,
            (LOADER_NAME, "import"): 1,
            ("_p99", "def"): 1,
            ("test_b2_fingerprint_correlation_p99_under_20ms", "def"): 1,
            ("test_b10_partitioned_list_and_filter_p99", "def"): 1,
            (B11_TEST_NAME, "def"): 1,
        }
    ),
}

ALLOWED_BUILTINS = {
    "abs", "dict", "enumerate", "float", "int", "len", "list", "max", "min",
    "print", "range", "reversed", "round", "sorted", "str", "sum", "tuple", "zip",
}

_IMPORT_ALIASES = {
    "statistics", "time", "uuid", "os", "yaml", "ThreadPoolExecutor", "datetime",
    "timezone", "Path", "pytest", "text", "command", "Config", "PostgresContainer",
    "ensure_month", "make_engine", "make_session_factory", "actor_system",
    "write_audit", "find_open_by_fingerprint", "LLMCallRecord", "PGTraceStore",
    "dash_services", LOADER_NAME, "annotations",
}
ALLOWED_FREE_NAMES = _IMPORT_ALIASES | {"__file__"} | ALLOWED_BUILTINS

# The one denylist in this rule set, used only to *widen* a ban (A2c) and never
# to permit anything.
REFLECTIVE_NAMES = {
    "getattr", "setattr", "delattr", "hasattr", "vars", "globals", "locals",
    "dir", "eval", "exec", "compile", "open", "input", "type", "object",
    "super", "__import__", "importlib", "os", "sys", "inspect", "operator",
    "functools", "builtins", "breakpoint",
}

PERMITTED_LOCAL_IMPORTS = {
    (BENCH_NAME, "test_b10_partitioned_list_and_filter_p99", "dash_services",
     "dashboard_api.services"),
}

# A7a — the complete attribute inventory of the two files, and nothing beyond.
ALLOWED_ATTRIBUTES = {
    # database objects (Engine / Connection / Session / trace store)
    "begin", "execute", "commit", "insert_llm_call",
    # `connect` warms one per-writer engine outside the timed window; it opens a
    # connection and emits no statement of its own.
    "connect",
    # testcontainers
    "get_connection_url",
    # alembic
    "upgrade", "set_main_option",
    # pytest
    "fixture",
    # stdlib and plain-object helpers
    "safe_load", "with_name", "read_text", "resolve", "parents", "perf_counter",
    "now", "year", "month", "utc", "uuid4", "median", "append", "submit",
    "result", "map",
    # `shutdown` closes the executor after the timed window; `join` is
    # str.join building the `B11 writer_map=` diagnostic; `cpu_count` is
    # os.cpu_count() for the `B11 env=` fingerprint.
    "shutdown", "join", "cpu_count",
    # product module attribute
    "list_investigations",
}

# Kept, but demoted from rule to diagnostic (errata pass 4): when an attribute
# fails A7a *and* is one of these, the message says so.
SQL_EXECUTION_SINKS = {
    "exec_driver_sql", "execution_options", "update_execution_options",
    "engine_execution_options", "executemany", "executescript", "scalar",
    "scalars", "stream", "stream_scalars", "raw_connection", "driver_connection",
    "dbapi_connection", "cursor", "connection", "run_callable",
    "set_isolation_level", "flush", "bulk_save_objects", "bulk_insert_mappings",
}
ALLOWED_SQL_VERBS = {"SELECT", "INSERT", "WITH", "ANALYZE"}
A8_FORBIDDEN_PATTERNS = (
    r"pool_size\s*=",
    r"max_overflow\s*=",
    r"fsync\s*=",
    r"synchronous_commit\s*=",
    r"full_page_writes\s*=",
    r"-c\s+fsync",
)

ALLOWED_DSN_SOURCES = (
    "<PostgresContainer instance>.get_connection_url()",
    'scale_pg["dsn"]',
)

EXPECTED_ANCESTOR_CONFTESTS = {"conftest.py"}
ALLOWED_PYTEST_INI_KEYS = {"asyncio_mode"}
FORBIDDEN_ROOT_PYTEST_CONFIG = ("tox.ini", "setup.cfg", "pyproject.toml")

EXPECTED_REPO_ROOT_IMPORTABLES = {"conftest"}
EXPECTED_PACKAGE_DIRS = {
    "libs/py/rca_common/rca_common",
    "services/gateway/gateway",
    "services/worker/worker",
    "services/dashboard-api/dashboard_api",
}
EXPECTED_PACKAGING_FILES = {
    "libs/py/rca_common/pyproject.toml",
    "services/gateway/pyproject.toml",
    "services/worker/pyproject.toml",
    "services/dashboard-api/pyproject.toml",
}
BENCHMARK_WORKFLOWS = (".github/workflows/ci.yml",)
GUARDED_JOBS = ("benchmark", "functional")
EXPECTED_B11_COMMAND = (
    "services/worker/.venv/bin/python -m pytest "
    "tests/benchmark/test_pg_scale.py -v -s"
)
# One physical line inside a `run:` block scalar, so normalization is the
# identity and the guard can both compare it and execute it.
EXPECTED_ENV_HYGIENE_COMMAND = (
    'bad="$(awk \'BEGIN { for (k in ENVIRON) { p = substr(k, 1, 6); '
    'if (p != "PYTHON" && p != "PYTEST") continue; print k } }\')"; '
    'if [ -n "$bad" ]; then printf \'FP-M6-31 A10(v): forbidden PYTHON*/PYTEST* '
    'environment key present before the measured invocation:\\n%s\\n\' "$bad" >&2; exit 1; fi'
)

# --------------------------------------------------------------------------
# Clean baselines (verbatim copies of the post-M6 files).
# --------------------------------------------------------------------------

CLEAN_CONFTEST = """\
\"\"\"Shared seeded PG fixture for B2/B10/B11 (design.md §11.1.3).\"\"\"
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from testcontainers.postgres import PostgresContainer

from rca_common.db.partitions import ensure_month
from rca_common.db.session import make_engine, make_session_factory

REPO_ROOT = Path(__file__).resolve().parents[2]
RCA_COMMON_DIR = REPO_ROOT / "libs" / "py" / "rca_common"


def _months_back(n: int) -> list[tuple[int, int]]:
    now = datetime.now(timezone.utc)
    y, m = now.year, now.month
    out: list[tuple[int, int]] = []
    for _ in range(n):
        out.append((y, m))
        m -= 1
        if m == 0:
            m = 12
            y -= 1
    return list(reversed(out))


def _run_migrations(dsn: str) -> None:
    \"\"\"Migrate via the alembic Python API (no PATH dependency on the alembic binary).\"\"\"
    cfg = Config(str(RCA_COMMON_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(RCA_COMMON_DIR / "migrations"))
    cfg.set_main_option("sqlalchemy.url", dsn)
    command.upgrade(cfg, "head")


def load_b11_writer_model():
    manifest = yaml.safe_load(
        Path(__file__).with_name("thresholds.yaml").read_text(encoding="utf-8")
    )
    by_id = {entry["id"]: entry for entry in manifest["benchmarks"]}
    return by_id["B11"]["concurrency_model"]["writer_processes"]


@pytest.fixture(scope="session")
def scale_pg():
    \"\"\"Session-scoped Postgres with B2/B10/B11 seed data (server-side INSERT…SELECT).

    Uses stock durable Postgres settings (same as production chart/compose —
    no fsync/synchronous_commit overrides). B11 measures application insert
    throughput under that contract via the production insert_llm_call path.
    \"\"\"
    pg = PostgresContainer(
        "postgres:16-alpine",
        dbname="dbagent",
        username="dbagent",
        password="dbagent",
    )
    with pg:
        dsn = pg.get_connection_url()
        _run_migrations(dsn)
        # Production-default pool (make_engine kwargs empty). B11 gives each
        # simulated writer its own engine; the seed fixture uses one engine only.
        engine = make_engine(dsn)
        factory = make_session_factory(engine)

        months = _months_back(12)
        with engine.begin() as conn:
            for y, m in months:
                ensure_month(conn, "investigations", y, m)
                ensure_month(conn, "llm_calls", y, m)
                ensure_month(conn, "audit_log", y, m)

            # FK parents for investigations.platform_key (plat-0 … plat-9).
            conn.execute(
                text(
                    \"\"\"
                    INSERT INTO platforms (
                      platform_key, platform_type, deployment, display_name, status, config
                    )
                    SELECT
                      'plat-' || g::text,
                      'presto',
                      'k8s',
                      'plat-' || g::text,
                      'online',
                      '{}'::jsonb
                    FROM generate_series(0, 9) AS g
                    ON CONFLICT (platform_key) DO NOTHING
                    \"\"\"
                )
            )

            conn.execute(
                text(
                    \"\"\"
                    INSERT INTO alert_events (
                      event_id, fingerprint, source, platform_key, severity,
                      payload_ref, normalized, disposition, received_at
                    )
                    SELECT
                      gen_random_uuid(),
                      'fp-' || (g % 5000)::text,
                      'grafana',
                      'plat-' || (g % 10)::text,
                      'high',
                      NULL,
                      '{}'::jsonb,
                      'opened',
                      now() - ((g % 3600) * interval '1 second')
                    FROM generate_series(1, 1000000) AS g
                    \"\"\"
                )
            )
            conn.execute(text("ANALYZE alert_events"))

            # workflow_id is NOT NULL; seed unique ids so the constraint holds.
            conn.execute(
                text(
                    \"\"\"
                    INSERT INTO investigations (
                      investigation_id, created_at, platform_key, status,
                      workflow_id, budget, spent, rca_report
                    )
                    SELECT
                      gen_random_uuid(),
                      date_trunc('month', now()) - ((g % 12) * interval '1 month')
                        + ((g % 28) * interval '1 day'),
                      'plat-' || (g % 10)::text,
                      (ARRAY['OPEN','RESOLVED','CLOSED_SUMMARY','NEEDS_HUMAN'])[1 + (g % 4)],
                      'wf-seed-' || g::text,
                      '{}'::jsonb,
                      '{}'::jsonb,
                      jsonb_build_object(
                        'status', 'concluded',
                        'root_cause', jsonb_build_object(
                          'category',
                          (ARRAY['resource','configuration','capacity','query'])[1 + (g % 4)],
                          'summary', 'seed'
                        )
                      )
                    FROM generate_series(1, 100000) AS g
                    \"\"\"
                )
            )
            # Attach a realistic fraction of llm_calls to seeded investigations
            # so B10's cost aggregation and llm_calls_investigation_id_idx are
            # exercised (partial index WHERE investigation_id IS NOT NULL).
            # Map g%100000 → investigations via a numbered CTE (no per-row OFFSET).
            conn.execute(
                text(
                    \"\"\"
                    WITH inv AS (
                      SELECT investigation_id,
                             row_number() OVER (ORDER BY created_at) - 1 AS rn
                      FROM investigations
                    )
                    INSERT INTO llm_calls (
                      call_id, created_at, investigation_id, agent_role, model,
                      prompt_ref, response_ref, input_tokens, output_tokens,
                      cost_usd, latency_ms
                    )
                    SELECT
                      gen_random_uuid(),
                      date_trunc('month', now()) - ((g % 12) * interval '1 month')
                        + ((g % 20) * interval '1 day'),
                      CASE
                        WHEN g % 5 = 0 THEN inv.investigation_id
                        ELSE NULL
                      END,
                      'rca',
                      'mock',
                      'p', 'r', 10, 5, 0.001, 50
                    FROM generate_series(1, 2500000) AS g
                    LEFT JOIN inv ON inv.rn = (g % 100000)
                    \"\"\"
                )
            )
            conn.execute(
                text(
                    \"\"\"
                    INSERT INTO audit_log (investigation_id, actor, action, detail, at)
                    SELECT
                      NULL,
                      'system',
                      'event_received',
                      '{}'::jsonb,
                      date_trunc('month', now()) - ((g % 12) * interval '1 month')
                        + ((g % 20) * interval '1 day')
                    FROM generate_series(1, 2500000) AS g
                    \"\"\"
                )
            )
            conn.execute(text("ANALYZE investigations"))
            conn.execute(text("ANALYZE llm_calls"))
            conn.execute(text("ANALYZE audit_log"))

        yield {"dsn": dsn, "factory": factory, "engine": engine}
"""

CLEAN_BENCH = """\
\"\"\"B2 / B10 / B11 scale benchmarks (design.md FP-M6-20/21/22).\"\"\"
from __future__ import annotations

import os
import statistics
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import pytest
from sqlalchemy import text

from rca_common.audit import actor_system, write_audit
from rca_common.db.session import make_engine, make_session_factory
from rca_common.investigation_repo import find_open_by_fingerprint
from rca_common.llmclient.tracestore import LLMCallRecord, PGTraceStore

# Sibling conftest (pytest prepends tests/benchmark/ on sys.path for this module).
from conftest import load_b11_writer_model


def _p99(samples: list[float]) -> float:
    if not samples:
        return 0.0
    s = sorted(samples)
    idx = max(0, int(round(0.99 * (len(s) - 1))))
    return s[idx]


def test_b2_fingerprint_correlation_p99_under_20ms(scale_pg):
    factory = scale_pg["factory"]
    with factory() as session:
        find_open_by_fingerprint(
            session,
            fingerprint="fp-1",
            platform_key="plat-1",
            correlation_window_seconds=1800,
        )
        session.commit()

    samples_ms: list[float] = []
    for i in range(200):
        fp = f"fp-{i % 5000}"
        plat = f"plat-{i % 10}"
        t0 = time.perf_counter()
        with factory() as session:
            find_open_by_fingerprint(
                session,
                fingerprint=fp,
                platform_key=plat,
                correlation_window_seconds=1800,
            )
            session.commit()
        samples_ms.append((time.perf_counter() - t0) * 1000)
    p99 = _p99(samples_ms)
    assert p99 < 20.0, (
        f"B2 p99={p99:.2f}ms (threshold 20ms); median={statistics.median(samples_ms):.2f}"
    )


def test_b10_partitioned_list_and_filter_p99(scale_pg):
    \"\"\"Two shapes through real dashboard_api.services.list_investigations.\"\"\"
    from dashboard_api import services as dash_services

    factory = scale_pg["factory"]
    samples_cursor: list[float] = []
    samples_filter: list[float] = []

    for _ in range(50):
        with factory() as session:
            t0 = time.perf_counter()
            dash_services.list_investigations(session, limit=50)
            samples_cursor.append((time.perf_counter() - t0) * 1000)

            t0 = time.perf_counter()
            dash_services.list_investigations(
                session,
                status=["RESOLVED"],
                platform_key="plat-1",
                category="resource",
                limit=50,
            )
            samples_filter.append((time.perf_counter() - t0) * 1000)
            session.commit()

    p99_c = _p99(samples_cursor)
    p99_f = _p99(samples_filter)
    assert p99_c < 200.0, f"B10 cursor p99={p99_c:.2f}ms"
    assert p99_f < 200.0, f"B10 filter p99={p99_f:.2f}ms"


def test_b11_audit_llm_insert_throughput(scale_pg):
    \"\"\"Combined audit + llm_calls insert rate under durable Postgres.

    Writer count and mapping come from B11's structured concurrency_model
    (design.md §11.1.3 / FP-M6-22): four processes in the default deployment,
    each with an independent make_engine-default pool. Threads proxy processes.
    \"\"\"
    dsn = scale_pg["dsn"]
    writers = load_b11_writer_model()
    n_iters = 800
    now = datetime.now(timezone.utc)

    # One independent engine per writer at make_engine defaults.
    # Built and warmed *outside* the timed window so we measure insert rate only.
    engines = []
    factories = []
    stores = []
    for _ in writers:
        eng = make_engine(dsn)
        fac = make_session_factory(eng)
        with eng.connect() as conn:
            conn.execute(text("SELECT 1"))
        engines.append(eng)
        factories.append(fac)
        stores.append(PGTraceStore(session_factory=fac))

    def _run_writer(idx: int) -> int:
        \"\"\"Return rows committed by writers[idx].

        One commit per row — production shape for write_audit / insert_llm_call.
        Session is held open across commits (same connection from the pool),
        matching a long-lived process rather than open/close per row.
        \"\"\"
        factory = factories[idx]
        store = stores[idx]
        process = writers[idx]["process"]
        rows = 0
        with factory() as session:
            for i in range(n_iters):
                if process == "temporal-worker" and i % 2 == 1:
                    store.insert_llm_call(
                        LLMCallRecord(
                            call_id=uuid.uuid4(),
                            investigation_id=None,
                            round=None,
                            agent_role="rca",
                            model="mock",
                            provider=None,
                            prompt_ref="p",
                            response_ref="r",
                            input_tokens=1,
                            output_tokens=1,
                            cost_usd=0.0,
                            latency_ms=1,
                            error=None,
                            created_at=now,
                        )
                    )
                else:
                    write_audit(
                        session,
                        action="event_received",
                        actor=actor_system(),
                        detail={"i": i, "writer": process},
                    )
                    session.commit()
                rows += 1
        return rows

    writer_map = ",".join(
        f"{w['process']}:{'+'.join(w['tables'])}" for w in writers
    )

    def _warmup(idx: int) -> None:
        factory = factories[idx]
        process = writers[idx]["process"]
        with factory() as session:
            for i in range(50):
                write_audit(
                    session,
                    action="event_received",
                    actor=actor_system(),
                    detail={"i": i, "writer": process, "warmup": True},
                )
                session.commit()

    # Pool created and warmed outside the timed window.
    pool = ThreadPoolExecutor(max_workers=len(writers))
    try:
        list(pool.map(_warmup, range(len(writers))))
        t0 = time.perf_counter()
        committed = list(pool.map(_run_writer, range(len(writers))))
        elapsed = time.perf_counter() - t0
    finally:
        pool.shutdown(wait=True)
    total_rows = sum(committed)
    rate = total_rows / elapsed if elapsed > 0 else 0.0

    # Single-writer diagnostic on a pre-warmed engine (printed; not the bar).
    t_sw = time.perf_counter()
    sw_rows = 0
    with factories[0]() as session:
        for i in range(100):
            write_audit(
                session,
                action="event_received",
                actor=actor_system(),
                detail={"i": i, "writer": "single"},
            )
            session.commit()
            sw_rows += 1
    sw_elapsed = time.perf_counter() - t_sw
    single_writer_rate = sw_rows / sw_elapsed if sw_elapsed > 0 else 0.0
    serial_commit_ms = 1000.0 / single_writer_rate if single_writer_rate > 0 else 0.0
    combined_over_single = rate / single_writer_rate if single_writer_rate > 0 else 0.0
    env_line = (
        f"B11 env=cpus={os.cpu_count()},"
        f"serial_commit_ms={serial_commit_ms:.3f},"
        f"combined_over_single={combined_over_single:.2f}"
    )
    print(f"B11 writers={len(writers)}")
    print(f"B11 writer_map={writer_map}")
    print(f"B11 single_writer_rate={single_writer_rate:.1f}/s")
    print(env_line)
    assert rate >= 1000.0, (
        f"B11 combined insert rate={rate:.1f}/s (threshold 1000); "
        f"B11 writers={len(writers)}; B11 writer_map={writer_map}; "
        f"B11 single_writer_rate={single_writer_rate:.1f}/s; {env_line}"
    )
"""

ROOT_CONFTEST_SOURCE = """\
\"\"\"Repo-root pytest conftest.

Makes the repo root importable as a namespace-package root (PEP 420, no
`__init__.py` files needed) so functional tests under `tests/` can do
`from tests.mocks.llm.mock_llm_server import MockLLMServer` regardless of
which subdirectory pytest is invoked from.
\"\"\"
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
"""


# --------------------------------------------------------------------------
# Failure helpers — every message begins with an exact rule token + ": ".
# --------------------------------------------------------------------------


def _fail(rule: str, msg: str) -> NoReturn:
    raise AssertionError(f"{rule}: {msg}")


def _require(cond: object, rule: str, msg: str) -> None:
    if not cond:
        _fail(rule, msg)


# --------------------------------------------------------------------------
# AST helpers.
# --------------------------------------------------------------------------

_SCOPE_NODES = (
    ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda,
    ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp,
)


def _parent_map(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    return parents


def _is_module_scope(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    cur = parents.get(node)
    while cur is not None:
        if isinstance(cur, _SCOPE_NODES):
            return False
        cur = parents.get(cur)
    return True


def _enclosing_module_function(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> str | None:
    """Name of the outermost module-level function containing `node`."""
    name = None
    cur = parents.get(node)
    while cur is not None:
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
            name = cur.name
        cur = parents.get(cur)
    return name


def _name_targets(target: ast.AST):
    if isinstance(target, ast.Name):
        yield target
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            yield from _name_targets(elt)
    elif isinstance(target, ast.Starred):
        yield from _name_targets(target.value)


def collect_binding_occurrences(tree: ast.AST) -> list[tuple[str, str, ast.AST]]:
    """L0's exhaustive enumeration: (name, kind, node) for **every** binding
    occurrence of every name, at every scope, regardless of reachability."""
    out: list[tuple[str, str, ast.AST]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                out.append((alias.asname or alias.name.split(".")[0], "import", node))
        elif isinstance(node, ast.Assign):
            for tgt in node.targets:
                out.extend((n.id, "assign", n) for n in _name_targets(tgt))
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            if node.target is not None:
                out.extend((n.id, "assign", n) for n in _name_targets(node.target))
        elif isinstance(node, ast.NamedExpr):
            out.extend((n.id, "assign", n) for n in _name_targets(node.target))
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            out.extend((n.id, "for", n) for n in _name_targets(node.target))
        elif isinstance(node, ast.comprehension):
            out.extend((n.id, "for", n) for n in _name_targets(node.target))
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    out.extend(
                        (n.id, "with", n) for n in _name_targets(item.optional_vars)
                    )
        elif isinstance(node, ast.ExceptHandler):
            if node.name:
                out.append((node.name, "except", node))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.append((node.name, "def", node))
        elif isinstance(node, ast.ClassDef):
            out.append((node.name, "class", node))
        elif isinstance(node, ast.arguments):
            for arg in [*node.posonlyargs, *node.args, *node.kwonlyargs]:
                out.append((arg.arg, "arg", arg))
            for arg in (node.vararg, node.kwarg):
                if arg is not None:
                    out.append((arg.arg, "arg", arg))
        elif isinstance(node, ast.MatchAs) and node.name:
            out.append((node.name, "match", node))
        elif isinstance(node, ast.MatchStar) and node.name:
            out.append((node.name, "match", node))
        elif isinstance(node, ast.MatchMapping) and node.rest:
            out.append((node.rest, "match", node))
        elif isinstance(node, ast.Global):
            out.extend((n, "global", node) for n in node.names)
        elif isinstance(node, ast.Nonlocal):
            out.extend((n, "nonlocal", node) for n in node.names)
        elif isinstance(node, ast.Delete):
            for tgt in node.targets:
                out.extend((n.id, "del", n) for n in _name_targets(tgt))
    return out


def collect_module_bindings(src: str) -> Counter:
    """A2b: the multiset of (name, kind) bound **at module scope**.

    Derived from ``collect_binding_occurrences`` — the same exhaustive
    enumeration L0 uses — filtered to the occurrences that are *not* inside any
    nested scope (function, lambda, class, comprehension).  Deriving it rather
    than re-walking the tree is what makes the claim in the module docstring
    true: every binding form the enumeration knows about is inventoried here
    too, so a form cannot be handled in one place and forgotten in the other.

    The predecessor recursed into ``For``/``With``/``Try``/``Match`` *bodies*
    but never recorded the names those statements themselves bind, so a
    module-scope ``for guard_hole in []: pass`` was an unrecorded binding that
    passed the inventory (code review round 5, C1).  Reachability is still
    never consulted: an ``if False:`` body binds exactly as much as any other.
    """
    tree = ast.parse(src)
    parents = _parent_map(tree)
    counts: Counter = Counter()
    for name, kind, node in collect_binding_occurrences(tree):
        if _is_module_scope(node, parents):
            counts[(name, kind)] += 1
    return counts


def import_pairs(src: str) -> list[tuple[str | None, str | None, str | None, ast.AST]]:
    """(module, name, asname, node) for every import in the file."""
    out = []
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                out.append((alias.name, None, alias.asname, node))
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                out.append((node.module or "", alias.name, alias.asname, node))
    return out


def _callee_name(call: ast.Call) -> str | None:
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


# --------------------------------------------------------------------------
# Isolated child interpreters.  Every manifest read and the loader execution go
# through one of these two helpers: the guard is itself a pytest test, so its
# own interpreter has imported every ancestor conftest and every installed
# plugin, any of which could patch `yaml.safe_load` for the guard's own reads.
# --------------------------------------------------------------------------

MANIFEST_READ_SCRIPT = r'''
import json, sys
from pathlib import Path

import yaml

path, key_path = sys.argv[1], sys.argv[2]
if key_path != "benchmarks[id=B11].concurrency_model":
    raise SystemExit("unsupported key path: %r" % (key_path,))
data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
by_id = {entry["id"]: entry for entry in data["benchmarks"]}
print(json.dumps(by_id["B11"]["concurrency_model"]))
'''


def _run_isolated(script: str, *args: str) -> subprocess.CompletedProcess:
    with tempfile.TemporaryDirectory() as empty_cwd:
        return subprocess.run(
            [sys.executable, "-I", "-c", script, *args],
            capture_output=True,
            text=True,
            cwd=empty_cwd,
        )


def read_manifest_isolated(
    thresholds_path: Path = THRESHOLDS, key_path: str = MANIFEST_KEY_PATH
) -> dict:
    """The guard's only route to `thresholds.yaml` (errata pass 5)."""
    proc = _run_isolated(MANIFEST_READ_SCRIPT, str(thresholds_path), key_path)
    assert proc.returncode == 0, (
        f"isolated manifest read failed: rc={proc.returncode} stderr={proc.stderr}"
    )
    return json.loads(proc.stdout)


LOADER_PROBE_SCRIPT = r'''
import ast, json, sys
from pathlib import Path

import yaml

conftest_path, thresholds_path = Path(sys.argv[1]), Path(sys.argv[2])
out = {"returned": None, "manifest_writer_processes": None, "writers": None,
       "types_ok": False, "error": None}
try:
    module = ast.parse(conftest_path.read_text(encoding="utf-8"))
    fns = [n for n in module.body
           if isinstance(n, ast.FunctionDef) and n.name == "load_b11_writer_model"]
    if len(fns) != 1:
        raise RuntimeError("expected exactly one loader FunctionDef, found %d" % len(fns))
    synthetic = ast.Module(body=[fns[0]], type_ignores=[])
    ast.fix_missing_locations(synthetic)
    code = compile(synthetic, filename=str(conftest_path), mode="exec")
    namespace = {"yaml": yaml, "Path": Path, "__file__": str(conftest_path),
                 "__builtins__": {}}
    exec(code, namespace)
    returned = namespace["load_b11_writer_model"]()
    out["types_ok"] = type(returned) is list and all(
        type(element) is dict for element in returned
    )
    manifest = yaml.safe_load(thresholds_path.read_text(encoding="utf-8"))
    by_id = {entry["id"]: entry for entry in manifest["benchmarks"]}
    model = by_id["B11"]["concurrency_model"]
    out["manifest_writer_processes"] = model["writer_processes"]
    out["writers"] = model["writers"]
    out["returned"] = returned
except Exception as exc:
    out["error"] = "%s: %s" % (type(exc).__name__, exc)
print(json.dumps(out))
'''

IMPORT_SURFACE_SCRIPT = r'''
import importlib.machinery, json, os, re, subprocess, sys
from pathlib import Path

import yaml

repo = Path(sys.argv[1])
hygiene = sys.argv[2]
expected_b11 = sys.argv[3]
allowed_imports = json.loads(sys.argv[4])
guarded_jobs = json.loads(sys.argv[5])
workflows = json.loads(sys.argv[6])
expected_root_importables = set(json.loads(sys.argv[7]))
expected_package_dirs = set(json.loads(sys.argv[8]))
expected_packaging = set(json.loads(sys.argv[9]))

errors = []
SUFFIXES = sorted(
    importlib.machinery.SOURCE_SUFFIXES
    + importlib.machinery.BYTECODE_SUFFIXES
    + importlib.machinery.EXTENSION_SUFFIXES,
    key=len,
    reverse=True,
)
SKIP = {".git", ".venv", "node_modules", "__pycache__"}


def stem_of(name):
    for suffix in SUFFIXES:
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return None


def is_pkg(directory):
    return any((directory / ("__init__" + s)).is_file() for s in SUFFIXES)


def importables(directory):
    found = set()
    if not directory.is_dir():
        return found
    for entry in directory.iterdir():
        if entry.name in SKIP or entry.name.startswith("."):
            continue
        if entry.is_file():
            stem = stem_of(entry.name)
            if stem and stem != "__init__":
                found.add(stem)
        elif entry.is_dir() and is_pkg(entry):
            found.add(entry.name)
    return found


# (i) the repository root's importable top-level names
root_importables = importables(repo)
if root_importables != expected_root_importables:
    errors.append("(i) repo-root importables %s != %s"
                  % (sorted(root_importables), sorted(expected_root_importables)))

# (ii) no directory that can become an import root holds a shadowing name
shadowable = set(sys.stdlib_module_names)
for module, _name in allowed_imports:
    shadowable.add(module.split(".")[0])
shadowable |= {"sitecustomize", "usercustomize", "_pytest", "pluggy",
               "iniconfig", "packaging"}
# `conftest` enters the derived set through the tier's own
# `from conftest import load_b11_writer_model`, but it is not shadowable in the
# sense (ii) is about: pytest resolves conftest modules **by path**, A9 pins the
# whole ancestor chain and the root file's content verbatim, and (i) pins the
# root's importable names.  Leaving it in would flag every honest conftest.py in
# the repository (design-review D3: a default-deny rule that rejects honest
# shipped code is a false positive).
shadowable.discard("conftest")
for dirpath, dirnames, filenames in os.walk(repo):
    dirnames[:] = [d for d in dirnames if d not in SKIP]
    directory = Path(dirpath)
    if is_pkg(directory):
        continue
    for filename in filenames:
        stem = stem_of(filename)
        if stem and stem in shadowable:
            rel = (directory / filename).relative_to(repo).as_posix()
            errors.append("(ii) shadowing module %s" % rel)
    for dirname in dirnames:
        sub = directory / dirname
        rel = sub.relative_to(repo).as_posix()
        if dirname in shadowable and is_pkg(sub) and rel not in expected_package_dirs:
            errors.append("(ii) shadowing package %s" % rel)

# (iii) no repository package declares a pytest plugin
packaging_files = set()
for dirpath, dirnames, filenames in os.walk(repo):
    dirnames[:] = [d for d in dirnames if d not in SKIP]
    for filename in filenames:
        if filename in ("pyproject.toml", "setup.cfg", "setup.py"):
            packaging_files.add(
                (Path(dirpath) / filename).relative_to(repo).as_posix()
            )
if packaging_files != expected_packaging:
    errors.append("(iii) packaging files %s != %s"
                  % (sorted(packaging_files), sorted(expected_packaging)))
for rel in sorted(packaging_files):
    if "pytest11" in (repo / rel).read_text(encoding="utf-8", errors="replace"):
        errors.append("(iii) pytest11 entry point declared in %s" % rel)


def normalize(run):
    return re.sub(r"\s+", " ", re.sub(r"\\\s*\n", " ", run or "")).strip()


def env_keys_bad(mapping, where):
    for key in mapping or {}:
        if key.startswith("PYTHON") or key.startswith("PYTEST"):
            errors.append("(iv) %s defines forbidden env key %s" % (where, key))


# (iv) the CI invocation adds nothing
for workflow_rel in workflows:
    workflow_path = repo / workflow_rel
    if not workflow_path.is_file():
        errors.append("(iv) missing workflow %s" % workflow_rel)
        continue
    data = yaml.safe_load(workflow_path.read_text(encoding="utf-8")) or {}
    defaults = (data.get("defaults") or {}).get("run") or {}
    if defaults.get("working-directory"):
        errors.append("(iv) workflow declares defaults.run.working-directory")
    if defaults.get("shell"):
        errors.append("(iv) workflow declares defaults.run.shell")
    env_keys_bad(data.get("env"), "workflow %s" % workflow_rel)
    jobs = data.get("jobs") or {}
    for job_name in guarded_jobs:
        job = jobs.get(job_name)
        if job is None:
            errors.append("(iv) missing job %s in %s" % (job_name, workflow_rel))
            continue
        if job.get("runs-on") != "ubuntu-latest":
            errors.append("(iv) job %s runs-on %r" % (job_name, job.get("runs-on")))
        if "container" in job:
            errors.append("(iv) job %s declares container:" % job_name)
        if "strategy" in job:
            errors.append("(iv) job %s declares strategy:" % job_name)
        job_defaults = (job.get("defaults") or {}).get("run") or {}
        if job_defaults.get("shell"):
            errors.append("(iv) job %s declares defaults.run.shell" % job_name)
        if job_defaults.get("working-directory"):
            errors.append("(iv) job %s declares defaults.run.working-directory" % job_name)
        env_keys_bad(job.get("env"), "job %s" % job_name)
        steps = job.get("steps") or []
        for step in steps:
            env_keys_bad(step.get("env"), "job %s step %r" % (job_name, step.get("name")))
            if step.get("shell"):
                errors.append("(iv) job %s step %r declares shell:"
                              % (job_name, step.get("name")))
            run = normalize(step.get("run"))
            if "-m pytest" in run:
                for token in run.split():
                    if token == "-p" or (token.startswith("-p") and token != "-p"):
                        errors.append("(iv) job %s step %r passes %s to pytest"
                                      % (job_name, step.get("name"), token))
            # (v)(b) no step of these jobs writes the job environment
            if "GITHUB_ENV" in (step.get("run") or ""):
                errors.append("(v)(b) job %s step %r writes GITHUB_ENV"
                              % (job_name, step.get("name")))
        if job_name == "benchmark":
            measured = [i for i, s in enumerate(steps)
                        if "tests/benchmark/" in normalize(s.get("run"))]
            label = "B11"
        else:
            measured = [i for i, s in enumerate(steps)
                        if "-m pytest" in normalize(s.get("run"))]
            label = "functional pytest"
        if len(measured) != 1:
            errors.append("(iv) job %s has %d %s steps, expected exactly 1"
                          % (job_name, len(measured), label))
            continue
        index = measured[0]
        if job_name == "benchmark":
            actual = normalize(steps[index].get("run"))
            if actual != expected_b11:
                errors.append("(iv) B11 command %r != %r" % (actual, expected_b11))
        if steps[index].get("working-directory"):
            errors.append("(iv) job %s measured step declares working-directory"
                          % job_name)
        if index == 0:
            errors.append("(iv) job %s measured step has no preceding hygiene gate"
                          % job_name)
            continue
        gate = steps[index - 1]
        gate_run = normalize(gate.get("run"))
        if gate_run != normalize(hygiene):
            errors.append("(iv) job %s hygiene gate run %r != pinned command"
                          % (job_name, gate_run))
        for banned in ("if", "shell", "working-directory", "env", "continue-on-error"):
            if banned in gate:
                errors.append("(iv) job %s hygiene gate declares %s:"
                              % (job_name, banned))

# (v)(a) the pinned gate command is proved to discriminate
clean_env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": "/tmp",
             "LC_ALL": "C"}
POISON_PROBE_KEYS = ("PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME", "PYTHONOPTIMIZE",
                     "PYTEST_PLUGINS")
result = subprocess.run(["/bin/bash", "-e", "-c", hygiene], env=clean_env,
                        capture_output=True, text=True)
if result.returncode != 0:
    errors.append("(v)(a) hygiene gate failed on a clean environment: %s"
                  % result.stderr.strip())
for key in POISON_PROBE_KEYS:
    poisoned = dict(clean_env)
    poisoned[key] = "/tmp/b11-hook"
    result = subprocess.run(["/bin/bash", "-e", "-c", hygiene], env=poisoned,
                            capture_output=True, text=True)
    if result.returncode == 0:
        errors.append("(v)(a) hygiene gate did not reject %s" % key)

print(json.dumps({"errors": errors}))
'''


# --------------------------------------------------------------------------
# L0-L3 — the loader layers.
# --------------------------------------------------------------------------


def check_L0(src: str) -> None:
    """The loader's free names are bound once each, by the import that produces
    the real object; `__file__` is not bound at all; and the loader's own name
    is bound exactly once, by one module-level `def`."""
    tree = ast.parse(src)
    parents = _parent_map(tree)
    occurrences = collect_binding_occurrences(tree)
    by_name: dict[str, list[tuple[str, ast.AST]]] = {}
    for name, kind, node in occurrences:
        by_name.setdefault(name, []).append((kind, node))

    module_loaders = [
        n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == LOADER_NAME
    ]
    _require(
        len(module_loaders) == 1,
        "L0",
        f"expected exactly one module-level `def {LOADER_NAME}`, found "
        f"{len(module_loaders)}",
    )
    _require(
        not any(
            isinstance(n, ast.AsyncFunctionDef) and n.name == LOADER_NAME
            for n in ast.walk(tree)
        ),
        "L0",
        f"`async def {LOADER_NAME}` is not the loader",
    )
    loader_bindings = by_name.get(LOADER_NAME, [])
    _require(
        len(loader_bindings) == 1,
        "L0",
        f"{LOADER_NAME} is bound {len(loader_bindings)} times "
        f"({[k for k, _ in loader_bindings]}); it may only be bound by its own def, "
        "so it cannot be wrapped after definition",
    )

    yaml_bindings = by_name.get("yaml", [])
    _require(
        len(yaml_bindings) == 1,
        "L0",
        f"`yaml` has {len(yaml_bindings)} bindings "
        f"({[k for k, _ in yaml_bindings]}); exactly one `import yaml` is allowed",
    )
    kind, node = yaml_bindings[0]
    _require(
        kind == "import"
        and isinstance(node, ast.Import)
        and _is_module_scope(node, parents)
        and len(node.names) == 1
        and node.names[0].name == "yaml"
        and node.names[0].asname is None,
        "L0",
        "`yaml` must be bound by a module-scope, single-alias, unaliased "
        f"`import yaml` (got kind={kind!r})",
    )

    path_bindings = by_name.get("Path", [])
    _require(
        len(path_bindings) == 1,
        "L0",
        f"`Path` has {len(path_bindings)} bindings "
        f"({[k for k, _ in path_bindings]}); exactly one "
        "`from pathlib import Path` is allowed",
    )
    kind, node = path_bindings[0]
    _require(
        kind == "import"
        and isinstance(node, ast.ImportFrom)
        and _is_module_scope(node, parents)
        and node.module == "pathlib"
        and node.level == 0
        and len(node.names) == 1
        and node.names[0].name == "Path"
        and node.names[0].asname is None,
        "L0",
        "`Path` must be bound by a module-scope, single-alias, unaliased "
        f"`from pathlib import Path` (got kind={kind!r})",
    )

    file_bindings = by_name.get("__file__", [])
    _require(
        not file_bindings,
        "L0",
        f"`__file__` is bound {len(file_bindings)} times; it must be bound nowhere",
    )


def _loader_node(src: str) -> ast.FunctionDef:
    tree = ast.parse(src)
    nodes = [
        n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == LOADER_NAME
    ]
    if len(nodes) != 1:
        _fail("L1", f"expected exactly one module-level `def {LOADER_NAME}`")
    return nodes[0]


def _strip_docstring(body: list[ast.stmt]) -> list[ast.stmt]:
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        return body[1:]
    return body


_L1_FORBIDDEN_ANYWHERE = (
    ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.With, ast.AsyncWith,
    ast.Match, ast.Raise, ast.Assert, ast.Delete, ast.AugAssign, ast.AnnAssign,
    ast.Global, ast.Nonlocal, ast.Import, ast.ImportFrom, ast.Lambda, ast.IfExp,
    ast.Await, ast.Yield, ast.YieldFrom, ast.FunctionDef, ast.AsyncFunctionDef,
    ast.ClassDef,
)
if hasattr(ast, "TryStar"):  # pragma: no branch - 3.11+
    _L1_FORBIDDEN_ANYWHERE = _L1_FORBIDDEN_ANYWHERE + (ast.TryStar,)

_RETURN_CHAIN_FORBIDDEN = (
    ast.Call, ast.Attribute, ast.BinOp, ast.Compare, ast.BoolOp, ast.IfExp,
    ast.Starred,
)


def check_L1(src: str) -> None:
    """Shape, default-deny: straight-line, pure subscript-chain return, closed
    free-name allowlist, closed attribute allowlist."""
    fn = _loader_node(src)
    args = fn.args
    _require(
        not args.posonlyargs and not args.args and not args.kwonlyargs
        and args.vararg is None and args.kwarg is None
        and not args.defaults and not args.kw_defaults,
        "L1",
        "the loader takes no parameters of any kind",
    )
    _require(not fn.decorator_list, "L1", "the loader carries no decorator")
    _require(
        fn.returns is None,
        "L1",
        "the loader carries no return annotation (it would be evaluated at "
        "definition time inside L3's empty-builtins namespace)",
    )

    for node in ast.walk(fn):
        if node is fn:
            continue
        _require(
            not isinstance(node, _L1_FORBIDDEN_ANYWHERE),
            "L1",
            f"forbidden node {type(node).__name__} in the loader — it must be a "
            "straight read",
        )
        if isinstance(node, ast.comprehension):
            _require(
                node.ifs == [] and node.is_async == 0,
                "L1",
                "a comprehension in the loader may not be filtered or async",
            )
    for node in ast.walk(fn):
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            _require(
                len(node.generators) == 1,
                "L1",
                "a comprehension in the loader has exactly one generator",
            )

    body = _strip_docstring(list(fn.body))
    _require(body, "L1", "the loader body is empty")
    _require(
        isinstance(body[-1], ast.Return),
        "L1",
        "the loader body ends in exactly one Return",
    )
    for stmt in body[:-1]:
        _require(
            isinstance(stmt, ast.Assign),
            "L1",
            f"the loader body is Assign statements then one Return; found "
            f"{type(stmt).__name__}",
        )
    _require(
        sum(isinstance(s, ast.Return) for s in ast.walk(fn)) == 1,
        "L1",
        "the loader contains exactly one Return",
    )

    ret = body[-1]
    assert isinstance(ret, ast.Return)
    _require(ret.value is not None, "L1", "the loader returns a value")
    node = ret.value
    while isinstance(node, ast.Subscript):
        _require(
            isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str),
            "L1",
            "the returned subscript chain uses string-Constant slices only",
        )
        node = node.value
    _require(
        isinstance(node, ast.Name),
        "L1",
        "the returned subscript chain bottoms out in a Name bound earlier in the "
        f"loader; found {type(node).__name__}",
    )
    for inner in ast.walk(ret):
        _require(
            not isinstance(inner, _RETURN_CHAIN_FORBIDDEN),
            "L1",
            f"forbidden {type(inner).__name__} inside the loader's return — "
            "doubling, concatenation, slicing and re-ordering are unwritable there",
        )

    bound = {
        name for name, _kind, _node in collect_binding_occurrences(fn)
    }
    _require(
        node.id in bound,
        "L1",
        f"the returned Name {node.id!r} is not bound earlier in the loader",
    )
    free = {
        n.id
        for n in ast.walk(fn)
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id not in bound
    }
    _require(
        free <= LOADER_FREE_NAMES,
        "L1",
        f"free names {sorted(free - LOADER_FREE_NAMES)} are outside the closed set "
        f"{sorted(LOADER_FREE_NAMES)} — the loader must be self-contained and "
        "reflection-free",
    )
    for inner in ast.walk(fn):
        if isinstance(inner, ast.Attribute):
            _require(
                inner.attr in LOADER_ATTRIBUTES,
                "L1",
                f"attribute {inner.attr!r} is outside the closed loader set "
                f"{sorted(LOADER_ATTRIBUTES)}",
            )


def check_L2(src: str) -> None:
    """The pinned form, compared by normalized `ast.dump`."""
    fn = _loader_node(src)
    stripped = ast.FunctionDef(
        name=fn.name,
        args=fn.args,
        body=_strip_docstring(list(fn.body)),
        decorator_list=fn.decorator_list,
        returns=fn.returns,
        type_comment=None,
    )
    if hasattr(fn, "type_params"):  # pragma: no branch - 3.12+
        stripped.type_params = list(getattr(fn, "type_params", []))
    ast.fix_missing_locations(stripped)
    pinned = ast.parse(LOADER_SOURCE).body[0]
    assert isinstance(pinned, ast.FunctionDef)
    pinned.body = _strip_docstring(list(pinned.body))
    _require(
        ast.dump(stripped, include_attributes=False)
        == ast.dump(pinned, include_attributes=False),
        "L2",
        "the loader differs from the pinned loader of consequence 4(b); a "
        "re-pinning must land in this guard's diff",
    )


def check_L3(conftest_path: Path, thresholds_path: Path) -> None:
    """Behavior, at empty builtins, in an isolated child interpreter."""
    proc = _run_isolated(
        LOADER_PROBE_SCRIPT, str(conftest_path), str(thresholds_path)
    )
    _require(
        proc.returncode == 0 and proc.stdout.strip(),
        "L3",
        f"isolated loader probe failed: rc={proc.returncode} stderr={proc.stderr}",
    )
    try:
        out = json.loads(proc.stdout)
    except json.JSONDecodeError:
        _fail("L3", f"unparseable probe stdout: {proc.stdout!r} stderr={proc.stderr}")
    _require(out["error"] is None, "L3", f"loader raised in isolation: {out['error']}")
    _require(
        out["types_ok"] is True,
        "L3",
        "the loader must return a plain list of plain dicts (exact type identity)",
    )
    _require(
        out["returned"] == out["manifest_writer_processes"],
        "L3",
        "the loader is not a pure pass-through of "
        "concurrency_model.writer_processes",
    )
    _require(
        out["returned"] == EXPECTED_CONCURRENCY_MODEL["writer_processes"],
        "L3",
        "the loader's return differs from the guard's own "
        "EXPECTED_CONCURRENCY_MODEL literal — a matched manifest-and-loader edit "
        "still fails here",
    )
    _require(
        len(out["returned"]) == out["writers"] == EXPECTED_CONCURRENCY_MODEL["writers"],
        "L3",
        f"writers={out['writers']} but the loader returned "
        f"{len(out['returned'])} elements",
    )


# --------------------------------------------------------------------------
# W2-W4 — derivation, declared symbols, diagnostics.
# --------------------------------------------------------------------------


def _b11_function_in(tree: ast.Module) -> ast.FunctionDef:
    nodes = [
        n
        for n in tree.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        and n.name == B11_TEST_NAME
    ]
    if len(nodes) != 1:
        _fail("W2", f"expected exactly one `def {B11_TEST_NAME}`")
    node = nodes[0]
    assert isinstance(node, ast.FunctionDef)
    return node


def check_W2(src: str) -> None:
    """Derivation — structural, not lexical: one width, one executor derived
    from it, one engine per element."""
    tree = ast.parse(src)
    b11 = _b11_function_in(tree)

    loads = [
        n
        for n in ast.walk(b11)
        if isinstance(n, ast.Assign)
        and len(n.targets) == 1
        and isinstance(n.targets[0], ast.Name)
        and isinstance(n.value, ast.Call)
        and isinstance(n.value.func, ast.Name)
        and n.value.func.id == LOADER_NAME
    ]
    _require(
        len(loads) == 1,
        "W2",
        f"expected exactly one `W = {LOADER_NAME}()` assignment in "
        f"{B11_TEST_NAME}, found {len(loads)}",
    )
    target = loads[0].targets[0]
    assert isinstance(target, ast.Name)
    width = target.id

    rebindings = [
        (name, kind)
        for name, kind, _node in collect_binding_occurrences(b11)
        if name == width
    ]
    _require(
        len(rebindings) == 1,
        "W2",
        f"{width!r} is bound {len(rebindings)} times in {B11_TEST_NAME} "
        f"({[k for _n, k in rebindings]}); it may be bound only by the load",
    )

    parents = _parent_map(b11)
    for node in ast.walk(b11):
        if not (isinstance(node, ast.Name) and node.id == width):
            continue
        if not isinstance(node.ctx, ast.Load):
            continue
        parent = parents.get(node)
        ok = False
        if isinstance(parent, ast.Call) and isinstance(parent.func, ast.Name):
            ok = parent.func.id in {"len", "enumerate"} and node in parent.args
        elif isinstance(parent, (ast.For, ast.AsyncFor)):
            ok = parent.iter is node
        elif isinstance(parent, ast.comprehension):
            ok = parent.iter is node
        elif isinstance(parent, ast.Subscript):
            ok = parent.value is node and isinstance(parent.ctx, ast.Load)
        _require(
            ok,
            "W2",
            f"{width!r} may only be used as len({width}), iterated, or "
            f"subscripted; found it under {type(parent).__name__} at line "
            f"{node.lineno}",
        )

    executors = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call) and _callee_name(n) == "ThreadPoolExecutor"
    ]
    _require(
        len(executors) == 1,
        "W2",
        f"expected exactly one ThreadPoolExecutor construction in the file, found "
        f"{len(executors)} — the width must be realized as concurrent writers",
    )
    executor = executors[0]
    _require(
        not executor.args
        and len(executor.keywords) == 1
        and executor.keywords[0].arg == "max_workers",
        "W2",
        "ThreadPoolExecutor takes exactly one keyword, max_workers",
    )
    max_workers = executor.keywords[0].value
    _require(
        isinstance(max_workers, ast.Call)
        and isinstance(max_workers.func, ast.Name)
        and max_workers.func.id == "len"
        and len(max_workers.args) == 1
        and not max_workers.keywords
        and isinstance(max_workers.args[0], ast.Name)
        and max_workers.args[0].id == width,
        "W2",
        f"max_workers must be exactly len({width}); arithmetic on the derived "
        "width is unwritable",
    )
    _require(
        any(n is executor for n in ast.walk(b11)),
        "W2",
        f"the executor must be constructed inside {B11_TEST_NAME}",
    )

    engine_loops = [
        n
        for n in ast.walk(b11)
        if isinstance(n, (ast.For, ast.AsyncFor))
        and isinstance(n.iter, ast.Name)
        and n.iter.id == width
    ]
    engine_comps = [
        n
        for n in ast.walk(b11)
        if isinstance(n, ast.comprehension)
        and isinstance(n.iter, ast.Name)
        and n.iter.id == width
        and any(
            isinstance(c, ast.Call) and _callee_name(c) == "make_engine"
            for c in ast.walk(n)
        )
    ]
    builders = engine_loops + engine_comps
    _require(
        len(builders) >= 1,
        "W2",
        f"the engine list must be built by one iteration over {width}",
    )
    engine_builders = [
        b
        for b in builders
        if any(
            isinstance(c, ast.Call) and _callee_name(c) == "make_engine"
            for c in ast.walk(b)
        )
    ]
    _require(
        len(engine_builders) == 1,
        "W2",
        f"exactly one iteration over {width} may construct engines, found "
        f"{len(engine_builders)}",
    )
    engine_calls = [
        c
        for c in ast.walk(engine_builders[0])
        if isinstance(c, ast.Call) and _callee_name(c) == "make_engine"
    ]
    _require(
        len(engine_calls) == 1,
        "W2",
        "one engine per writer: the iteration over the writer set constructs "
        f"exactly one engine, found {len(engine_calls)}",
    )
    all_engine_calls = [
        c
        for c in ast.walk(b11)
        if isinstance(c, ast.Call) and _callee_name(c) == "make_engine"
    ]
    _require(
        len(all_engine_calls) == 1,
        "W2",
        f"{B11_TEST_NAME} constructs engines only inside the per-writer loop, "
        f"found {len(all_engine_calls)} make_engine calls",
    )

    pool_assigns = [
        n
        for n in ast.walk(b11)
        if isinstance(n, ast.Assign)
        and len(n.targets) == 1
        and isinstance(n.targets[0], ast.Name)
        and n.value is executor
    ]
    _require(
        len(pool_assigns) == 1,
        "W2",
        "the executor must be bound to exactly one name",
    )
    pool_target = pool_assigns[0].targets[0]
    assert isinstance(pool_target, ast.Name)
    pool_name = pool_target.id
    # Code review round 6, C1: constructing the real executor then rebinding
    # `pool` to a fake that returns forged counts without calling the writer
    # used to pass, because only the constructor→name edge was pinned.
    pool_bindings = [
        (name, kind)
        for name, kind, _node in collect_binding_occurrences(b11)
        if name == pool_name
    ]
    _require(
        pool_bindings == [(pool_name, "assign")],
        "W2",
        f"the pool name {pool_name!r} must be bound exactly once, to the "
        f"checked ThreadPoolExecutor constructor; found {pool_bindings}",
    )
    _check_w2_measured_rate(b11, width, pool_name)


def _is_perf_counter_call(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "perf_counter"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "time"
        and not node.args
        and not node.keywords
    )


def _zero_constant(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, (int, float))
        and not isinstance(node.value, bool)
        and node.value == 0
    )


def _check_w2_measured_rate(b11: ast.FunctionDef, width: str, pool: str) -> None:
    """W2, rate integrity — the asserted number must be *the* measurement.

    Constructing an executor proves nothing on its own: code review round 5
    (C1) replaced the real ``pool.map(_run_writer, ...)`` with a serial
    comprehension and divided the (much larger) elapsed time by the writer
    count, and the previous W2 passed both.  At ~500 real inserts/s that
    reports ~2000/s while running zero concurrency.

    So the whole chain from the executor to the asserted constant is pinned
    structurally, backwards from the assertion:

        assert  rate      >= <threshold>
        rate    = rows / elapsed  (optionally guarded by `elapsed > 0`)
        rows    = sum(committed)
        elapsed = time.perf_counter() - t0        <- nothing else, no BinOp
        committed = list(pool.map(_run_writer, range(len(writers))))
        t0      = time.perf_counter()

    Every intermediate name is bound exactly once and *loaded* only at the one
    place this chain names, which is what forbids arithmetic between the raw
    timer read and the division: there is nowhere else to put it.  The counted
    loop inside the writer function is pinned too, so the numerator cannot be
    inflated the way the denominator was.
    """
    bindings = collect_binding_occurrences(b11)

    def binding_kinds(name: str) -> list[str]:
        return [k for n, k, _node in bindings if n == name]

    def bound_once(name: str, what: str) -> None:
        kinds = binding_kinds(name)
        _require(
            kinds == ["assign"],
            "W2",
            f"{what} {name!r} must be bound exactly once, by assignment; "
            f"found {kinds}",
        )

    def sole_assign(name: str, what: str) -> ast.Assign:
        assigns = [
            n
            for n in ast.walk(b11)
            if isinstance(n, ast.Assign)
            and len(n.targets) == 1
            and isinstance(n.targets[0], ast.Name)
            and n.targets[0].id == name
        ]
        _require(
            len(assigns) == 1,
            "W2",
            f"{what} {name!r} must have exactly one `{name} = ...`; "
            f"found {len(assigns)}",
        )
        return assigns[0]

    def loads(name: str) -> list[ast.Name]:
        return [
            n
            for n in ast.walk(b11)
            if isinstance(n, ast.Name) and n.id == name and isinstance(n.ctx, ast.Load)
        ]

    def only_loaded_at(name: str, allowed: list[ast.AST], what: str) -> None:
        found = loads(name)
        extra = [n for n in found if not any(n is a for a in allowed)]
        _require(
            not extra,
            "W2",
            f"{what} {name!r} may only be read as the measurement chain reads "
            f"it; found {len(extra)} other use(s), first at line "
            f"{getattr(extra[0], 'lineno', '?') if extra else '?'}",
        )
        _require(
            len(found) == len(allowed),
            "W2",
            f"{what} {name!r} must be read exactly {len(allowed)} time(s) in "
            f"the measurement chain; found {len(found)}",
        )

    # (1) the single threshold assertion names the rate.
    asserts = [n for n in ast.walk(b11) if isinstance(n, ast.Assert)]
    _require(
        len(asserts) == 1,
        "W2",
        f"{B11_TEST_NAME} must make exactly one assertion (the B11 bar); "
        f"found {len(asserts)}",
    )
    test = asserts[0].test
    _require(
        isinstance(test, ast.Compare)
        and len(test.ops) == 1
        and isinstance(test.ops[0], ast.GtE)
        and isinstance(test.left, ast.Name)
        and isinstance(test.comparators[0], ast.Constant)
        and isinstance(test.comparators[0].value, (int, float)),
        "W2",
        "the B11 assertion must be `<rate name> >= <numeric threshold>`",
    )
    assert isinstance(test, ast.Compare) and isinstance(test.left, ast.Name)
    rate_name = test.left.id

    # (2) rate = rows / elapsed, optionally guarded by `elapsed > 0`.
    bound_once(rate_name, "the measured rate")
    rate_value = sole_assign(rate_name, "the measured rate").value
    guard_load: ast.AST | None = None
    if isinstance(rate_value, ast.IfExp):
        guard = rate_value.test
        _require(
            isinstance(guard, ast.Compare)
            and len(guard.ops) == 1
            and isinstance(guard.ops[0], ast.Gt)
            and isinstance(guard.left, ast.Name)
            and _zero_constant(guard.comparators[0])
            and _zero_constant(rate_value.orelse),
            "W2",
            "the only guard permitted on the rate is `<elapsed> > 0`, with 0 "
            "as the fallback",
        )
        assert isinstance(guard, ast.Compare) and isinstance(guard.left, ast.Name)
        guard_load = guard.left
        quotient = rate_value.body
    else:
        quotient = rate_value
    _require(
        isinstance(quotient, ast.BinOp)
        and isinstance(quotient.op, ast.Div)
        and isinstance(quotient.left, ast.Name)
        and isinstance(quotient.right, ast.Name),
        "W2",
        "the rate must be exactly `<rows> / <elapsed>`: no scaling, no "
        "post-processing between the measurement and the bar",
    )
    assert isinstance(quotient, ast.BinOp)
    assert isinstance(quotient.left, ast.Name) and isinstance(quotient.right, ast.Name)
    rows_name, elapsed_name = quotient.left.id, quotient.right.id
    if guard_load is not None:
        assert isinstance(guard_load, ast.Name)
        _require(
            guard_load.id == elapsed_name,
            "W2",
            f"the rate guard tests {guard_load.id!r}, not the divisor "
            f"{elapsed_name!r}",
        )

    # (3) elapsed = time.perf_counter() - t0, and nothing else.
    bound_once(elapsed_name, "the elapsed time")
    elapsed_assign = sole_assign(elapsed_name, "the elapsed time")
    delta = elapsed_assign.value
    _require(
        isinstance(delta, ast.BinOp)
        and isinstance(delta.op, ast.Sub)
        and _is_perf_counter_call(delta.left)
        and isinstance(delta.right, ast.Name),
        "W2",
        f"{elapsed_name!r} must be exactly `time.perf_counter() - <start>`; "
        "dividing, scaling or otherwise post-processing the raw delta forges "
        "the rate",
    )
    assert isinstance(delta, ast.BinOp) and isinstance(delta.right, ast.Name)
    start_name = delta.right.id
    only_loaded_at(
        elapsed_name,
        [quotient.right] + ([guard_load] if guard_load is not None else []),
        "the elapsed time",
    )

    bound_once(start_name, "the timer start")
    start_assign = sole_assign(start_name, "the timer start")
    _require(
        _is_perf_counter_call(start_assign.value),
        "W2",
        f"{start_name!r} must be exactly `time.perf_counter()`",
    )
    only_loaded_at(start_name, [delta.right], "the timer start")

    # (4) rows = sum(committed).
    bound_once(rows_name, "the committed row count")
    rows_assign = sole_assign(rows_name, "the committed row count")
    total = rows_assign.value
    _require(
        isinstance(total, ast.Call)
        and isinstance(total.func, ast.Name)
        and total.func.id == "sum"
        and len(total.args) == 1
        and isinstance(total.args[0], ast.Name)
        and not total.keywords,
        "W2",
        f"{rows_name!r} must be exactly `sum(<executor results>)`",
    )
    assert isinstance(total, ast.Call) and isinstance(total.args[0], ast.Name)
    committed_name = total.args[0].id
    only_loaded_at(rows_name, [quotient.left], "the committed row count")

    # (5) committed = list(pool.map(_run_writer, range(len(writers)))).
    bound_once(committed_name, "the executor results")
    committed_assign = sole_assign(committed_name, "the executor results")
    materialized = committed_assign.value
    _require(
        isinstance(materialized, ast.Call)
        and isinstance(materialized.func, ast.Name)
        and materialized.func.id == "list"
        and len(materialized.args) == 1
        and not materialized.keywords,
        "W2",
        f"{committed_name!r} must be `list(...)`: an unconsumed lazy map "
        "returns before the writers have run and makes the elapsed time zero",
    )
    assert isinstance(materialized, ast.Call)
    mapped = materialized.args[0]
    _require(
        isinstance(mapped, ast.Call)
        and isinstance(mapped.func, ast.Attribute)
        and mapped.func.attr == "map"
        and isinstance(mapped.func.value, ast.Name)
        and mapped.func.value.id == pool,
        "W2",
        f"the timed work must be `{pool}.map(...)`: a serial loop or "
        "comprehension over the writers realizes none of the pinned width",
    )
    assert isinstance(mapped, ast.Call)
    _require(
        len(mapped.args) == 2 and not mapped.keywords,
        "W2",
        f"{pool}.map takes exactly the writer function and the writer index set",
    )
    _require(
        isinstance(mapped.args[0], ast.Name)
        and mapped.args[0].id == WRITER_FUNC_NAME,
        "W2",
        f"the executor must drive {WRITER_FUNC_NAME}() itself",
    )
    index_set = mapped.args[1]
    _require(
        isinstance(index_set, ast.Call)
        and isinstance(index_set.func, ast.Name)
        and index_set.func.id == "range"
        and len(index_set.args) == 1
        and not index_set.keywords
        and isinstance(index_set.args[0], ast.Call)
        and isinstance(index_set.args[0].func, ast.Name)
        and index_set.args[0].func.id == "len"
        and len(index_set.args[0].args) == 1
        and not index_set.args[0].keywords
        and isinstance(index_set.args[0].args[0], ast.Name)
        and index_set.args[0].args[0].id == width,
        "W2",
        f"the writer index set must be exactly `range(len({width}))` — the "
        "complete, unmodified writer set",
    )
    only_loaded_at(committed_name, [total.args[0]], "the executor results")

    # (6) the writer function is defined once and reached only through the map.
    writer_defs = [
        n
        for n in ast.walk(b11)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        and n.name == WRITER_FUNC_NAME
    ]
    _require(
        len(writer_defs) == 1,
        "W2",
        f"expected exactly one `def {WRITER_FUNC_NAME}` inside {B11_TEST_NAME}",
    )
    only_loaded_at(WRITER_FUNC_NAME, [mapped.args[0]], "the writer function")

    # (7) ordering: start, work and stop are consecutive in one block.
    parents = _parent_map(b11)
    _require(
        parents.get(start_assign) is parents.get(committed_assign)
        is parents.get(elapsed_assign),
        "W2",
        "the timer start, the executor call and the timer stop must live in "
        "one block, so nothing untimed can be moved between them",
    )
    _require(
        start_assign.lineno < committed_assign.lineno < elapsed_assign.lineno,
        "W2",
        "the timed window must open before the executor call and close after it",
    )

    _check_w2_writer_body(writer_defs[0])


def _nested_deferred(
    node: ast.AST, parents: dict[ast.AST, ast.AST], scope_root: ast.AST
) -> bool:
    """True when ``node`` sits inside a nested deferred scope under ``scope_root``.

    Lambdas, nested functions/classes and comprehensions are deferred: a
    production writer mentioned only inside one of them is never invoked by the
    counted loop, so counting it forges the numerator (code review round 6, C1).
    """
    cur = parents.get(node)
    while cur is not None and cur is not scope_root:
        if isinstance(cur, _SCOPE_NODES):
            return True
        cur = parents.get(cur)
    return False


def _under_conditional_expr(
    node: ast.AST, parents: dict[ast.AST, ast.AST], scope_root: ast.AST
) -> bool:
    """True when ``node`` sits under a *deferred* short-circuit / ternary slot.

    Expression-level short-circuit can name a production call without evaluating
    it (code review round 7, C1; round 8, C1), but not every child of a
    ``BoolOp`` / ``IfExp`` / ``Compare`` / ``AnnAssign`` is deferred
    (design-review D1):

    - ``BoolOp``: only descendants of ``values[1:]`` are conditional; ``values[0]``
      is always evaluated (``write_audit(...) or True`` is live).
    - ``IfExp``: only descendants of ``body`` / ``orelse`` are conditional;
      ``test`` is always evaluated (``x if write_audit(...) else y`` is live).
    - ``Compare``: only descendants of ``comparators[1:]`` are conditional
      (chained comparison short-circuit: ``False == True == writer(...)``);
      ``left`` and ``comparators[0]`` are always evaluated.
    - ``AnnAssign``: only descendants of ``annotation`` are deferred (function-
      local annotation expressions are not evaluated at runtime);
      ``value`` is always evaluated (``x: int = write_audit(...)`` is live).

    Walks the ancestor chain from ``node`` and, at each relevant parent,
    inspects the parent edge the walk arrived on — not merely whether such an
    ancestor exists.
    """
    cur = node
    while True:
        parent = parents.get(cur)
        if parent is None or parent is scope_root:
            return False
        if isinstance(parent, ast.BoolOp):
            # Deferred only when the walk came through a short-circuitable
            # operand (values[1:]). values[0] is always evaluated.
            try:
                idx = parent.values.index(cur)
            except ValueError:
                # Not a values child (e.g. the operator node) — keep walking.
                cur = parent
                continue
            if idx >= 1:
                return True
            cur = parent
            continue
        if isinstance(parent, ast.IfExp):
            # Deferred only when the walk came through body or orelse; test
            # is always evaluated.
            if cur is parent.body or cur is parent.orelse:
                return True
            cur = parent
            continue
        if isinstance(parent, ast.Compare):
            # Chained comparison short-circuit: left and comparators[0] are
            # always evaluated; comparators[1:] only run if earlier links hold.
            if cur is parent.left:
                cur = parent
                continue
            try:
                idx = parent.comparators.index(cur)
            except ValueError:
                cur = parent
                continue
            if idx >= 1:
                return True
            cur = parent
            continue
        if isinstance(parent, ast.AnnAssign):
            # Local annotation expressions are not evaluated at runtime;
            # the optional value is.
            if cur is parent.annotation:
                return True
            cur = parent
            continue
        if isinstance(parent, _SCOPE_NODES):
            return False
        cur = parent


def _live_calls(
    root: ast.AST, parents: dict[ast.AST, ast.AST], scope_root: ast.AST
) -> list[ast.Call]:
    """Calls under ``root`` that are reached directly — not merely defined.

    Excludes deferred scopes (lambda/nested def/comprehension) and expression-
    level short-circuit / ternary / annotation slots that are not always
    evaluated (``BoolOp.values[1:]``, ``IfExp.body`` / ``IfExp.orelse``,
    ``Compare.comparators[1:]``, ``AnnAssign.annotation``; see
    ``_under_conditional_expr``).
    """
    return [
        n
        for n in ast.walk(root)
        if isinstance(n, ast.Call)
        and not _nested_deferred(n, parents, scope_root)
        and not _under_conditional_expr(n, parents, scope_root)
    ]


def _writes_here(
    node: ast.stmt, parents: dict[ast.AST, ast.AST], scope_root: ast.AST
) -> bool:
    return any(
        _callee_name(n) in WRITER_PRODUCTION_CALLS
        for n in _live_calls(node, parents, scope_root)
    )


def _every_path_writes(
    body: list[ast.stmt], parents: dict[ast.AST, ast.AST], scope_root: ast.AST
) -> bool:
    """True when control cannot reach the end of `body` without calling one of
    the production writers.

    Deliberately conservative: a loop or an `if` without an `else` is never
    counted as a guaranteed write, because it may execute zero times.
    """
    for stmt in body:
        if isinstance(stmt, ast.If):
            if (
                stmt.orelse
                and _every_path_writes(stmt.body, parents, scope_root)
                and _every_path_writes(stmt.orelse, parents, scope_root)
            ):
                return True
            continue
        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            if _every_path_writes(stmt.body, parents, scope_root):
                return True
            continue
        if isinstance(stmt, (ast.For, ast.AsyncFor, ast.While, ast.Try)):
            continue
        if _writes_here(stmt, parents, scope_root):
            return True
    return False


def _is_commit_call(node: ast.Call) -> bool:
    """``session.commit()`` — a real call, not the bare attribute ``session.commit``."""
    return (
        isinstance(node.func, ast.Attribute)
        and node.func.attr == "commit"
        and not node.args
        and not node.keywords
    )


def _every_path_commits(
    body: list[ast.stmt], parents: dict[ast.AST, ast.AST], scope_root: ast.AST
) -> bool:
    """True when every path through ``body`` reaches a live ``*.commit()`` call.

    Used only on the audit branch, where write_audit is durable only after
    commit (code review round 6, C1: replacing ``session.commit()`` with the
    bare attribute rolled the counted rows back and still passed).
    """
    for stmt in body:
        if isinstance(stmt, ast.If):
            if (
                stmt.orelse
                and _every_path_commits(stmt.body, parents, scope_root)
                and _every_path_commits(stmt.orelse, parents, scope_root)
            ):
                return True
            continue
        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            if _every_path_commits(stmt.body, parents, scope_root):
                return True
            continue
        if isinstance(stmt, (ast.For, ast.AsyncFor, ast.While, ast.Try)):
            continue
        if any(
            _is_commit_call(n) for n in _live_calls(stmt, parents, scope_root)
        ):
            return True
    return False


def _paths_with_write_audit(
    body: list[ast.stmt], parents: dict[ast.AST, ast.AST], scope_root: ast.AST
) -> list[list[ast.stmt]]:
    """Collect statement lists that form a path containing a live write_audit."""
    found: list[list[ast.stmt]] = []

    def walk(stmts: list[ast.stmt], prefix: list[ast.stmt]) -> None:
        for index, stmt in enumerate(stmts):
            rest = stmts[index + 1 :]
            if isinstance(stmt, ast.If):
                walk(stmt.body + rest, prefix)
                if stmt.orelse:
                    walk(stmt.orelse + rest, prefix)
                elif not _writes_here(stmt, parents, scope_root):
                    # no else and no write in the test: fall through
                    continue
                return
            if isinstance(stmt, (ast.With, ast.AsyncWith)):
                walk(stmt.body + rest, prefix)
                return
            if _writes_here(stmt, parents, scope_root):
                # Does this statement (or its live calls) include write_audit?
                if any(
                    _callee_name(n) == "write_audit"
                    for n in _live_calls(stmt, parents, scope_root)
                ):
                    found.append(prefix + [stmt] + rest)
                return
            prefix = prefix + [stmt]
        # no write on this path

    walk(body, [])
    return found


def _check_w2_writer_body(writer: ast.FunctionDef) -> None:
    """W2, numerator integrity: what the writer *returns* is a count of rows it
    actually wrote, one per iteration of one real loop."""
    parents = _parent_map(writer)
    returns = [n for n in ast.walk(writer) if isinstance(n, ast.Return)]
    _require(
        len(returns) == 1 and isinstance(returns[0].value, ast.Name),
        "W2",
        f"{WRITER_FUNC_NAME} must have exactly one `return <counter>`; a "
        "computed return value forges the row count",
    )
    counter = returns[0].value
    assert isinstance(counter, ast.Name)

    loops = [n for n in ast.walk(writer) if isinstance(n, (ast.For, ast.AsyncFor))]
    _require(
        len(loops) == 1,
        "W2",
        f"{WRITER_FUNC_NAME} must have exactly one write loop; found {len(loops)}",
    )
    loop = loops[0]

    resets = [
        n
        for n in ast.walk(writer)
        if isinstance(n, ast.Assign)
        and any(t.id == counter.id for t in _name_targets(n.targets[0]))
    ]
    _require(
        len(resets) == 1 and _zero_constant(resets[0].value),
        "W2",
        f"{counter.id!r} must start at 0 exactly once",
    )
    increments = [
        n
        for n in ast.walk(writer)
        if isinstance(n, ast.AugAssign)
        and isinstance(n.target, ast.Name)
        and n.target.id == counter.id
    ]
    _require(
        len(increments) == 1
        and isinstance(increments[0].op, ast.Add)
        and isinstance(increments[0].value, ast.Constant)
        and increments[0].value.value == 1,
        "W2",
        f"{counter.id!r} may only ever be incremented by exactly 1",
    )
    _require(
        loop.body and loop.body[-1] is increments[0],
        "W2",
        f"{counter.id!r} must be incremented by the last statement of the write "
        "loop itself, so a counted iteration is always a completed one",
    )
    _require(
        _every_path_writes(loop.body, parents, writer),
        "W2",
        f"every path through {WRITER_FUNC_NAME}'s write loop must reach one of "
        f"{list(WRITER_PRODUCTION_CALLS)}; a conditional write counts rows it "
        "never wrote",
    )
    other_bindings = [
        (name, kind)
        for name, kind, node in collect_binding_occurrences(writer)
        if name == counter.id and node is not increments[0].target
    ]
    _require(
        len(other_bindings) == 1,
        "W2",
        f"{counter.id!r} is bound {len(other_bindings) + 1} times in "
        f"{WRITER_FUNC_NAME}; only the reset and the +1 are permitted",
    )

    # Live calls only: a writer mentioned inside an uninvoked lambda/nested def
    # is not a measured write (code review round 6, C1).
    live = _live_calls(loop, parents, writer)
    called_in_loop = {_callee_name(n) for n in live}
    for required in WRITER_PRODUCTION_CALLS:
        _require(
            required in called_in_loop,
            "W2",
            f"the counted loop in {WRITER_FUNC_NAME} must drive the production "
            f"writer {required}() as a live call (not inside a lambda/nested "
            f"function); a loop that counts rows it never wrote measures nothing",
        )

    # Audit branch durability: every path that calls write_audit must also
    # call session.commit() — the bare attribute is not enough.
    audit_paths = _paths_with_write_audit(loop.body, parents, writer)
    _require(
        audit_paths,
        "W2",
        f"{WRITER_FUNC_NAME} must have at least one live write_audit() path",
    )
    for path in audit_paths:
        _require(
            _every_path_commits(path, parents, writer),
            "W2",
            "every path that calls write_audit() must also call session.commit(); "
            "without the call the counted audit rows roll back and the rate is "
            "forged",
        )


W3_DECLARED_SYMBOLS = {"write_audit", "Write", "insert_llm_call"}
W3_FORBIDDEN_CALLEES = ("executemany", "copy_from")
W3_FORBIDDEN_SUBSTRINGS = ("bulk_", "_batch")


def check_W3(src: str) -> None:
    """Only declared symbols: the benchmark drives the production writers named
    in B11's call_sites and no batch/COPY sink."""
    declared = {
        site["symbol"]
        for wp in EXPECTED_CONCURRENCY_MODEL["writer_processes"]
        for site in wp["call_sites"]
    }
    _require(
        declared == W3_DECLARED_SYMBOLS,
        "W3",
        f"declared call_sites symbols {sorted(declared)} != "
        f"{sorted(W3_DECLARED_SYMBOLS)}",
    )
    tree = ast.parse(src)
    b11 = _b11_function_in(tree)
    called = {
        _callee_name(n) for n in ast.walk(b11) if isinstance(n, ast.Call)
    }
    for required in ("write_audit", "insert_llm_call"):
        _require(
            required in called,
            "W3",
            f"{B11_TEST_NAME} must drive the production writer {required}()",
        )
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _callee_name(node) or ""
        _require(
            name not in W3_FORBIDDEN_CALLEES
            and not any(part in name for part in W3_FORBIDDEN_SUBSTRINGS),
            "W3",
            f"undeclared batch writer {name!r}: B11 drives the production "
            "per-row writers only",
        )
        if isinstance(node.func, ast.Name) and node.func.id == "text":
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    _require(
                        "COPY " not in arg.value.upper(),
                        "W3",
                        "COPY is not one of B11's declared writers",
                    )


def check_W4(src: str) -> None:
    """Diagnostics: all four fixed prefixes of consequence 3."""
    for prefix in DIAGNOSTIC_PREFIXES:
        _require(
            prefix in src,
            "W4",
            f"missing diagnostic prefix {prefix!r}; the assertion message and the "
            "printed lines must carry the derivation",
        )


# --------------------------------------------------------------------------
# A1-A10 — the benchmark tier's configuration surface.
# --------------------------------------------------------------------------


def check_A1(bench_dir: Path) -> None:
    expected = {CONFTEST_NAME, BENCH_NAME, "thresholds.yaml"}
    names = {
        p.name
        for p in bench_dir.iterdir()
        if p.name != "__pycache__" and not p.name.startswith(".")
    }
    _require(names == expected, "A1", f"tier inventory {sorted(names)} != {sorted(expected)}")


def check_A2a(sources: dict[str, str]) -> None:
    for fname, src in sources.items():
        for module, name, asname, _node in import_pairs(src):
            permitted = (module, name) in ALLOWED_BENCHMARK_IMPORTS
            if permitted and asname is not None:
                # An alias is only permitted where PERMITTED_LOCAL_IMPORTS says
                # so; a renamed import is otherwise a new name in the tier.
                permitted = any(
                    entry[0] == fname
                    and entry[2] == asname
                    and entry[3] == f"{module}.{name}"
                    for entry in PERMITTED_LOCAL_IMPORTS
                )
            _require(
                permitted,
                "A2a",
                f"import {module!r}/{name!r} as {asname!r} in {fname} is not in "
                "ALLOWED_BENCHMARK_IMPORTS",
            )


def check_A2b(sources: dict[str, str]) -> None:
    for fname, src in sources.items():
        expected = EXPECTED_MODULE_BINDINGS.get(fname)
        _require(expected is not None, "A2b", f"no binding literal for {fname}")
        got = collect_module_bindings(src)
        _require(
            got == expected,
            "A2b",
            f"module-scope bindings for {fname}: extra="
            f"{sorted((got - expected).elements())} missing="
            f"{sorted((expected - got).elements())}",
        )


def _reserved_names(fname: str) -> set[str]:
    module_names = {name for (name, _kind) in EXPECTED_MODULE_BINDINGS.get(fname, {})}
    return ALLOWED_FREE_NAMES | module_names | REFLECTIVE_NAMES


def check_A2c(sources: dict[str, str]) -> None:
    for fname, src in sources.items():
        reserved = _reserved_names(fname)
        expected = EXPECTED_MODULE_BINDINGS.get(fname, Counter())
        tree = ast.parse(src)
        parents = _parent_map(tree)
        for name, kind, node in collect_binding_occurrences(tree):
            if name not in reserved:
                continue
            if _is_module_scope(node, parents) and expected.get((name, kind)):
                continue
            enclosing = _enclosing_module_function(node, parents)
            if kind == "import" and any(
                entry[0] == fname and entry[1] == enclosing and entry[2] == name
                for entry in PERMITTED_LOCAL_IMPORTS
            ):
                continue
            _fail(
                "A2c",
                f"reserved name {name!r} bound ({kind}) in {fname}"
                f"{'::' + enclosing if enclosing else ''} at line "
                f"{getattr(node, 'lineno', '?')}",
            )


def check_A2d(sources: dict[str, str]) -> None:
    for fname, src in sources.items():
        declared = {name for (name, _kind) in EXPECTED_MODULE_BINDINGS.get(fname, {})}
        tree = ast.parse(src)
        parents = _parent_map(tree)
        locals_by_function: dict[str, set[str]] = {}
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                locals_by_function[node.name] = {
                    name for name, _kind, _n in collect_binding_occurrences(node)
                }
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)):
                continue
            if node.id in ALLOWED_FREE_NAMES or node.id in declared:
                continue
            enclosing = _enclosing_module_function(node, parents)
            if enclosing and node.id in locals_by_function.get(enclosing, set()):
                continue
            _fail(
                "A2d",
                f"loaded name {node.id!r} in {fname}"
                f"{'::' + enclosing if enclosing else ''} at line {node.lineno} is "
                "in none of the three closed sets",
            )


def check_A3(sources: dict[str, str]) -> None:
    for fname, src in sources.items():
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.Attribute):
                _require(
                    not node.attr.startswith("_"),
                    "A3",
                    f"private attribute {node.attr!r} in {fname} at line "
                    f"{node.lineno}",
                )
            if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign, ast.Delete)):
                targets = (
                    node.targets
                    if isinstance(node, (ast.Assign, ast.Delete))
                    else [node.target]
                )
                for tgt in targets:
                    _require(
                        not isinstance(tgt, ast.Attribute),
                        "A3",
                        f"attribute assignment/deletion target in {fname} at line "
                        f"{node.lineno} — an allowlisted import cannot be "
                        "monkeypatched",
                    )
            if isinstance(node, ast.NamedExpr):
                _require(
                    not isinstance(node.target, ast.Attribute),
                    "A3",
                    f"attribute walrus target in {fname} at line {node.lineno}",
                )
            if isinstance(node, ast.Call):
                for arg in node.args:
                    _require(
                        not isinstance(arg, ast.Starred),
                        "A3",
                        f"starred positional argument in {fname} at line "
                        f"{node.lineno}",
                    )
                for kw in node.keywords:
                    _require(
                        kw.arg is not None,
                        "A3",
                        f"**-unpacking keyword in {fname} at line {node.lineno}",
                    )


def check_A4(sources: dict[str, str]) -> None:
    for fname, src in sources.items():
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.Call) and _callee_name(node) == "make_engine":
                _require(
                    len(node.args) == 1 and not node.keywords,
                    "A4",
                    f"make_engine in {fname} at line {node.lineno} takes exactly one "
                    "positional argument and zero keywords "
                    f"(got {len(node.args)} positional, "
                    f"{[k.arg for k in node.keywords]} keywords)",
                )


def _dsn_value_ok(value: ast.AST) -> bool:
    if isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute):
        return value.func.attr == "get_connection_url"
    if isinstance(value, ast.Subscript):
        return isinstance(value.slice, ast.Constant) and value.slice.value == "dsn"
    return False


def _check_dsn_name(fname: str, src: str, tree: ast.AST, node: ast.AST, where: str) -> None:
    _require(
        isinstance(node, ast.Name),
        "A5",
        f"{where} in {fname} must be a bare Name from {ALLOWED_DSN_SOURCES}; found "
        f"{type(node).__name__} at line {getattr(node, 'lineno', '?')}",
    )
    assert isinstance(node, ast.Name)
    name = node.id
    assigns = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Assign)
        and any(t.id == name for t in _iter_assign_names(n))
    ]
    params = [
        (fn, arg)
        for fn in ast.walk(tree)
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))
        for arg in [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]
        if arg.arg == name
    ]
    _require(
        assigns or params,
        "A5",
        f"{where} in {fname}: {name!r} has no binding in the file",
    )
    for assign in assigns:
        _require(
            _dsn_value_ok(assign.value),
            "A5",
            f"{name!r} in {fname} is bound at line {assign.lineno} from something "
            f"other than {ALLOWED_DSN_SOURCES}",
        )
    for fn, _arg in params:
        callers = [
            c
            for c in ast.walk(tree)
            if isinstance(c, ast.Call) and _callee_name(c) == fn.name
        ]
        _require(
            callers,
            "A5",
            f"{fname}: {fn.name} takes {name!r} but is never called in the file",
        )
        for call in callers:
            for arg in call.args:
                _require(
                    isinstance(arg, ast.Name),
                    "A5",
                    f"{fname}: {fn.name} is called at line {call.lineno} with a "
                    "computed DSN",
                )


def _iter_assign_names(node: ast.Assign):
    for tgt in node.targets:
        yield from _name_targets(tgt)


def check_A5(sources: dict[str, str]) -> None:
    """DSN purity: no f-string, `+`, `%`, `.format(`, `.replace(` or literal on
    the path to make_engine or to alembic's `sqlalchemy.url`."""
    for fname, src in sources.items():
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if _callee_name(node) == "make_engine" and node.args:
                _check_dsn_name(fname, src, tree, node.args[0], "the make_engine DSN")
            if _callee_name(node) == "set_main_option" and len(node.args) == 2:
                first = node.args[0]
                if isinstance(first, ast.Constant) and first.value == "sqlalchemy.url":
                    _check_dsn_name(
                        fname, src, tree, node.args[1], "the alembic sqlalchemy.url"
                    )


def check_A6(sources: dict[str, str]) -> None:
    containers = []
    holder = {}
    for fname, src in sources.items():
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _callee_name(node) == "PostgresContainer":
                containers.append(node)
                holder[id(node)] = (fname, tree)
    _require(
        len(containers) == 1,
        "A6",
        f"exactly one PostgresContainer(...) call in the tier, found "
        f"{len(containers)}",
    )
    call = containers[0]
    fname, tree = holder[id(call)]
    _require(
        len(call.args) == 1
        and isinstance(call.args[0], ast.Constant)
        and isinstance(call.args[0].value, str),
        "A6",
        f"PostgresContainer in {fname} takes exactly one positional image literal",
    )
    _require(
        {kw.arg for kw in call.keywords} == {"dbname", "username", "password"},
        "A6",
        f"PostgresContainer keywords {sorted(str(kw.arg) for kw in call.keywords)} != "
        "{dbname, password, username}",
    )
    bound = None
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and node.value is call:
            names = list(_iter_assign_names(node))
            if len(names) == 1:
                bound = names[0].id
    _require(bound is not None, "A6", "the container must be bound to one name")
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == bound
        ):
            _require(
                node.attr == "get_connection_url",
                "A6",
                f"only get_connection_url may be invoked on the container; found "
                f"{node.attr!r} at line {node.lineno}",
            )


def check_A7a(sources: dict[str, str]) -> None:
    for fname, src in sources.items():
        for node in ast.walk(ast.parse(src)):
            if not isinstance(node, ast.Attribute):
                continue
            if node.attr in ALLOWED_ATTRIBUTES:
                continue
            if node.attr in SQL_EXECUTION_SINKS:
                _fail(
                    "A7a",
                    f"this is a SQL execution sink: {node.attr!r} in {fname} at line "
                    f"{node.lineno}",
                )
            _fail(
                "A7a",
                f"attribute {node.attr!r} in {fname} at line {node.lineno} is not in "
                "ALLOWED_ATTRIBUTES",
            )


def check_A7b(sources: dict[str, str]) -> None:
    for fname, src in sources.items():
        for node in ast.walk(ast.parse(src)):
            if not (isinstance(node, ast.Call) and _callee_name(node) == "execute"):
                continue
            _require(
                not node.keywords and 1 <= len(node.args) <= 2,
                "A7b",
                f".execute(...) in {fname} at line {node.lineno} takes one or two "
                "positional arguments and no keywords",
            )
            first = node.args[0]
            _require(
                isinstance(first, ast.Call)
                and isinstance(first.func, ast.Name)
                and first.func.id == "text"
                and len(first.args) == 1
                and not first.keywords
                and isinstance(first.args[0], ast.Constant)
                and isinstance(first.args[0].value, str),
                "A7b",
                f".execute(...) in {fname} at line {node.lineno} takes exactly "
                "text(<str literal>) as its first argument",
            )
            if len(node.args) == 2:
                _require(
                    isinstance(node.args[1], (ast.Dict, ast.Name)),
                    "A7b",
                    f".execute(...) bind parameters in {fname} at line {node.lineno} "
                    "must be a dict literal or a bare Name",
                )


def check_A7c(sources: dict[str, str]) -> None:
    for fname, src in sources.items():
        for node in ast.walk(ast.parse(src)):
            if not (isinstance(node, ast.Call) and _callee_name(node) == "text"):
                continue
            for arg in node.args:
                if not (isinstance(arg, ast.Constant) and isinstance(arg.value, str)):
                    continue
                lines = []
                for line in arg.value.splitlines():
                    if "--" in line:
                        line = line[: line.index("--")]
                    lines.append(line)
                sql = "\n".join(lines).strip()
                verb = sql.split(None, 1)[0].upper() if sql else ""
                _require(
                    verb in ALLOWED_SQL_VERBS,
                    "A7c",
                    f"SQL verb {verb!r} in {fname} at line {node.lineno} is not in "
                    f"{sorted(ALLOWED_SQL_VERBS)}",
                )


def check_A8(sources: dict[str, str]) -> None:
    """Retained backstop, over the raw file text."""
    for fname, src in sources.items():
        for pattern in A8_FORBIDDEN_PATTERNS:
            for line_no, line in enumerate(src.splitlines(), start=1):
                _require(
                    not re.search(pattern, line),
                    "A8",
                    f"forbidden pattern {pattern!r} in {fname} at line {line_no}",
                )


def check_A9(repo_root: Path) -> None:
    """The tier's ancestor import surface."""
    found = set()
    current = (repo_root / "tests" / "benchmark").parent
    while True:
        candidate = current / CONFTEST_NAME
        if candidate.is_file():
            found.add(candidate.relative_to(repo_root).as_posix())
        if current == repo_root or current.parent == current:
            break
        current = current.parent
    _require(
        found == EXPECTED_ANCESTOR_CONFTESTS,
        "A9",
        f"ancestor conftests {sorted(found)} != {sorted(EXPECTED_ANCESTOR_CONFTESTS)}",
    )
    root_conftest = repo_root / CONFTEST_NAME
    src = root_conftest.read_text(encoding="utf-8")
    got = ast.parse(src)
    got.body = _strip_docstring(list(got.body))
    pinned = ast.parse(ROOT_CONFTEST_SOURCE)
    pinned.body = _strip_docstring(list(pinned.body))
    _require(
        ast.dump(got, include_attributes=False)
        == ast.dump(pinned, include_attributes=False),
        "A9",
        "the repo-root conftest.py drifted from ROOT_CONFTEST_SOURCE",
    )
    _require((repo_root / "pytest.ini").is_file(), "A9", "pytest.ini must exist")
    for banned in FORBIDDEN_ROOT_PYTEST_CONFIG:
        _require(
            not (repo_root / banned).exists(),
            "A9",
            f"repo-root {banned} can inject pytest configuration",
        )
    keys = set()
    in_section = False
    for line in (repo_root / "pytest.ini").read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_section = stripped == "[pytest]"
            continue
        if in_section and stripped and not stripped.startswith("#") and "=" in stripped:
            keys.add(stripped.split("=", 1)[0].strip())
    _require(
        keys <= ALLOWED_PYTEST_INI_KEYS,
        "A9",
        f"pytest.ini keys {sorted(keys)} outside {sorted(ALLOWED_PYTEST_INI_KEYS)}",
    )


def check_A10(repo_root: Path) -> None:
    """The repository contributes nothing to the benchmark process's startup and
    import surface, proved from an interpreter no repository file can reach."""
    proc = _run_isolated(
        IMPORT_SURFACE_SCRIPT,
        str(repo_root),
        EXPECTED_ENV_HYGIENE_COMMAND,
        EXPECTED_B11_COMMAND,
        json.dumps(sorted(ALLOWED_BENCHMARK_IMPORTS)),
        json.dumps(list(GUARDED_JOBS)),
        json.dumps(list(BENCHMARK_WORKFLOWS)),
        json.dumps(sorted(EXPECTED_REPO_ROOT_IMPORTABLES)),
        json.dumps(sorted(EXPECTED_PACKAGE_DIRS)),
        json.dumps(sorted(EXPECTED_PACKAGING_FILES)),
    )
    _require(
        proc.returncode == 0 and proc.stdout.strip(),
        "A10",
        f"isolated import-surface child failed: rc={proc.returncode} "
        f"stderr={proc.stderr}",
    )
    errors = json.loads(proc.stdout)["errors"]
    _require(not errors, "A10", "; ".join(errors))


# --------------------------------------------------------------------------
# C1-C7 — every call site is a real production call in the declaring process's
# own code.
# --------------------------------------------------------------------------


def _site_lines(repo_root: Path, site: dict) -> list[str]:
    return (repo_root / site["file"]).read_text(encoding="utf-8").splitlines()


def _expr_hits(repo_root: Path, site: dict) -> list[int]:
    return [
        i + 1
        for i, line in enumerate(_site_lines(repo_root, site))
        if site["expr"] in line
    ]


def check_C1(site: dict, repo_root: Path) -> None:
    _require(
        (repo_root / site["file"]).is_file(),
        "C1",
        f"call_sites.file {site['file']!r} does not exist",
    )


def check_C2(site: dict) -> None:
    _require(
        site["symbol"] in site["expr"],
        "C2",
        f"symbol {site['symbol']!r} does not occur inside expr {site['expr']!r}",
    )


def check_C3(site: dict, repo_root: Path) -> None:
    lines = _site_lines(repo_root, site)
    line_no = int(site["line"])
    _require(
        1 <= line_no <= len(lines),
        "C3",
        f"{site['file']}:{line_no} is past the end of the file "
        f"({len(lines)} lines); expr occurs at {_expr_hits(repo_root, site)}",
    )
    _require(
        site["expr"] in lines[line_no - 1].strip(),
        "C3",
        f"{site['file']}:{line_no} does not contain {site['expr']!r}; expr occurs "
        f"at lines {_expr_hits(repo_root, site)}",
    )


def check_C4(site: dict, process: str, via: dict | None = None) -> None:
    rel = site["file"]
    _require(
        rel not in WRITER_DEFINITION_FILES,
        "C4",
        f"{rel} is a writer definition, not a caller — a definition can never be "
        "passed off as a call site",
    )
    root = PROCESS_SOURCE_ROOTS[process]
    if rel.startswith(root):
        return
    if (
        via is not None
        and rel.startswith(SHARED_LIB_ROOT)
        and str(via["file"]).startswith(root)
    ):
        return
    _require(
        False,
        "C4",
        f"{rel} is outside {process}'s source root {root!r} and is not shared "
        f"library code entered from it",
    )


def check_C5(site: dict, repo_root: Path) -> None:
    """The syntactic proof: a parsed call node whose callee spells `symbol` and
    lies inside the declared `expr`."""
    rel = site["file"]
    if not rel.endswith(".py"):
        return  # proved by the Go guard; C7 asserts that guard exists
    line_no = int(site["line"])
    text = (repo_root / rel).read_text(encoding="utf-8")
    lines = text.splitlines()
    line_text = lines[line_no - 1]
    encoded = line_text.encode("utf-8")
    expr = site["expr"].encode("utf-8")
    _require(
        expr in encoded,
        "C5",
        f"{rel}:{line_no} does not contain {site['expr']!r}",
    )
    start = encoded.index(expr)
    end = start + len(expr)
    tree = ast.parse(text)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or node.lineno != line_no:
            continue
        func = node.func
        name = func.id if isinstance(func, ast.Name) else (
            func.attr if isinstance(func, ast.Attribute) else None
        )
        if name != site["symbol"]:
            continue
        if func.end_col_offset is not None and start <= func.end_col_offset <= end:
            return
    _fail(
        "C5",
        f"no parsed ast.Call to {site['symbol']!r} covered by {site['expr']!r} at "
        f"{rel}:{line_no} — a comment or string literal is not a call; expr occurs "
        f"at lines {_expr_hits(repo_root, site)}",
    )


def _enclosing_qualified_name(tree: ast.AST, line_no: int) -> str | None:
    parents = _parent_map(tree)
    best = None
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.lineno <= line_no <= (node.end_lineno or node.lineno):
            if best is None or node.lineno > best.lineno:
                best = node
    if best is None:
        return None
    qualifier = None
    cur = parents.get(best)
    while cur is not None:
        if isinstance(cur, ast.ClassDef):
            qualifier = cur.name
            break
        cur = parents.get(cur)
    return f"{qualifier}.{best.name}" if qualifier else best.name


def check_C6(site: dict, repo_root: Path) -> None:
    rel = site["file"]
    if not rel.endswith(".py"):
        return
    line_no = int(site["line"])
    tree = ast.parse((repo_root / rel).read_text(encoding="utf-8"))
    enclosing = _enclosing_qualified_name(tree, line_no)
    _require(
        enclosing == site["in"],
        "C6",
        f"{rel}:{line_no} is inside {enclosing!r}, not the pinned enclosing "
        f"function {site['in']!r}",
    )


def check_C7(site: dict, repo_root: Path) -> None:
    if not str(site["file"]).endswith(".go"):
        return
    guard = repo_root / GO_GUARD
    _require(
        guard.is_file(),
        "C7",
        f"{GO_GUARD} must exist: a .go call site can only be proved by a Go parser",
    )
    _require(
        GO_GUARD_FUNC in guard.read_text(encoding="utf-8"),
        "C7",
        f"{GO_GUARD} must declare {GO_GUARD_FUNC}",
    )


def check_call_site(site: dict, process: str, repo_root: Path) -> None:
    """The five ordered manifest-side checks, then the syntactic proof."""
    check_C1(site, repo_root)
    check_C2(site)
    check_C3(site, repo_root)
    check_C4(site, process, via=site.get("via"))
    check_C5(site, repo_root)
    check_C6(site, repo_root)
    check_C7(site, repo_root)
    via = site.get("via")
    if via:
        check_C1(via, repo_root)
        check_C2(via)
        check_C3(via, repo_root)
        check_C4(via, process)
        check_C5(via, repo_root)
        check_C6(via, repo_root)
        check_C7(via, repo_root)


# --------------------------------------------------------------------------
# Reading real inputs.
# --------------------------------------------------------------------------


def tier_sources(repo_root: Path = REPO_ROOT) -> dict[str, str]:
    bench_dir = repo_root / "tests" / "benchmark"
    return {
        CONFTEST_NAME: (bench_dir / CONFTEST_NAME).read_text(encoding="utf-8"),
        BENCH_NAME: (bench_dir / BENCH_NAME).read_text(encoding="utf-8"),
    }


def _run_all_checkers(repo_root: Path) -> None:
    """Every checker, against a whole repository tree."""
    bench_dir = repo_root / "tests" / "benchmark"
    sources = tier_sources(repo_root)
    check_A1(bench_dir)
    check_A2a(sources)
    check_A2b(sources)
    check_A2c(sources)
    check_A2d(sources)
    check_A3(sources)
    check_A4(sources)
    check_A5(sources)
    check_A6(sources)
    check_A7a(sources)
    check_A7b(sources)
    check_A7c(sources)
    check_A8(sources)
    check_A9(repo_root)
    check_A10(repo_root)
    check_L0(sources[CONFTEST_NAME])
    check_L1(sources[CONFTEST_NAME])
    check_L2(sources[CONFTEST_NAME])
    check_L3(bench_dir / CONFTEST_NAME, bench_dir / "thresholds.yaml")
    check_W2(sources[BENCH_NAME])
    check_W3(sources[BENCH_NAME])
    check_W4(sources[BENCH_NAME])
    model = read_manifest_isolated(bench_dir / "thresholds.yaml")
    for wp in model["writer_processes"]:
        for site in wp["call_sites"]:
            check_call_site(site, wp["process"], repo_root)


# --------------------------------------------------------------------------
# The three positive tests.
# --------------------------------------------------------------------------


def test_b11_declares_exactly_four_writer_processes_matching_shipped_code():
    """(i) the whole object against the guard's literal; (ii) every call site is
    a real production call in the declaring process's own code."""
    model = read_manifest_isolated()
    assert model == EXPECTED_CONCURRENCY_MODEL, (
        "B11.concurrency_model differs from EXPECTED_CONCURRENCY_MODEL"
    )
    tables: set[str] = set()
    for wp in model["writer_processes"]:
        tables.update(wp["tables"])
        for site in wp["call_sites"]:
            check_call_site(site, wp["process"], REPO_ROOT)
    assert model["writers"] == len(model["writer_processes"]) == 4
    assert tables == {"audit_log", "llm_calls"}
    assert {
        wp["process"] for wp in model["writer_processes"] if "llm_calls" in wp["tables"]
    } == {"temporal-worker"}


def test_b11_harness_derives_its_width_from_the_manifest_and_widens_nothing():
    src = CONFTEST.read_text(encoding="utf-8")
    check_L0(src)
    check_L1(src)
    check_L2(src)
    check_L3(CONFTEST, THRESHOLDS)
    bench = BENCH.read_text(encoding="utf-8")
    check_W2(bench)
    check_W3(bench)
    check_W4(bench)


def test_b11_benchmark_tier_database_configuration_is_allowlisted():
    sources = tier_sources()
    check_A1(BENCH_DIR)
    check_A2a(sources)
    check_A2b(sources)
    check_A2c(sources)
    check_A2d(sources)
    check_A3(sources)
    check_A4(sources)
    check_A5(sources)
    check_A6(sources)
    check_A7a(sources)
    check_A7b(sources)
    check_A7c(sources)
    check_A8(sources)
    check_A9(REPO_ROOT)
    check_A10(REPO_ROOT)


# --------------------------------------------------------------------------
# The fourth test: the guard is proved discriminating, not merely green.
# --------------------------------------------------------------------------

CALL_SITE_FILES = sorted(
    {
        site["file"]
        for wp in EXPECTED_CONCURRENCY_MODEL["writer_processes"]
        for site in wp["call_sites"]
    }
    | {
        site["via"]["file"]
        for wp in EXPECTED_CONCURRENCY_MODEL["writer_processes"]
        for site in wp["call_sites"]
        if site.get("via")
    }
)


def _seed_repo(root: Path) -> None:
    """CLEAN_REPO_TREE: the miniature repository every fixture mutates."""
    (root / CONFTEST_NAME).write_text(ROOT_CONFTEST_SOURCE, encoding="utf-8")
    (root / "pytest.ini").write_text(
        (REPO_ROOT / "pytest.ini").read_text(encoding="utf-8"), encoding="utf-8"
    )
    bench = root / "tests" / "benchmark"
    bench.mkdir(parents=True)
    (bench / CONFTEST_NAME).write_text(CLEAN_CONFTEST, encoding="utf-8")
    (bench / BENCH_NAME).write_text(CLEAN_BENCH, encoding="utf-8")
    (bench / "thresholds.yaml").write_text(
        THRESHOLDS.read_text(encoding="utf-8"), encoding="utf-8"
    )
    for rel in sorted(EXPECTED_PACKAGING_FILES) + list(BENCHMARK_WORKFLOWS) + [
        GO_GUARD
    ] + CALL_SITE_FILES:
        dest = root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text((REPO_ROOT / rel).read_text(encoding="utf-8"), encoding="utf-8")
    mocks = root / "tests" / "mocks" / "llm"
    mocks.mkdir(parents=True, exist_ok=True)
    (mocks / "mock_llm_server.py").write_text("#\n", encoding="utf-8")


def _seeded(mutate: Callable[[Path], None], run: Callable[[Path], None]):
    """Seed CLEAN_REPO_TREE, apply one minimal mutation, run a real checker."""

    def thunk() -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _seed_repo(root)
            mutate(root)
            run(root)

    return thunk


def _write(root: Path, rel: str, text: str) -> None:
    (root / rel).write_text(text, encoding="utf-8")


def _replace(root: Path, rel: str, old: str, new: str, count: int = -1) -> None:
    path = root / rel
    src = path.read_text(encoding="utf-8")
    assert old in src, f"fixture precondition: {old!r} not found in {rel}"
    path.write_text(src.replace(old, new, count) if count > 0 else src.replace(old, new),
                    encoding="utf-8")


TIER_CONFTEST = f"tests/benchmark/{CONFTEST_NAME}"
TIER_BENCH = f"tests/benchmark/{BENCH_NAME}"

RETURN_LINE = 'return by_id["B11"]["concurrency_model"]["writer_processes"]'


def _loader_src(root: Path) -> str:
    return (root / TIER_CONFTEST).read_text(encoding="utf-8")


def _bench_src(root: Path) -> str:
    return (root / TIER_BENCH).read_text(encoding="utf-8")


def _bypass_writes_in_uninvoked_lambdas(root: Path) -> None:
    """Round-6 review bypass 1 (C1): both production writers wrapped in
    uninvoked lambdas while ``rows += 1`` is retained — the AST still names
    the writers, but nothing is written."""
    _replace(
        root,
        TIER_BENCH,
        "                    store.insert_llm_call(\n"
        "                        LLMCallRecord(\n",
        "                    (lambda: store.insert_llm_call(\n"
        "                        LLMCallRecord(\n",
    )
    # Close the lambda after the insert_llm_call call's closing paren.  The
    # clean baseline ends that call with ``)\n`` at the same indent as the
    # ``store.insert_llm_call(`` line; wrap that terminator.
    _replace(
        root,
        TIER_BENCH,
        "                        )\n"
        "                    )\n"
        "                else:\n"
        "                    write_audit(\n",
        "                        )\n"
        "                    ))\n"
        "                else:\n"
        "                    (lambda: write_audit(\n",
    )
    _replace(
        root,
        TIER_BENCH,
        "                        detail={\"i\": i, \"writer\": process},\n"
        "                    )\n"
        "                    session.commit()\n",
        "                        detail={\"i\": i, \"writer\": process},\n"
        "                    ))\n"
        "                    (lambda: session.commit())\n",
    )


def _bypass_pool_rebound_to_fake(root: Path) -> None:
    """Round-6 review bypass 2 (C1): real executor constructed, then ``pool``
    rebound to a fake whose ``map`` returns 800 without invoking the writer."""
    _replace(
        root,
        TIER_BENCH,
        "    pool = ThreadPoolExecutor(max_workers=len(writers))\n",
        "    pool = ThreadPoolExecutor(max_workers=len(writers))\n"
        "    class _FakePool:\n"
        "        def map(self, fn, indexes):\n"
        "            return [800 for _ in indexes]\n"
        "    pool = _FakePool()\n",
    )


def _bypass_session_commit_not_called(root: Path) -> None:
    """Round-6 review bypass 3 (C1): ``session.commit()`` replaced by the bare
    attribute so counted audit writes roll back."""
    _replace(
        root,
        TIER_BENCH,
        "                    session.commit()\n",
        "                    session.commit\n",
    )


def _bypass_writes_in_nested_def(root: Path) -> None:
    """Adversarial C1 variation: production writers live only inside a nested
    ``def`` that the loop never calls — same deferred-scope class as the lambda
    case, different AST node."""
    _replace(
        root,
        TIER_BENCH,
        "            for i in range(n_iters):\n"
        "                if process == \"temporal-worker\" and i % 2 == 1:\n"
        "                    store.insert_llm_call(\n",
        "            def _deferred_writes(i):\n"
        "                if process == \"temporal-worker\" and i % 2 == 1:\n"
        "                    store.insert_llm_call(\n",
    )
    # Drop the counter increment's enclosing loop body down to a bare +1 so
    # the deferred def is the only place the writers appear.
    _replace(
        root,
        TIER_BENCH,
        "                    session.commit()\n"
        "                rows += 1\n",
        "                    session.commit()\n"
        "            for i in range(n_iters):\n"
        "                rows += 1\n",
    )


def _bypass_commit_only_in_uninvoked_lambda(root: Path) -> None:
    """Adversarial C1 variation: write_audit is live but commit is only named
    inside an uninvoked lambda — inventory would see a Call if it walked
    deferred scopes."""
    _replace(
        root,
        TIER_BENCH,
        "                    session.commit()\n",
        "                    (lambda: session.commit())\n",
    )


def _bypass_writes_under_boolop_and(root: Path) -> None:
    """Round-7 review C1: ``False and writer(...)`` short-circuits — the AST
    still names both production writers while nothing is written."""
    _replace(
        root,
        TIER_BENCH,
        "                    store.insert_llm_call(\n",
        "                    False and store.insert_llm_call(\n",
    )
    _replace(
        root,
        TIER_BENCH,
        "                    write_audit(\n",
        "                    False and write_audit(\n",
    )


def _bypass_writes_under_ifexp(root: Path) -> None:
    """Round-7 review C1: both writers as ``writer(...) if False else None``."""
    _replace(
        root,
        TIER_BENCH,
        "                    store.insert_llm_call(\n"
        "                        LLMCallRecord(\n",
        "                    (store.insert_llm_call(\n"
        "                        LLMCallRecord(\n",
    )
    _replace(
        root,
        TIER_BENCH,
        "                        )\n"
        "                    )\n"
        "                else:\n"
        "                    write_audit(\n",
        "                        )\n"
        "                    ) if False else None)\n"
        "                else:\n"
        "                    (write_audit(\n",
    )
    _replace(
        root,
        TIER_BENCH,
        "                        detail={\"i\": i, \"writer\": process},\n"
        "                    )\n"
        "                    session.commit()\n",
        "                        detail={\"i\": i, \"writer\": process},\n"
        "                    ) if False else None)\n"
        "                    session.commit()\n",
    )


def _bypass_commit_under_boolop_and(root: Path) -> None:
    """Round-7 review C1: ``False and session.commit()`` — write_audit runs
    but the commit never executes, so counted audit rows roll back."""
    _replace(
        root,
        TIER_BENCH,
        "                    session.commit()\n",
        "                    False and session.commit()\n",
    )


def _positive_write_as_boolop_first_operand(root: Path) -> None:
    """D1 positive control: a write as ``BoolOp.values[0]`` is always evaluated.

    ``write_audit(...) or True`` names the production call under a BoolOp but
    the first operand is unconditional — the guard must still count it live.
    """
    _replace(
        root,
        TIER_BENCH,
        "                        detail={\"i\": i, \"writer\": process},\n"
        "                    )\n"
        "                    session.commit()\n",
        "                        detail={\"i\": i, \"writer\": process},\n"
        "                    ) or True\n"
        "                    session.commit()\n",
    )


def _positive_write_as_ifexp_test(root: Path) -> None:
    """D1 positive control: a write as ``IfExp.test`` is always evaluated.

    ``session if write_audit(...) else session`` places the production call in
    the ternary's test slot — the guard must still count it live.
    """
    _replace(
        root,
        TIER_BENCH,
        "                    write_audit(\n"
        "                        session,\n"
        "                        action=\"event_received\",\n"
        "                        actor=actor_system(),\n"
        "                        detail={\"i\": i, \"writer\": process},\n"
        "                    )\n"
        "                    session.commit()\n",
        "                    session if write_audit(\n"
        "                        session,\n"
        "                        action=\"event_received\",\n"
        "                        actor=actor_system(),\n"
        "                        detail={\"i\": i, \"writer\": process},\n"
        "                    ) else session\n"
        "                    session.commit()\n",
    )


def _bypass_writes_under_chained_compare(root: Path) -> None:
    """Round-8 review C1: ``False == True == writer(...)`` short-circuits later
    comparators — the AST still names both production writers while nothing
    is written.
    """
    _replace(
        root,
        TIER_BENCH,
        "                    store.insert_llm_call(\n",
        "                    False == True == store.insert_llm_call(\n",
    )
    _replace(
        root,
        TIER_BENCH,
        "                    write_audit(\n",
        "                    False == True == write_audit(\n",
    )


def _bypass_writes_under_annassign_annotation(root: Path) -> None:
    """Round-8 review C1: value-less local annotations are not evaluated.

    ``_never: write_audit(...)`` names the production call in
    ``AnnAssign.annotation`` without executing it.
    """
    _replace(
        root,
        TIER_BENCH,
        "                    store.insert_llm_call(\n",
        "                    _never_llm: store.insert_llm_call(\n",
    )
    _replace(
        root,
        TIER_BENCH,
        "                    write_audit(\n",
        "                    _never_audit: write_audit(\n",
    )


def _bypass_commit_under_chained_compare(root: Path) -> None:
    """Round-8 review C1: ``False == True == session.commit()`` — write_audit
    runs but the commit never executes, so counted audit rows roll back.
    """
    _replace(
        root,
        TIER_BENCH,
        "                    session.commit()\n",
        "                    False == True == session.commit()\n",
    )


def _bypass_commit_under_annassign_annotation(root: Path) -> None:
    """Round-8 review C1: ``_never: session.commit()`` — annotation not run."""
    _replace(
        root,
        TIER_BENCH,
        "                    session.commit()\n",
        "                    _never_commit: session.commit()\n",
    )


def _positive_write_as_compare_left(root: Path) -> None:
    """D1 positive control: a write as ``Compare.left`` is always evaluated."""
    _replace(
        root,
        TIER_BENCH,
        "                        detail={\"i\": i, \"writer\": process},\n"
        "                    )\n"
        "                    session.commit()\n",
        "                        detail={\"i\": i, \"writer\": process},\n"
        "                    ) == True\n"
        "                    session.commit()\n",
    )


def _positive_write_as_compare_first_comparator(root: Path) -> None:
    """D1 positive control: a write as ``Compare.comparators[0]`` is live."""
    _replace(
        root,
        TIER_BENCH,
        "                    write_audit(\n"
        "                        session,\n"
        "                        action=\"event_received\",\n"
        "                        actor=actor_system(),\n"
        "                        detail={\"i\": i, \"writer\": process},\n"
        "                    )\n"
        "                    session.commit()\n",
        "                    True == write_audit(\n"
        "                        session,\n"
        "                        action=\"event_received\",\n"
        "                        actor=actor_system(),\n"
        "                        detail={\"i\": i, \"writer\": process},\n"
        "                    )\n"
        "                    session.commit()\n",
    )


def _positive_write_as_annassign_value(root: Path) -> None:
    """D1 positive control: a write as ``AnnAssign.value`` is always evaluated."""
    _replace(
        root,
        TIER_BENCH,
        "                    write_audit(\n"
        "                        session,\n"
        "                        action=\"event_received\",\n"
        "                        actor=actor_system(),\n"
        "                        detail={\"i\": i, \"writer\": process},\n"
        "                    )\n"
        "                    session.commit()\n",
        "                    _committed: int = write_audit(\n"
        "                        session,\n"
        "                        action=\"event_received\",\n"
        "                        actor=actor_system(),\n"
        "                        detail={\"i\": i, \"writer\": process},\n"
        "                    )\n"
        "                    session.commit()\n",
    )


def _fixtures() -> list[tuple[str, str, Callable[[], None]]]:
    cases: list[tuple[str, str, Callable[[], None]]] = []

    def add(case_id: str, rule_id: str, thunk: Callable[[], None]) -> None:
        cases.append((case_id, rule_id, thunk))

    def loader_mutation(old: str, new: str, checker: str = "L1", count: int = -1):
        runners = {
            "L0": lambda root: check_L0(_loader_src(root)),
            "L1": lambda root: check_L1(_loader_src(root)),
            "L2": lambda root: check_L2(_loader_src(root)),
            "L3": lambda root: check_L3(
                root / TIER_CONFTEST, root / "tests" / "benchmark" / "thresholds.yaml"
            ),
        }
        return _seeded(
            lambda root: _replace(root, TIER_CONFTEST, old, new, count),
            runners[checker],
        )

    # ---- loader ----------------------------------------------------------
    add(
        "loader_import_alias_rebound",
        "L0",
        _seeded(
            lambda root: _write(
                root,
                TIER_CONFTEST,
                "class yaml:\n"
                "    @staticmethod\n"
                "    def safe_load(text):\n"
                "        return {}\n\n\n" + _loader_src(root),
            ),
            lambda root: check_L0(_loader_src(root)),
        ),
    )
    add(
        "loader_env_conditioned_doubling",
        "L1",
        loader_mutation(
            RETURN_LINE,
            'return by_id["B11"]["concurrency_model"]["writer_processes"] '
            'if "pytest" not in globals() else '
            'by_id["B11"]["concurrency_model"]["writer_processes"] * 2',
        ),
    )
    add(
        "loader_import_sniff",
        "L1",
        loader_mutation(
            RETURN_LINE,
            'return __import__("sys").modules and by_id["B11"]'
            '["concurrency_model"]["writer_processes"]',
        ),
    )
    add(
        "loader_stack_inspection",
        "L1",
        loader_mutation(
            RETURN_LINE,
            'return inspect.stack() and by_id["B11"]["concurrency_model"]'
            '["writer_processes"]',
        ),
    )
    add(
        "loader_list_subclass_spoof",
        "L1",
        loader_mutation(
            "def load_b11_writer_model():",
            "def load_b11_writer_model():\n"
            "    class _L(list):\n"
            "        def __eq__(self, other):\n"
            "            return True\n",
        ),
    )
    add(
        "loader_doubling",
        "L1",
        loader_mutation(RETURN_LINE, RETURN_LINE + " * 2"),
    )
    add(
        "loader_slice_and_reorder",
        "L1",
        loader_mutation(RETURN_LINE, RETURN_LINE + "[:]"),
    )
    add(
        "loader_reads_other_path",
        "L1",
        loader_mutation(
            'Path(__file__).with_name("thresholds.yaml")',
            'Path(REPO_ROOT) / "thresholds.yaml"',
        ),
    )
    add(
        "loader_reformatted_but_pinned_form_kept",
        "L2",
        _seeded(
            lambda root: _replace(
                root,
                TIER_CONFTEST,
                RETURN_LINE,
                'return by_id["B11"]["concurrency_model"]["writer_process"]',
            ),
            lambda root: check_L2(_loader_src(root)),
        ),
    )
    add(
        "manifest_writer_processes_doubled",
        "L3",
        _seeded(
            lambda root: _replace(
                root,
                "tests/benchmark/thresholds.yaml",
                "    writers: 4\n",
                "    writers: 8\n",
            ),
            lambda root: check_L3(
                root / TIER_CONFTEST, root / "tests" / "benchmark" / "thresholds.yaml"
            ),
        ),
    )

    # ---- width -----------------------------------------------------------
    def bench_case(old: str, new: str, checker, count: int = -1):
        return _seeded(
            lambda root: _replace(root, TIER_BENCH, old, new, count), checker
        )

    add(
        "width_arithmetic",
        "W2",
        bench_case(
            "max_workers=len(writers)",
            "max_workers=len(writers) * 2",
            lambda root: check_W2(_bench_src(root)),
        ),
    )
    add(
        "width_rebind",
        "W2",
        bench_case(
            "writers = load_b11_writer_model()",
            "writers = load_b11_writer_model()\n    writers = writers * 2",
            lambda root: check_W2(_bench_src(root)),
        ),
    )
    add(
        "width_zero_executors_serialized_writers",
        "W2",
        bench_case(
            "    pool = ThreadPoolExecutor(max_workers=len(writers))",
            "    pool = None",
            lambda root: check_W2(_bench_src(root)),
        ),
    )
    add(
        "width_shared_engine_for_every_writer",
        "W2",
        bench_case(
            "    for _ in writers:\n        eng = make_engine(dsn)",
            "    eng = make_engine(dsn)\n    for _ in writers:",
            lambda root: check_W2(_bench_src(root)),
        ),
    )
    # Code review round 5, C1: an executor that exists but drives nothing, and
    # an elapsed time that is post-processed before the division.  Both passed
    # the round-4 W2, which only proved the executor was *constructed*.
    add(
        "width_serial_substitution_for_the_map_call",
        "W2",
        bench_case(
            "        committed = list(pool.map(_run_writer, range(len(writers))))",
            "        committed = [_run_writer(i) for i in range(len(writers))]",
            lambda root: check_W2(_bench_src(root)),
        ),
    )
    add(
        "width_elapsed_time_divided_by_the_writer_count",
        "W2",
        bench_case(
            "        elapsed = time.perf_counter() - t0",
            "        elapsed = (time.perf_counter() - t0) / len(writers)",
            lambda root: check_W2(_bench_src(root)),
        ),
    )
    add(
        "width_executor_results_left_lazy",
        "W2",
        bench_case(
            "        committed = list(pool.map(_run_writer, range(len(writers))))",
            "        committed = pool.map(_run_writer, range(len(writers)))",
            lambda root: check_W2(_bench_src(root)),
        ),
    )
    add(
        "width_writer_index_set_shrunk",
        "W2",
        bench_case(
            "pool.map(_run_writer, range(len(writers)))",
            "pool.map(_run_writer, range(1))",
            lambda root: check_W2(_bench_src(root)),
        ),
    )
    add(
        "width_rate_scaled_after_the_division",
        "W2",
        bench_case(
            "    rate = total_rows / elapsed if elapsed > 0 else 0.0",
            "    rate = total_rows / elapsed * 4 if elapsed > 0 else 0.0",
            lambda root: check_W2(_bench_src(root)),
        ),
    )
    add(
        "width_row_count_multiplied_on_return",
        "W2",
        bench_case(
            "        return rows\n",
            "        return rows * 4\n",
            lambda root: check_W2(_bench_src(root)),
        ),
    )
    add(
        "width_counter_incremented_without_writing",
        "W2",
        bench_case(
            "                    write_audit(\n",
            "                    _noop(\n",
            lambda root: check_W2(_bench_src(root)),
        ),
    )
    add(
        "width_one_write_branch_removed",
        "W2",
        bench_case(
            "                    store.insert_llm_call(",
            "                    _skip(",
            lambda root: check_W2(_bench_src(root)),
        ),
    )
    add(
        "width_most_iterations_skip_the_write",
        "W2",
        bench_case(
            '                if process == "temporal-worker" and i % 2 == 1:',
            "                if i % 100 != 0:\n"
            "                    pass\n"
            '                elif process == "temporal-worker" and i % 2 == 1:',
            lambda root: check_W2(_bench_src(root)),
        ),
    )
    add(
        "width_counter_incremented_before_the_write",
        "W2",
        bench_case(
            "            for i in range(n_iters):\n",
            "            for i in range(n_iters):\n                rows += 1\n",
            lambda root: check_W2(_bench_src(root)),
        ),
    )
    # Code review round 6, C1: three previously-unlisted mutations that passed
    # the round-5 guard — deferred scopes, pool rebind, and a non-call commit.
    add(
        "width_writes_wrapped_in_uninvoked_lambdas",
        "W2",
        _seeded(_bypass_writes_in_uninvoked_lambdas, lambda root: check_W2(_bench_src(root))),
    )
    add(
        "width_pool_rebound_to_fake_map",
        "W2",
        _seeded(_bypass_pool_rebound_to_fake, lambda root: check_W2(_bench_src(root))),
    )
    add(
        "width_session_commit_not_called",
        "W2",
        _seeded(_bypass_session_commit_not_called, lambda root: check_W2(_bench_src(root))),
    )
    add(
        "width_writes_in_nested_def",
        "W2",
        _seeded(_bypass_writes_in_nested_def, lambda root: check_W2(_bench_src(root))),
    )
    add(
        "width_commit_only_in_uninvoked_lambda",
        "W2",
        _seeded(
            _bypass_commit_only_in_uninvoked_lambda,
            lambda root: check_W2(_bench_src(root)),
        ),
    )
    # Code review round 7, C1: expression-level short-circuit / ternary that
    # names production writers without executing them.
    add(
        "width_writes_under_boolop_and",
        "W2",
        _seeded(_bypass_writes_under_boolop_and, lambda root: check_W2(_bench_src(root))),
    )
    add(
        "width_writes_under_ifexp",
        "W2",
        _seeded(_bypass_writes_under_ifexp, lambda root: check_W2(_bench_src(root))),
    )
    add(
        "width_commit_under_boolop_and",
        "W2",
        _seeded(
            _bypass_commit_under_boolop_and, lambda root: check_W2(_bench_src(root))
        ),
    )
    # Code review round 8, C1: chained Compare short-circuit and AnnAssign
    # annotation slots that name production writers without executing them.
    add(
        "width_writes_under_chained_compare",
        "W2",
        _seeded(
            _bypass_writes_under_chained_compare,
            lambda root: check_W2(_bench_src(root)),
        ),
    )
    add(
        "width_writes_under_annassign_annotation",
        "W2",
        _seeded(
            _bypass_writes_under_annassign_annotation,
            lambda root: check_W2(_bench_src(root)),
        ),
    )
    add(
        "width_commit_under_chained_compare",
        "W2",
        _seeded(
            _bypass_commit_under_chained_compare,
            lambda root: check_W2(_bench_src(root)),
        ),
    )
    add(
        "width_commit_under_annassign_annotation",
        "W2",
        _seeded(
            _bypass_commit_under_annassign_annotation,
            lambda root: check_W2(_bench_src(root)),
        ),
    )
    add(
        "caller_less_batch_symbol",
        "W3",
        bench_case(
            "store.insert_llm_call(",
            "store.insert_llm_calls_batch(",
            lambda root: check_W3(_bench_src(root)),
        ),
    )
    add(
        "diagnostic_prefix_dropped",
        "W4",
        bench_case(
            "B11 single_writer_rate=",
            "B11 sw_rate=",
            lambda root: check_W4(_bench_src(root)),
        ),
    )

    # ---- reflection and sinks -------------------------------------------
    def tier_case(rel: str, old: str, new: str, checker, count: int = -1):
        return _seeded(lambda root: _replace(root, rel, old, new, count), checker)

    def append_case(rel: str, extra: str, checker):
        def mutate(root: Path) -> None:
            path = root / rel
            path.write_text(path.read_text(encoding="utf-8") + extra, encoding="utf-8")

        return _seeded(mutate, checker)

    a2d = lambda root: check_A2d(tier_sources(root))  # noqa: E731
    a3 = lambda root: check_A3(tier_sources(root))  # noqa: E731
    a7a = lambda root: check_A7a(tier_sources(root))  # noqa: E731

    add(
        "reflective_exec_driver_sql",
        "A2d",
        tier_case(
            TIER_BENCH,
            'conn.execute(text("SELECT 1"))',
            'getattr(conn, "exec_driver_sql")("SET synchronous_commit TO off")',
            a2d,
        ),
    )
    add(
        "dunder_dict_lookup",
        "A3",
        tier_case(
            TIER_BENCH,
            'conn.execute(text("SELECT 1"))',
            'conn.__dict__["exec_driver_sql"]("SET synchronous_commit TO off")',
            a3,
        ),
    )
    add(
        "monkeypatch_allowlisted_import",
        "A3",
        append_case(TIER_CONFTEST, "\nyaml.safe_load = _double\n", a3),
    )
    add(
        "kwargs_unpacking_engine",
        "A3",
        tier_case(
            TIER_BENCH,
            "make_engine(dsn)",
            'make_engine(dsn, **{"pool_size": 16})',
            a3,
        ),
    )
    add(
        "nested_session_connection",
        "A7a",
        tier_case(
            TIER_BENCH,
            'conn.execute(text("SELECT 1"))',
            'session.connection().exec_driver_sql(text("SET synchronous_commit TO off"))',
            a7a,
        ),
    )
    add(
        "raw_cursor_execute",
        "A7a",
        tier_case(
            TIER_BENCH,
            'conn.execute(text("SELECT 1"))',
            'eng.raw_connection().cursor().execute("SET synchronous_commit TO off")',
            a7a,
        ),
    )
    add(
        "execution_options",
        "A7a",
        tier_case(
            TIER_BENCH,
            'conn.execute(text("SELECT 1"))',
            'eng.execution_options(isolation_level="AUTOCOMMIT")',
            a7a,
        ),
    )
    add(
        "unenumerated_sql_method_flush",
        "A7a",
        tier_case(TIER_BENCH, "session.commit()", "session.flush()", a7a, count=1),
    )

    # ---- tier configuration ---------------------------------------------
    add(
        "extra_tier_file",
        "A1",
        _seeded(
            lambda root: _write(root, "tests/benchmark/postgresql.conf", "fsync=off\n"),
            lambda root: check_A1(root / "tests" / "benchmark"),
        ),
    )
    def dead_bound_getattr(root: Path) -> None:
        """Design-review round 5: a dead module-scope binding bought pass 4's
        `bound anywhere in the file` exemption for the builtin it shadows."""
        _replace(
            root,
            TIER_CONFTEST,
            '            conn.execute(text("ANALYZE alert_events"))',
            '            getattr(conn, "exec_driver_sql")'
            '("SET synchronous_commit TO off")',
        )
        _write(
            root,
            TIER_CONFTEST,
            "if False:\n    getattr = None\n" + _loader_src(root),
        )

    add("dead_bound_getattr", "A2d", _seeded(dead_bound_getattr, a2d))
    add(
        "module_binding_inventory_drift",
        "A2b",
        append_case(
            TIER_CONFTEST,
            "\n_WIDEN = 16\n",
            lambda root: check_A2b(tier_sources(root)),
        ),
    )
    # Code review round 5, C1: the inventory recursed into these statements'
    # bodies but never recorded the names the statements themselves bind, so a
    # module-scope `for guard_hole in []: pass` was invisible to A2b.
    for case_id, statement in (
        ("module_scope_for_target_binding", "\nfor guard_hole in []:\n    pass\n"),
        (
            "module_scope_with_as_binding",
            "\nwith open(__file__) as guard_hole:\n    pass\n",
        ),
        (
            "module_scope_except_as_binding",
            "\ntry:\n    pass\nexcept OSError as guard_hole:\n    pass\n",
        ),
        (
            "module_scope_match_capture_binding",
            "\nmatch []:\n    case [guard_hole]:\n        pass\n",
        ),
        ("module_scope_walrus_binding", "\nif (guard_hole := 1):\n    pass\n"),
    ):
        add(
            case_id,
            "A2b",
            append_case(
                TIER_CONFTEST,
                statement,
                lambda root: check_A2b(tier_sources(root)),
            ),
        )
    add(
        "reserved_name_bound_in_nested_scope",
        "A2c",
        tier_case(
            TIER_CONFTEST,
            "        months = _months_back(12)",
            "        for yaml in []:\n            pass\n"
            "        months = _months_back(12)",
            lambda root: check_A2c(tier_sources(root)),
        ),
    )
    add(
        "ancestor_conftest_monkeypatch",
        "A9",
        _seeded(
            lambda root: _write(
                root,
                CONFTEST_NAME,
                ROOT_CONFTEST_SOURCE + "\nimport yaml\nyaml.safe_load = _double\n",
            ),
            lambda root: check_A9(root),
        ),
    )
    add(
        "unlisted_import",
        "A2a",
        append_case(
            TIER_CONFTEST, "\nimport psycopg\n", lambda root: check_A2a(tier_sources(root))
        ),
    )
    add(
        "pool_widening_keyword",
        "A4",
        tier_case(
            TIER_BENCH,
            "make_engine(dsn)",
            "make_engine(dsn, pool_size=16, max_overflow=16)",
            lambda root: check_A4(tier_sources(root)),
        ),
    )
    add(
        "dsn_embedded_server_option",
        "A5",
        tier_case(
            TIER_BENCH,
            "make_engine(dsn)",
            'make_engine(dsn + "?options=-c%20synchronous_commit%3Doff")',
            lambda root: check_A5(tier_sources(root)),
        ),
    )
    add(
        "fsync_via_container_command",
        "A7a",
        tier_case(
            TIER_CONFTEST,
            "    with pg:",
            '    pg.with_command("-c fsync=off")\n    with pg:',
            a7a,
        ),
    )
    add(
        "set_via_text_to_off",
        "A7c",
        tier_case(
            TIER_BENCH,
            'text("SELECT 1")',
            'text("SET synchronous_commit TO off")',
            lambda root: check_A7c(tier_sources(root)),
        ),
    )
    add(
        "durability_backstop_pattern",
        "A8",
        append_case(
            TIER_CONFTEST,
            "\n# widened: pool_size = 16\n",
            lambda root: check_A8(tier_sources(root)),
        ),
    )
    add(
        "container_extra_method",
        "A6",
        tier_case(
            TIER_CONFTEST,
            "        password=\"dbagent\",\n    )",
            "        password=\"dbagent\",\n        driver=None,\n    )",
            lambda root: check_A6(tier_sources(root)),
        ),
    )
    add(
        "execute_non_literal_statement",
        "A7b",
        tier_case(
            TIER_BENCH,
            'conn.execute(text("SELECT 1"))',
            "conn.execute(text(dsn))",
            lambda root: check_A7b(tier_sources(root)),
        ),
    )

    # ---- process startup and import surface ------------------------------
    a10 = lambda root: check_A10(root)  # noqa: E731

    add(
        "repo_sitecustomize_monkeypatch",
        "A10",
        _seeded(
            lambda root: _write(
                root,
                "sitecustomize.py",
                "import yaml\n_real = yaml.safe_load\n"
                "def safe_load(text):\n"
                "    data = _real(text)\n"
                "    return data\n"
                "yaml.safe_load = safe_load\n",
            ),
            a10,
        ),
    )
    add(
        "repo_root_yaml_shadow",
        "A10",
        _seeded(
            lambda root: _write(root, "yaml.py", "def safe_load(text):\n    return {}\n"),
            a10,
        ),
    )

    def nested_shadow(root: Path) -> None:
        _write(root, "tests/mocks/llm/json.py", "def loads(s):\n    return {}\n")

    add("nested_import_root_shadow", "A10", _seeded(nested_shadow, a10))

    def pytest11(root: Path) -> None:
        path = root / "services" / "worker" / "pyproject.toml"
        path.write_text(
            path.read_text(encoding="utf-8")
            + '\n[project.entry-points.pytest11]\nrca_bench = "worker.bench_hook"\n',
            encoding="utf-8",
        )

    add("pytest11_entry_point_plugin", "A10", _seeded(pytest11, a10))
    add(
        "ci_injects_pytest_plugin",
        "A10",
        _seeded(
            lambda root: _replace(
                root,
                ".github/workflows/ci.yml",
                "tests/benchmark/test_pg_scale.py -v -s",
                "tests/benchmark/test_pg_scale.py -v -s -p rca_bench",
            ),
            a10,
        ),
    )
    add(
        "ci_env_injects_pythonpath",
        "A10",
        _seeded(
            lambda root: _replace(
                root,
                ".github/workflows/ci.yml",
                "  benchmark:\n    name:",
                "  benchmark:\n    env:\n      PYTHONPATH: .\n    name:",
            ),
            a10,
        ),
    )

    def sourceless(root: Path) -> None:
        pkg = root / "yaml"
        pkg.mkdir()
        src = pkg / "__init__.py"
        src.write_text("def safe_load(text):\n    return {}\n", encoding="utf-8")
        py_compile.compile(str(src), cfile=str(pkg / "__init__.pyc"), doraise=True)
        src.unlink()

    add("repo_root_sourceless_yaml_package", "A10", _seeded(sourceless, a10))

    def github_env(root: Path) -> None:
        _replace(
            root,
            ".github/workflows/ci.yml",
            "      - name: FP-M6-31 A10(v) environment hygiene before B2/B10/B11",
            "      - name: seed the hook\n"
            '        run: echo "PYTHONPATH=/tmp/b11-hook" >> "$GITHUB_ENV"\n'
            "      - name: FP-M6-31 A10(v) environment hygiene before B2/B10/B11",
        )

    add("ci_persists_pythonpath_via_github_env", "A10", _seeded(github_env, a10))

    def gut_hygiene(root: Path) -> None:
        """Round-8: both hygiene commands replaced by a no-op, names kept."""
        path = root / ".github" / "workflows" / "ci.yml"
        text = path.read_text(encoding="utf-8")
        text = text.replace(EXPECTED_ENV_HYGIENE_COMMAND, "true")
        assert "ENVIRON" not in text, "fixture precondition: gate not gutted"
        path.write_text(text, encoding="utf-8")

    add("ci_hygiene_gate_gutted_to_a_noop", "A10", _seeded(gut_hygiene, a10))

    # ---- call sites ------------------------------------------------------
    ingest_site = EXPECTED_CONCURRENCY_MODEL["writer_processes"][0]["call_sites"][0]
    worker_site = EXPECTED_CONCURRENCY_MODEL["writer_processes"][3]["call_sites"][1]
    go_site = EXPECTED_CONCURRENCY_MODEL["writer_processes"][2]["call_sites"][0]

    add(
        "call_site_file_missing",
        "C1",
        _seeded(
            lambda root: (root / ingest_site["file"]).unlink(),
            lambda root: check_C1(ingest_site, root),
        ),
    )
    add(
        "call_site_symbol_outside_expr",
        "C2",
        _seeded(
            lambda root: None,
            lambda root: check_C2({**ingest_site, "expr": "session.commit("}),
        ),
    )
    add(
        "call_site_line_drift",
        "C3",
        _seeded(
            lambda root: _replace(
                root,
                ingest_site["file"],
                "class IngestService",
                "# drift\nclass IngestService",
                1,
            ),
            lambda root: check_C3(ingest_site, root),
        ),
    )
    add(
        "call_site_is_definition",
        "C4",
        _seeded(
            lambda root: None,
            lambda root: check_C4(
                {
                    **worker_site,
                    "file": "libs/py/rca_common/rca_common/llmclient/tracestore.py",
                },
                "temporal-worker",
                via=worker_site["via"],
            ),
        ),
    )
    add(
        "call_site_outside_process_root",
        "C4",
        _seeded(
            lambda root: None,
            lambda root: check_C4(
                {**ingest_site, "file": "services/worker/worker/activities/investigation.py"},
                "ingest-gateway",
            ),
        ),
    )

    def _replace_statement(root: Path, site: dict, first_line: str) -> None:
        """Replace the whole statement anchored at `site["line"]` with
        `first_line`, keeping the file parseable and the line numbering
        stable."""
        path = root / site["file"]
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines(keepends=True)
        start = int(site["line"])
        stmts = [
            n
            for n in ast.walk(ast.parse(text))
            if isinstance(n, ast.stmt) and n.lineno == start
        ]
        assert stmts, "fixture precondition: no statement at the pinned line"
        end = max(n.end_lineno or start for n in stmts)
        indent = " " * (len(lines[start - 1]) - len(lines[start - 1].lstrip()))
        block = [f"{indent}{first_line}\n"] + [f"{indent}# pad\n"] * (end - start)
        lines[start - 1 : end] = block
        path.write_text("".join(lines), encoding="utf-8")

    def comment_out_call(root: Path) -> None:
        _replace_statement(root, ingest_site, "# write_audit(")

    add(
        "call_site_in_comment",
        "C5",
        _seeded(comment_out_call, lambda root: check_C5(ingest_site, root)),
    )

    def string_anchor_wrong_scope(root: Path) -> None:
        """Round-8: `expr` present on `line` as a plain string while the real
        parsed call is gone from the pinned scope."""
        _replace_statement(root, ingest_site, '_anchor = "write_audit("')

    add(
        "call_site_string_anchor_wrong_scope",
        "C5",
        _seeded(string_anchor_wrong_scope, lambda root: check_C5(ingest_site, root)),
    )
    add(
        "call_site_enclosing_function_drift",
        "C6",
        _seeded(
            lambda root: None,
            lambda root: check_C6({**ingest_site, "in": "IngestService.not_ingest"}, root),
        ),
    )
    add(
        "go_guard_deleted",
        "C7",
        _seeded(
            lambda root: (root / GO_GUARD).unlink(),
            lambda root: check_C7(go_site, root),
        ),
    )

    return cases


BYPASS_FIXTURES = _fixtures()


def test_b11_guard_baselines_pass_every_checker():
    """Meta-assertion: no fixture can be vacuously red, and a rule that would
    reject honest shipped code fails here rather than in CI."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        _seed_repo(root)
        _run_all_checkers(root)


@pytest.mark.parametrize(
    "case_id,rule_id,thunk",
    BYPASS_FIXTURES,
    ids=[c[0] for c in BYPASS_FIXTURES],
)
def test_b11_guard_rejects_known_bypasses(case_id, rule_id, thunk):
    """Every bypass any review round proposed fails at its named rule ID."""
    with pytest.raises(AssertionError) as excinfo:
        thunk()
    message = str(excinfo.value)
    token = message.split(":", 1)[0]
    assert token == rule_id, (
        f"{case_id}: expected rule {rule_id!r}, got token {token!r} from {message!r}"
    )


def _bypass_yaml_rebinding(root: Path) -> None:
    """Round-4 review bypass 1: a module-scope `class yaml:` whose `safe_load`
    doubles `writer_processes`, above a byte-identical copy of the pinned
    loader — eight writers under ordinary pytest collection."""
    tier = root / TIER_CONFTEST
    doubled = {
        "benchmarks": [
            {
                "id": "B11",
                "concurrency_model": {
                    **EXPECTED_CONCURRENCY_MODEL,
                    "writers": 8,
                    "writer_processes": (
                        EXPECTED_CONCURRENCY_MODEL["writer_processes"] * 2
                    ),
                },
            }
        ]
    }
    tier.write_text(
        "class yaml:\n"
        "    def safe_load(text):\n"
        f"        return {doubled!r}\n\n\n" + tier.read_text(encoding="utf-8"),
        encoding="utf-8",
    )


def _bypass_zero_executors(root: Path) -> None:
    """Round-4 review bypass 2: no executor at all — the four writers run
    serially, so the width the manifest pins is never realized."""
    _replace(
        root,
        TIER_BENCH,
        "    pool = ThreadPoolExecutor(max_workers=len(writers))",
        "    pool = None",
    )


def _bypass_string_anchor(root: Path) -> None:
    """Round-4 review bypass 3: `expr` present on the pinned line as plain text
    while no parsed call to the writer remains in the pinned scope."""
    site = EXPECTED_CONCURRENCY_MODEL["writer_processes"][0]["call_sites"][0]
    path = root / site["file"]
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)
    start = int(site["line"])
    end = max(
        n.end_lineno or start
        for n in ast.walk(ast.parse(text))
        if isinstance(n, ast.stmt) and n.lineno == start
    )
    indent = " " * (len(lines[start - 1]) - len(lines[start - 1].lstrip()))
    lines[start - 1 : end] = [f'{indent}_anchor = "write_audit("\n'] + [
        f"{indent}# pad\n"
    ] * (end - start)
    path.write_text("".join(lines), encoding="utf-8")


def _bypass_gutted_hygiene(root: Path) -> None:
    """Round-4 review bypass 4: both hygiene gates reduced to `true`, their
    step names kept, so a name-based adjacency check still passes."""
    path = root / ".github" / "workflows" / "ci.yml"
    path.write_text(
        path.read_text(encoding="utf-8").replace(EXPECTED_ENV_HYGIENE_COMMAND, "true"),
        encoding="utf-8",
    )


REVIEW_ROUND_4_BYPASSES = [
    ("module_scope_yaml_rebinding", {"A2b", "A2c", "L0"}, _bypass_yaml_rebinding),
    ("zero_executors_serialized_writers", {"W2"}, _bypass_zero_executors),
    ("string_anchor_wrong_enclosing_scope", {"C5"}, _bypass_string_anchor),
    ("ci_hygiene_commands_gutted_to_true", {"A10"}, _bypass_gutted_hygiene),
]


@pytest.mark.parametrize(
    "case_id,rule_ids,mutate",
    REVIEW_ROUND_4_BYPASSES,
    ids=[c[0] for c in REVIEW_ROUND_4_BYPASSES],
)
def test_b11_guard_rejects_review_round_4_bypasses_end_to_end(case_id, rule_ids, mutate):
    """The four bypasses code-review round 4 verified against the previous
    guard, each run through the **whole** checker suite rather than one rule."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        _seed_repo(root)
        mutate(root)
        with pytest.raises(AssertionError) as excinfo:
            _run_all_checkers(root)
    token = str(excinfo.value).split(":", 1)[0]
    assert token in rule_ids, (
        f"{case_id}: expected rejection by one of {sorted(rule_ids)}, got "
        f"{token!r} from {str(excinfo.value)!r}"
    )


def _bypass_serial_writers_with_forged_elapsed(root: Path) -> None:
    """Round-5 review bypass 1 (C1), verbatim: the real concurrent map replaced
    by a serial comprehension **and** the elapsed time divided by the writer
    count, so a ~500/s single writer reports ~2000/s combined."""
    _replace(
        root,
        TIER_BENCH,
        "        committed = list(pool.map(_run_writer, range(len(writers))))\n"
        "        elapsed = time.perf_counter() - t0",
        "        committed = [_run_writer(i) for i in range(len(writers))]\n"
        "        elapsed = (time.perf_counter() - t0) / len(writers)",
    )


def _bypass_unrecorded_module_binding(root: Path) -> None:
    """Round-5 review bypass 2 (C1): a module-scope binding form the A2b
    inventory never recorded, appended to the loader's own file."""
    path = root / TIER_CONFTEST
    path.write_text(
        path.read_text(encoding="utf-8") + "\nfor guard_hole in []:\n    pass\n",
        encoding="utf-8",
    )


REVIEW_ROUND_5_BYPASSES = [
    ("serial_writers_with_forged_elapsed", {"W2"}, _bypass_serial_writers_with_forged_elapsed),
    ("unrecorded_module_scope_for_binding", {"A2b", "A2d"}, _bypass_unrecorded_module_binding),
]


@pytest.mark.parametrize(
    "case_id,rule_ids,mutate",
    REVIEW_ROUND_5_BYPASSES,
    ids=[c[0] for c in REVIEW_ROUND_5_BYPASSES],
)
def test_b11_guard_rejects_review_round_5_bypasses_end_to_end(case_id, rule_ids, mutate):
    """The two bypasses code-review round 5 verified against the round-4 guard,
    each run through the **whole** checker suite rather than one rule."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        _seed_repo(root)
        mutate(root)
        with pytest.raises(AssertionError) as excinfo:
            _run_all_checkers(root)
    token = str(excinfo.value).split(":", 1)[0]
    assert token in rule_ids, (
        f"{case_id}: expected rejection by one of {sorted(rule_ids)}, got "
        f"{token!r} from {str(excinfo.value)!r}"
    )


REVIEW_ROUND_6_BYPASSES = [
    ("writes_wrapped_in_uninvoked_lambdas", {"W2"}, _bypass_writes_in_uninvoked_lambdas),
    ("pool_rebound_to_fake_map", {"W2"}, _bypass_pool_rebound_to_fake),
    ("session_commit_not_called", {"W2"}, _bypass_session_commit_not_called),
    # Own adversarial variations on the same three routes (deferred scope,
    # pool rebind class, commit-not-called class).
    ("writes_in_nested_def", {"W2"}, _bypass_writes_in_nested_def),
    ("commit_only_in_uninvoked_lambda", {"W2"}, _bypass_commit_only_in_uninvoked_lambda),
]

REVIEW_ROUND_7_BYPASSES = [
    ("writes_under_boolop_and", {"W2"}, _bypass_writes_under_boolop_and),
    ("writes_under_ifexp", {"W2"}, _bypass_writes_under_ifexp),
    ("commit_under_boolop_and", {"W2"}, _bypass_commit_under_boolop_and),
]

REVIEW_ROUND_8_BYPASSES = [
    ("writes_under_chained_compare", {"W2"}, _bypass_writes_under_chained_compare),
    (
        "writes_under_annassign_annotation",
        {"W2"},
        _bypass_writes_under_annassign_annotation,
    ),
    ("commit_under_chained_compare", {"W2"}, _bypass_commit_under_chained_compare),
    (
        "commit_under_annassign_annotation",
        {"W2"},
        _bypass_commit_under_annassign_annotation,
    ),
]


@pytest.mark.parametrize(
    "case_id,rule_ids,mutate",
    REVIEW_ROUND_6_BYPASSES,
    ids=[c[0] for c in REVIEW_ROUND_6_BYPASSES],
)
def test_b11_guard_rejects_review_round_6_bypasses_end_to_end(case_id, rule_ids, mutate):
    """The round-6 C1 bypasses (and adversarial variations) verified end to end
    against the whole checker suite rather than one rule."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        _seed_repo(root)
        mutate(root)
        with pytest.raises(AssertionError) as excinfo:
            _run_all_checkers(root)
    token = str(excinfo.value).split(":", 1)[0]
    assert token in rule_ids, (
        f"{case_id}: expected rejection by one of {sorted(rule_ids)}, got "
        f"{token!r} from {str(excinfo.value)!r}"
    )


@pytest.mark.parametrize(
    "case_id,rule_ids,mutate",
    REVIEW_ROUND_7_BYPASSES,
    ids=[c[0] for c in REVIEW_ROUND_7_BYPASSES],
)
def test_b11_guard_rejects_review_round_7_bypasses_end_to_end(case_id, rule_ids, mutate):
    """Round-7 C1: BoolOp / IfExp short-circuit routes rejected end to end."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        _seed_repo(root)
        mutate(root)
        with pytest.raises(AssertionError) as excinfo:
            _run_all_checkers(root)
    token = str(excinfo.value).split(":", 1)[0]
    assert token in rule_ids, (
        f"{case_id}: expected rejection by one of {sorted(rule_ids)}, got "
        f"{token!r} from {str(excinfo.value)!r}"
    )


@pytest.mark.parametrize(
    "case_id,rule_ids,mutate",
    REVIEW_ROUND_8_BYPASSES,
    ids=[c[0] for c in REVIEW_ROUND_8_BYPASSES],
)
def test_b11_guard_rejects_review_round_8_bypasses_end_to_end(case_id, rule_ids, mutate):
    """Round-8 C1: Compare.comparators[1:] / AnnAssign.annotation rejected."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        _seed_repo(root)
        mutate(root)
        with pytest.raises(AssertionError) as excinfo:
            _run_all_checkers(root)
    token = str(excinfo.value).split(":", 1)[0]
    assert token in rule_ids, (
        f"{case_id}: expected rejection by one of {sorted(rule_ids)}, got "
        f"{token!r} from {str(excinfo.value)!r}"
    )


def test_b11_guard_positive_control_loader_formatting():
    """The pinned form still passes under different line breaks and an added
    docstring, so L2 is proved not to be brittle about formatting."""
    reformatted = (
        "def load_b11_writer_model():\n"
        '    """Pass-through of B11\'s writer_processes."""\n'
        "    # reformatted, semantically identical\n"
        "    manifest = yaml.safe_load(\n"
        "        Path(__file__)\n"
        '        .with_name("thresholds.yaml")\n'
        '        .read_text(encoding="utf-8")\n'
        "    )\n"
        "    by_id = {\n"
        '        entry["id"]: entry\n'
        '        for entry in manifest["benchmarks"]\n'
        "    }\n"
        '    return by_id["B11"]["concurrency_model"]["writer_processes"]\n'
    )
    source = "import yaml\nfrom pathlib import Path\n\n\n" + reformatted
    check_L0(source)
    check_L1(source)
    check_L2(source)


# D1 positive controls: honest, unconditionally-evaluated expression-level
# forms must still pass every checker (same clean-baseline mechanism as
# test_b11_guard_baselines_pass_every_checker — seed, mutate, _run_all_checkers
# with no expected raise).  Complements the round-7/8 negatives that prove
# short-circuited / never-taken / annotation slots are rejected.
D1_POSITIVE_CONTROLS = [
    (
        "write_as_boolop_first_operand",
        _positive_write_as_boolop_first_operand,
    ),
    (
        "write_as_ifexp_test",
        _positive_write_as_ifexp_test,
    ),
    (
        "write_as_compare_left",
        _positive_write_as_compare_left,
    ),
    (
        "write_as_compare_first_comparator",
        _positive_write_as_compare_first_comparator,
    ),
    (
        "write_as_annassign_value",
        _positive_write_as_annassign_value,
    ),
]


@pytest.mark.parametrize(
    "case_id,mutate",
    D1_POSITIVE_CONTROLS,
    ids=[c[0] for c in D1_POSITIVE_CONTROLS],
)
def test_b11_guard_positive_control_live_under_boolop_ifexp(case_id, mutate):
    """D1: eager BoolOp/IfExp/Compare/AnnAssign slots are live — checkers pass."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        _seed_repo(root)
        mutate(root)
        _run_all_checkers(root)


def test_b11_guard_positive_control_real_repository():
    """Every checker, against the real tree."""
    _run_all_checkers(REPO_ROOT)
