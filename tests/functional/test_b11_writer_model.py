"""FP-M6-31: B11's writer model enforced outside the benchmark tier.

Hermetic — no database, no benchmark execution.  design.md Section 11.1.3,
*B11's writer model*, consequence 4 (errata passes 1-9, rev 2.5).

Every rule is a module-level ``check_<ID>`` function taking **plain data** — a
filename plus source text, an object decoded from the manifest, a set of file
names, or a directory path — and raising ``AssertionError`` whose message
**begins with a stable rule ID followed by** ``": "``.  Thirty-six IDs, one
checker function each:

    L0-L3   the loader layers (the width test's part (i))
    W2-W4   the width test's remaining parts
    A1, A2a-A2d, A3-A6, A7a-A7c, A8, A9, A10   the allowlist rules
    C1-C7   the call-site checks
    B11D1-B11D5   the host/storage diagnostics that decide no outcome
                  (design/slices/b11-host-diagnostics, FP-B11HD-1..5)

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
# GC-3 (design/slices/gc-3-reference-topology/design.md §3.4/§3.8): the tracked
# model-keyed B1 reference-topology decision carrier lives in this directory by
# design -- the B1 launcher's `route` command reads it there and the benchmark
# driver sees it through its existing read-only /workspace mount. It is
# generated evidence, not a B11 tier source: it is never imported, never
# executed, and configures no database. A1 names it explicitly so the tier
# inventory stays a closed set that still rejects every OTHER new file.
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
    "writers": 7,
    "pool": "per-writer-independent",
    "pool_widening": "none",
    "durability": "stock",
    "writer_processes": [
        {
            "process": "ingest-gateway",
            "processes": 4,
            "tables": ["audit_log"],
            "call_sites": [
                {
                    # GC-2: the remaining real under-lock write_audit call.
                    # The committed-existing-case merge writes its own audit
                    # row inside merge_existing_event_with_audit; B11's
                    # threshold, writer count, pool model and durability are
                    # unchanged by that. GC-5 moved that fused statement
                    # into the shared merge group, which shifted this call
                    # site's LINE; the resolved value is re-synchronised here
                    # and in the manifest, and one audit row per ingested
                    # alert on four mutually exclusive branches is unchanged.
                    "file": "services/gateway/gateway/ingest.py",
                    "line": 252,
                    "in": "IngestService._ingest_txn",
                    "symbol": "write_audit",
                    "expr": "write_audit(",
                }
            ],
        },
        {
            "process": "dashboard-api",
            "processes": 1,
            "tables": ["audit_log"],
            "call_sites": [
                {
                    "file": "services/dashboard-api/dashboard_api/services.py",
                    "line": 470,
                    "in": "decide_approval_atomic",
                    "symbol": "write_audit",
                    "expr": "write_audit(",
                }
            ],
        },
        {
            "process": "probe-gateway",
            "processes": 1,
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
            "processes": 1,
            "tables": ["audit_log", "llm_calls"],
            "call_sites": [
                {
                    "file": "services/worker/worker/activities/investigation.py",
                    "line": 147,
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
                        "line": 246,
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
# pass 9), plus the fifth canonical line added by the B11 host/storage
# diagnostics slice.  Guard *data*, not a rule ID of their own: W4 asserts all
# five, and dropping any one of them is red there.
DIAGNOSTIC_PREFIXES = (
    "B11 writers=",
    "B11 writer_map=",
    "B11 single_writer_rate=",
    "B11 env=",
    "B11 diagnostics=",
)

# A2a — the closed (module, name) import inventory of the benchmark tier.
# `name is None` means a plain `import <module>`.
ALLOWED_BENCHMARK_IMPORTS = {
    ("__future__", "annotations"),
    ("statistics", None),
    ("time", None),
    ("uuid", None),
    # `os` is imported for exactly two admitted calls: `os.cpu_count()`, which
    # feeds the `B11 env=cpus=` fingerprint consequence 3 requires (errata pass
    # 9), and `os.sysconf("SC_CLK_TCK")`, the tick rate the host/storage
    # diagnostics divide by (B11D2 pins that literal argument).  A7a admits
    # `cpu_count` and `sysconf` and nothing else, so `os.environ` still fails.
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
    # B11 host/storage diagnostics slice §3.3/§3.7: eight exact bindings and no
    # more.  The four host-counter parsers are B1's SHIPPED pure functions,
    # imported through the ordinary namespace boundary the root conftest
    # already establishes -- not copied, not loaded dynamically (the tier's
    # default-deny import inventory still has no `importlib`, no `subprocess`
    # and no B1 live-test module), and not re-implemented here.
    ("collections.abc", "Mapping"),
    ("docker.errors", "DockerException"),
    ("sqlalchemy.exc", "SQLAlchemyError"),
    ("urllib.parse", "quote"),
    ("services.gateway.tests.b1_reference_profile", "counter_delta"),
    ("services.gateway.tests.b1_reference_profile", "parse_proc_stat_steal_ticks"),
    ("services.gateway.tests.b1_reference_profile", "parse_psi_total"),
    ("services.gateway.tests.b1_reference_profile", "steal_ticks_to_usec"),
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
            # B11 host/storage diagnostics slice §3.7.  Exactly ONE `Path`
            # binding: every admitted file-read route needs it, a second
            # binding or a function-local import is A2b/A2c-red, and it adds
            # no capability the tier did not already allow its sibling.
            ("Path", "import"): 1,
            ("Mapping", "import"): 1,
            ("DockerException", "import"): 1,
            ("SQLAlchemyError", "import"): 1,
            ("quote", "import"): 1,
            ("counter_delta", "import"): 1,
            ("parse_proc_stat_steal_ticks", "import"): 1,
            ("parse_psi_total", "import"): 1,
            ("steal_ticks_to_usec", "import"): 1,
            ("B11_DIAGNOSTIC_PREFIX", "assign"): 1,
            ("B11_DIAGNOSTIC_UNAVAILABLE", "assign"): 1,
            ("B11_DIAGNOSTIC_FIELDS", "assign"): 1,
            ("B11_CONTAINER_MOUNT_SCRIPT", "assign"): 1,
            ("B11_CONTAINER_BLOCK_SCRIPT", "assign"): 1,
            ("_encode_b11_value", "def"): 1,
            ("_writer_instance_label", "def"): 1,
            ("_serialize_writer_elapsed_rows", "def"): 1,
            ("_serialize_b11_diagnostics", "def"): 1,
            ("_read_b11_host_snapshot", "def"): 1,
            ("_b11_host_delta_values", "def"): 1,
            ("_decode_b11_mountinfo_field", "def"): 1,
            ("_parse_b11_container_mount_output", "def"): 1,
            ("_mountinfo_record_for_path", "def"): 1,
            ("_parse_b11_container_block_output", "def"): 1,
            ("_exec_b11_container_text", "def"): 1,
            ("_read_b11_container_block_identity", "def"): 1,
            ("_read_b11_storage_identity", "def"): 1,
            ("_p99", "def"): 1,
            ("test_b2_fingerprint_correlation_p99_under_20ms", "def"): 1,
            ("test_b10_partitioned_list_and_filter_p99", "def"): 1,
            (B11_TEST_NAME, "def"): 1,
            ("test_b11_host_parser_reuse_is_direct", "def"): 1,
            ("test_b11_host_diagnostics_read_declared_sources", "def"): 1,
            ("test_b11_host_reader_observes_real_proc_stat", "def"): 1,
            ("test_b11_storage_identity_reads_target_postgres_container", "def"): 1,
            (
                "test_b11_storage_identity_fails_soft_without_substituting_another_mount",
                "def",
            ): 1,
            ("test_b11_diagnostics_schema_is_canonical_and_comma_safe", "def"): 1,
            ("test_b11_diagnostic_sampling_brackets_the_timed_window", "def"): 1,
        }
    ),
}

ALLOWED_BUILTINS = {
    "abs", "dict", "enumerate", "float", "int", "len", "list", "max", "min",
    "print", "range", "reversed", "round", "sorted", "str", "sum", "tuple", "zip",
    # B11 host/storage diagnostics slice §3.7: the fail-soft readers and the
    # canonical serializer need these and nothing reflective.  `object` stays
    # in REFLECTIVE_NAMES, so annotating a container handle with it is still
    # A2c/A2d-red.
    "all", "AssertionError", "bytes", "isinstance", "OSError", "set", "ValueError",
}

_IMPORT_ALIASES = {
    "statistics", "time", "uuid", "os", "yaml", "ThreadPoolExecutor", "datetime",
    "timezone", "Path", "pytest", "text", "command", "Config", "PostgresContainer",
    "ensure_month", "make_engine", "make_session_factory", "actor_system",
    "write_audit", "find_open_by_fingerprint", "LLMCallRecord", "PGTraceStore",
    "dash_services", LOADER_NAME, "annotations",
    # B11 host/storage diagnostics slice §3.7 (`Path` was already here).
    "Mapping", "DockerException", "SQLAlchemyError", "quote", "counter_delta",
    "parse_proc_stat_steal_ticks", "parse_psi_total", "steal_ticks_to_usec",
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
    # B11 host/storage diagnostics slice §3.7.  `sysconf` extends the narrow
    # `os.cpu_count()` exception to exactly `os.sysconf("SC_CLK_TCK")` (the
    # diagnostics source guard pins that literal argument, and `os` stays in
    # REFLECTIVE_NAMES); `one` reads the fixture engine's single
    # data_directory row; `get_wrapped_container`/`exec_run` are the only
    # Docker surface, reached only through the two signed handle parameters.
    # Deliberately NOT admitted: readlink, get_docker_client, reload, attrs,
    # image, id, client, containers, run, host, cwd.
    "sysconf", "one", "get", "is_absolute", "relative_to", "splitlines",
    "split", "strip", "startswith", "isdecimal", "decode",
    "get_wrapped_container", "exec_run",
    # Fixture-write locality (A7a): legal only inside
    # `test_b11_host_diagnostics_read_declared_sources`, which builds its
    # throwaway proc/PSI inputs under tmp_path.  Production diagnostics and
    # the storage fixtures write nothing.
    "mkdir", "write_text",
}

# A7a locality: the only function in the tier that may call these.
FIXTURE_WRITE_ATTRIBUTES = {"mkdir", "write_text"}
FIXTURE_WRITE_FUNCTION = "test_b11_host_diagnostics_read_declared_sources"

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
# bench-on-demand FP-BOD-1: the benchmark job names every top-level test in
# tests/benchmark/test_pg_scale.py EXCEPT the live audit/LLM throughput node,
# which left CI with B1 and is measured on demand. A whole-file `pytest
# tests/benchmark/test_pg_scale.py` would run it again, so this pin is an
# equality on the node-id list rather than on the file.
_B11_CI_NODE_IDS = (
    "test_b2_fingerprint_correlation_p99_under_20ms",
    "test_b10_partitioned_list_and_filter_p99",
    "test_b11_host_parser_reuse_is_direct",
    "test_b11_host_diagnostics_read_declared_sources",
    "test_b11_host_reader_observes_real_proc_stat",
    "test_b11_storage_identity_reads_target_postgres_container",
    "test_b11_storage_identity_fails_soft_without_substituting_another_mount",
    "test_b11_diagnostics_schema_is_canonical_and_comma_safe",
    "test_b11_diagnostic_sampling_brackets_the_timed_window",
)
EXPECTED_B11_COMMAND = (
    "services/worker/.venv/bin/python -m pytest "
    + " ".join(f"tests/benchmark/test_pg_scale.py::{name}" for name in _B11_CI_NODE_IDS)
    + " -v -s"
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

        yield {"dsn": dsn, "factory": factory, "engine": engine, "container": pg}
"""

CLEAN_BENCH = """\
\"\"\"B2 / B10 / B11 scale benchmarks (design.md FP-M6-20/21/22).\"\"\"
from __future__ import annotations

import os
import statistics
import time
import uuid
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import pytest
from docker.errors import DockerException
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from rca_common.audit import actor_system, write_audit
from rca_common.db.session import make_engine, make_session_factory
from rca_common.investigation_repo import find_open_by_fingerprint
from rca_common.llmclient.tracestore import LLMCallRecord, PGTraceStore
from services.gateway.tests.b1_reference_profile import (
    counter_delta,
    parse_proc_stat_steal_ticks,
    parse_psi_total,
    steal_ticks_to_usec,
)

# Sibling conftest (pytest prepends tests/benchmark/ on sys.path for this module).
from conftest import load_b11_writer_model

# B11's fifth, canonical diagnostic line (design/slices/b11-host-diagnostics
# §3.2).  The four legacy `B11 ...=` lines keep their exact prefixes and
# meanings; this one is appended, printed once per completed measurement,
# before the unchanged threshold assertion.  Every one of the 21 fields is
# outcome-inert: none can move the threshold, the outcome, the exit code, a
# retry or a skip.  bench-on-demand (FP-BOD-4) deleted the one exception there
# used to be: `host_psi_io_full_usec` no longer feeds any branch at all.  The
# stall classifier that appended a label to an already-red message existed to
# tell one shared-runner red from another, and B11 left per-push CI, so ALL 21
# fields are reported-only now and a miss is the `rate >= 1000.0` assertion
# with its own rate message and nothing after it.  The label itself is pinned
# absent from this file by
# tests/functional/test_b11_writer_model.py::test_b11_rate_bar_has_no_stall_suffix,
# so it is deliberately not spelled here.
B11_DIAGNOSTIC_PREFIX = "B11 diagnostics="
B11_DIAGNOSTIC_UNAVAILABLE = "unavailable"
B11_DIAGNOSTIC_FIELDS = (
    "combined_rate_per_sec",
    "serial_commit_ms",
    "combined_over_single",
    "writer_elapsed_rows",
    "host_steal_usec",
    "host_psi_cpu_some_usec",
    "host_psi_cpu_full_usec",
    "host_psi_io_some_usec",
    "host_psi_io_full_usec",
    "host_psi_memory_some_usec",
    "host_psi_memory_full_usec",
    "storage_pgdata_path",
    "storage_filesystem",
    "storage_mount_source",
    "storage_mount_root",
    "storage_mount_point",
    "storage_device_majmin",
    "storage_block_device",
    "storage_rotational",
    "storage_scheduler",
    "storage_model",
)

# The two closed scripts B11 runs, unprivileged, as OS user `postgres`, inside
# the exact PostgreSQL container the seeded fixture is already running.  Docker
# exec joins that container's mount namespace, which is also the server's own
# view, so the mount record and block attributes describe the storage under
# PostgreSQL's data directory -- never the pytest process's filesystem.  Each
# takes its one container-derived value as a validated positional argument.
B11_CONTAINER_MOUNT_SCRIPT = r\"\"\"
pgdata="$1"
case "$pgdata" in
    /*) ;;
    *) exit 2 ;;
esac
resolved="$(readlink -f "$pgdata" 2>/dev/null)" || exit 2
[ -n "$resolved" ] || exit 2
printf 'pgdata_resolved=%s\\n' "$resolved"
cat /proc/self/mountinfo
\"\"\".strip()

B11_CONTAINER_BLOCK_SCRIPT = r\"\"\"
majmin="$1"
case "$majmin" in
    *[!0-9:]*|:*|*:|*:*:*) exit 2 ;;
    [0-9]*:[0-9]*) ;;
    *) exit 2 ;;
esac
device="$(readlink -f "/sys/dev/block/$majmin" 2>/dev/null)" || exit 0
[ -n "$device" ] || exit 0
candidate="$device"
if [ -f "$candidate/partition" ]; then
    candidate="$(dirname "$candidate")" || exit 0
fi
case "$(basename "$candidate")" in
    dm-*)
        # majmin was copied above; replacing $1 here is intentional.
        set -- "$candidate"/slaves/*
        if [ "$#" -eq 1 ] && [ -e "$1" ]; then
            slave="$(readlink -f "$1" 2>/dev/null)" || slave=""
            if [ -n "$slave" ]; then
                candidate="$slave"
                if [ -f "$candidate/partition" ]; then
                    candidate="$(dirname "$candidate")" || exit 0
                fi
            fi
        fi
        ;;
esac
name="$(basename "$candidate")" || exit 0
[ -n "$name" ] && printf 'block_device=%s\\n' "$name"
for spec in rotational:queue/rotational scheduler:queue/scheduler model:device/model; do
    key="${spec%%:*}"
    rel="${spec#*:}"
    [ -r "$candidate/$rel" ] || continue
    value="$(cat "$candidate/$rel" 2>/dev/null)" || continue
    [ -n "$value" ] || continue
    printf '%s=%s\\n' "$key" "$value"
done
\"\"\".strip()


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


def _encode_b11_value(value: str) -> str:
    \"\"\"Percent-encode one free-form diagnostic value (B1-compatible safe set).

    Uppercase hex, and the only unencoded characters are ``A-Z a-z 0-9 - . _ ~
    : +``.  Comma, equals, percent, whitespace, slash and newline are all
    encoded, so no value can forge a field boundary or split the physical line.
    \"\"\"
    return quote(value, safe="-._~:+")


def _writer_instance_label(entry, index: int) -> str:
    \"\"\"The percent-encoded label of one writer process instance.

    The safe set here is ``A-Z a-z 0-9 - . _ ~ #`` -- ``:`` and ``+`` are the
    writer entry's own separators, so they are encoded and a future process
    name cannot forge an entry boundary.
    \"\"\"
    process = entry["process"]
    label = process + "#" + str(index) if process == "ingest-gateway" else process
    return quote(label, safe="#")


def _serialize_writer_elapsed_rows(
    instances, writer_elapsed_rows: list[tuple[float, int] | None]
) -> str:
    \"\"\"The ``writer_elapsed_rows`` field: seven ordered elapsed/row entries.

    Entries are ``+``-joined, never comma-joined, in the manifest-derived
    ``instances`` order.  Every slot of the preallocated side channel must have
    been replaced by exactly one writer, so an added, omitted or duplicated
    entry raises here rather than being reported.
    \"\"\"
    assert len(writer_elapsed_rows) == len(instances), (
        f"B11 writer side channel has {len(writer_elapsed_rows)} slots for "
        f"{len(instances)} writer instances"
    )
    entries = []
    labels = []
    for idx in range(len(instances)):
        measured = writer_elapsed_rows[idx]
        assert measured is not None, (
            f"B11 writer instance {idx} recorded no elapsed/row pair"
        )
        elapsed_seconds = measured[0]
        rows = measured[1]
        assert elapsed_seconds >= 0 and rows >= 0, (
            f"B11 writer instance {idx} reported {measured!r}"
        )
        label = _writer_instance_label(instances[idx][0], instances[idx][1])
        rendered = f"{label}:{elapsed_seconds * 1000:.3f}:{rows}"
        assert "," not in rendered, f"B11 writer entry {rendered!r} carries a comma"
        labels.append(label)
        entries.append(rendered)
    assert len(set(labels)) == len(labels), (
        f"B11 writer labels are not unique: {labels}"
    )
    return "+".join(entries)


def _serialize_b11_diagnostics(values: Mapping[str, str]) -> str:
    \"\"\"The one canonical, comma-safe ``B11 diagnostics=`` line.

    Exactly ``B11_DIAGNOSTIC_FIELDS``, in that order: an extra key, a missing
    key, a reordered mapping, an empty value or a raw comma/newline inside a
    value is a harness defect and raises rather than being printed.
    \"\"\"
    assert isinstance(values, Mapping), f"B11 diagnostics are not a mapping: {values!r}"
    assert tuple(values) == B11_DIAGNOSTIC_FIELDS, (
        f"B11 diagnostic fields {tuple(values)} != {B11_DIAGNOSTIC_FIELDS}"
    )
    entries = []
    for field in B11_DIAGNOSTIC_FIELDS:
        value = values[field]
        assert isinstance(value, str) and value, (
            f"B11 diagnostic field {field!r} has no value"
        )
        assert "," not in value and "\\n" not in value, (
            f"B11 diagnostic field {field!r} value {value!r} is not comma-safe"
        )
        entries.append(f"{field}={value}")
    return B11_DIAGNOSTIC_PREFIX + ",".join(entries)


def _read_b11_host_snapshot(
    *,
    proc_stat_path: Path = Path("/proc/stat"),
    psi_root: Path = Path("/proc/pressure"),
) -> dict[str, int | None]:
    \"\"\"One boundary sample of the host's steal and PSI counters.

    Parsing is the B1 host-noise slice's shipped pure code, imported directly:
    the kernel aggregate steal row is read in raw ticks (the microsecond
    conversion is exact only after the window's subtraction) and each pressure
    file's exact ``some``/``full`` ``total=`` counter is read separately.  PSI
    averages are never read: they average over time outside this window.  Every
    member fails soft on its own -- a missing CPU ``full`` record does not erase
    CPU ``some``, and a missing memory file does not erase CPU or I/O.
    \"\"\"
    snapshot: dict[str, int | None] = {
        "steal_ticks": None,
        "psi_cpu_some": None,
        "psi_cpu_full": None,
        "psi_io_some": None,
        "psi_io_full": None,
        "psi_memory_some": None,
        "psi_memory_full": None,
    }
    try:
        snapshot["steal_ticks"] = parse_proc_stat_steal_ticks(
            proc_stat_path.read_text(encoding="utf-8")
        )[0]
    except (OSError, ValueError):
        snapshot["steal_ticks"] = None
    for resource in ("cpu", "io", "memory"):
        try:
            pressure = (psi_root / resource).read_text(encoding="utf-8")
        except (OSError, ValueError):
            continue
        for record in ("some", "full"):
            try:
                snapshot["psi_" + resource + "_" + record] = parse_psi_total(
                    pressure, record
                )
            except (OSError, ValueError):
                snapshot["psi_" + resource + "_" + record] = None
    return snapshot


def _b11_host_delta_values(
    before: Mapping[str, int | None],
    after: Mapping[str, int | None],
    *,
    clock_ticks: int | None,
) -> dict[str, str]:
    \"\"\"Render the seven host fields from two boundary snapshots.

    Subtraction first, conversion after: ``counter_delta`` refuses a counter
    that decreased inside the window and ``steal_ticks_to_usec`` converts only
    the already-subtracted tick delta.  A reset, a missing end, a malformed
    value or an unreadable source renders that one field ``unavailable`` --
    never zero -- while a real zero delta renders ``0``.  An unusable clock-tick
    rate costs only ``host_steal_usec``; PSI is already microseconds.
    \"\"\"
    values: dict[str, str] = {}
    for resource in ("cpu", "io", "memory"):
        for record in ("some", "full"):
            key = "psi_" + resource + "_" + record
            start = before.get(key)
            end = after.get(key)
            rendered = B11_DIAGNOSTIC_UNAVAILABLE
            if isinstance(start, int) and isinstance(end, int):
                try:
                    rendered = str(counter_delta(start, end, label=key))
                except (OSError, ValueError):
                    rendered = B11_DIAGNOSTIC_UNAVAILABLE
            values["host_" + key + "_usec"] = rendered
    start = before.get("steal_ticks")
    end = after.get("steal_ticks")
    rendered = B11_DIAGNOSTIC_UNAVAILABLE
    if isinstance(start, int) and isinstance(end, int) and isinstance(clock_ticks, int):
        try:
            rendered = str(
                steal_ticks_to_usec(
                    counter_delta(start, end, label="steal_ticks"),
                    clock_ticks=clock_ticks,
                )
            )
        except (OSError, ValueError):
            rendered = B11_DIAGNOSTIC_UNAVAILABLE
    values["host_steal_usec"] = rendered
    return values


def _decode_b11_mountinfo_field(value: str) -> str:
    \"\"\"Decode the four escapes the kernel emits in a mountinfo field.

    ``\\\\040`` space, ``\\\\011`` tab, ``\\\\012`` newline, ``\\\\134`` backslash --
    and nothing else.  Any other backslash sequence did not come from the
    kernel's own encoder, so it is refused rather than passed through as a
    possibly forged path boundary.
    \"\"\"
    parts = value.split("\\\\")
    decoded = parts[0]
    for part in parts[1:]:
        if part.startswith("040"):
            decoded = decoded + " " + part[3:]
        elif part.startswith("011"):
            decoded = decoded + "\\t" + part[3:]
        elif part.startswith("012"):
            decoded = decoded + "\\n" + part[3:]
        elif part.startswith("134"):
            decoded = decoded + "\\\\" + part[3:]
        else:
            raise ValueError(f"unknown mountinfo escape in {value!r}")
    return decoded


def _parse_b11_container_mount_output(output: str) -> tuple[str, str]:
    \"\"\"Split the mount exec's framed response into (resolved path, mountinfo).

    The frame proves the mountinfo bytes arrived in the same closed exec
    response as the container-resolved PGDATA path: a missing frame, a
    duplicated frame, content before the frame, a relative/traversing/empty
    resolved path or an empty mount table is refused.
    \"\"\"
    lines = output.splitlines()
    frame = "pgdata_resolved="
    if not lines or not lines[0].startswith(frame):
        raise ValueError(f"B11 mount exec emitted no leading frame: {output!r}")
    resolved = lines[0][len(frame) :]
    if (
        not resolved
        or not Path(resolved).is_absolute()
        or ".." in resolved.split("/")
    ):
        raise ValueError(f"B11 container-resolved PGDATA path {resolved!r} is unusable")
    rest = lines[1:]
    if not rest:
        raise ValueError("B11 mount exec emitted no mountinfo record")
    for line in rest:
        if line.startswith(frame):
            raise ValueError("B11 mount exec emitted a duplicate frame")
    return resolved, "\\n".join(rest)


def _mountinfo_record_for_path(
    mountinfo_output: str, container_path: str
) -> dict[str, str | None]:
    \"\"\"The target container's own mount record covering ``container_path``.

    Selection is by decoded path components, never by string prefix, so
    ``/var/lib/postgresql/data-old`` cannot cover ``/var/lib/postgresql/data``,
    and the unique longest covering mount point wins.  A container ``/`` record
    is a valid answer here because it was read inside the target container.  A
    malformed record or a tie is unavailable rather than guessed; an individual
    unusable root, source, filesystem or major:minor costs only that field.
    \"\"\"
    record: dict[str, str | None] = {
        "storage_mount_root": None,
        "storage_mount_point": None,
        "storage_filesystem": None,
        "storage_mount_source": None,
        "storage_device_majmin": None,
    }
    if not Path(container_path).is_absolute():
        return record
    best_pre = None
    best_post = None
    best_depth = -1
    ambiguous = False
    for line in mountinfo_output.splitlines():
        if not line.strip():
            continue
        halves = line.split(" - ", 1)
        if len(halves) != 2:
            return record
        pre = halves[0].split()
        post = halves[1].split()
        if len(pre) < 6 or len(post) < 3:
            return record
        try:
            point = _decode_b11_mountinfo_field(pre[4])
        except ValueError:
            return record
        if not Path(point).is_absolute():
            return record
        try:
            Path(container_path).relative_to(Path(point))
        except ValueError:
            continue
        depth = len([component for component in point.split("/") if component])
        if depth > best_depth:
            best_pre = pre
            best_post = post
            best_depth = depth
            ambiguous = False
        elif depth == best_depth:
            ambiguous = True
    if best_pre is None or best_post is None or ambiguous:
        return record
    try:
        root = _decode_b11_mountinfo_field(best_pre[3])
    except ValueError:
        root = ""
    try:
        point = _decode_b11_mountinfo_field(best_pre[4])
    except ValueError:
        point = ""
    try:
        filesystem = _decode_b11_mountinfo_field(best_post[0])
    except ValueError:
        filesystem = ""
    try:
        source = _decode_b11_mountinfo_field(best_post[1])
    except ValueError:
        source = ""
    record["storage_mount_root"] = root if root else None
    record["storage_mount_point"] = point if point else None
    record["storage_filesystem"] = filesystem if filesystem else None
    record["storage_mount_source"] = source if source else None
    device = best_pre[2].split(":")
    if len(device) == 2 and device[0].isdecimal() and device[1].isdecimal():
        record["storage_device_majmin"] = best_pre[2]
    return record


def _parse_b11_container_block_output(output: str) -> dict[str, str]:
    \"\"\"The four block members of the block exec's response.

    Only ``block_device``, ``rotational``, ``scheduler`` and ``model`` exist;
    every member starts at ``unavailable`` and an empty, duplicated or invalid
    one costs only itself.  An unknown key cannot come from the closed script,
    so it is a harness-schema defect and raises.
    \"\"\"
    values = {
        "storage_block_device": B11_DIAGNOSTIC_UNAVAILABLE,
        "storage_rotational": B11_DIAGNOSTIC_UNAVAILABLE,
        "storage_scheduler": B11_DIAGNOSTIC_UNAVAILABLE,
        "storage_model": B11_DIAGNOSTIC_UNAVAILABLE,
    }
    seen = []
    for line in output.splitlines():
        if not line.strip():
            continue
        parts = line.split("=", 1)
        key = parts[0]
        assert len(parts) == 2 and key in (
            "block_device",
            "rotational",
            "scheduler",
            "model",
        ), f"B11 block script emitted an unknown member {line!r}"
        value = parts[1].strip()
        if key in seen:
            values["storage_" + key] = B11_DIAGNOSTIC_UNAVAILABLE
            continue
        seen.append(key)
        if not value:
            continue
        if key == "rotational" and value not in ("0", "1"):
            continue
        values["storage_" + key] = value
    return values


def _exec_b11_container_text(wrapped_container, argv: list[str]) -> str:
    \"\"\"Run one of the two closed scripts in the target container, unprivileged.

    Only the two argv shapes in the slice design reach Docker, each with its one
    container-derived value already validated as a positional argument; every
    other argv is a harness defect and raises before the daemon is touched.  A
    nonzero exit or a non-bytes response is an environmental reading, not a
    defect, so it raises ``ValueError`` and the caller renders the affected
    fields unavailable.
    \"\"\"
    assert isinstance(argv, list) and len(argv) == 5, f"B11 exec argv {argv!r}"
    assert argv[0] == "/bin/sh" and argv[1] == "-c", f"B11 exec argv {argv!r}"
    if argv[3] == "b11-mount":
        assert argv[2] == B11_CONTAINER_MOUNT_SCRIPT, "B11 mount script replaced"
        lines = argv[4].splitlines()
        assert (
            len(lines) == 1
            and lines[0] == argv[4]
            and Path(argv[4]).is_absolute()
            and ".." not in argv[4].split("/")
        ), f"B11 mount exec PGDATA argument {argv[4]!r} is not a validated path"
    else:
        assert argv[3] == "b11-block", f"B11 exec argv {argv!r}"
        assert argv[2] == B11_CONTAINER_BLOCK_SCRIPT, "B11 block script replaced"
        device = argv[4].split(":")
        assert (
            len(device) == 2 and device[0].isdecimal() and device[1].isdecimal()
        ), f"B11 block exec device argument {argv[4]!r} is not major:minor"
    exit_code, output = wrapped_container.exec_run(
        argv,
        stdout=True,
        stderr=False,
        stdin=False,
        tty=False,
        privileged=False,
        user="postgres",
        detach=False,
        stream=False,
        socket=False,
        environment=None,
        workdir=None,
        demux=False,
    )
    if exit_code != 0:
        raise ValueError(f"B11 container exec {argv[3]!r} exited {exit_code!r}")
    if not isinstance(output, bytes):
        raise ValueError(f"B11 container exec {argv[3]!r} returned {output!r}")
    return output.decode("utf-8")


def _read_b11_container_block_identity(
    wrapped_container, device_majmin: str
) -> dict[str, str]:
    \"\"\"The exposed block attributes for one device, from the same container.\"\"\"
    values = {
        "storage_block_device": B11_DIAGNOSTIC_UNAVAILABLE,
        "storage_rotational": B11_DIAGNOSTIC_UNAVAILABLE,
        "storage_scheduler": B11_DIAGNOSTIC_UNAVAILABLE,
        "storage_model": B11_DIAGNOSTIC_UNAVAILABLE,
    }
    try:
        output = _exec_b11_container_text(
            wrapped_container,
            [
                "/bin/sh",
                "-c",
                B11_CONTAINER_BLOCK_SCRIPT,
                "b11-block",
                device_majmin,
            ],
        )
    except (ValueError, DockerException):
        return values
    return _parse_b11_container_block_output(output)


def _read_b11_storage_identity(container, pgdata_path: str) -> dict[str, str]:
    \"\"\"The storage identity PostgreSQL itself sees under its data directory.

    Everything is read by unprivileged exec in the exact running PostgreSQL
    container: the pytest process's ``/``, ``/proc`` and ``/sys``, the Docker
    daemon's own mount view and any host backing path are never candidates and
    are never substituted.  Docker volume class and host path are not claimed at
    all -- what the container does not expose stays ``unavailable``.
    \"\"\"
    values = {
        "storage_pgdata_path": B11_DIAGNOSTIC_UNAVAILABLE,
        "storage_filesystem": B11_DIAGNOSTIC_UNAVAILABLE,
        "storage_mount_source": B11_DIAGNOSTIC_UNAVAILABLE,
        "storage_mount_root": B11_DIAGNOSTIC_UNAVAILABLE,
        "storage_mount_point": B11_DIAGNOSTIC_UNAVAILABLE,
        "storage_device_majmin": B11_DIAGNOSTIC_UNAVAILABLE,
        "storage_block_device": B11_DIAGNOSTIC_UNAVAILABLE,
        "storage_rotational": B11_DIAGNOSTIC_UNAVAILABLE,
        "storage_scheduler": B11_DIAGNOSTIC_UNAVAILABLE,
        "storage_model": B11_DIAGNOSTIC_UNAVAILABLE,
    }
    if not pgdata_path or pgdata_path == B11_DIAGNOSTIC_UNAVAILABLE:
        return values
    values["storage_pgdata_path"] = _encode_b11_value(pgdata_path)
    lines = pgdata_path.splitlines()
    if (
        len(lines) != 1
        or lines[0] != pgdata_path
        or not Path(pgdata_path).is_absolute()
        or ".." in pgdata_path.split("/")
    ):
        return values
    try:
        wrapped_container = container.get_wrapped_container()
        resolved, mountinfo_output = _parse_b11_container_mount_output(
            _exec_b11_container_text(
                wrapped_container,
                [
                    "/bin/sh",
                    "-c",
                    B11_CONTAINER_MOUNT_SCRIPT,
                    "b11-mount",
                    pgdata_path,
                ],
            )
        )
    except (ValueError, DockerException):
        return values
    record = _mountinfo_record_for_path(mountinfo_output, resolved)
    for key in (
        "storage_mount_root",
        "storage_mount_point",
        "storage_filesystem",
        "storage_mount_source",
    ):
        member = record.get(key)
        if member:
            values[key] = _encode_b11_value(member)
    device_majmin = record.get("storage_device_majmin")
    if not device_majmin:
        return values
    values["storage_device_majmin"] = device_majmin
    if int(device_majmin.split(":")[0]) == 0:
        return values
    block = _read_b11_container_block_identity(wrapped_container, device_majmin)
    for key in (
        "storage_block_device",
        "storage_rotational",
        "storage_scheduler",
        "storage_model",
    ):
        member = block.get(key)
        if member and member != B11_DIAGNOSTIC_UNAVAILABLE:
            values[key] = _encode_b11_value(member)
    return values


def test_b11_audit_llm_insert_throughput(scale_pg):
    \"\"\"Combined audit + llm_calls insert rate under durable Postgres.

    Writer count and mapping come from B11's structured concurrency_model
    (design.md §11.1.3 / FP-M6-22 / FP-IG-21): four writer *services*, seven
    process *instances* in the default deployment, each with an independent
    make_engine-default pool. Threads proxy process instances.

    The fifth, canonical `B11 diagnostics=` line is outcome-inert: it is
    printed on a pass and before a threshold failure and changes no knob, no
    threshold and no outcome (design/slices/b11-host-diagnostics §3.6).  Its
    one message-only use is `host_psi_io_full_usec`, read after the bar has
    already failed so the failure text can name the observed I/O-full symptom
    (design/slices/b11-gate-policy §3.2); the gate stays `rate >= 1000.0` and
    no reading of any kind can produce a pass, a skip or a retry.
    \"\"\"
    dsn = scale_pg["dsn"]
    writers = load_b11_writer_model()
    instances = [
        (entry, i)
        for entry in writers
        for i in range(entry["processes"])
    ]
    n_iters = 800
    now = datetime.now(timezone.utc)

    # Storage identity first: PostgreSQL's own effective data_directory, then
    # the mount record and exposed block attributes at that path read *inside
    # the running server's own container*.  Both execs and all parsing finish
    # before any B11 engine, connection or row warmup, so no diagnostic I/O is
    # adjacent to the timed window (§3.4/§3.5).
    try:
        with scale_pg["engine"].connect() as conn:
            pgdata_row = conn.execute(
                text("SELECT current_setting('data_directory')")
            ).one()
        pgdata_path = pgdata_row[0]
    except SQLAlchemyError:
        pgdata_path = B11_DIAGNOSTIC_UNAVAILABLE
    storage_values = _read_b11_storage_identity(scale_pg["container"], pgdata_path)
    writer_elapsed_rows = [None] * len(instances)

    # One independent engine per process instance at make_engine defaults.
    # Built and warmed *outside* the timed window so we measure insert rate only.
    engines = []
    factories = []
    stores = []
    for _ in instances:
        eng = make_engine(dsn)
        fac = make_session_factory(eng)
        with eng.connect() as conn:
            conn.execute(text("SELECT 1"))
        engines.append(eng)
        factories.append(fac)
        stores.append(PGTraceStore(session_factory=fac))

    def _run_writer(idx: int) -> int:
        \"\"\"Return rows committed by instances[idx].

        One commit per row — production shape for write_audit / insert_llm_call.
        Session is held open across commits (same connection from the pool),
        matching a long-lived process rather than open/close per row.

        The two boundary clock reads and the one distinct-index side-channel
        assignment are the only added writer-path operations; both lie outside
        the counted row loop, and the recorded row count is the same bare
        counter this function returns.
        \"\"\"
        factory = factories[idx]
        store = stores[idx]
        process = instances[idx][0]["process"]
        rows = 0
        writer_t0 = time.perf_counter()
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
        writer_elapsed_rows[idx] = (time.perf_counter() - writer_t0, rows)
        return rows

    writer_map = ",".join(
        f"{(entry['process'] + '#' + str(i)) if entry['process'] == 'ingest-gateway' else entry['process']}"
        f":{'+'.join(entry['tables'])}"
        for entry, i in instances
    )

    def _warmup(idx: int) -> None:
        factory = factories[idx]
        process = instances[idx][0]["process"]
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
    pool = ThreadPoolExecutor(max_workers=len(instances))
    try:
        list(pool.map(_warmup, range(len(instances))))
        try:
            clock_ticks = os.sysconf("SC_CLK_TCK")
        except (OSError, ValueError):
            clock_ticks = None
        host_before = _read_b11_host_snapshot()
        t0 = time.perf_counter()
        committed = list(pool.map(_run_writer, range(len(instances))))
        elapsed = time.perf_counter() - t0
        host_after = _read_b11_host_snapshot()
    finally:
        pool.shutdown(wait=True)
    total_rows = sum(committed)
    rate = total_rows / elapsed if elapsed > 0 else 0.0
    host_values = _b11_host_delta_values(
        host_before, host_after, clock_ticks=clock_ticks
    )

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
    diagnostic_values = {
        "combined_rate_per_sec": f"{rate:.1f}",
        "serial_commit_ms": f"{serial_commit_ms:.3f}",
        "combined_over_single": f"{combined_over_single:.2f}",
        "writer_elapsed_rows": _serialize_writer_elapsed_rows(
            instances, writer_elapsed_rows
        ),
        "host_steal_usec": host_values["host_steal_usec"],
        "host_psi_cpu_some_usec": host_values["host_psi_cpu_some_usec"],
        "host_psi_cpu_full_usec": host_values["host_psi_cpu_full_usec"],
        "host_psi_io_some_usec": host_values["host_psi_io_some_usec"],
        "host_psi_io_full_usec": host_values["host_psi_io_full_usec"],
        "host_psi_memory_some_usec": host_values["host_psi_memory_some_usec"],
        "host_psi_memory_full_usec": host_values["host_psi_memory_full_usec"],
        "storage_pgdata_path": storage_values["storage_pgdata_path"],
        "storage_filesystem": storage_values["storage_filesystem"],
        "storage_mount_source": storage_values["storage_mount_source"],
        "storage_mount_root": storage_values["storage_mount_root"],
        "storage_mount_point": storage_values["storage_mount_point"],
        "storage_device_majmin": storage_values["storage_device_majmin"],
        "storage_block_device": storage_values["storage_block_device"],
        "storage_rotational": storage_values["storage_rotational"],
        "storage_scheduler": storage_values["storage_scheduler"],
        "storage_model": storage_values["storage_model"],
    }
    print(f"B11 writers={len(instances)}")
    print(f"B11 writer_map={writer_map}")
    print(f"B11 single_writer_rate={single_writer_rate:.1f}/s")
    print(env_line)
    print(_serialize_b11_diagnostics(diagnostic_values))
    # FP-BOD-4: the bar, and nothing after it. A miss is this assertion
    # failure with its existing rate message; there is no stall suffix, no
    # classification and no gate-outcome label. None of the 21 diagnostic
    # fields printed above enters this condition or this message.
    assert rate >= 1000.0, (
        f"B11 combined insert rate={rate:.1f}/s (threshold 1000); "
        f"B11 writers={len(instances)}; B11 writer_map={writer_map}; "
        f"B11 single_writer_rate={single_writer_rate:.1f}/s; {env_line}"
    )


def test_b11_host_parser_reuse_is_direct():
    \"\"\"FP-B11HD-2: the four host-counter helpers are B1's shipped pure code.

    Every imported binding is exercised here against fixed inputs; the
    independent source guard requires their literal
    `services.gateway.tests.b1_reference_profile` import provenance, so a copy,
    a redefinition or a dynamic load is rejected there rather than drifting.
    \"\"\"
    aggregate, per_cpu = parse_proc_stat_steal_ticks(
        "cpu  10 0 20 30 0 0 0 800 0 0\\n"
        "cpu0 5 0 10 15 0 0 0 500 0 0\\n"
        "cpu1 5 0 10 15 0 0 0 300 0 0\\n"
        "intr 1 2 3\\n"
    )
    assert aggregate == 800, aggregate
    assert per_cpu == {0: 500, 1: 300}, per_cpu
    pressure = (
        "some avg10=1.00 avg60=2.00 avg300=3.00 total=1234\\n"
        "full avg10=4.00 avg60=5.00 avg300=6.00 total=56\\n"
    )
    assert parse_psi_total(pressure, "some") == 1234
    assert parse_psi_total(pressure, "full") == 56
    assert counter_delta(10, 25, label="steal") == 15
    assert steal_ticks_to_usec(15, clock_ticks=100) == 150000


def test_b11_host_diagnostics_read_declared_sources(tmp_path):
    \"\"\"FP-B11HD-2: exact steal and PSI deltas from the declared paths.

    Deterministic files prove the aggregate steal row (not the per-CPU sum),
    both PSI records of all three resources, tick-first subtraction through
    `os.sysconf("SC_CLK_TCK")`'s rate, a numeric zero delta, and field-local
    failure: a reset, a malformed value, a missing record, a missing file or an
    unusable clock rate costs only the member it belongs to.
    \"\"\"
    proc_root = tmp_path / "proc"
    proc_root.mkdir()
    psi_root = tmp_path / "pressure"
    psi_root.mkdir()
    partial_root = tmp_path / "pressure-partial"
    partial_root.mkdir()
    stat_path = proc_root / "stat"

    def _stat(steal):
        return (
            f"cpu  10 0 20 30 0 0 0 {steal} 0 0\\n"
            f"cpu0 5 0 10 15 0 0 0 {steal} 0 0\\n"
        )

    def _psi(some_total, full_total, average):
        return (
            f"some avg10={average} avg60=0.00 avg300=0.00 total={some_total}\\n"
            f"full avg10={average} avg60=0.00 avg300=0.00 total={full_total}\\n"
        )

    def _snapshot(stat_body, cpu_body, io_body, memory_body):
        stat_path.write_text(stat_body, encoding="utf-8")
        (psi_root / "cpu").write_text(cpu_body, encoding="utf-8")
        (psi_root / "io").write_text(io_body, encoding="utf-8")
        (psi_root / "memory").write_text(memory_body, encoding="utf-8")
        return _read_b11_host_snapshot(proc_stat_path=stat_path, psi_root=psi_root)

    before = _snapshot(
        _stat(1000), _psi(100, 10, "9.99"), _psi(200, 20, "9.99"), _psi(300, 30, "9.99")
    )
    after = _snapshot(
        _stat(1007), _psi(123, 10, "0.00"), _psi(255, 26, "0.00"), _psi(300, 37, "0.00")
    )
    assert before["steal_ticks"] == 1000, before
    assert before["psi_cpu_some"] == 100, before
    values = _b11_host_delta_values(before, after, clock_ticks=100)
    # 7 ticks at 100 Hz = 70_000 us: subtraction first, conversion after.
    assert values["host_steal_usec"] == "70000", values
    assert values["host_psi_cpu_some_usec"] == "23", values
    assert values["host_psi_cpu_full_usec"] == "0", values
    assert values["host_psi_io_some_usec"] == "55", values
    assert values["host_psi_io_full_usec"] == "6", values
    assert values["host_psi_memory_some_usec"] == "0", values
    assert values["host_psi_memory_full_usec"] == "7", values
    assert tuple(sorted(values)) == (
        "host_psi_cpu_full_usec",
        "host_psi_cpu_some_usec",
        "host_psi_io_full_usec",
        "host_psi_io_some_usec",
        "host_psi_memory_full_usec",
        "host_psi_memory_some_usec",
        "host_steal_usec",
    ), tuple(sorted(values))

    # A different tick rate changes only the steal conversion.
    assert _b11_host_delta_values(before, after, clock_ticks=1000)[
        "host_steal_usec"
    ] == "7000"
    # An unusable tick rate costs the steal field alone.
    no_rate = _b11_host_delta_values(before, after, clock_ticks=None)
    assert no_rate["host_steal_usec"] == B11_DIAGNOSTIC_UNAVAILABLE, no_rate
    assert no_rate["host_psi_cpu_some_usec"] == "23", no_rate

    # A counter that reset inside the window is unavailable, never zero.
    reset = _b11_host_delta_values(after, before, clock_ticks=100)
    assert reset["host_steal_usec"] == B11_DIAGNOSTIC_UNAVAILABLE, reset
    assert reset["host_psi_cpu_some_usec"] == B11_DIAGNOSTIC_UNAVAILABLE, reset
    assert reset["host_psi_memory_some_usec"] == "0", reset

    # A missing `full` record leaves `some` intact.
    half = _snapshot(
        _stat(1007),
        "some avg10=0.00 avg60=0.00 avg300=0.00 total=123\\n",
        _psi(255, 26, "0.00"),
        _psi(300, 37, "0.00"),
    )
    assert half["psi_cpu_some"] == 123, half
    assert half["psi_cpu_full"] is None, half
    half_values = _b11_host_delta_values(before, half, clock_ticks=100)
    assert half_values["host_psi_cpu_some_usec"] == "23", half_values
    assert (
        half_values["host_psi_cpu_full_usec"] == B11_DIAGNOSTIC_UNAVAILABLE
    ), half_values

    # A malformed steal field costs steal alone; the PSI members survive.
    malformed = _snapshot(
        "cpu  10 0 20 30 0 0 0 seven 0 0\\ncpu0 1 0 1 1 0 0 0 1 0 0\\n",
        _psi(123, 10, "0.00"),
        _psi(255, 26, "0.00"),
        _psi(300, 37, "0.00"),
    )
    assert malformed["steal_ticks"] is None, malformed
    malformed_values = _b11_host_delta_values(before, malformed, clock_ticks=100)
    assert (
        malformed_values["host_steal_usec"] == B11_DIAGNOSTIC_UNAVAILABLE
    ), malformed_values
    assert malformed_values["host_psi_io_some_usec"] == "55", malformed_values

    # A missing pressure file costs only its own resource.
    (partial_root / "cpu").write_text(_psi(123, 10, "0.00"), encoding="utf-8")
    partial = _read_b11_host_snapshot(proc_stat_path=stat_path, psi_root=partial_root)
    assert partial["psi_cpu_some"] == 123, partial
    assert partial["psi_io_some"] is None, partial
    assert partial["psi_memory_full"] is None, partial

    # A missing /proc/stat costs only steal.
    absent = _read_b11_host_snapshot(
        proc_stat_path=proc_root / "absent", psi_root=psi_root
    )
    assert absent["steal_ticks"] is None, absent
    assert absent["psi_cpu_some"] == 123, absent


def test_b11_host_reader_observes_real_proc_stat():
    \"\"\"FP-B11HD-2: the default reader reads this host's real /proc.

    Container-free, and deliberately assertion-free about the values: what is
    required is that a readable source produces a reading, so an implementation
    whose synthetic fixtures pass while its live reader always reports
    `unavailable` is red here.
    \"\"\"
    before = _read_b11_host_snapshot()
    after = _read_b11_host_snapshot()
    values = _b11_host_delta_values(before, after, clock_ticks=100)
    assert values["host_steal_usec"].isdecimal(), values
    for resource in ("cpu", "io", "memory"):
        try:
            Path("/proc/pressure/" + resource).read_text(encoding="utf-8")
        except OSError:
            continue
        assert values[
            "host_psi_" + resource + "_some_usec"
        ].isdecimal(), values


def test_b11_storage_identity_reads_target_postgres_container():
    \"\"\"FP-B11HD-3: the mount and block identity at PostgreSQL's own PGDATA.

    The fake is the exact target container: its mountinfo carries a decoy
    `/workspace` mount, an always-covering `/` record and a sibling
    `...-old` mount, so a first-record choice, a string-prefix match or a
    substituted test-process mount table cannot produce these values.  The two
    unprivileged exec calls are asserted argument by argument.
    \"\"\"
    calls = []
    mount_bytes = (
        b"pgdata_resolved=/var/lib/postgresql/data/pgdata\\n"
        b"23 1 0:24 / / rw,relatime - overlay overlay rw\\n"
        b"27 23 0:26 / /workspace rw,relatime - fuse.fuse-overlayfs fuse-overlayfs rw\\n"
        b"41 23 259:3 /volumes/pg\\\\040data /var/lib/postgresql/data rw shared:1 - ext4 /dev/nvme0n1p3 rw\\n"
        b"44 23 259:3 /volumes/old /var/lib/postgresql/data-old rw - ext4 /dev/nvme0n1p3 rw\\n"
    )
    block_bytes = (
        b"block_device=nvme0n1\\n"
        b"rotational=0\\n"
        b"scheduler=[none] mq-deadline\\n"
        b"model=Amazon Elastic Block Store\\n"
    )

    class _Wrapped:
        def exec_run(
            self,
            cmd,
            stdout,
            stderr,
            stdin,
            tty,
            privileged,
            user,
            detach,
            stream,
            socket,
            environment,
            workdir,
            demux,
        ):
            calls.append(
                (
                    cmd,
                    stdout,
                    stderr,
                    stdin,
                    tty,
                    privileged,
                    user,
                    detach,
                    stream,
                    socket,
                    environment,
                    workdir,
                    demux,
                )
            )
            if cmd[3] == "b11-mount":
                return (0, mount_bytes)
            return (0, block_bytes)

    class _Container:
        def get_wrapped_container(self):
            return _Wrapped()

    values = _read_b11_storage_identity(
        _Container(), "/var/lib/postgresql/data/pgdata"
    )
    assert len(calls) == 2, calls
    assert calls[0][0] == [
        "/bin/sh",
        "-c",
        B11_CONTAINER_MOUNT_SCRIPT,
        "b11-mount",
        "/var/lib/postgresql/data/pgdata",
    ], calls[0][0]
    assert calls[0][1:] == (
        True,
        False,
        False,
        False,
        False,
        "postgres",
        False,
        False,
        False,
        None,
        None,
        False,
    ), calls[0][1:]
    assert calls[1][0] == [
        "/bin/sh",
        "-c",
        B11_CONTAINER_BLOCK_SCRIPT,
        "b11-block",
        "259:3",
    ], calls[1][0]
    assert calls[1][1:] == calls[0][1:], calls[1][1:]
    assert values["storage_pgdata_path"] == "%2Fvar%2Flib%2Fpostgresql%2Fdata%2Fpgdata"
    assert values["storage_filesystem"] == "ext4", values
    assert values["storage_mount_source"] == "%2Fdev%2Fnvme0n1p3", values
    assert values["storage_mount_root"] == "%2Fvolumes%2Fpg%20data", values
    assert values["storage_mount_point"] == "%2Fvar%2Flib%2Fpostgresql%2Fdata", values
    assert values["storage_device_majmin"] == "259:3", values
    assert values["storage_block_device"] == "nvme0n1", values
    assert values["storage_rotational"] == "0", values
    assert values["storage_scheduler"] == "%5Bnone%5D%20mq-deadline", values
    assert values["storage_model"] == "Amazon%20Elastic%20Block%20Store", values

    # A symlinked server path: selection follows the container-resolved path in
    # the same framed response, while the reported path stays the server's own.
    linked_calls = []

    class _LinkedWrapped:
        def exec_run(
            self,
            cmd,
            stdout,
            stderr,
            stdin,
            tty,
            privileged,
            user,
            detach,
            stream,
            socket,
            environment,
            workdir,
            demux,
        ):
            linked_calls.append(cmd)
            if cmd[3] == "b11-mount":
                return (0, mount_bytes)
            return (0, block_bytes)

    class _LinkedContainer:
        def get_wrapped_container(self):
            return _LinkedWrapped()

    linked = _read_b11_storage_identity(_LinkedContainer(), "/srv/pgdata-link")
    assert linked_calls[0][4] == "/srv/pgdata-link", linked_calls[0]
    assert linked["storage_pgdata_path"] == "%2Fsrv%2Fpgdata-link", linked
    assert linked["storage_mount_point"] == "%2Fvar%2Flib%2Fpostgresql%2Fdata", linked
    assert linked["storage_block_device"] == "nvme0n1", linked


def test_b11_storage_identity_fails_soft_without_substituting_another_mount():
    \"\"\"FP-B11HD-3/5: every unexposed member is unavailable, nothing is invented.

    Overlay2, rootless fuse, a zero major, malformed and ambiguous mount
    points, a failed exec, absent or masked sysfs, partial and invalid block
    output, the device-mapper shapes and a Docker API failure each preserve
    every independently valid reading and substitute nothing.
    \"\"\"
    pgdata = "/var/lib/postgresql/data"

    def _fake(responses, calls):
        class _Wrapped:
            def exec_run(
                self,
                cmd,
                stdout,
                stderr,
                stdin,
                tty,
                privileged,
                user,
                detach,
                stream,
                socket,
                environment,
                workdir,
                demux,
            ):
                calls.append(cmd)
                return responses[len(calls) - 1]

        class _Container:
            def get_wrapped_container(self):
                return _Wrapped()

        return _Container()

    # (a) overlay2 root: a valid virtual filesystem, a zero major, no block exec.
    calls = []
    overlay = _read_b11_storage_identity(
        _fake(
            [
                (
                    0,
                    b"pgdata_resolved=/var/lib/postgresql/data\\n"
                    b"23 1 0:24 / / rw,relatime - overlay overlay rw\\n",
                )
            ],
            calls,
        ),
        pgdata,
    )
    assert len(calls) == 1, calls
    assert overlay["storage_filesystem"] == "overlay", overlay
    assert overlay["storage_mount_source"] == "overlay", overlay
    assert overlay["storage_mount_root"] == "%2F", overlay
    assert overlay["storage_mount_point"] == "%2F", overlay
    assert overlay["storage_device_majmin"] == "0:24", overlay
    assert overlay["storage_block_device"] == B11_DIAGNOSTIC_UNAVAILABLE, overlay
    assert overlay["storage_rotational"] == B11_DIAGNOSTIC_UNAVAILABLE, overlay

    # (b) rootless fuse-overlayfs.
    calls = []
    rootless = _read_b11_storage_identity(
        _fake(
            [
                (
                    0,
                    b"pgdata_resolved=/var/lib/postgresql/data\\n"
                    b"23 1 0:31 / / rw - fuse.fuse-overlayfs fuse-overlayfs rw\\n",
                )
            ],
            calls,
        ),
        pgdata,
    )
    assert rootless["storage_filesystem"] == "fuse.fuse-overlayfs", rootless
    assert rootless["storage_mount_source"] == "fuse-overlayfs", rootless
    assert len(calls) == 1, calls

    # (c) a malformed mount point prevents an honest selection.
    calls = []
    malformed = _read_b11_storage_identity(
        _fake(
            [
                (
                    0,
                    b"pgdata_resolved=/var/lib/postgresql/data\\n"
                    b"23 1 0:24 / relative rw - ext4 /dev/sda1 rw\\n",
                )
            ],
            calls,
        ),
        pgdata,
    )
    assert malformed["storage_mount_point"] == B11_DIAGNOSTIC_UNAVAILABLE, malformed
    assert malformed["storage_filesystem"] == B11_DIAGNOSTIC_UNAVAILABLE, malformed
    assert (
        malformed["storage_pgdata_path"] == "%2Fvar%2Flib%2Fpostgresql%2Fdata"
    ), malformed

    # (d) two equally specific covering records are ambiguous, not guessed.
    calls = []
    ambiguous = _read_b11_storage_identity(
        _fake(
            [
                (
                    0,
                    b"pgdata_resolved=/var/lib/postgresql/data\\n"
                    b"41 23 259:3 /a /var/lib/postgresql/data rw - ext4 /dev/sda1 rw\\n"
                    b"42 23 259:4 /b /var/lib/postgresql/data rw - xfs /dev/sdb1 rw\\n",
                )
            ],
            calls,
        ),
        pgdata,
    )
    assert ambiguous["storage_filesystem"] == B11_DIAGNOSTIC_UNAVAILABLE, ambiguous
    assert (
        ambiguous["storage_device_majmin"] == B11_DIAGNOSTIC_UNAVAILABLE
    ), ambiguous

    # (e) malformed root/source/major fields cost only themselves.
    calls = []
    fields = _read_b11_storage_identity(
        _fake(
            [
                (
                    0,
                    b"pgdata_resolved=/var/lib/postgresql/data\\n"
                    b"41 23 25x:3 /volumes\\\\099pg /var/lib/postgresql/data rw - ext4 /dev/sda1 rw\\n",
                )
            ],
            calls,
        ),
        pgdata,
    )
    assert fields["storage_mount_point"] == "%2Fvar%2Flib%2Fpostgresql%2Fdata", fields
    assert fields["storage_filesystem"] == "ext4", fields
    assert fields["storage_mount_source"] == "%2Fdev%2Fsda1", fields
    assert fields["storage_mount_root"] == B11_DIAGNOSTIC_UNAVAILABLE, fields
    assert fields["storage_device_majmin"] == B11_DIAGNOSTIC_UNAVAILABLE, fields
    assert len(calls) == 1, calls

    # (f) a nonzero exec exit preserves only the server's own PGDATA path.
    calls = []
    failed = _read_b11_storage_identity(_fake([(2, b"")], calls), pgdata)
    assert failed["storage_pgdata_path"] == "%2Fvar%2Flib%2Fpostgresql%2Fdata", failed
    assert failed["storage_mount_point"] == B11_DIAGNOSTIC_UNAVAILABLE, failed
    assert failed["storage_filesystem"] == B11_DIAGNOSTIC_UNAVAILABLE, failed
    assert len(calls) == 1, calls

    # (g) an unframed mountinfo response is refused: no proof of provenance.
    calls = []
    unframed = _read_b11_storage_identity(
        _fake([(0, b"41 23 259:3 / /var/lib/postgresql/data rw - ext4 /dev/sda1 rw\\n")], calls),
        pgdata,
    )
    assert unframed["storage_mount_point"] == B11_DIAGNOSTIC_UNAVAILABLE, unframed

    # (h) absent or masked sysfs: every mount member survives.
    calls = []
    masked = _read_b11_storage_identity(
        _fake(
            [
                (
                    0,
                    b"pgdata_resolved=/var/lib/postgresql/data\\n"
                    b"41 23 259:3 / /var/lib/postgresql/data rw - ext4 /dev/sda1 rw\\n",
                ),
                (0, b""),
            ],
            calls,
        ),
        pgdata,
    )
    assert len(calls) == 2, calls
    assert masked["storage_device_majmin"] == "259:3", masked
    assert masked["storage_filesystem"] == "ext4", masked
    assert masked["storage_block_device"] == B11_DIAGNOSTIC_UNAVAILABLE, masked
    assert masked["storage_model"] == B11_DIAGNOSTIC_UNAVAILABLE, masked

    # (i) partial, invalid and duplicated block members, each field-local.
    calls = []
    partial = _read_b11_storage_identity(
        _fake(
            [
                (
                    0,
                    b"pgdata_resolved=/var/lib/postgresql/data\\n"
                    b"41 23 259:3 / /var/lib/postgresql/data rw - ext4 /dev/sda1 rw\\n",
                ),
                (
                    0,
                    b"block_device=dm-0\\nrotational=7\\nmodel=\\nmodel=Fake\\n",
                ),
            ],
            calls,
        ),
        pgdata,
    )
    assert partial["storage_block_device"] == "dm-0", partial
    assert partial["storage_rotational"] == B11_DIAGNOSTIC_UNAVAILABLE, partial
    assert partial["storage_scheduler"] == B11_DIAGNOSTIC_UNAVAILABLE, partial
    assert partial["storage_model"] == B11_DIAGNOSTIC_UNAVAILABLE, partial

    # (j) the device-mapper shapes the script can return: a kept dm node when
    # zero or several slaves are exposed, the sole slave's parent when exactly
    # one is.  The implementation never chooses among several backing devices.
    for emitted, expected in (
        (b"block_device=dm-0\\nrotational=1\\n", "dm-0"),
        (b"block_device=sda\\nrotational=1\\n", "sda"),
    ):
        calls = []
        mapper = _read_b11_storage_identity(
            _fake(
                [
                    (
                        0,
                        b"pgdata_resolved=/var/lib/postgresql/data\\n"
                        b"41 23 253:0 / /var/lib/postgresql/data rw - ext4 /dev/dm-0 rw\\n",
                    ),
                    (0, emitted),
                ],
                calls,
            ),
            pgdata,
        )
        assert mapper["storage_block_device"] == expected, mapper
        assert mapper["storage_rotational"] == "1", mapper

    # (k) an unknown block member is a harness-schema defect, not a reading.
    rejected = False
    try:
        _parse_b11_container_block_output("block_device=sda\\nvendor=ACME\\n")
    except AssertionError:
        rejected = True
    assert rejected, "an unknown block key must raise"

    # (l) a Docker API failure leaves every container-read field unavailable.
    class _Broken:
        def get_wrapped_container(self):
            raise DockerException("no daemon")

    broken = _read_b11_storage_identity(_Broken(), pgdata)
    assert broken["storage_pgdata_path"] == "%2Fvar%2Flib%2Fpostgresql%2Fdata", broken
    assert broken["storage_mount_point"] == B11_DIAGNOSTIC_UNAVAILABLE, broken
    assert broken["storage_block_device"] == B11_DIAGNOSTIC_UNAVAILABLE, broken

    # (m) a failed data_directory query, and a traversing path, read nothing.
    calls = []
    unknown = _read_b11_storage_identity(
        _fake([], calls), B11_DIAGNOSTIC_UNAVAILABLE
    )
    assert unknown["storage_pgdata_path"] == B11_DIAGNOSTIC_UNAVAILABLE, unknown
    assert len(calls) == 0, calls
    calls = []
    traversing = _read_b11_storage_identity(_fake([], calls), "/var/lib/../etc")
    assert traversing["storage_pgdata_path"] == "%2Fvar%2Flib%2F..%2Fetc", traversing
    assert traversing["storage_mount_point"] == B11_DIAGNOSTIC_UNAVAILABLE, traversing
    assert len(calls) == 0, calls

    # (n) the exec helper refuses every argv outside the two closed shapes,
    # before Docker is touched.
    class _NeverCalled:
        def exec_run(
            self,
            cmd,
            stdout,
            stderr,
            stdin,
            tty,
            privileged,
            user,
            detach,
            stream,
            socket,
            environment,
            workdir,
            demux,
        ):
            raise AssertionError("Docker must not be reached")

    for argv in (
        ["/bin/sh", "-c", "cat /proc/self/mountinfo", "b11-mount", "/data"],
        ["/bin/sh", "-c", B11_CONTAINER_MOUNT_SCRIPT, "b11-mount", "relative"],
        ["/bin/sh", "-c", B11_CONTAINER_MOUNT_SCRIPT, "b11-mount", "/a/../b"],
        ["/bin/sh", "-c", B11_CONTAINER_BLOCK_SCRIPT, "b11-block", "8:0:1"],
        ["/bin/sh", "-c", B11_CONTAINER_BLOCK_SCRIPT, "b11-block", "sda"],
        ["nsenter", "-t", "1", "b11-mount", "/data"],
    ):
        refused = False
        try:
            _exec_b11_container_text(_NeverCalled(), argv)
        except AssertionError:
            refused = True
        assert refused, argv


def test_b11_diagnostics_schema_is_canonical_and_comma_safe():
    \"\"\"FP-B11HD-1: one fixed-prefix physical line, 21 fields, no raw comma.

    The serializer is the only thing that can print the line, and it refuses a
    missing, extra, reordered or empty field and any raw comma or newline in a
    value; writer entries are `+`-joined so a writer can never forge a
    top-level field boundary.
    \"\"\"
    instances = [({"process": "ingest-gateway"}, i) for i in range(4)] + [
        ({"process": "dashboard-api"}, 0),
        ({"process": "probe-gateway"}, 0),
        ({"process": "temporal-worker"}, 0),
    ]
    measured = [
        (7.5, 800),
        (7.25, 800),
        (7.125, 800),
        (7.0625, 800),
        (6.5, 800),
        (6.25, 800),
        (6.125, 799),
    ]
    writer_field = _serialize_writer_elapsed_rows(instances, measured)
    assert writer_field == (
        "ingest-gateway#0:7500.000:800+"
        "ingest-gateway#1:7250.000:800+"
        "ingest-gateway#2:7125.000:800+"
        "ingest-gateway#3:7062.500:800+"
        "dashboard-api:6500.000:800+"
        "probe-gateway:6250.000:800+"
        "temporal-worker:6125.000:799"
    ), writer_field
    assert len(writer_field.split("+")) == 7, writer_field
    assert "," not in writer_field, writer_field

    # A future process name cannot forge an entry or field boundary.
    forged = _serialize_writer_elapsed_rows(
        [({"process": "a,b+c:d e"}, 0)], [(1.0, 1)]
    )
    assert forged == "a%2Cb%2Bc%3Ad%20e:1000.000:1", forged

    for broken_instances, broken_measured in (
        (instances, measured[:6]),
        (instances, [None] + measured[1:]),
        (
            [({"process": "dashboard-api"}, 0), ({"process": "dashboard-api"}, 0)],
            [(1.0, 1), (1.0, 1)],
        ),
        (instances, [(-1.0, 800)] + measured[1:]),
    ):
        rejected = False
        try:
            _serialize_writer_elapsed_rows(broken_instances, broken_measured)
        except AssertionError:
            rejected = True
        assert rejected, broken_measured

    values = {
        "combined_rate_per_sec": "743.7",
        "serial_commit_ms": "1.264",
        "combined_over_single": "0.94",
        "writer_elapsed_rows": writer_field,
        "host_steal_usec": "0",
        "host_psi_cpu_some_usec": "123",
        "host_psi_cpu_full_usec": B11_DIAGNOSTIC_UNAVAILABLE,
        "host_psi_io_some_usec": "456",
        "host_psi_io_full_usec": "7",
        "host_psi_memory_some_usec": "0",
        "host_psi_memory_full_usec": "0",
        "storage_pgdata_path": "%2Fvar%2Flib%2Fpostgresql%2Fdata",
        "storage_filesystem": "ext4",
        "storage_mount_source": "%2Fdev%2Fnvme0n1p1",
        "storage_mount_root": "%2F",
        "storage_mount_point": "%2Fvar%2Flib%2Fpostgresql%2Fdata",
        "storage_device_majmin": "259:1",
        "storage_block_device": "nvme0n1",
        "storage_rotational": "0",
        "storage_scheduler": "%5Bnone%5D%20mq-deadline",
        "storage_model": "Amazon%20Elastic%20Block%20Store",
    }
    line = _serialize_b11_diagnostics(values)
    assert line == (
        "B11 diagnostics=combined_rate_per_sec=743.7,serial_commit_ms=1.264,"
        "combined_over_single=0.94,writer_elapsed_rows=" + writer_field + ","
        "host_steal_usec=0,host_psi_cpu_some_usec=123,"
        "host_psi_cpu_full_usec=unavailable,host_psi_io_some_usec=456,"
        "host_psi_io_full_usec=7,host_psi_memory_some_usec=0,"
        "host_psi_memory_full_usec=0,"
        "storage_pgdata_path=%2Fvar%2Flib%2Fpostgresql%2Fdata,"
        "storage_filesystem=ext4,storage_mount_source=%2Fdev%2Fnvme0n1p1,"
        "storage_mount_root=%2F,"
        "storage_mount_point=%2Fvar%2Flib%2Fpostgresql%2Fdata,"
        "storage_device_majmin=259:1,storage_block_device=nvme0n1,"
        "storage_rotational=0,storage_scheduler=%5Bnone%5D%20mq-deadline,"
        "storage_model=Amazon%20Elastic%20Block%20Store"
    ), line
    assert line.startswith(B11_DIAGNOSTIC_PREFIX), line
    assert len(line.splitlines()) == 1, line
    body = line.split("=", 1)[1]
    fields = body.split(",")
    assert len(fields) == len(B11_DIAGNOSTIC_FIELDS) == 21, fields
    for number, entry in enumerate(fields):
        halves = entry.split("=")
        assert len(halves) == 2, entry
        assert halves[0] == B11_DIAGNOSTIC_FIELDS[number], entry
        assert halves[1], entry

    # Percent-encoding: uppercase hex, and every boundary character encoded.
    assert _encode_b11_value("Amazon Elastic Block Store") == (
        "Amazon%20Elastic%20Block%20Store"
    )
    assert _encode_b11_value("/dev/nvme0n1p1") == "%2Fdev%2Fnvme0n1p1"
    assert _encode_b11_value("a,b") == "a%2Cb"
    assert _encode_b11_value("a=b") == "a%3Db"
    assert _encode_b11_value("a\\nb") == "a%0Ab"
    assert _encode_b11_value("a%b") == "a%25b"
    assert _encode_b11_value("é") == "%C3%A9"
    assert _encode_b11_value("keep-._~:+") == "keep-._~:+"

    missing = dict(values)
    del missing["storage_model"]
    extra = dict(values)
    extra["storage_zone"] = "eu-west-1a"
    reordered = {}
    for name in reversed(B11_DIAGNOSTIC_FIELDS):
        reordered[name] = values[name]
    raw_comma = dict(values)
    raw_comma["storage_model"] = "Amazon, Elastic"
    raw_newline = dict(values)
    raw_newline["storage_scheduler"] = "none\\nmq-deadline"
    empty = dict(values)
    empty["storage_filesystem"] = ""
    for broken in (missing, extra, reordered, raw_comma, raw_newline, empty):
        rejected = False
        try:
            _serialize_b11_diagnostics(broken)
        except AssertionError:
            rejected = True
        assert rejected, tuple(broken)


def test_b11_diagnostic_sampling_brackets_the_timed_window():
    \"\"\"FP-B11HD-4/5: every diagnostic read lies outside the measured work.

    A lexical line-order check over this file: PGDATA and both possible storage
    execs finish before the first engine, connection and row warmup; the
    in-place `elapsed` assignment follows the map immediately and the closing
    host read is the next action; the two writer-boundary clock reads and the
    one side-channel assignment stay outside the counted row loop; and no
    diagnostic I/O, formatting or printing is inside either timed loop.  The
    real AST proof and the movement mutations live in the independent guard
    tests/functional/test_b11_writer_model.py.
    \"\"\"
    lines = Path(__file__).read_text(encoding="utf-8").splitlines()
    opened = None
    closed = len(lines)
    for number, body in enumerate(lines):
        if body.startswith("def test_b11_audit_llm_insert_throughput(scale_pg):"):
            opened = number
        elif opened is not None and body.startswith("def "):
            closed = number
            break
    assert opened is not None, "the B11 benchmark function moved"

    def _sole(marker):
        hits = []
        for number in range(opened, closed):
            if lines[number].strip() == marker:
                hits.append(number)
        assert len(hits) == 1, f"expected exactly one {marker!r}, found {hits}"
        return hits[0]

    def _sole_containing(fragment):
        hits = []
        for number in range(opened, closed):
            if fragment in lines[number]:
                hits.append(number)
        assert len(hits) == 1, f"expected one line with {fragment!r}, found {hits}"
        return hits[0]

    def _indent(number):
        return len(lines[number]) - len(lines[number].strip())

    query = _sole("pgdata_row = conn.execute(")
    storage = _sole(
        'storage_values = _read_b11_storage_identity(scale_pg["container"], pgdata_path)'
    )
    preallocation = _sole("writer_elapsed_rows = [None] * len(instances)")
    engine = _sole_containing("= make_engine(")
    connection_warmup = _sole('conn.execute(text("SELECT 1"))')
    row_warmup = _sole("list(pool.map(_warmup, range(len(instances))))")
    tick_rate = _sole('clock_ticks = os.sysconf("SC_CLK_TCK")')
    host_open = _sole("host_before = _read_b11_host_snapshot()")
    window_open = _sole("t0 = time.perf_counter()")
    mapped = _sole("committed = list(pool.map(_run_writer, range(len(instances))))")
    window_close = _sole("elapsed = time.perf_counter() - t0")
    host_close = _sole("host_after = _read_b11_host_snapshot()")
    single_writer = _sole("t_sw = time.perf_counter()")
    single_close = _sole("sw_elapsed = time.perf_counter() - t_sw")
    writer_open = _sole("writer_t0 = time.perf_counter()")
    side_channel = _sole(
        "writer_elapsed_rows[idx] = (time.perf_counter() - writer_t0, rows)"
    )
    row_loop = _sole("for i in range(n_iters):")
    writer_return = _sole("return rows")
    canonical = _sole("print(_serialize_b11_diagnostics(diagnostic_values))")
    bar = _sole("assert rate >= 1000.0, (")
    single_loop = _sole("for i in range(100):")
    warmup_loop = _sole("for i in range(50):")
    _sole("n_iters = 800")

    # (1) all storage work precedes every engine, connection and row warmup.
    assert query < storage < preallocation < engine, (query, storage, engine)
    assert storage < connection_warmup < row_warmup, (storage, row_warmup)

    # (2) the window opens after the host read and closes in place.
    assert row_warmup < tick_rate < host_open < window_open, (tick_rate, host_open)
    assert mapped == window_open + 1, (window_open, mapped)
    assert window_close == mapped + 1, (mapped, window_close)
    assert host_close == window_close + 1, (window_close, host_close)
    assert host_close < single_writer < canonical < bar, (host_close, bar)

    # (3) the writer takes two boundary clocks and writes one slot, both
    # outside its counted row loop.
    assert writer_open < row_loop < side_channel < writer_return, (
        writer_open,
        side_channel,
    )
    assert _indent(writer_open) == _indent(side_channel) == _indent(writer_return)
    assert _indent(row_loop) > _indent(side_channel), (row_loop, side_channel)

    # (4) neither timed loop contains diagnostic work.
    for start, stop in ((row_loop, side_channel), (single_loop, single_close)):
        for number in range(start + 1, stop):
            for token in (
                "_read_b11_host_snapshot",
                "_read_b11_storage_identity",
                "_exec_b11_container_text",
                "_parse_b11_container",
                "_mountinfo_record_for_path",
                "_serialize_",
                "_encode_b11_value",
                "perf_counter",
                "print(",
                "read_text",
                "exec_run",
                "/proc",
                "/sys",
            ):
                assert token not in lines[number], (number, token, lines[number])
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

# FP-IG-11: closed allowlist of exactly two keys. bench-on-demand FP-BOD-4
# deleted the `gate_policy` object with the stall label it described.
MANIFEST_ALLOWED_KEYS = frozenset(
    {
        "benchmarks[id=B11].concurrency_model",
        "benchmarks[id=B11].notes",
    }
)

MANIFEST_READ_SCRIPT = r'''
import json, sys
from pathlib import Path

import yaml

path, key_path = sys.argv[1], sys.argv[2]
allowed = {
    "benchmarks[id=B11].concurrency_model",
    "benchmarks[id=B11].notes",
}
if key_path not in allowed:
    raise SystemExit("unsupported key path: %r" % (key_path,))
data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
by_id = {entry["id"]: entry for entry in data["benchmarks"]}
if key_path.endswith(".notes"):
    print(json.dumps(by_id["B11"]["notes"]))
else:
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
    expected_names = [e["process"] for e in EXPECTED_CONCURRENCY_MODEL["writer_processes"]]
    got_names = [e.get("process") for e in out["returned"]]
    _require(
        got_names == expected_names,
        "L3",
        f"writer_processes must be the four named entries {expected_names}; "
        f"got {got_names}",
    )
    proc_counts: list[int] = []
    for entry in out["returned"]:
        _require(
            "processes" in entry,
            "L3",
            "every writer_processes entry must carry an explicit int "
            "processes >= 1 (no default, no .get fallback)",
        )
        n = entry["processes"]
        _require(
            type(n) is int and not isinstance(n, bool) and n >= 1,
            "L3",
            f"processes must be int >= 1, got {n!r}",
        )
        proc_counts.append(n)
    _require(
        sum(proc_counts) == out["writers"] == EXPECTED_CONCURRENCY_MODEL["writers"],
        "L3",
        f"writers={out['writers']} but Σ processes={sum(proc_counts)}",
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

    def _is_processes_range(node: ast.AST, entry_name: str) -> bool:
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "range"
            and len(node.args) == 1
            and not node.keywords
            and isinstance(node.args[0], ast.Subscript)
            and isinstance(node.args[0].value, ast.Name)
            and node.args[0].value.id == entry_name
            and isinstance(node.args[0].slice, ast.Constant)
            and node.args[0].slice.value == "processes"
        )

    expansions = []
    for n in ast.walk(b11):
        if not (
            isinstance(n, ast.Assign)
            and len(n.targets) == 1
            and isinstance(n.targets[0], ast.Name)
            and isinstance(n.value, ast.ListComp)
        ):
            continue
        gens = n.value.generators
        if (
            len(gens) == 2
            and not gens[0].ifs
            and not gens[1].ifs
            and isinstance(gens[0].iter, ast.Name)
            and gens[0].iter.id == width
            and isinstance(gens[0].target, ast.Name)
            and _is_processes_range(gens[1].iter, gens[0].target.id)
        ):
            expansions.append(n)
    _require(
        len(expansions) == 1,
        "W2",
        "expected exactly one expansion assignment — a single list "
        f"comprehension over {width} whose inner iterator is "
        "range(entry[\"processes\"]) and nothing else",
    )
    expansion = expansions[0].targets[0]
    assert isinstance(expansion, ast.Name)
    instances = expansion.id
    exp_rebindings = [
        (name, kind)
        for name, kind, _node in collect_binding_occurrences(b11)
        if name == instances
    ]
    _require(
        len(exp_rebindings) == 1,
        "W2",
        f"{instances!r} is bound {len(exp_rebindings)} times; it may be bound "
        "only by the expansion",
    )

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
        and max_workers.args[0].id == instances,
        "W2",
        f"max_workers must be exactly len({instances}) (the expansion), not "
        f"len({width}); arithmetic on the derived width is unwritable",
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
        and n.iter.id == instances
    ]
    engine_comps = [
        n
        for n in ast.walk(b11)
        if isinstance(n, ast.comprehension)
        and isinstance(n.iter, ast.Name)
        and n.iter.id == instances
        and any(
            isinstance(c, ast.Call) and _callee_name(c) == "make_engine"
            for c in ast.walk(n)
        )
    ]
    builders = engine_loops + engine_comps
    _require(
        len(builders) >= 1,
        "W2",
        f"the engine list must be built by one iteration over {instances}",
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
        f"exactly one iteration over {instances} may construct engines, found "
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
    _check_w2_measured_rate(b11, instances, pool_name)


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
    """Diagnostics: every prefix in DIAGNOSTIC_PREFIXES -- consequence 3's four,
    plus `B11 diagnostics=` from the host/storage diagnostics slice (five)."""
    for prefix in DIAGNOSTIC_PREFIXES:
        _require(
            prefix in src,
            "W4",
            f"missing diagnostic prefix {prefix!r}; the assertion message and the "
            "printed lines must carry the derivation",
        )


# --------------------------------------------------------------------------
# B11D1-B11D5 — the reported-only host/storage diagnostics
# (design/slices/b11-host-diagnostics, FP-B11HD-1..5).  Five more module-level
# `check_<ID>` functions over plain source text, on exactly the same terms as
# the rules above: every literal the guard trusts is written HERE, so a matched
# edit to the benchmark and to CLEAN_BENCH still fails.
# --------------------------------------------------------------------------

B11_CANONICAL_PREFIX = "B11 diagnostics="
B11_CANONICAL_UNAVAILABLE = "unavailable"
B11_CANONICAL_FIELDS = (
    "combined_rate_per_sec",
    "serial_commit_ms",
    "combined_over_single",
    "writer_elapsed_rows",
    "host_steal_usec",
    "host_psi_cpu_some_usec",
    "host_psi_cpu_full_usec",
    "host_psi_io_some_usec",
    "host_psi_io_full_usec",
    "host_psi_memory_some_usec",
    "host_psi_memory_full_usec",
    "storage_pgdata_path",
    "storage_filesystem",
    "storage_mount_source",
    "storage_mount_root",
    "storage_mount_point",
    "storage_device_majmin",
    "storage_block_device",
    "storage_rotational",
    "storage_scheduler",
    "storage_model",
)
B11_PARSER_MODULE = "services.gateway.tests.b1_reference_profile"
B11_HOST_PARSERS = (
    "counter_delta",
    "parse_proc_stat_steal_ticks",
    "parse_psi_total",
    "steal_ticks_to_usec",
)
B11_HOST_SOURCES = ("/proc/stat", "/proc/pressure")
B11_CLOCK_TICK_NAME = "SC_CLK_TCK"
B11_STORAGE_FUNCTIONS = (
    "_decode_b11_mountinfo_field",
    "_parse_b11_container_mount_output",
    "_mountinfo_record_for_path",
    "_parse_b11_container_block_output",
    "_exec_b11_container_text",
    "_read_b11_container_block_identity",
    "_read_b11_storage_identity",
)
B11_DIAGNOSTIC_FUNCTIONS = (
    "_encode_b11_value",
    "_writer_instance_label",
    "_serialize_writer_elapsed_rows",
    "_serialize_b11_diagnostics",
    "_read_b11_host_snapshot",
    "_b11_host_delta_values",
) + B11_STORAGE_FUNCTIONS
# Calls that must never appear inside a timed loop (B11's own row loop or the
# single-writer diagnostic loop).
B11_TIMED_LOOP_FORBIDDEN_CALLS = frozenset(
    B11_DIAGNOSTIC_FUNCTIONS
    + ("print", "read_text", "write_text", "exec_run", "get_wrapped_container",
       "perf_counter", "sysconf", "quote")
)
# Only these exception types may be caught in the benchmark tier: a bare
# `except`/`except Exception` would swallow a serializer or schema defect and
# report it as an environmental `unavailable`.
B11_ALLOWED_EXCEPTIONS = frozenset(
    {"OSError", "ValueError", "DockerException", "SQLAlchemyError", "AssertionError"}
)
B11_EXEC_KWARGS = (
    ("stdout", True),
    ("stderr", False),
    ("stdin", False),
    ("tty", False),
    ("privileged", False),
    ("user", "postgres"),
    ("detach", False),
    ("stream", False),
    ("socket", False),
    ("environment", None),
    ("workdir", None),
    ("demux", False),
)
B11_FORBIDDEN_STORAGE_TOKENS = (
    "/proc",
    "/sys",
    "nsenter",
    "pid_mode",
    "SYS_PTRACE",
    "security_opt",
    "cap_add",
    "GraphDriver",
    "Mounts",
    "docker.sock",
)
B11_FORBIDDEN_STORAGE_KEYWORDS = frozenset(
    {"pid_mode", "security_opt", "cap_add", "cap_drop", "privileged", "network_mode",
     "userns_mode", "devices", "volumes", "mounts"}
)
# The guard's own copies of the two closed scripts.  Independent of the
# benchmark file and of CLEAN_BENCH on purpose: changing the PGDATA
# validation, the in-container resolution, the framing, the mountinfo path,
# the major:minor validation, the container sysfs paths, the partition mapping
# or the unique-device-mapper-slave rule must fail here.
B11_MOUNT_SCRIPT = r"""
pgdata="$1"
case "$pgdata" in
    /*) ;;
    *) exit 2 ;;
esac
resolved="$(readlink -f "$pgdata" 2>/dev/null)" || exit 2
[ -n "$resolved" ] || exit 2
printf 'pgdata_resolved=%s\n' "$resolved"
cat /proc/self/mountinfo
""".strip()
B11_BLOCK_SCRIPT = r"""
majmin="$1"
case "$majmin" in
    *[!0-9:]*|:*|*:|*:*:*) exit 2 ;;
    [0-9]*:[0-9]*) ;;
    *) exit 2 ;;
esac
device="$(readlink -f "/sys/dev/block/$majmin" 2>/dev/null)" || exit 0
[ -n "$device" ] || exit 0
candidate="$device"
if [ -f "$candidate/partition" ]; then
    candidate="$(dirname "$candidate")" || exit 0
fi
case "$(basename "$candidate")" in
    dm-*)
        # majmin was copied above; replacing $1 here is intentional.
        set -- "$candidate"/slaves/*
        if [ "$#" -eq 1 ] && [ -e "$1" ]; then
            slave="$(readlink -f "$1" 2>/dev/null)" || slave=""
            if [ -n "$slave" ]; then
                candidate="$slave"
                if [ -f "$candidate/partition" ]; then
                    candidate="$(dirname "$candidate")" || exit 0
                fi
            fi
        fi
        ;;
esac
name="$(basename "$candidate")" || exit 0
[ -n "$name" ] && printf 'block_device=%s\n' "$name"
for spec in rotational:queue/rotational scheduler:queue/scheduler model:device/model; do
    key="${spec%%:*}"
    rel="${spec#*:}"
    [ -r "$candidate/$rel" ] || continue
    value="$(cat "$candidate/$rel" 2>/dev/null)" || continue
    [ -n "$value" ] || continue
    printf '%s=%s\n' "$key" "$value"
done
""".strip()


def _module_function(tree: ast.Module, name: str, rule: str) -> ast.FunctionDef:
    nodes = [
        n
        for n in tree.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name
    ]
    _require(len(nodes) == 1, rule, f"expected exactly one module-level `def {name}`")
    node = nodes[0]
    assert isinstance(node, ast.FunctionDef)
    return node


def _module_constant(tree: ast.Module, name: str, rule: str) -> ast.AST:
    values = [
        n.value
        for n in tree.body
        if isinstance(n, ast.Assign)
        and len(n.targets) == 1
        and isinstance(n.targets[0], ast.Name)
        and n.targets[0].id == name
    ]
    _require(len(values) == 1, rule, f"expected exactly one `{name} = ...` constant")
    return values[0]


def _stripped_string_constant(node: ast.AST, rule: str, what: str) -> str:
    """The text of a `\"\"\"...\"\"\".strip()` module constant."""
    _require(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "strip"
        and not node.args
        and not node.keywords
        and isinstance(node.func.value, ast.Constant)
        and isinstance(node.func.value.value, str),
        rule,
        f"{what} must be one string literal followed by .strip()",
    )
    assert isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    assert isinstance(node.func.value, ast.Constant)
    return node.func.value.value.strip()


def _block_positions(fn: ast.AST) -> dict[int, tuple[int, int]]:
    """`id(statement) -> (id(owning block list), index in that block)`."""
    out: dict[int, tuple[int, int]] = {}
    for node in ast.walk(fn):
        for _field, value in ast.iter_fields(node):
            if not isinstance(value, list):
                continue
            for index, item in enumerate(value):
                if isinstance(item, ast.stmt):
                    out[id(item)] = (id(value), index)
    return out


def _enclosing_statement(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> ast.stmt:
    cur: ast.AST | None = node
    while cur is not None and not isinstance(cur, ast.stmt):
        cur = parents.get(cur)
    assert isinstance(cur, ast.stmt)
    return cur


def _docstring_constants(tree: ast.AST) -> set[int]:
    """Ids of every docstring Constant, so prose about a path is not a read."""
    out: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(
            node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            continue
        first = node.body[0] if node.body else None
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            out.add(id(first.value))
    return out


def _own_scope_nodes(fn: ast.AST) -> list[ast.AST]:
    """Nodes of `fn` itself, excluding every nested function body."""
    nested = [
        n
        for n in ast.walk(fn)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)) and n is not fn
    ]
    inner = set()
    for node in nested:
        for child in ast.walk(node):
            inner.add(id(child))
    return [n for n in ast.walk(fn) if id(n) not in inner]


def _calls_named(scope: ast.AST, name: str) -> list[ast.Call]:
    return [
        n
        for n in ast.walk(scope)
        if isinstance(n, ast.Call) and _callee_name(n) == name
    ]


def check_B11D1(src: str) -> None:
    """FP-B11HD-1: one canonical, comma-safe, fixed-prefix line before the bar."""
    tree = ast.parse(src)
    prefix = _module_constant(tree, "B11_DIAGNOSTIC_PREFIX", "B11D1")
    _require(
        isinstance(prefix, ast.Constant) and prefix.value == B11_CANONICAL_PREFIX,
        "B11D1",
        f"B11_DIAGNOSTIC_PREFIX must be exactly {B11_CANONICAL_PREFIX!r}",
    )
    unavailable = _module_constant(tree, "B11_DIAGNOSTIC_UNAVAILABLE", "B11D1")
    _require(
        isinstance(unavailable, ast.Constant)
        and unavailable.value == B11_CANONICAL_UNAVAILABLE,
        "B11D1",
        f"B11_DIAGNOSTIC_UNAVAILABLE must be exactly {B11_CANONICAL_UNAVAILABLE!r}",
    )
    fields = _module_constant(tree, "B11_DIAGNOSTIC_FIELDS", "B11D1")
    _require(
        isinstance(fields, ast.Tuple)
        and all(
            isinstance(e, ast.Constant) and isinstance(e.value, str)
            for e in fields.elts
        ),
        "B11D1",
        "B11_DIAGNOSTIC_FIELDS must be a tuple of string literals",
    )
    assert isinstance(fields, ast.Tuple)
    declared = tuple(e.value for e in fields.elts)
    _require(
        declared == B11_CANONICAL_FIELDS,
        "B11D1",
        f"B11_DIAGNOSTIC_FIELDS {declared} != the pinned 21-field schema "
        f"{B11_CANONICAL_FIELDS}",
    )

    # The two serializers' separators: a comma joins top-level fields, a `+`
    # joins writer entries.  Comma-joining the writer entries would forge 7
    # extra top-level fields.
    for name, separator in (
        ("_serialize_b11_diagnostics", ","),
        ("_serialize_writer_elapsed_rows", "+"),
    ):
        fn = _module_function(tree, name, "B11D1")
        joins = _calls_named(fn, "join")
        _require(
            len(joins) == 1
            and isinstance(joins[0].func, ast.Attribute)
            and isinstance(joins[0].func.value, ast.Constant)
            and joins[0].func.value.value == separator,
            "B11D1",
            f"{name} must join exactly once, on {separator!r}",
        )

    b11 = _b11_function_in(tree)
    prints = _calls_named(b11, "print")
    canonical = [
        n
        for n in prints
        if len(n.args) == 1
        and isinstance(n.args[0], ast.Call)
        and _callee_name(n.args[0]) == "_serialize_b11_diagnostics"
    ]
    _require(
        len(prints) == len(DIAGNOSTIC_PREFIXES) and len(canonical) == 1,
        "B11D1",
        f"{B11_TEST_NAME} must print exactly {len(DIAGNOSTIC_PREFIXES)} diagnostic "
        f"lines, exactly one of which is the canonical serializer's; found "
        f"{len(prints)} prints and {len(canonical)} canonical",
    )
    asserts = [n for n in ast.walk(b11) if isinstance(n, ast.Assert)]
    _require(
        len(asserts) == 1 and canonical[0].lineno < asserts[0].lineno,
        "B11D1",
        "the canonical line must be printed before the threshold assertion, so a "
        "completed below-threshold measurement emits the identical schema",
    )
    serialized = canonical[0].args[0]
    assert isinstance(serialized, ast.Call)
    _require(
        len(serialized.args) == 1
        and isinstance(serialized.args[0], ast.Name)
        and not serialized.keywords,
        "B11D1",
        "the canonical line is serialized from exactly one mapping name",
    )
    mapping_name = serialized.args[0]
    assert isinstance(mapping_name, ast.Name)
    assigns = [
        n
        for n in ast.walk(b11)
        if isinstance(n, ast.Assign)
        and len(n.targets) == 1
        and isinstance(n.targets[0], ast.Name)
        and n.targets[0].id == mapping_name.id
    ]
    _require(
        len(assigns) == 1 and isinstance(assigns[0].value, ast.Dict),
        "B11D1",
        f"{mapping_name.id!r} must be built by exactly one dict literal",
    )
    mapping = assigns[0].value
    assert isinstance(mapping, ast.Dict)
    _require(
        all(isinstance(k, ast.Constant) and isinstance(k.value, str) for k in mapping.keys),
        "B11D1",
        "every canonical field key must be a string literal",
    )
    keys = tuple(k.value for k in mapping.keys)
    _require(
        keys == B11_CANONICAL_FIELDS,
        "B11D1",
        f"the canonical mapping names {keys}, not the pinned schema in order — a "
        "dropped, duplicated, added or reordered field",
    )


def check_B11D2(src: str) -> None:
    """FP-B11HD-2: the host readings come from B1's shipped parsers and real /proc."""
    tree = ast.parse(src)
    shared = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.ImportFrom) and n.module == B11_PARSER_MODULE
    ]
    _require(
        len(shared) == 1,
        "B11D2",
        f"expected exactly one `from {B11_PARSER_MODULE} import ...`, found "
        f"{len(shared)}",
    )
    imported = shared[0]
    _require(
        imported.level == 0
        and tuple(sorted(a.name for a in imported.names)) == tuple(sorted(B11_HOST_PARSERS))
        and all(a.asname is None for a in imported.names),
        "B11D2",
        f"the shared import must name exactly {sorted(B11_HOST_PARSERS)}, unaliased "
        "and absolute",
    )
    for node in ast.walk(tree):
        modules = []
        if isinstance(node, ast.Import):
            modules = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            modules = [node.module or ""]
        for module in modules:
            _require(
                not module.startswith("importlib")
                and module != "subprocess"
                and "test_b1_ingest_burst" not in module,
                "B11D2",
                f"{module!r} is a dynamic-load or live-B1 route; the shared parsers "
                "are imported by name and nothing else",
            )
    called = {_callee_name(n) for n in ast.walk(tree) if isinstance(n, ast.Call)}
    for parser in B11_HOST_PARSERS:
        _require(
            parser in called,
            "B11D2",
            f"the shared parser {parser}() is imported but never exercised",
        )
    for name, kind, node in collect_binding_occurrences(tree):
        if name in B11_HOST_PARSERS:
            _require(
                kind == "import",
                "B11D2",
                f"{name!r} is bound by {kind} at line {getattr(node, 'lineno', '?')}: "
                "a local copy of a shared parser drifts from the shipped one",
            )
    path_bindings = [
        (name, kind) for name, kind, _n in collect_binding_occurrences(tree) if name == "Path"
    ]
    _require(
        path_bindings == [("Path", "import")],
        "B11D2",
        f"exactly one module-scope `Path` import is admitted; found {path_bindings}",
    )

    reader = _module_function(tree, "_read_b11_host_snapshot", "B11D2")
    _require(
        not reader.args.args
        and not reader.args.posonlyargs
        and [a.arg for a in reader.args.kwonlyargs] == ["proc_stat_path", "psi_root"],
        "B11D2",
        "_read_b11_host_snapshot takes exactly the two keyword-only source paths",
    )
    defaults = []
    for default in reader.args.kw_defaults:
        _require(
            isinstance(default, ast.Call)
            and isinstance(default.func, ast.Name)
            and default.func.id == "Path"
            and len(default.args) == 1
            and isinstance(default.args[0], ast.Constant),
            "B11D2",
            "each host source default must be Path(<literal>)",
        )
        assert isinstance(default, ast.Call) and isinstance(default.args[0], ast.Constant)
        defaults.append(default.args[0].value)
    _require(
        tuple(defaults) == B11_HOST_SOURCES,
        "B11D2",
        f"the declared host sources {tuple(defaults)} != {B11_HOST_SOURCES}; a "
        "reader pointed at a fixture-only root proves nothing about this host",
    )

    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "os"
        ):
            _require(
                node.attr in ("cpu_count", "sysconf"),
                "B11D2",
                f"os.{node.attr} at line {node.lineno} is outside the narrow "
                "os.cpu_count()/os.sysconf(\"SC_CLK_TCK\") exception",
            )
    sysconf = [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "sysconf"
    ]
    _require(
        len(sysconf) == 1
        and len(sysconf[0].args) == 1
        and not sysconf[0].keywords
        and isinstance(sysconf[0].args[0], ast.Constant)
        and sysconf[0].args[0].value == B11_CLOCK_TICK_NAME,
        "B11D2",
        f"exactly one os.sysconf({B11_CLOCK_TICK_NAME!r}) call is admitted",
    )
    b11 = _b11_function_in(tree)
    _require(
        any(n is sysconf[0] for n in ast.walk(b11)),
        "B11D2",
        "the clock-tick rate must be read inside the benchmark, at its boundary",
    )

    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        _require(
            node.type is not None,
            "B11D2",
            f"bare `except` at line {node.lineno}: a harness defect would be "
            "reported as an environmental `unavailable`",
        )
        caught = node.type.elts if isinstance(node.type, ast.Tuple) else [node.type]
        for entry in caught:
            _require(
                isinstance(entry, ast.Name) and entry.id in B11_ALLOWED_EXCEPTIONS,
                "B11D2",
                f"caught exception at line {node.lineno} is outside "
                f"{sorted(B11_ALLOWED_EXCEPTIONS)}",
            )


def check_B11D3(src: str) -> None:
    """FP-B11HD-3: storage identity comes from the exact target container only."""
    tree = ast.parse(src)
    b11 = _b11_function_in(tree)
    parents = _parent_map(tree)

    def _fixture_subscripts(key: str) -> list[ast.Subscript]:
        return [
            n
            for n in ast.walk(tree)
            if isinstance(n, ast.Subscript)
            and isinstance(n.value, ast.Name)
            and n.value.id == "scale_pg"
            and isinstance(n.slice, ast.Constant)
            and n.slice.value == key
        ]

    handles = _fixture_subscripts("container")
    _require(
        len(handles) == 1,
        "B11D3",
        f'exactly one scale_pg["container"] read is admitted, found {len(handles)}',
    )
    holder = parents.get(handles[0])
    _require(
        isinstance(holder, ast.Call)
        and _callee_name(holder) == "_read_b11_storage_identity"
        and len(holder.args) == 2
        and holder.args[0] is handles[0]
        and not holder.keywords,
        "B11D3",
        'scale_pg["container"] may only be the first argument of '
        "_read_b11_storage_identity(container, pgdata_path)",
    )
    _require(
        any(n is holder for n in ast.walk(b11)),
        "B11D3",
        "the storage identity must be resolved inside the benchmark itself",
    )

    engines = _fixture_subscripts("engine")
    _require(
        len(engines) == 1,
        "B11D3",
        f'exactly one scale_pg["engine"] read is admitted, found {len(engines)}',
    )
    engine_use = parents.get(engines[0])
    _require(
        isinstance(engine_use, ast.Attribute)
        and engine_use.attr == "connect"
        and engine_use.value is engines[0],
        "B11D3",
        'the PGDATA query must open its connection on scale_pg["engine"]',
    )
    queries = [
        n
        for n in ast.walk(b11)
        if isinstance(n, ast.Call)
        and _callee_name(n) == "text"
        and n.args
        and isinstance(n.args[0], ast.Constant)
        and "current_setting" in str(n.args[0].value)
    ]
    _require(
        len(queries) == 1
        and queries[0].args[0].value == "SELECT current_setting('data_directory')",
        "B11D3",
        "PGDATA must come from the running server's own "
        "current_setting('data_directory'), not from an assumed image default",
    )

    wrapped = _calls_named(tree, "get_wrapped_container")
    _require(
        len(wrapped) == 1
        and isinstance(wrapped[0].func, ast.Attribute)
        and isinstance(wrapped[0].func.value, ast.Name)
        and wrapped[0].func.value.id == "container"
        and not wrapped[0].args
        and not wrapped[0].keywords,
        "B11D3",
        "exactly one get_wrapped_container() call, on the signed `container` "
        "parameter, is admitted",
    )
    resolver = _module_function(tree, "_read_b11_storage_identity", "B11D3")
    _require(
        [a.arg for a in resolver.args.args] == ["container", "pgdata_path"],
        "B11D3",
        "_read_b11_storage_identity(container, pgdata_path) is the signed handle "
        "boundary",
    )
    _require(
        any(n is wrapped[0] for n in ast.walk(resolver)),
        "B11D3",
        "the wrapped container may only be obtained inside "
        "_read_b11_storage_identity",
    )

    execs = _calls_named(tree, "exec_run")
    _require(
        len(execs) == 1
        and isinstance(execs[0].func, ast.Attribute)
        and isinstance(execs[0].func.value, ast.Name)
        and execs[0].func.value.id == "wrapped_container",
        "B11D3",
        "exactly one exec_run call, on the signed `wrapped_container` parameter",
    )
    runner = _module_function(tree, "_exec_b11_container_text", "B11D3")
    _require(
        [a.arg for a in runner.args.args] == ["wrapped_container", "argv"],
        "B11D3",
        "_exec_b11_container_text(wrapped_container, argv) is the only exec route",
    )
    _require(
        any(n is execs[0] for n in ast.walk(runner)),
        "B11D3",
        "exec_run may only be called inside _exec_b11_container_text",
    )
    call = execs[0]
    _require(
        len(call.args) == 1
        and isinstance(call.args[0], ast.Name)
        and call.args[0].id == "argv",
        "B11D3",
        "exec_run takes exactly the validated argv list",
    )
    kwargs = []
    for kw in call.keywords:
        _require(
            kw.arg is not None and isinstance(kw.value, ast.Constant),
            "B11D3",
            "every exec_run keyword must be a named constant",
        )
        assert isinstance(kw.value, ast.Constant)
        kwargs.append((kw.arg, kw.value.value))
    _require(
        tuple(kwargs) == B11_EXEC_KWARGS,
        "B11D3",
        f"exec_run keywords {tuple(kwargs)} != the unprivileged pinned set "
        f"{B11_EXEC_KWARGS}",
    )

    # Handle closure: neither signed name may be rebound, read anywhere else,
    # or carry any other attribute.
    for name, allowed_attr in (
        ("container", "get_wrapped_container"),
        ("wrapped_container", "exec_run"),
    ):
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id == name
            ):
                continue
            _require(
                node.attr == allowed_attr,
                "B11D3",
                f"{name}.{node.attr} at line {node.lineno}: the only admitted "
                f"attribute on that handle is {allowed_attr}",
            )
    handle_bindings = sorted(
        (name, kind)
        for name, kind, _n in collect_binding_occurrences(tree)
        if name in ("container", "wrapped_container")
    )
    _require(
        handle_bindings
        == [
            ("container", "arg"),
            ("wrapped_container", "arg"),
            ("wrapped_container", "arg"),
            ("wrapped_container", "assign"),
        ],
        "B11D3",
        f"container-handle bindings {handle_bindings} are not exactly the signed "
        "parameters plus the one get_wrapped_container() result",
    )
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)):
            continue
        if node.id not in ("container", "wrapped_container"):
            continue
        holder = parents.get(node)
        ok = False
        if isinstance(holder, ast.Attribute):
            ok = holder.value is node
        elif isinstance(holder, ast.Call):
            ok = (
                bool(holder.args)
                and holder.args[0] is node
                and _callee_name(holder)
                in ("_exec_b11_container_text", "_read_b11_container_block_identity")
            )
        _require(
            ok,
            "B11D3",
            f"{node.id!r} at line {node.lineno} escapes the signed route: a handle "
            "may only be used as the pinned attribute receiver or as the first "
            "argument of the two signed helpers",
        )

    mount_script = _stripped_string_constant(
        _module_constant(tree, "B11_CONTAINER_MOUNT_SCRIPT", "B11D3"),
        "B11D3",
        "B11_CONTAINER_MOUNT_SCRIPT",
    )
    block_script = _stripped_string_constant(
        _module_constant(tree, "B11_CONTAINER_BLOCK_SCRIPT", "B11D3"),
        "B11D3",
        "B11_CONTAINER_BLOCK_SCRIPT",
    )
    _require(
        mount_script == B11_MOUNT_SCRIPT,
        "B11D3",
        "the container mount script drifted from the pinned closed script",
    )
    _require(
        block_script == B11_BLOCK_SCRIPT,
        "B11D3",
        "the container block script drifted from the pinned closed script",
    )

    for owner, script_name, frame in (
        ("_read_b11_storage_identity", "B11_CONTAINER_MOUNT_SCRIPT", "b11-mount"),
        ("_read_b11_container_block_identity", "B11_CONTAINER_BLOCK_SCRIPT", "b11-block"),
    ):
        fn = _module_function(tree, owner, "B11D3")
        argvs = [
            n
            for n in ast.walk(fn)
            if isinstance(n, ast.List)
            and n.elts
            and isinstance(n.elts[0], ast.Constant)
            and n.elts[0].value == "/bin/sh"
        ]
        _require(
            len(argvs) == 1,
            "B11D3",
            f"{owner} must build exactly one exec argv, found {len(argvs)}",
        )
        elts = argvs[0].elts
        _require(
            len(elts) == 5
            and isinstance(elts[1], ast.Constant)
            and elts[1].value == "-c"
            and isinstance(elts[2], ast.Name)
            and elts[2].id == script_name
            and isinstance(elts[3], ast.Constant)
            and elts[3].value == frame
            and isinstance(elts[4], ast.Name),
            "B11D3",
            f"{owner}'s argv must be the exact closed shape "
            f'["/bin/sh", "-c", {script_name}, "{frame}", <validated value>]',
        )

    docstrings = _docstring_constants(tree)
    for name in B11_STORAGE_FUNCTIONS + (B11_TEST_NAME,):
        fn = (
            b11
            if name == B11_TEST_NAME
            else _module_function(tree, name, "B11D3")
        )
        for node in ast.walk(fn):
            if id(node) in docstrings:
                continue
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                for token in B11_FORBIDDEN_STORAGE_TOKENS:
                    _require(
                        token not in node.value,
                        "B11D3",
                        f"{name} mentions {token!r} at line {node.lineno}: storage "
                        "bytes come only from the two closed container scripts, "
                        "never from the test process or a Docker inspect field",
                    )
            if isinstance(node, ast.Call):
                for kw in node.keywords:
                    _require(
                        kw.arg not in B11_FORBIDDEN_STORAGE_KEYWORDS
                        or node is execs[0],
                        "B11D3",
                        f"{name} passes {kw.arg!r} at line {node.lineno}: no "
                        "privilege, capability, namespace or helper-container "
                        "option is admitted",
                    )


def check_B11D4(src: str) -> None:
    """FP-B11HD-4: every diagnostic read lies outside the measured work."""
    tree = ast.parse(src)
    b11 = _b11_function_in(tree)
    parents = _parent_map(b11)
    positions = _block_positions(b11)

    def _statement_of(node: ast.AST) -> ast.stmt:
        return _enclosing_statement(node, parents)

    storage_calls = _calls_named(b11, "_read_b11_storage_identity")
    _require(len(storage_calls) == 1, "B11D4", "one storage resolution per run")
    query_calls = [
        n for n in ast.walk(b11) if isinstance(n, ast.Call) and _callee_name(n) == "one"
    ]
    _require(len(query_calls) == 1, "B11D4", "one data_directory query per run")
    engine_calls = _calls_named(b11, "make_engine")
    _require(len(engine_calls) == 1, "B11D4", "one make_engine call site")
    connect_calls = [
        n
        for n in _calls_named(b11, "connect")
        if not (
            isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Subscript)
        )
    ]
    warmup_maps = [
        n
        for n in _calls_named(b11, "map")
        if len(n.args) == 2
        and isinstance(n.args[0], ast.Name)
        and n.args[0].id == "_warmup"
    ]
    _require(len(warmup_maps) == 1, "B11D4", "one row-warmup map call")
    storage_line = storage_calls[0].lineno
    _require(
        query_calls[0].lineno < storage_line,
        "B11D4",
        "the server's data_directory must be read before the storage identity",
    )
    _require(
        storage_line < engine_calls[0].lineno,
        "B11D4",
        "storage resolution must finish before the first B11 engine is built",
    )
    for node in connect_calls:
        _require(
            storage_line < node.lineno,
            "B11D4",
            "storage resolution must finish before any connection warmup",
        )
    _require(
        storage_line < warmup_maps[0].lineno,
        "B11D4",
        "storage resolution must finish before the row warmup",
    )

    prealloc = [
        n
        for n in ast.walk(b11)
        if isinstance(n, ast.Assign)
        and len(n.targets) == 1
        and isinstance(n.targets[0], ast.Name)
        and isinstance(n.value, ast.BinOp)
        and isinstance(n.value.op, ast.Mult)
        and isinstance(n.value.left, ast.List)
        and len(n.value.left.elts) == 1
        and isinstance(n.value.left.elts[0], ast.Constant)
        and n.value.left.elts[0].value is None
    ]
    _require(
        len(prealloc) == 1,
        "B11D4",
        "exactly one `[None] * <width>` writer side channel must be preallocated",
    )
    side_channel_name = prealloc[0].targets[0]
    assert isinstance(side_channel_name, ast.Name)
    width = prealloc[0].value
    assert isinstance(width, ast.BinOp)
    _require(
        isinstance(width.right, ast.Call)
        and isinstance(width.right.func, ast.Name)
        and width.right.func.id == "len"
        and len(width.right.args) == 1
        and isinstance(width.right.args[0], ast.Name),
        "B11D4",
        "the side channel must be exactly as wide as the derived writer set",
    )
    instances_name = width.right.args[0]
    assert isinstance(instances_name, ast.Name)
    _require(
        storage_line < prealloc[0].lineno < engine_calls[0].lineno,
        "B11D4",
        "the side channel is preallocated after storage resolution and before the "
        "engines",
    )

    host_reads = _calls_named(b11, "_read_b11_host_snapshot")
    _require(
        len(host_reads) == 2,
        "B11D4",
        f"exactly two host snapshots bracket the window, found {len(host_reads)}",
    )
    maps = [
        n
        for n in _calls_named(b11, "map")
        if len(n.args) == 2
        and isinstance(n.args[0], ast.Name)
        and n.args[0].id == WRITER_FUNC_NAME
    ]
    _require(len(maps) == 1, "B11D4", "one timed executor map call")
    map_stmt = _statement_of(maps[0])
    map_block, map_index = positions[id(map_stmt)]
    ordered = [
        (host_reads[0], map_index - 2, "the opening host read"),
        (None, map_index - 1, "the timer start"),
        (None, map_index, "the executor map"),
        (None, map_index + 1, "the in-place elapsed assignment"),
        (host_reads[1], map_index + 2, "the closing host read"),
    ]
    for node, index, what in ordered:
        if node is None:
            continue
        stmt = _statement_of(node)
        _require(
            positions[id(stmt)] == (map_block, index),
            "B11D4",
            f"{what} must be statement {index} of the timed block, immediately "
            "adjacent to the window — nothing may lie between the samples",
        )
    tick_calls = [
        n
        for n in ast.walk(b11)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "sysconf"
    ]
    _require(
        len(tick_calls) == 1 and tick_calls[0].lineno < host_reads[0].lineno,
        "B11D4",
        "the clock-tick rate is read before the opening host snapshot",
    )
    _require(
        host_reads[0].lineno > warmup_maps[0].lineno,
        "B11D4",
        "the opening host read follows the row warmup",
    )

    # The writer: two boundary clocks and one distinct-index assignment, both
    # outside the counted row loop, and the recorded count is the same bare
    # counter the writer returns.
    writer = [
        n
        for n in ast.walk(b11)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        and n.name == WRITER_FUNC_NAME
    ][0]
    assert isinstance(writer, ast.FunctionDef)
    writer_positions = _block_positions(writer)
    body = writer.body
    withs = [n for n in body if isinstance(n, ast.With)]
    _require(len(withs) == 1, "B11D4", "the writer opens exactly one session block")
    with_index = body.index(withs[0])
    _require(
        with_index >= 1 and len(body) >= with_index + 3,
        "B11D4",
        "the writer's session block must be surrounded by its opening clock, its "
        "one side-channel assignment and the unchanged return",
    )
    opening = body[with_index - 1]
    _require(
        isinstance(opening, ast.Assign)
        and len(opening.targets) == 1
        and isinstance(opening.targets[0], ast.Name)
        and _is_perf_counter_call(opening.value),
        "B11D4",
        "the writer's opening clock must be the statement directly preceding its "
        "session block",
    )
    writer_t0 = opening.targets[0]
    assert isinstance(writer_t0, ast.Name)
    closing = body[with_index + 1]
    returns = [n for n in body if isinstance(n, ast.Return)]
    _require(
        len(returns) == 1 and body[with_index + 2] is returns[0],
        "B11D4",
        "the writer's side-channel assignment must sit between the closed session "
        "and the unchanged return",
    )
    counter = returns[0].value
    assert isinstance(counter, ast.Name)
    _require(
        isinstance(closing, ast.Assign)
        and len(closing.targets) == 1
        and isinstance(closing.targets[0], ast.Subscript)
        and isinstance(closing.targets[0].value, ast.Name)
        and closing.targets[0].value.id == side_channel_name.id
        and isinstance(closing.targets[0].slice, ast.Name)
        and closing.targets[0].slice.id == writer.args.args[0].arg,
        "B11D4",
        f"the writer must write exactly {side_channel_name.id}[<its own index>]",
    )
    assert isinstance(closing, ast.Assign)
    recorded = closing.value
    _require(
        isinstance(recorded, ast.Tuple)
        and len(recorded.elts) == 2
        and isinstance(recorded.elts[0], ast.BinOp)
        and isinstance(recorded.elts[0].op, ast.Sub)
        and _is_perf_counter_call(recorded.elts[0].left)
        and isinstance(recorded.elts[0].right, ast.Name)
        and recorded.elts[0].right.id == writer_t0.id
        and isinstance(recorded.elts[1], ast.Name)
        and recorded.elts[1].id == counter.id,
        "B11D4",
        "the recorded pair must be exactly "
        "(time.perf_counter() - <opening clock>, <the returned counter>): neither "
        "member may be fabricated independently",
    )
    subscript_assigns = [
        n
        for n in ast.walk(writer)
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Subscript) for t in n.targets)
    ]
    _require(
        len(subscript_assigns) == 1 and subscript_assigns[0] is closing,
        "B11D4",
        "the writer writes the side channel exactly once",
    )
    _require(
        writer_positions[id(closing)][0] == id(body),
        "B11D4",
        "the side-channel assignment must stay in the writer's own body, never "
        "inside the counted row loop",
    )
    clocks = [n for n in ast.walk(writer) if _is_perf_counter_call(n)]
    _require(
        len(clocks) == 2,
        "B11D4",
        f"the writer takes exactly two boundary clock reads, found {len(clocks)}",
    )

    # Neither timed loop may contain diagnostic work.
    for loop in [n for n in ast.walk(b11) if isinstance(n, (ast.For, ast.AsyncFor))]:
        for node in ast.walk(loop):
            if not isinstance(node, ast.Call):
                continue
            name = _callee_name(node) or ""
            _require(
                name not in B11_TIMED_LOOP_FORBIDDEN_CALLS,
                "B11D4",
                f"{name}() at line {node.lineno} lies inside a timed loop; every "
                "proc, sysfs, container, formatting and printing operation stays "
                "outside the measured work",
            )

    serializers = _calls_named(b11, "_serialize_writer_elapsed_rows")
    _require(
        len(serializers) == 1
        and len(serializers[0].args) == 2
        and isinstance(serializers[0].args[0], ast.Name)
        and serializers[0].args[0].id == instances_name.id
        and isinstance(serializers[0].args[1], ast.Name)
        and serializers[0].args[1].id == side_channel_name.id,
        "B11D4",
        "the per-writer report must be serialized from the manifest-derived "
        "instances and the preallocated side channel, never from the executor "
        "result",
    )


def check_B11D5(src: str, notes: str) -> None:
    """FP-B11HD-5: the diagnostics decide no threshold outcome, and every fixed
    value stands.

    Structural only.  It owns the absence of a diagnostic-conditioned *outcome*
    branch -- no diagnostic name may reach the bar, an `if`/`while`/ternary
    test, a skip or a retry -- and the fixed 800/50/100 row counts.  It does not
    own or deny anything about the deleted stall classification: FP-BOD-4
    removed it, and no module-level branch on a diagnostic value remains.
    """
    tree = ast.parse(src)
    b11 = _b11_function_in(tree)
    _require(
        not b11.decorator_list,
        "B11D5",
        "the benchmark carries no marker: no skip, xfail, rerun or conditional",
    )
    asserts = [n for n in ast.walk(b11) if isinstance(n, ast.Assert)]
    _require(
        len(asserts) == 1
        and isinstance(asserts[0].test, ast.Compare)
        and isinstance(asserts[0].test.comparators[0], ast.Constant)
        and asserts[0].test.comparators[0].value == 1000.0,
        "B11D5",
        "the only failure-producing expression remains `rate >= 1000.0`",
    )
    _require(
        not [n for n in _own_scope_nodes(b11) if isinstance(n, (ast.Return, ast.Raise))],
        "B11D5",
        "the benchmark may not return or raise before its bar",
    )
    for node in ast.walk(b11):
        if isinstance(node, ast.Call):
            name = _callee_name(node) or ""
            _require(
                name not in ("skip", "xfail", "importorskip", "exit", "fail"),
                "B11D5",
                f"{name}() at line {node.lineno} would replace the threshold "
                "result with a non-threshold outcome",
            )

    iters = [
        n
        for n in ast.walk(b11)
        if isinstance(n, ast.Assign)
        and len(n.targets) == 1
        and isinstance(n.targets[0], ast.Name)
        and n.targets[0].id == "n_iters"
    ]
    _require(
        len(iters) == 1
        and isinstance(iters[0].value, ast.Constant)
        and iters[0].value.value == 800,
        "B11D5",
        "the timed row count per writer remains 800",
    )
    ranges = sorted(
        n.args[0].value
        for n in _calls_named(b11, "range")
        if len(n.args) == 1 and isinstance(n.args[0], ast.Constant)
    )
    _require(
        ranges == [50, 100],
        "B11D5",
        f"the fixed warmup and single-writer row counts {ranges} != [50, 100]",
    )

    # No branch, guard or assertion may read a diagnostic value.
    diagnostic_names = set()
    for node in ast.walk(b11):
        if not (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
        ):
            continue
        produced = [
            c
            for c in ast.walk(node.value)
            if isinstance(c, ast.Call)
            and (_callee_name(c) or "") in B11_DIAGNOSTIC_FUNCTIONS
        ]
        if produced or isinstance(node.value, ast.Dict):
            diagnostic_names.add(node.targets[0].id)
    for node in ast.walk(b11):
        if isinstance(node, ast.Try):
            for handler in node.handlers:
                for inner in ast.walk(handler):
                    if isinstance(inner, ast.Call):
                        _require(
                            (_callee_name(inner) or "") not in ("skip", "xfail"),
                            "B11D5",
                            "a failed diagnostic read may not skip the benchmark",
                        )
    tests = []
    for node in ast.walk(b11):
        if isinstance(node, (ast.If, ast.While, ast.IfExp)):
            tests.append(node.test)
        elif isinstance(node, ast.Assert):
            tests.append(node.test)
    for test in tests:
        for node in ast.walk(test):
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                _require(
                    node.id not in diagnostic_names,
                    "B11D5",
                    f"a diagnostic value {node.id!r} decides a branch or the bar at "
                    f"line {node.lineno}; `unavailable` is a reportable value, not "
                    "a skip, a retry or a threshold exemption",
                )
    # bench-on-demand FP-BOD-4: and no diagnostic value reaches the bar's
    # MESSAGE either. The stall classification read `host_psi_io_full_usec`
    # here to append a label to an already-red result; that suffix is deleted,
    # and a miss is now the rate assertion with its own message and nothing
    # after it.
    for node in ast.walk(b11):
        if not isinstance(node, ast.Assert) or node.msg is None:
            continue
        for inner in ast.walk(node.msg):
            if isinstance(inner, ast.Name) and isinstance(inner.ctx, ast.Load):
                _require(
                    inner.id not in diagnostic_names,
                    "B11D5",
                    f"a diagnostic value {inner.id!r} reaches the bar's failure "
                    f"message at line {inner.lineno}; a miss is the rate "
                    "assertion and nothing appended to it",
                )

    for phrase in (
        "B11 diagnostics=",
        "inside the running PostgreSQL container",
        "unavailable",
        "reported-only",
    ):
        _require(
            phrase in notes,
            "B11D5",
            f"the B11 manifest notes must declare {phrase!r}: the provenance and "
            "the reported-only status of the new fields are part of the entry",
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
        tree = ast.parse(src)
        parents = _parent_map(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Attribute):
                continue
            if node.attr in FIXTURE_WRITE_ATTRIBUTES:
                # Locality, not just membership: a filesystem write is legal
                # only in the one test that builds throwaway proc/PSI inputs.
                enclosing = _enclosing_module_function(node, parents)
                _require(
                    fname == BENCH_NAME and enclosing == FIXTURE_WRITE_FUNCTION,
                    "A7a",
                    f"fixture-write attribute {node.attr!r} in {fname}"
                    f"{'::' + enclosing if enclosing else ''} at line "
                    f"{node.lineno} is legal only inside "
                    f"{FIXTURE_WRITE_FUNCTION}",
                )
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
    check_B11D1(sources[BENCH_NAME])
    check_B11D2(sources[BENCH_NAME])
    check_B11D3(sources[BENCH_NAME])
    check_B11D4(sources[BENCH_NAME])
    check_B11D5(
        sources[BENCH_NAME],
        read_manifest_isolated(
            bench_dir / "thresholds.yaml", key_path="benchmarks[id=B11].notes"
        ),
    )


# --------------------------------------------------------------------------
# The three positive tests.
# --------------------------------------------------------------------------


def test_b11_declares_exactly_four_writer_processes_matching_shipped_code():
    """(i) the whole object against the guard's literal; (ii) every call site is
    a real production call in the declaring process's own code.
    FP-IG-11: also parse notes for event_*:NNN line references."""
    model = read_manifest_isolated()
    assert model == EXPECTED_CONCURRENCY_MODEL, (
        "B11.concurrency_model differs from EXPECTED_CONCURRENCY_MODEL"
    )
    tables: set[str] = set()
    for wp in model["writer_processes"]:
        tables.update(wp["tables"])
        for site in wp["call_sites"]:
            check_call_site(site, wp["process"], REPO_ROOT)
    assert len(model["writer_processes"]) == 4
    assert model["writers"] == sum(wp["processes"] for wp in model["writer_processes"]) == 7
    assert tables == {"audit_log", "llm_calls"}
    assert {
        wp["process"] for wp in model["writer_processes"] if "llm_calls" in wp["tables"]
    } == {"temporal-worker"}

    # FP-IG-11 notes extension: three event_*:NNN references equal resolved lines.
    notes = read_manifest_isolated(key_path="benchmarks[id=B11].notes")
    import re

    refs = dict(re.findall(r"(event_(?:merged|received|rejected)):(\d+)", notes))
    assert set(refs) == {"event_merged", "event_received", "event_rejected"}, refs
    # Resolve write_audit lines from the shipped file by action string.
    ingest_src = (REPO_ROOT / "services/gateway/gateway/ingest.py").read_text(
        encoding="utf-8"
    )
    lines = ingest_src.splitlines()
    resolved: dict[str, int] = {}
    for i, line in enumerate(lines, start=1):
        if "write_audit(" not in line:
            continue
        # Look ahead a few lines for the action=
        window = "\n".join(lines[i - 1 : i + 5])
        for action in ("event_merged", "event_received", "event_rejected"):
            if f'action="{action}"' in window or f"action='{action}'" in window:
                resolved.setdefault(action, i)
    for action, lineno in refs.items():
        assert action in resolved, f"notes cites {action} but file has no write_audit"
        assert int(lineno) == resolved[action], (
            f"notes {action}:{lineno} != resolved {resolved[action]}"
        )
    # GC-2: those three references are the ONLY line numbers B11 declares. An
    # unparsed one -- the retired "second call site at line 165" prose, say --
    # is a carrier nothing resolves, so it can go stale silently.
    unparsed = re.sub(r"event_(?:merged|received|rejected):\d+", "", notes)
    for pattern in (r"\bline\s+\d+", r"\bat\s+line\b", r"\blines\s+\d+"):
        assert not re.search(pattern, unparsed), (
            f"B11 notes carry an unparsed line reference matching {pattern}"
        )


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


def test_b11_diagnostics_are_reported_only_and_fixed():
    """FP-B11HD-1/3/4/5: the independent, unconstrained source guard.

    The benchmark-tier tests are written under the closed §3.7 inventory, so
    this one owns the real AST proof: the fifth fixed prefix and the exact
    21-field schema, the direct B1 parser provenance and the single `Path`
    binding, the honest per-writer side channel with the shipped W2 chain
    untouched, the target-container exec route with every test-process,
    privileged and helper-container substitute rejected, storage resolution
    before warmup, the print before the bar, the unchanged threshold, writer,
    pool, durability and fixture values, and the absence of any
    diagnostic-conditioned outcome branch, skip, retry or timed-loop read.

    bench-on-demand FP-BOD-4 deleted the stall classifier, so the claim is
    unqualified again: no diagnostic-conditioned branch exists anywhere in the
    benchmark, and nothing follows the bar's own rate message.
    """
    sources = tier_sources()
    src = sources[BENCH_NAME]
    notes = read_manifest_isolated(key_path="benchmarks[id=B11].notes")
    check_B11D1(src)
    check_B11D2(src)
    check_B11D3(src)
    check_B11D4(src)
    check_B11D5(src, notes)
    check_W4(src)
    check_W2(src)
    check_A6(sources)
    check_A7a(sources)
    # The fixture's sole admitted handoff of the exact running container.
    assert '"container": pg' in sources[CONFTEST_NAME], (
        "the seeded fixture must yield the running PostgresContainer B11 inspects"
    )

    # Non-redundancy (slice §3.7): rebinding the handle and reading an
    # attribute that IS in ALLOWED_ATTRIBUTES keeps A7a green, so the
    # provenance guard is not restating a rule another checker already owns.
    rebound = src.replace(
        '    values["storage_pgdata_path"] = _encode_b11_value(pgdata_path)\n',
        '    values["storage_pgdata_path"] = _encode_b11_value(pgdata_path)\n'
        "    handle = container\n"
        '    handle.get("Id")\n',
    )
    assert rebound != src, "fixture precondition: the rebind anchor moved"
    check_A7a({CONFTEST_NAME: sources[CONFTEST_NAME], BENCH_NAME: rebound})
    with pytest.raises(AssertionError) as excinfo:
        check_B11D3(rebound)
    assert str(excinfo.value).split(":", 1)[0] == "B11D3", str(excinfo.value)


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
    # The miniature repository carries the same tier inventory as the real one,
    # so the A1 "extra_tier_file" control still fires for the file it adds and
    # never for a file this seed forgot to write.
    for rel in sorted(EXPECTED_PACKAGING_FILES) + list(BENCHMARK_WORKFLOWS) + [
        GO_GUARD
    ] + CALL_SITE_FILES:
        dest = root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text((REPO_ROOT / rel).read_text(encoding="utf-8"), encoding="utf-8")
    # The four package markers the real tree already carries.  A10(ii) derives
    # its shadowable set from the tier's own import inventory, which now
    # includes the top-level name `services`: without these markers the
    # miniature tree would report a shadowing module the real tree does not
    # have, and the control would be measuring the seed rather than the rule.
    # Nothing is exempted here -- removing any one of them is A10-red.
    for rel in sorted(EXPECTED_PACKAGE_DIRS):
        marker = root / rel / "__init__.py"
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("", encoding="utf-8")
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
        "    pool = ThreadPoolExecutor(max_workers=len(instances))\n",
        "    pool = ThreadPoolExecutor(max_workers=len(instances))\n"
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
                "    writers: 7\n",
                "    writers: 8\n",
            ),
            lambda root: check_L3(
                root / TIER_CONFTEST, root / "tests" / "benchmark" / "thresholds.yaml"
            ),
        ),
    )
    add(
        "manifest_processes_sum_not_writers",
        "L3",
        _seeded(
            lambda root: _replace(
                root,
                "tests/benchmark/thresholds.yaml",
                "        processes: 4\n",
                "        processes: 3\n",
            ),
            lambda root: check_L3(
                root / TIER_CONFTEST, root / "tests" / "benchmark" / "thresholds.yaml"
            ),
        ),
    )
    add(
        "manifest_entry_missing_processes_key",
        "L3",
        _seeded(
            lambda root: _replace(
                root,
                "tests/benchmark/thresholds.yaml",
                "      - process: dashboard-api\n        processes: 1\n",
                "      - process: dashboard-api\n",
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
        "width_executor_bound_to_loader_len",
        "W2",
        bench_case(
            "max_workers=len(instances)",
            "max_workers=len(writers)",
            lambda root: check_W2(_bench_src(root)),
        ),
    )
    add(
        "width_arithmetic",
        "W2",
        bench_case(
            "max_workers=len(instances)",
            "max_workers=len(instances) * 2",
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
            "    pool = ThreadPoolExecutor(max_workers=len(instances))",
            "    pool = None",
            lambda root: check_W2(_bench_src(root)),
        ),
    )
    add(
        "width_shared_engine_for_every_writer",
        "W2",
        bench_case(
            "    for _ in instances:\n        eng = make_engine(dsn)",
            "    eng = make_engine(dsn)\n    for _ in instances:",
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
            "        committed = list(pool.map(_run_writer, range(len(instances))))",
            "        committed = [_run_writer(i) for i in range(len(instances))]",
            lambda root: check_W2(_bench_src(root)),
        ),
    )
    add(
        "width_elapsed_time_divided_by_the_writer_count",
        "W2",
        bench_case(
            "        elapsed = time.perf_counter() - t0",
            "        elapsed = (time.perf_counter() - t0) / len(instances)",
            lambda root: check_W2(_bench_src(root)),
        ),
    )
    add(
        "width_executor_results_left_lazy",
        "W2",
        bench_case(
            "        committed = list(pool.map(_run_writer, range(len(instances))))",
            "        committed = pool.map(_run_writer, range(len(instances)))",
            lambda root: check_W2(_bench_src(root)),
        ),
    )
    add(
        "width_writer_index_set_shrunk",
        "W2",
        bench_case(
            "pool.map(_run_writer, range(len(instances)))",
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
                "            -v -s",
                "            -v -s -p rca_bench",
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
            "      - name: FP-M6-31 A10(v) environment hygiene before B2/B10",
            "      - name: seed the hook\n"
            '        run: echo "PYTHONPATH=/tmp/b11-hook" >> "$GITHUB_ENV"\n'
            "      - name: FP-M6-31 A10(v) environment hygiene before B2/B10",
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

    # ---- B11 host/storage diagnostics (FP-B11HD-1..5) --------------------
    def diag_case(old: str, new: str, checker, count: int = -1):
        return _seeded(
            lambda root: _replace(root, TIER_BENCH, old, new, count), checker
        )

    def b11d1(root: Path) -> None:
        check_B11D1(_bench_src(root))

    def b11d2(root: Path) -> None:
        check_B11D2(_bench_src(root))

    def b11d3(root: Path) -> None:
        check_B11D3(_bench_src(root))

    def b11d4(root: Path) -> None:
        check_B11D4(_bench_src(root))

    def b11d5(root: Path) -> None:
        check_B11D5(
            _bench_src(root),
            read_manifest_isolated(
                root / "tests" / "benchmark" / "thresholds.yaml",
                key_path="benchmarks[id=B11].notes",
            ),
        )

    # canonical grammar
    add(
        "diagnostics_field_deleted",
        "B11D1",
        diag_case('    "storage_model",\n)', ")", b11d1),
    )
    add(
        "diagnostics_field_reordered",
        "B11D1",
        diag_case(
            '    "storage_rotational",\n    "storage_scheduler",\n',
            '    "storage_scheduler",\n    "storage_rotational",\n',
            b11d1,
            count=1,
        ),
    )
    add(
        "diagnostics_prefix_changed",
        "B11D1",
        diag_case(
            'B11_DIAGNOSTIC_PREFIX = "B11 diagnostics="',
            'B11_DIAGNOSTIC_PREFIX = "B11 diag="',
            b11d1,
        ),
    )
    add(
        "diagnostics_unavailable_literal_changed",
        "B11D1",
        diag_case(
            'B11_DIAGNOSTIC_UNAVAILABLE = "unavailable"',
            'B11_DIAGNOSTIC_UNAVAILABLE = "0"',
            b11d1,
        ),
    )
    add(
        "diagnostics_writer_entries_comma_joined",
        "B11D1",
        diag_case('return "+".join(entries)', 'return ",".join(entries)', b11d1),
    )
    add(
        "diagnostics_mapping_field_dropped",
        "B11D1",
        diag_case(
            '        "storage_model": storage_values["storage_model"],\n',
            "",
            b11d1,
        ),
    )
    add(
        "diagnostics_mapping_field_duplicated",
        "B11D1",
        diag_case(
            '        "storage_model": storage_values["storage_model"],\n',
            '        "storage_model": storage_values["storage_model"],\n'
            '        "storage_model": storage_values["storage_model"],\n',
            b11d1,
        ),
    )
    add(
        "diagnostics_canonical_print_removed",
        "B11D1",
        diag_case(
            "    print(_serialize_b11_diagnostics(diagnostic_values))\n", "", b11d1
        ),
    )

    def canonical_print_after_the_bar(root: Path) -> None:
        _replace(
            root,
            TIER_BENCH,
            "    print(_serialize_b11_diagnostics(diagnostic_values))\n",
            "",
        )
        _replace(
            root,
            TIER_BENCH,
            '        f"B11 single_writer_rate={single_writer_rate:.1f}/s; {env_line}"\n'
            "    )\n",
            '        f"B11 single_writer_rate={single_writer_rate:.1f}/s; {env_line}"\n'
            "    )\n"
            "    print(_serialize_b11_diagnostics(diagnostic_values))\n",
        )

    add(
        "diagnostics_printed_after_the_bar",
        "B11D1",
        _seeded(canonical_print_after_the_bar, b11d1),
    )

    # host readings and their provenance
    add(
        "host_parsers_from_another_module",
        "B11D2",
        diag_case(
            "from services.gateway.tests.b1_reference_profile import (",
            "from services.gateway.tests.b1_e2e_profile_substitute import (",
            b11d2,
        ),
    )
    add(
        "host_parser_aliased",
        "B11D2",
        diag_case(
            "    counter_delta,\n", "    counter_delta as counter_delta,\n", b11d2
        ),
    )
    add(
        "host_parser_redefined_locally",
        "B11D2",
        diag_case(
            "def _encode_b11_value(value: str) -> str:",
            "def counter_delta(before, after, *, label):\n"
            "    return after - before\n"
            "\n"
            "\n"
            "def _encode_b11_value(value: str) -> str:",
            b11d2,
        ),
    )
    add(
        "host_proc_stat_source_redirected",
        "B11D2",
        diag_case(
            'proc_stat_path: Path = Path("/proc/stat")',
            'proc_stat_path: Path = Path("/tmp/b11-fixture-stat")',
            b11d2,
        ),
    )
    add(
        "host_psi_root_redirected",
        "B11D2",
        diag_case(
            'psi_root: Path = Path("/proc/pressure")',
            'psi_root: Path = Path("/tmp/b11-fixture-pressure")',
            b11d2,
        ),
    )
    add(
        "host_clock_tick_name_changed",
        "B11D2",
        diag_case(
            'os.sysconf("SC_CLK_TCK")', 'os.sysconf("SC_NPROCESSORS_ONLN")', b11d2
        ),
    )
    add(
        "host_os_member_widened",
        "B11D2",
        diag_case("os.cpu_count()", "os.getloadavg()", b11d2),
    )
    add(
        "host_reader_swallows_every_error",
        "B11D2",
        diag_case(
            "    except (OSError, ValueError):\n        snapshot",
            "    except Exception:\n        snapshot",
            b11d2,
        ),
    )

    # storage provenance
    def storage_read_from_the_test_process(root: Path) -> None:
        _replace(
            root,
            TIER_BENCH,
            "            _exec_b11_container_text(\n"
            "                wrapped_container,\n"
            "                [\n"
            '                    "/bin/sh",\n'
            '                    "-c",\n'
            "                    B11_CONTAINER_MOUNT_SCRIPT,\n"
            '                    "b11-mount",\n'
            "                    pgdata_path,\n"
            "                ],\n"
            "            )\n",
            '            Path("/proc/self/mountinfo").read_text(encoding="utf-8")\n',
        )

    add(
        "storage_read_from_the_test_process",
        "B11D3",
        _seeded(storage_read_from_the_test_process, b11d3),
    )
    add(
        "storage_exec_privileged",
        "B11D3",
        diag_case("        privileged=False,\n", "        privileged=True,\n", b11d3),
    )
    add(
        "storage_exec_user_changed",
        "B11D3",
        diag_case('        user="postgres",\n', '        user="root",\n', b11d3),
    )
    add(
        "storage_exec_gains_a_namespace_option",
        "B11D3",
        diag_case(
            "        demux=False,\n", '        demux=False,\n        pid_mode="host",\n', b11d3
        ),
    )
    add(
        "storage_mount_script_reads_another_table",
        "B11D3",
        diag_case("cat /proc/self/mountinfo", "cat /etc/mtab", b11d3),
    )
    add(
        "storage_block_script_picks_one_of_several_slaves",
        "B11D3",
        diag_case(
            'if [ "$#" -eq 1 ] && [ -e "$1" ]; then',
            'if [ "$#" -ge 1 ] && [ -e "$1" ]; then',
            b11d3,
        ),
    )
    add(
        "storage_pgdata_hard_coded",
        "B11D3",
        diag_case(
            'text("SELECT current_setting(\'data_directory\')")',
            'text("SELECT \'/var/lib/postgresql/data\'")',
            b11d3,
        ),
    )
    add(
        "storage_container_from_another_fixture_key",
        "B11D3",
        diag_case(
            '_read_b11_storage_identity(scale_pg["container"], pgdata_path)',
            '_read_b11_storage_identity(scale_pg["factory"], pgdata_path)',
            b11d3,
        ),
    )
    add(
        "storage_query_from_another_fixture_key",
        "B11D3",
        diag_case(
            '        with scale_pg["engine"].connect() as conn:',
            '        with scale_pg["factory"]().connect() as conn:',
            b11d3,
        ),
    )
    add(
        "storage_argv_frame_changed",
        "B11D3",
        diag_case('                    "b11-mount",\n', '                    "mount",\n', b11d3),
    )

    def container_handle_rebound_and_read(root: Path) -> None:
        """The non-redundancy mutation: `get` stays in ALLOWED_ATTRIBUTES, so
        A7a is green while the provenance guard must be red."""
        _replace(
            root,
            TIER_BENCH,
            "    values[\"storage_pgdata_path\"] = _encode_b11_value(pgdata_path)\n",
            "    values[\"storage_pgdata_path\"] = _encode_b11_value(pgdata_path)\n"
            "    handle = container\n"
            "    handle.get(\"Id\")\n",
        )

    add(
        "storage_handle_rebound_then_read",
        "B11D3",
        _seeded(container_handle_rebound_and_read, b11d3),
    )
    add(
        "storage_handle_rebound_then_unlisted_attribute",
        "A7a",
        _seeded(
            lambda root: (
                container_handle_rebound_and_read(root),
                _replace(
                    root,
                    TIER_BENCH,
                    '    handle.get("Id")\n',
                    '    handle.get("Id")\n    handle.reload()\n',
                ),
            ),
            lambda root: check_A7a(tier_sources(root)),
        ),
    )
    add(
        "container_direct_attribute_in_conftest",
        "A6",
        _seeded(
            lambda root: _replace(
                root,
                TIER_CONFTEST,
                "        dsn = pg.get_connection_url()\n",
                "        dsn = pg.get_connection_url()\n        pg.reload()\n",
            ),
            lambda root: check_A6(tier_sources(root)),
        ),
    )
    add(
        "fixture_write_outside_its_own_test",
        "A7a",
        diag_case(
            "def _encode_b11_value(value: str) -> str:\n"
            '    """Percent-encode one free-form diagnostic value',
            "def _encode_b11_value(value: str) -> str:\n"
            '    Path("/tmp/b11-note").write_text(value, encoding="utf-8")\n'
            '    """Percent-encode one free-form diagnostic value',
            lambda root: check_A7a(tier_sources(root)),
        ),
    )

    # window ordering and the writer side channel
    def storage_after_engine_construction(root: Path) -> None:
        _replace(
            root,
            TIER_BENCH,
            "    storage_values = _read_b11_storage_identity("
            'scale_pg["container"], pgdata_path)\n',
            "",
        )
        _replace(
            root,
            TIER_BENCH,
            "    def _run_writer(idx: int) -> int:\n",
            "    storage_values = _read_b11_storage_identity("
            'scale_pg["container"], pgdata_path)\n\n'
            "    def _run_writer(idx: int) -> int:\n",
        )

    add(
        "storage_resolved_after_the_engines",
        "B11D4",
        _seeded(storage_after_engine_construction, b11d4),
    )
    add(
        "host_open_read_after_the_timer",
        "B11D4",
        diag_case(
            "        host_before = _read_b11_host_snapshot()\n"
            "        t0 = time.perf_counter()\n",
            "        t0 = time.perf_counter()\n"
            "        host_before = _read_b11_host_snapshot()\n",
            b11d4,
        ),
    )
    add(
        "host_close_read_before_the_elapsed_assignment",
        "B11D4",
        diag_case(
            "        elapsed = time.perf_counter() - t0\n"
            "        host_after = _read_b11_host_snapshot()\n",
            "        host_after = _read_b11_host_snapshot()\n"
            "        elapsed = time.perf_counter() - t0\n",
            b11d4,
        ),
    )
    add(
        "side_channel_written_inside_the_row_loop",
        "B11D4",
        diag_case(
            "                rows += 1\n"
            "        writer_elapsed_rows[idx] = (time.perf_counter() - writer_t0, rows)\n",
            "                rows += 1\n"
            "                writer_elapsed_rows[idx] = ("
            "time.perf_counter() - writer_t0, rows)\n",
            b11d4,
        ),
    )
    add(
        "side_channel_written_to_a_fixed_slot",
        "B11D4",
        diag_case(
            "        writer_elapsed_rows[idx] = (time.perf_counter() - writer_t0, rows)",
            "        writer_elapsed_rows[0] = (time.perf_counter() - writer_t0, rows)",
            b11d4,
        ),
    )
    add(
        "side_channel_row_count_forged",
        "B11D4",
        diag_case(
            "        writer_elapsed_rows[idx] = (time.perf_counter() - writer_t0, rows)",
            "        writer_elapsed_rows[idx] = (time.perf_counter() - writer_t0, n_iters)",
            b11d4,
        ),
    )
    add(
        "side_channel_elapsed_forged",
        "B11D4",
        diag_case(
            "        writer_elapsed_rows[idx] = (time.perf_counter() - writer_t0, rows)",
            "        writer_elapsed_rows[idx] = (0.001, rows)",
            b11d4,
        ),
    )
    add(
        "side_channel_width_detached_from_the_writer_set",
        "B11D4",
        diag_case(
            "    writer_elapsed_rows = [None] * len(instances)",
            "    writer_elapsed_rows = [None] * 7",
            b11d4,
        ),
    )
    add(
        "writer_opening_clock_moved_into_the_session",
        "B11D4",
        diag_case(
            "        writer_t0 = time.perf_counter()\n"
            "        with factory() as session:\n",
            "        with factory() as session:\n"
            "            writer_t0 = time.perf_counter()\n",
            b11d4,
        ),
    )
    add(
        "host_read_inside_the_row_loop",
        "B11D4",
        diag_case(
            "            for i in range(n_iters):\n",
            "            for i in range(n_iters):\n"
            "                _read_b11_host_snapshot()\n",
            b11d4,
        ),
    )
    add(
        "writer_report_serialized_from_the_executor_result",
        "B11D4",
        diag_case(
            "        \"writer_elapsed_rows\": _serialize_writer_elapsed_rows(\n"
            "            instances, writer_elapsed_rows\n"
            "        ),",
            "        \"writer_elapsed_rows\": _serialize_writer_elapsed_rows(\n"
            "            instances, committed\n"
            "        ),",
            b11d4,
        ),
    )

    # reported-only and the fixed B11 model
    add(
        "bar_threshold_lowered",
        "B11D5",
        diag_case("assert rate >= 1000.0, (", "assert rate >= 500.0, (", b11d5),
    )
    add(
        "timed_row_count_changed",
        "B11D5",
        diag_case("    n_iters = 800\n", "    n_iters = 100\n", b11d5),
    )
    add(
        "warmup_row_count_changed",
        "B11D5",
        diag_case("            for i in range(50):", "            for i in range(5):", b11d5),
    )
    add(
        "single_writer_row_count_changed",
        "B11D5",
        diag_case("        for i in range(100):", "        for i in range(10):", b11d5),
    )
    add(
        "bar_skipped_on_an_unavailable_reading",
        "B11D5",
        diag_case(
            "    assert rate >= 1000.0, (",
            '    if host_values["host_steal_usec"] == B11_DIAGNOSTIC_UNAVAILABLE:\n'
            '        pytest.skip("no host counters")\n'
            "    assert rate >= 1000.0, (",
            b11d5,
        ),
    )
    add(
        "bar_conditioned_on_a_storage_reading",
        "B11D5",
        diag_case(
            "    assert rate >= 1000.0, (",
            '    if storage_values["storage_rotational"] == "1":\n'
            "        return\n"
            "    assert rate >= 1000.0, (",
            b11d5,
        ),
    )
    add(
        "notes_drop_the_diagnostics_contract",
        "B11D5",
        _seeded(
            lambda root: _replace(
                root,
                "tests/benchmark/thresholds.yaml",
                "canonical B11 diagnostics= record",
                "canonical record",
            ),
            b11d5,
        ),
    )
    add(
        "seeded_package_marker_removed",
        "A10",
        _seeded(
            lambda root: (
                root / "services/dashboard-api/dashboard_api/__init__.py"
            ).unlink(),
            lambda root: check_A10(root),
        ),
    )
    add(
        "benchmark_path_import_duplicated",
        "A2b",
        diag_case(
            "from pathlib import Path\n",
            "from pathlib import Path\nfrom pathlib import Path\n",
            lambda root: check_A2b(tier_sources(root)),
            count=1,
        ),
    )
    add(
        "benchmark_path_import_removed",
        "A2b",
        diag_case(
            "from pathlib import Path\n",
            "",
            lambda root: check_A2b(tier_sources(root)),
            count=1,
        ),
    )
    add(
        "parser_parameter_renamed_to_reserved_text",
        "A2c",
        diag_case(
            "def _parse_b11_container_mount_output(output: str) -> tuple[str, str]:",
            "def _parse_b11_container_mount_output(text: str) -> tuple[str, str]:",
            lambda root: check_A2c(tier_sources(root)),
        ),
    )
    add(
        "container_handle_annotated_object",
        "A2d",
        diag_case(
            "def _exec_b11_container_text(wrapped_container, argv: list[str]) -> str:",
            "def _exec_b11_container_text("
            "wrapped_container: object, argv: list[str]) -> str:",
            lambda root: check_A2d(tier_sources(root)),
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
        "    pool = ThreadPoolExecutor(max_workers=len(instances))",
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
        "        committed = list(pool.map(_run_writer, range(len(instances))))\n"
        "        elapsed = time.perf_counter() - t0",
        "        committed = [_run_writer(i) for i in range(len(instances))]\n"
        "        elapsed = (time.perf_counter() - t0) / len(instances)",
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


def test_b11_guard_baselines_are_the_shipped_tier_verbatim():
    """The clean baselines are copies, and a copy that drifts is a lie.

    `CLEAN_BENCH` and `CLEAN_CONFTEST` are verbatim copies of the two files
    they seed a temporary repository from, and every bypass fixture mutates
    one of those copies rather than the tree. That only means anything while
    the copy IS the tree: a baseline that drifts leaves each of those
    fixtures proving a rule about text this repository no longer ships, and
    the drift itself is invisible -- seeding and re-running the checkers
    passes either way, because a stale comment breaks no rule.

    Named for exactly that: an edit to `tests/benchmark/test_pg_scale.py`
    (bench-on-demand FP-BOD-4 was one) that is not carried into the baseline
    beside it. Byte equality, because anything weaker would admit the
    difference that matters least and hide the one that matters most.
    """
    for name, live_path in (
        ("CLEAN_BENCH", BENCH),
        ("CLEAN_CONFTEST", CONFTEST),
    ):
        baseline = globals()[name]
        live = live_path.read_text(encoding="utf-8")
        assert baseline == live, (
            f"{name} has drifted from {live_path.name}: regenerate it from the "
            f"shipped file (lengths {len(baseline)} vs {len(live)})"
        )



# --------------------------------------------------------------------------
# bench-on-demand FP-BOD-4 — the bar, and nothing after it.
# --------------------------------------------------------------------------


def test_b11_rate_bar_has_no_stall_suffix():
    """FP-BOD-4 [function test]: `rate >= 1000.0` survives; the label does not.

    Named for two failures, and it takes both to go green.

    The first is a bar that moved off 1000.0 -- deleted, relaxed, turned into
    a `>` on a different quantity, or pointed at something other than the
    combined rate. That is read out of the AST of the live function, not out
    of the file's text: a comment or a docstring mentioning `1000.0` proves
    nothing.

    The second is the stall suffix surviving the slice. B11 left per-push CI,
    so `io_full_stall_observed` has nothing left to classify -- it existed to
    tell one shared-runner red from another -- and an on-demand miss has to
    stay a plain failure. Both the classifier and the label are required
    absent from the benchmark file, and the label from the manifest too, so a
    half-deletion that leaves either behind is red.

    Checking only `writers == 7` would stay green after the rate assert was
    removed, which is exactly why that is not this test.
    """
    src = BENCH.read_text(encoding="utf-8")
    tree = ast.parse(src)
    b11 = _b11_function_in(tree)

    # (1) The bar: one assert, `>=`, against the float 1000.0, on the name the
    # combined rate is bound to.
    asserts = [n for n in ast.walk(b11) if isinstance(n, ast.Assert)]
    assert len(asserts) == 1, [ast.unparse(a.test) for a in asserts]
    gate = asserts[0].test
    assert isinstance(gate, ast.Compare), ast.unparse(gate)
    assert len(gate.ops) == 1 and isinstance(gate.ops[0], ast.GtE), ast.unparse(gate)
    assert isinstance(gate.left, ast.Name), ast.unparse(gate)
    right = gate.comparators[0]
    assert isinstance(right, ast.Constant), ast.unparse(gate)
    assert right.value == 1000.0 and isinstance(right.value, float), right.value

    # ...and the left operand really is the combined insert rate: it is bound
    # once, from the two tables' committed rows over the measured window.
    rate_name = gate.left.id
    bindings = [
        n
        for n in ast.walk(b11)
        if isinstance(n, ast.Assign)
        and len(n.targets) == 1
        and isinstance(n.targets[0], ast.Name)
        and n.targets[0].id == rate_name
    ]
    assert len(bindings) == 1, [ast.unparse(n) for n in bindings]
    bound = bindings[0].value
    # `<rows> / <elapsed> if <elapsed> > 0 else 0.0`: a division of committed
    # rows by the measured window, with the zero-window guard the shipped code
    # already carries. A bar pointed at a constant, a single writer's rate or
    # anything that is not that quotient fails here.
    assert isinstance(bound, ast.IfExp), ast.unparse(bindings[0])
    quotient = bound.body
    assert isinstance(quotient, ast.BinOp) and isinstance(quotient.op, ast.Div), (
        ast.unparse(bindings[0])
    )
    rows_name = quotient.left
    assert isinstance(rows_name, ast.Name), ast.unparse(bindings[0])
    rows_bindings = [
        n
        for n in ast.walk(b11)
        if isinstance(n, ast.Assign)
        and len(n.targets) == 1
        and isinstance(n.targets[0], ast.Name)
        and n.targets[0].id == rows_name.id
    ]
    assert len(rows_bindings) == 1, [ast.unparse(n) for n in rows_bindings]
    assert ast.unparse(rows_bindings[0].value) == "sum(committed)", (
        ast.unparse(rows_bindings[0])
    )

    # (2) The stall classification is gone from the benchmark, name and label.
    for token in (
        "_b11_failure_classification",
        "io_full_stall_observed",
        "symptom_only_not_cause",
        "gate_outcome=red",
        "B11_IO_FULL_STALL_SHARE",
    ):
        assert token not in src, f"{token!r} survives in {BENCH_NAME}"

    # ...and from the manifest, where the `gate_policy` object carried it.
    manifest = THRESHOLDS.read_text(encoding="utf-8")
    for token in ("io_full_stall_observed", "gate_policy", "symptom_only_not_cause"):
        assert token not in manifest, f"{token!r} survives in thresholds.yaml"

    # (3) The seven-writer model and the entry's on-demand tier are unchanged
    # by the deletion: the bar is not the only thing a half-revert could take.
    model = read_manifest_isolated(key_path=MANIFEST_KEY_PATH)
    assert model["writers"] == 7, model["writers"]
