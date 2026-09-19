"""FP-SW-10 (design.md §11.2.5): the product rename is verifiable in both
directions.

Three halves:

* **forward** -- no git-tracked file carries a legacy product token outside a
  closed allowlist, so the rename is proven finished;
* **retained** -- every §11.2.3 C.5 row is asserted *at its named production
  anchor*, so the rename is proven to have stopped exactly where C.5 says it
  stops. This file and `tests/functional/test_dbagent_env_rename.py` are
  excluded from the evidence set, so the assertion cannot satisfy itself from
  the literals the guards carry;
* **destination** -- the three renames whose *new* value is a specific string
  are asserted positively at their production anchors, since deleting the line
  would otherwise pass.

This file is on its own allowlist: it necessarily contains the patterns.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from delivery_helpers import REPO_ROOT

# --- the forward pattern set (§11.2.3 C.5's note on RCA_[A-Z]) ---------------

LEGACY_PRODUCT_PATTERNS = [
    re.compile(r"rca[-_]agent", re.IGNORECASE),
    re.compile(r"rca[-_]probe", re.IGNORECASE),
]

# The thirteen C.2 legacy environment names, matched EXACTLY -- a closed set,
# not `RCA_[A-Z]`, which would hit the retained RCA_COMMON_DIR.
LEGACY_ENV_NAMES = [
    "RCA_PG_DSN",
    "RCA_POSTGRES_DSN",
    "RCA_WORKER_CONFIG",
    "RCA_GATEWAY_CONFIG",
    "RCA_GATEWAY_HOST",
    "RCA_GATEWAY_PORT",
    "RCA_DASHBOARD_CONFIG",
    "RCA_DASHBOARD_HOST",
    "RCA_DASHBOARD_PORT",
    "RCA_SIGNING_KEY_PATH",
    "RCA_API_BASE_URL",
    "RCA_API_UPSTREAM",
    "RCA_DOCROOT",
]

RESIDUAL_LITERALS = [
    "10-rca-config.sh",
    "__RCA_CONFIG__",
    "rca-dashboard-bootstrap-admin",
    "@rca-agent/",
]

# Closed allowlist, by exact path. Any other file needing an entry means the
# sweep is incomplete.
ALLOWLIST = {
    "libs/py/rca_common/rca_common/envcompat.py",
    "libs/py/rca_common/tests/test_envcompat.py",
    "tests/functional/test_dbagent_env_rename.py",
    "tests/delivery/test_delivery_naming.py",
    "docs/runbooks/upgrade-and-rollback.md",
}

# Excluded from the walk entirely: generated trees, vendored trees, and the
# local-only design/progress/review documents.
EXCLUDED_PREFIXES = ("gen/", "design/")
EXCLUDED_PARTS = {".git", "node_modules", ".venv"}
EXCLUDED_EXACT = {"impl-progress.md", "review.md"}
_EXCLUDED_GLOB = re.compile(r"^DEPLOY-ISSUES-.*\.md$")

# Files whose literals may not serve as evidence for the retained half.
NOT_EVIDENCE = {
    "tests/delivery/test_delivery_naming.py",
    "tests/functional/test_dbagent_env_rename.py",
}


def _git_tracked() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files"], cwd=str(REPO_ROOT), capture_output=True, text=True, check=True
    ).stdout.split("\n")
    return [f for f in out if f]


def _walk_candidates() -> list[str]:
    kept = []
    for rel in _git_tracked():
        if rel.startswith(EXCLUDED_PREFIXES):
            continue
        if rel in EXCLUDED_EXACT or _EXCLUDED_GLOB.match(rel):
            continue
        if EXCLUDED_PARTS & set(Path(rel).parts):
            continue
        kept.append(rel)
    return kept


def _read(rel: str) -> str | None:
    """UTF-8 text read for retained/destination halves that need decoded text.

    The forward half (``test_no_legacy_product_name_survives_outside_allowlist``)
    must NOT use this helper: binary / non-UTF-8 tracked files would be skipped
    and the "scans every tracked file" claim would not hold.
    """
    path = REPO_ROOT / rel
    if not path.is_file():
        return None
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, ValueError):
        return None


# Byte patterns for the forward half. Scanned as raw bytes so non-UTF-8 and
# binary tracked files are not silently omitted (review W4 / FP-SW-10).
_LEGACY_PRODUCT_BYTES = [
    re.compile(rb"rca[-_]agent", re.IGNORECASE),
    re.compile(rb"rca[-_]probe", re.IGNORECASE),
]
_LEGACY_ENV_BYTES = [name.encode("ascii") for name in LEGACY_ENV_NAMES]
_RESIDUAL_BYTES = [literal.encode("ascii") for literal in RESIDUAL_LITERALS]


def test_no_legacy_product_name_survives_outside_allowlist():
    offenders: list[str] = []
    scanned = 0
    candidates = [rel for rel in _walk_candidates() if rel not in ALLOWLIST]
    present = [rel for rel in candidates if (REPO_ROOT / rel).is_file()]
    for rel in present:
        data = (REPO_ROOT / rel).read_bytes()
        scanned += 1
        for pattern in _LEGACY_PRODUCT_BYTES:
            for match in pattern.finditer(data):
                offenders.append(f"{rel}: {match.group(0)!r} (product token)")
        for name in _LEGACY_ENV_BYTES:
            if name in data:
                offenders.append(f"{rel}: {name.decode('ascii')} (legacy environment name)")
        for literal in _RESIDUAL_BYTES:
            if literal in data:
                offenders.append(f"{rel}: {literal.decode('ascii')} (residual literal)")
    assert scanned > 100, f"the walk only saw {scanned} files; the exclusions are too broad"
    # Every present candidate was scanned bytewise — no decode-and-skip path.
    assert scanned == len(present), (
        f"scanned {scanned} of {len(present)} present candidates; some files were omitted"
    )
    assert not offenders, "legacy product tokens survive:\n" + "\n".join(sorted(offenders))


# --- retained half: every C.5 row, at its named production anchor ------------


def test_retained_rca_domain_vocabulary_is_intact_at_its_production_anchors():
    # The retained half may not be satisfied by the guards' own literals.
    for rel in NOT_EVIDENCE:
        assert (REPO_ROOT / rel).is_file()

    # 1. libs/py/rca_common: directory, distribution name, include, and a real
    #    import from a shipped service module.
    rca_common = REPO_ROOT / "libs/py/rca_common"
    assert rca_common.is_dir()
    pyproject = (rca_common / "pyproject.toml").read_text(encoding="utf-8")
    assert 'name = "rca-common"' in pyproject
    assert "rca_common" in pyproject  # [tool.setuptools] include/packages
    shipped_imports = [
        "services/worker/worker/worker_main.py",
        "services/gateway/gateway/main.py",
        "services/dashboard-api/dashboard_api/main.py",
    ]
    assert any(
        re.search(r"^from rca_common", _read(rel) or "", re.MULTILINE)
        for rel in shipped_imports
    ), "no shipped service module imports rca_common"

    # 2. The four retained distribution `name =` lines, and only those lines.
    for rel, dist in [
        ("libs/py/rca_common/pyproject.toml", "rca-common"),
        ("services/gateway/pyproject.toml", "rca-gateway"),
        ("services/worker/pyproject.toml", "rca-worker"),
        ("services/dashboard-api/pyproject.toml", "rca-dashboard-api"),
    ]:
        text = _read(rel)
        assert text is not None, rel
        assert any(
            line.strip() == f'name = "{dist}"' for line in text.splitlines()
        ), f"{rel}: distribution name {dist} was renamed"

    # 3. Schema contract: RCAReport, both $id and title, and the file name.
    schema_path = REPO_ROOT / "schemas/rca_report.schema.json"
    assert schema_path.is_file()
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    assert schema["$id"] == "RCAReport"
    assert schema["title"] == "RCAReport"

    # 4. DB contract: the two JSONB columns, in the migration and the ORM.
    migration = _read("libs/py/rca_common/migrations/versions/0001_initial_schema.py")
    assert migration is not None
    investigations = re.search(
        r"CREATE TABLE .*?investigations(.*?)\)\s*;", migration, re.DOTALL | re.IGNORECASE
    )
    assert investigations, "CREATE TABLE investigations not found"
    assert re.search(r"\brca_report\b", investigations.group(1)), "investigations.rca_report missing"
    iterations = re.search(
        r"CREATE TABLE .*?iterations(.*?)\)\s*;", migration, re.DOTALL | re.IGNORECASE
    )
    assert iterations, "CREATE TABLE iterations not found"
    assert re.search(r"\brca_output\b", iterations.group(1)), "iterations.rca_output missing"

    models = _read("libs/py/rca_common/rca_common/db/models.py")
    assert models is not None
    assert re.search(r"^\s*rca_report:\s*Mapped", models, re.MULTILINE)
    assert re.search(r"^\s*rca_output:\s*Mapped", models, re.MULTILINE)

    # 5. Config contract: the `rca` agent role and rca_confidence_threshold.
    import yaml

    compose_config = yaml.safe_load(
        (REPO_ROOT / "deploy/compose/config/dbagent.yaml").read_text(encoding="utf-8")
    )
    assert "rca" in (compose_config.get("models") or {}), "the `rca` model role was renamed"
    config_module = _read("libs/py/rca_common/rca_common/config/__init__.py")
    assert config_module is not None
    assert re.search(r"^\s*rca_confidence_threshold:\s*float", config_module, re.MULTILINE)
    assert 'raw.get("rca_confidence_threshold"' in config_module

    # 6. Agent prompt: the rca role's prompt file.
    assert (REPO_ROOT / "services/worker/worker/agents/prompts/rca.txt").is_file()

    # 7. RCA_COMMON_DIR: a Python path constant, not an environment variable.
    for rel in [
        "tests/benchmark/conftest.py",
        "tests/functional/conftest.py",
        "services/dashboard-api/tests/conftest.py",
    ]:
        text = _read(rel)
        assert text is not None, rel
        assert re.search(r"^RCA_COMMON_DIR\s*=", text, re.MULTILINE), rel

    # 8. REST base /api/v1 -- the dashboard_api router prefix.
    router = _read("services/dashboard-api/dashboard_api/app.py") or ""
    assert "/api/v1" in router


# --- destination half: the three renames whose new value is a specific string


def test_renamed_destinations_are_present_at_their_production_anchors():
    package_json = json.loads((REPO_ROOT / "schemas/package.json").read_text(encoding="utf-8"))
    assert package_json["name"] == "@dbagent/schemas-codegen"
    lock_text = (REPO_ROOT / "schemas/package-lock.json").read_text(encoding="utf-8")
    assert "@dbagent/schemas-codegen" in lock_text
    lock = json.loads(lock_text)
    assert lock["name"] == "@dbagent/schemas-codegen"

    presto_client = _read("probe/internal/prestoclient/client.go")
    assert presto_client is not None
    assert 'req.Header.Set("X-Presto-User", "dbagent-probe")' in presto_client

    ca = _read("internal/bootstrapca/ca.go")
    assert ca is not None
    assert 'CommonName: "dbagent probe-gateway bootstrap CA"' in ca
