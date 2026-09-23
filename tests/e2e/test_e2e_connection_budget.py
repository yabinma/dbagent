"""FP-IG-29 / FP-IG-31 runtime leg: live SHOW max_connections vs rendered supply.

Red against the unfixed deployment: live supply 100 < demand 145 + 13.
The static delivery leg cannot see a dropped or typo'd ``-c`` arg that
leaves the server at the compiled default while the chart says 160.
"""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

_DELIVERY = Path(__file__).resolve().parents[1] / "delivery"
_CB_PATH = _DELIVERY / "connection_budget.py"
_spec = importlib.util.spec_from_file_location("connection_budget", _CB_PATH)
assert _spec and _spec.loader
_cb = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _cb
_spec.loader.exec_module(_cb)

sys.path.insert(0, str(_DELIVERY))
from delivery_helpers import CHARTS, REPO_ROOT, helm_template, parse_manifests  # noqa: E402

PG_WORKLOAD = os.environ.get("E2E_PG_WORKLOAD", "deploy/dbagent-postgresql")
PG_DSN_IN_POD = os.environ.get(
    "E2E_PG_DSN_IN_POD", "postgresql://dbagent:dbagent@127.0.0.1:5432/dbagent"
)
E2E_OVERLAY = REPO_ROOT / "tests" / "e2e" / "values-dbagent.yaml"


def _kubectl(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["kubectl", "-n", "dbagent", *args],
        capture_output=True,
        text=True,
        check=False,
    )


def _psql(sql: str) -> str:
    proc = _kubectl(
        "exec", PG_WORKLOAD, "--", "psql", PG_DSN_IN_POD, "-At", "-c", sql
    )
    assert proc.returncode == 0, (
        f"psql {sql!r} failed (rc={proc.returncode}): "
        f"{proc.stderr.strip() or proc.stdout.strip()}"
    )
    return proc.stdout.strip()


@pytest.mark.e2e
def test_live_connection_supply_exceeds_configured_demand():
    """Live SHOW max_connections equals the rendered supply and fits demand.

    Weak form: grepping logs for 'too many clients' — green on any run whose
    burst misses the ceiling (exactly how 698fff1 passed).
    """
    docs = parse_manifests(
        helm_template(CHARTS / "dbagent", values=[str(E2E_OVERLAY)])
    )
    result = _cb.evaluate(docs)
    live = int(_psql("SHOW max_connections"))
    assert live == result.max_connections, (
        f"live SHOW max_connections={live} != rendered {result.max_connections}"
    )
    assert result.demand + _cb.RESERVE <= live, (
        f"demand {result.demand} + RESERVE {_cb.RESERVE} > live supply {live}"
    )
    assert result.demand == 145
    assert live == 160
