"""The alembic environment must not reconfigure the *host* process's logging.

`migrations/env.py` runs inside whatever process invokes alembic — the install
hook, the functional tier's session fixture, the e2e run — and
`logging.config.fileConfig` disables every already-created logger unless told
otherwise.  When it did, a later assertion on another component's log output
saw nothing at all, which is a silent, order-dependent failure rather than an
error.  Asserting on the call keeps the invariant where the defect was: the
call site.
"""
from __future__ import annotations

import ast
from pathlib import Path

MIGRATIONS_ENV = Path(__file__).resolve().parents[1] / "migrations" / "env.py"


def _file_config_calls() -> list[ast.Call]:
    tree = ast.parse(MIGRATIONS_ENV.read_text(encoding="utf-8"))
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and (
            (isinstance(node.func, ast.Name) and node.func.id == "fileConfig")
            or (isinstance(node.func, ast.Attribute) and node.func.attr == "fileConfig")
        )
    ]


def test_file_config_never_disables_the_callers_loggers():
    calls = _file_config_calls()
    assert calls, "migrations/env.py no longer configures logging at all"
    for call in calls:
        keywords = {kw.arg: kw.value for kw in call.keywords}
        node = keywords.get("disable_existing_loggers")
        assert node is not None, (
            "fileConfig() must pass disable_existing_loggers explicitly; the "
            "default (True) silences the loggers of whatever process ran the "
            "migration"
        )
        assert isinstance(node, ast.Constant) and node.value is False, (
            f"disable_existing_loggers must be False, got {ast.dump(node)}"
        )
