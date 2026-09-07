"""Legacy environment-variable detector (design.md §11.2.3 C.2/C.3).

The product rename ``rca-agent`` -> ``dbagent`` moved the process-level
environment namespace from ``RCA_*`` to ``DBAGENT_*``. There is deliberately
**no silent dual read**: a fallback would be permanent compatibility debt whose
whole point is to be invisible, and reading only the new name is worse, because
the observed failure is a ``FileNotFoundError`` on a default config path
several seconds later.

So every Python entry point calls :func:`reject_legacy_env` as its first
statement, and a legacy name present in the environment stops the process with
a message naming both the old and the new variable.

The check is **presence-based, not value-based**, and unconditional: a legacy
name set alongside the correct new one is still an error, because the operator
believes the old one is doing something.

Note that ``RCA_COMMON_DIR`` is deliberately *not* here. Despite its shape it
is not an environment variable at all -- it is a module-level Python constant
holding a path -- and it is retained by §11.2.3 C.5.
"""

from __future__ import annotations

import os
from collections.abc import Mapping

__all__ = ["LEGACY_ENV_RENAMES", "reject_legacy_env"]

#: The §11.2.3 C.2 table, verbatim and complete: thirteen names from its nine
#: rows (two rows are slash-separated pairs and one is a triple).
LEGACY_ENV_RENAMES: dict[str, str] = {
    "RCA_PG_DSN": "DBAGENT_PG_DSN",
    "RCA_POSTGRES_DSN": "DBAGENT_POSTGRES_DSN",
    "RCA_WORKER_CONFIG": "DBAGENT_WORKER_CONFIG",
    "RCA_GATEWAY_CONFIG": "DBAGENT_GATEWAY_CONFIG",
    "RCA_GATEWAY_HOST": "DBAGENT_GATEWAY_HOST",
    "RCA_GATEWAY_PORT": "DBAGENT_GATEWAY_PORT",
    "RCA_DASHBOARD_CONFIG": "DBAGENT_DASHBOARD_CONFIG",
    "RCA_DASHBOARD_HOST": "DBAGENT_DASHBOARD_HOST",
    "RCA_DASHBOARD_PORT": "DBAGENT_DASHBOARD_PORT",
    "RCA_SIGNING_KEY_PATH": "DBAGENT_SIGNING_KEY_PATH",
    "RCA_API_BASE_URL": "DBAGENT_API_BASE_URL",
    "RCA_API_UPSTREAM": "DBAGENT_API_UPSTREAM",
    "RCA_DOCROOT": "DBAGENT_DOCROOT",
}


def reject_legacy_env(environ: Mapping[str, str] | None = None) -> None:
    """Exit when any legacy ``RCA_*`` name from the closed table is present.

    Raises ``SystemExit`` listing **all** offending names, one line each, in
    the table's own order.
    """
    env = os.environ if environ is None else environ
    offenders = [old for old in LEGACY_ENV_RENAMES if old in env]
    if not offenders:
        return
    lines = [
        f"{old} is no longer read; rename it to {LEGACY_ENV_RENAMES[old]} "
        "(design.md §11.2.3 C.2)"
        for old in offenders
    ]
    raise SystemExit("\n".join(lines))
