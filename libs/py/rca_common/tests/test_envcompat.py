"""UT-SW-5 (design.md §11.2.5, FP-SW-8): the legacy-environment detector.

This file is on FP-SW-10's closed allowlist -- it necessarily names the
thirteen legacy `RCA_*` variables of §11.2.3 C.2.
"""

from __future__ import annotations

import pytest

from rca_common.envcompat import LEGACY_ENV_RENAMES, reject_legacy_env

# The C.2 table expanded to its thirteen names (nine rows: two slash-separated
# pairs and one triple). Written out here so the constant is checked against
# the design document rather than against itself.
C2_TABLE = {
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


def test_legacy_env_renames_equals_the_c2_table_exactly():
    assert LEGACY_ENV_RENAMES == C2_TABLE
    assert len(LEGACY_ENV_RENAMES) == 13


def test_rca_common_dir_is_not_an_environment_variable():
    # §11.2.3 C.2's note: RCA_COMMON_DIR is a Python path constant, retained
    # by C.5, and must not be swept into the environment rename.
    assert "RCA_COMMON_DIR" not in LEGACY_ENV_RENAMES


@pytest.mark.parametrize("old,new", sorted(C2_TABLE.items()))
def test_rejects_each_legacy_name_individually(old, new):
    with pytest.raises(SystemExit) as excinfo:
        reject_legacy_env({old: "whatever"})
    message = str(excinfo.value)
    assert message == f"{old} is no longer read; rename it to {new} (design.md §11.2.3 C.2)"


def test_message_lists_every_offender():
    env = {"RCA_PG_DSN": "x", "RCA_DOCROOT": "", "PATH": "/usr/bin"}
    with pytest.raises(SystemExit) as excinfo:
        reject_legacy_env(env)
    message = str(excinfo.value)
    assert "RCA_PG_DSN is no longer read; rename it to DBAGENT_PG_DSN" in message
    assert "RCA_DOCROOT is no longer read; rename it to DBAGENT_DOCROOT" in message
    assert len(message.splitlines()) == 2


def test_presence_based_not_value_based():
    # An empty value is still presence, and a legacy name set alongside the
    # correct new one is still an error.
    with pytest.raises(SystemExit):
        reject_legacy_env({"RCA_PG_DSN": ""})
    with pytest.raises(SystemExit):
        reject_legacy_env({"RCA_PG_DSN": "a", "DBAGENT_PG_DSN": "b"})


def test_silent_on_a_clean_environment_and_on_the_new_names():
    assert reject_legacy_env({}) is None
    assert reject_legacy_env({new: "v" for new in C2_TABLE.values()}) is None
    # Unprefixed names C.2 deliberately leaves alone.
    assert (
        reject_legacy_env(
            {
                "PROBE_CONFIG": "/etc/dbagent-probe/config.yaml",
                "PG_DSN": "postgresql://x",
                "BOOTSTRAP_TOKEN": "t",
                "RCA_COMMON_DIR": "/repo/libs/py/rca_common",
            }
        )
        is None
    )


def test_defaults_to_the_process_environment(monkeypatch):
    monkeypatch.delenv("RCA_PG_DSN", raising=False)
    assert reject_legacy_env() is None
    monkeypatch.setenv("RCA_PG_DSN", "postgresql://legacy")
    with pytest.raises(SystemExit):
        reject_legacy_env()
