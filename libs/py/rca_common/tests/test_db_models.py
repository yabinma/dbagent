"""Sanity tests for the SQLAlchemy ORM models (design.md Section 4.3).

No real database is required -- these tests only exercise the declarative
metadata (table names, column presence, DDL compilation) which is pure
Python and fast, per the Section 14.2 unit-tier isolation bar.
"""
from sqlalchemy.schema import CreateTable

from rca_common.db.models import (
    AUDIT_ACTIONS,
    AlertEventRow,
    Approval,
    AuditLog,
    Base,
    Evidence,
    Investigation,
    Iteration,
    LLMCall,
    Platform,
    Playbook,
    Probe,
    RemediationExecution,
    User,
)

EXPECTED_TABLES = {
    "platforms",
    "probes",
    "alert_events",
    "investigations",
    "iterations",
    "evidence",
    "llm_calls",
    "playbooks",
    "remediation_executions",
    "approvals",
    "users",
    "audit_log",
}


def test_all_section_4_3_tables_are_registered():
    assert set(Base.metadata.tables.keys()) == EXPECTED_TABLES


def test_every_model_ddl_compiles():
    # Compiling CREATE TABLE DDL for every model exercises column types,
    # FKs, and primary keys without needing a live database.
    for table in Base.metadata.tables.values():
        ddl = str(CreateTable(table))
        assert "CREATE TABLE" in ddl


def test_platform_table_columns():
    cols = {c.name for c in Platform.__table__.columns}
    assert cols == {
        "platform_key",
        "platform_type",
        "deployment",
        "display_name",
        "status",
        "config",
        "created_at",
    }
    assert Platform.__table__.primary_key.columns.keys() == ["platform_key"]


def test_probe_foreign_key_to_platform():
    fks = list(Probe.__table__.columns["platform_key"].foreign_keys)
    assert len(fks) == 1
    assert fks[0].column.table.name == "platforms"


def test_investigation_composite_primary_key():
    pk_cols = set(Investigation.__table__.primary_key.columns.keys())
    assert pk_cols == {"investigation_id", "created_at"}


def test_llm_calls_composite_primary_key_and_columns():
    pk_cols = set(LLMCall.__table__.primary_key.columns.keys())
    assert pk_cols == {"call_id", "created_at"}
    cols = {c.name for c in LLMCall.__table__.columns}
    assert {
        "investigation_id",
        "round",
        "agent_role",
        "model",
        "provider",
        "prompt_ref",
        "response_ref",
        "input_tokens",
        "output_tokens",
        "cost_usd",
        "latency_ms",
        "error",
    } <= cols


def test_iteration_composite_primary_key():
    pk_cols = set(Iteration.__table__.primary_key.columns.keys())
    assert pk_cols == {"investigation_id", "round"}


def test_audit_log_composite_primary_key():
    pk_cols = set(AuditLog.__table__.primary_key.columns.keys())
    assert pk_cols == {"seq", "at"}


def test_playbook_maturity_default_factory():
    default = Playbook.__table__.columns["maturity"].default.arg({})
    assert default == {"approved_runs": 0, "success": 0, "rollbacks": 0}


def test_evidence_defaults():
    assert Evidence.__table__.columns["redacted"].default.arg is False


def test_alert_event_table_name_and_pk():
    assert AlertEventRow.__tablename__ == "alert_events"
    assert AlertEventRow.__table__.primary_key.columns.keys() == ["event_id"]


def test_remediation_execution_fk_to_playbook():
    fks = list(RemediationExecution.__table__.columns["playbook_id"].foreign_keys)
    assert len(fks) == 1
    assert fks[0].column.table.name == "playbooks"


def test_approval_and_user_tables_present():
    assert Approval.__tablename__ == "approvals"
    assert User.__tablename__ == "users"
    assert User.__table__.columns["username"].unique is True
    assert "must_change_password" in {c.name for c in User.__table__.columns}


def test_audit_actions_enum_is_nonempty_and_unique():
    assert len(AUDIT_ACTIONS) == len(set(AUDIT_ACTIONS))
    assert "event_received" in AUDIT_ACTIONS
    assert "case_closed" in AUDIT_ACTIONS
    # M4 additions (Section 4.3 / 10.2)
    for action in (
        "case_paused",
        "case_resumed",
        "case_aborted",
        "budget_adjusted",
        "admin_config_changed",
    ):
        assert action in AUDIT_ACTIONS
