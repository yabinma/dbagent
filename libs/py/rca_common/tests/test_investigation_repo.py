"""Unit tests for investigation_repo helpers."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from rca_common.investigation_repo import (
    NON_TERMINAL_STATUSES,
    TERMINAL_STATUSES,
    create_approval,
    create_investigation,
    decide_approval,
    find_open_by_fingerprint,
    get_evidence,
    get_platform,
    insert_alert_event,
    insert_evidence,
    merge_platform_budget,
    open_case_from_event,
    record_iteration,
    update_investigation_status,
)


def test_merge_platform_budget_overrides():
    defaults = {"max_rounds": 15, "max_cost_usd": 10.0, "max_wall_seconds": 1800}
    merged = merge_platform_budget(defaults, {"budget": {"max_rounds": 3}})
    assert merged["max_rounds"] == 3
    assert merged["max_cost_usd"] == 10.0
    assert merge_platform_budget(defaults, None) == defaults
    assert merge_platform_budget(defaults, {"budget_defaults": {"max_cost_usd": 1.0}})["max_cost_usd"] == 1.0
    assert merge_platform_budget(defaults, {}) == defaults


def test_status_sets():
    assert "INVESTIGATING" in NON_TERMINAL_STATUSES
    assert "RESOLVED" in TERMINAL_STATUSES


def test_create_helpers_add_rows():
    session = MagicMock()
    inv_id = uuid.uuid4()
    inv = create_investigation(
        session,
        investigation_id=inv_id,
        platform_key="p",
        status="OPEN",
        trigger_event=uuid.uuid4(),
        workflow_id="wf",
        budget={"max_rounds": 1},
    )
    assert inv.investigation_id == inv_id
    session.add.assert_called()

    insert_alert_event(
        session,
        event_id=uuid.uuid4(),
        fingerprint="fp",
        source="s",
        platform_key="p",
        severity="high",
        payload_ref=None,
        normalized={},
        disposition="opened",
        investigation_id=inv_id,
    )
    record_iteration(
        session,
        investigation_id=inv_id,
        round_num=1,
        plan={"tool_calls": []},
        rca_output={"status": "concluded"},
    )
    insert_evidence(
        session,
        investigation_id=inv_id,
        round_num=1,
        tool_name="presto_nodes",
        args={},
        exit_code=0,
        summary="ok",
        payload_ref="s3://x",
        payload_bytes=10,
    )
    create_approval(session, investigation_id=inv_id, kind="raw_command", subject={"c": "cat x"})
    assert session.add.call_count >= 5


def test_get_platform_and_evidence():
    session = MagicMock()
    session.get = MagicMock(return_value="plat")
    assert get_platform(session, "k") == "plat"
    assert get_evidence(session, uuid.uuid4()) == "plat"
    assert get_evidence(session, "not-a-uuid") is None


def test_update_investigation_status():
    session = MagicMock()
    inv = MagicMock()
    inv.status = "OPEN"
    inv.rca_report = None
    inv.spent = {}
    inv.closed_at = None
    session.scalars = MagicMock(return_value=MagicMock(first=MagicMock(return_value=inv)))
    update_investigation_status(
        session, uuid.uuid4(), "RESOLVED", rca_report={"status": "concluded"}, spent={"rounds": 1}, close=True
    )
    assert inv.status == "RESOLVED"
    assert inv.rca_report["status"] == "concluded"
    assert inv.closed_at is not None

    session.scalars = MagicMock(return_value=MagicMock(first=MagicMock(return_value=None)))
    with pytest.raises(KeyError):
        update_investigation_status(session, uuid.uuid4(), "OPEN")


def test_decide_approval():
    session = MagicMock()
    row = MagicMock()
    row.decision = None
    session.get = MagicMock(return_value=row)
    decide_approval(session, uuid.uuid4(), decision="approved", comment="ok")
    assert row.decision == "approved"

    row.decision = "approved"
    with pytest.raises(ValueError):
        decide_approval(session, uuid.uuid4(), decision="denied")

    session.get = MagicMock(return_value=None)
    with pytest.raises(KeyError):
        decide_approval(session, uuid.uuid4(), decision="approved")


def test_open_case_from_event():
    session = MagicMock()
    inv = open_case_from_event(
        session,
        event={"event_id": str(uuid.uuid4()), "platform_key": "presto-us1"},
        workflow_id="wf-1",
        budget={"max_rounds": 5},
    )
    assert inv.platform_key == "presto-us1"
    assert session.add.call_count >= 2  # investigation + audit


def test_find_open_by_fingerprint_hits_and_misses():
    session = MagicMock()
    inv_id = uuid.uuid4()
    inv = MagicMock()
    inv.status = "INVESTIGATING"
    inv.investigation_id = inv_id

    # FP-IG-6: single SELECT … LIMIT 1; scalars().first() returns the Investigation.
    session.scalars = MagicMock(return_value=MagicMock(first=MagicMock(return_value=inv)))
    found = find_open_by_fingerprint(
        session,
        fingerprint="fp",
        platform_key="p",
        correlation_window_seconds=1800,
        now=datetime.now(timezone.utc),
    )
    assert found is inv
    session.scalars.assert_called_once()

    # Empty window → None
    session.scalars = MagicMock(return_value=MagicMock(first=MagicMock(return_value=None)))
    assert (
        find_open_by_fingerprint(
            session, fingerprint="x", platform_key="p", correlation_window_seconds=60
        )
        is None
    )
