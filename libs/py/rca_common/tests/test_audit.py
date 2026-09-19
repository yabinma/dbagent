"""Unit tests for audit writer."""
import uuid
from unittest.mock import MagicMock

import pytest

from rca_common.audit import actor_agent, actor_system, write_audit
from rca_common.db.models import AUDIT_ACTIONS


def test_actors():
    assert actor_system() == "system"
    assert actor_agent("rca") == "agent:rca"


def test_write_audit_rejects_unknown_action():
    session = MagicMock()
    with pytest.raises(ValueError):
        write_audit(session, action="not_a_real_action", actor="system")


def test_write_audit_ok():
    session = MagicMock()
    row = write_audit(
        session,
        action="case_opened",
        actor=actor_system(),
        investigation_id=uuid.uuid4(),
        detail={"x": 1},
    )
    assert row.action == "case_opened"
    session.add.assert_called_once()
    assert "case_opened" in AUDIT_ACTIONS
