"""UT-IG-6: correlation_lock_key and acquire_correlation_lock (FP-IG-16)."""
from __future__ import annotations

from unittest.mock import MagicMock

from sqlalchemy import text

from rca_common.investigation_repo import (
    acquire_correlation_lock,
    correlation_lock_key,
)


def test_correlation_lock_key_deterministic():
    a = correlation_lock_key("platform-a", "fp-1")
    b = correlation_lock_key("platform-a", "fp-1")
    assert a == b


def test_correlation_lock_key_order_sensitive():
    a = correlation_lock_key("platform-a", "fp-1")
    b = correlation_lock_key("fp-1", "platform-a")
    c = correlation_lock_key("platform-a", "fp-2")
    assert a != b
    assert a != c


def test_correlation_lock_key_signed_int64_range():
    for pk, fp in [
        ("p", "f"),
        ("x" * 200, "y" * 200),
        ("", ""),
        ("unicode-平台", "指纹"),
    ]:
        k = correlation_lock_key(pk, fp)
        assert isinstance(k, int)
        assert -(2**63) <= k < 2**63


def test_correlation_lock_key_stable_across_calls():
    keys = {correlation_lock_key("pk", "fp") for _ in range(20)}
    assert len(keys) == 1


def test_acquire_correlation_lock_emits_xact_lock():
    session = MagicMock()
    acquire_correlation_lock(session, "platform-a", "fp-1")
    session.execute.assert_called_once()
    args, kwargs = session.execute.call_args
    stmt = args[0]
    params = args[1] if len(args) > 1 else kwargs.get("parameters") or kwargs
    # text() statement names pg_advisory_xact_lock
    sql = str(stmt)
    assert "pg_advisory_xact_lock" in sql
    assert "pg_advisory_lock" not in sql.replace("pg_advisory_xact_lock", "")
    expected_key = correlation_lock_key("platform-a", "fp-1")
    # params may be dict
    if isinstance(params, dict):
        assert params.get("key") == expected_key
