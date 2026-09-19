"""Unit tests for rca_common.userauth (FP-M4-1 / FP-M4-3)."""
from rca_common.userauth import (
    MEMORY_COST,
    PARALLELISM,
    TIME_COST,
    hash_password,
    needs_rehash,
    verify_password,
)


def test_hash_and_verify_roundtrip():
    h = hash_password("correct-horse-battery")
    assert h.startswith("$argon2id$")
    assert verify_password(h, "correct-horse-battery") is True
    assert verify_password(h, "wrong-password") is False


def test_parameters_match_design():
    assert TIME_COST == 3
    assert MEMORY_COST == 65536
    assert PARALLELISM == 4
    h = hash_password("x" * 12)
    assert f"m={MEMORY_COST}" in h
    assert f"t={TIME_COST}" in h
    assert f"p={PARALLELISM}" in h


def test_verify_invalid_hash_returns_false():
    assert verify_password("not-a-hash", "anything") is False
    assert verify_password("", "x") is False


def test_needs_rehash_current_hash_false():
    h = hash_password("somepassword12")
    assert needs_rehash(h) is False


def test_needs_rehash_garbage_true():
    assert needs_rehash("garbage") is True
