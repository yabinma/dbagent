"""Unit tests for static_validate via activity path and rawcmd module re-export."""
import pytest

from rca_common.rawcmd import static_validate


def test_validator_accepts_allowlisted():
    assert static_validate("cat /tmp/x").ok


def test_validator_rejects_pipe():
    assert not static_validate("cat /tmp/x | tee /tmp/y").ok
