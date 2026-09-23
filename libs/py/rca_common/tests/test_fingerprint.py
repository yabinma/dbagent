"""Unit tests for fingerprint / error-signature normalization (Section 4.1)."""
from rca_common.fingerprint import compute_fingerprint, normalize_error_signature


def test_normalize_collapses_whitespace_and_case():
    assert normalize_error_signature("  Worker   OOM\nKilled  ") == "worker oom killed"


def test_fingerprint_stable_across_trivial_drift():
    a = compute_fingerprint("presto-us1", "Query failed: memory limit exceeded")
    b = compute_fingerprint("presto-us1", "  Query failed: Memory Limit Exceeded.  ")
    assert a == b
    assert len(a) == 64


def test_fingerprint_differs_by_platform():
    a = compute_fingerprint("presto-a", "same error")
    b = compute_fingerprint("presto-b", "same error")
    assert a != b


def test_fingerprint_differs_by_summary():
    a = compute_fingerprint("presto-a", "oom")
    b = compute_fingerprint("presto-a", "gc hang")
    assert a != b
