"""HMAC auth unit tests (Section 4.1 / F1) + B1 hot-path micro-benchmark."""
import time

import pytest

from rca_common.fingerprint import compute_fingerprint, normalize_error_signature

from gateway.hmac_auth import (
    HMACAuthError,
    compute_signature,
    resolve_source_secret,
    verify_signature,
)


def test_round_trip_signature():
    body = b'{"source":"grafana-prod","error_summary":"x"}'
    secret = "s3cr3t"
    sig = compute_signature(body, secret)
    verify_signature(body, signature_header=sig, secret=secret)
    verify_signature(body, signature_header=f"sha256={sig}", secret=secret)


def test_missing_signature():
    with pytest.raises(HMACAuthError, match="missing"):
        verify_signature(b"{}", signature_header=None, secret="s")


def test_invalid_signature():
    with pytest.raises(HMACAuthError, match="invalid"):
        verify_signature(b"{}", signature_header="deadbeef", secret="s")


def test_unknown_source():
    with pytest.raises(HMACAuthError, match="unknown"):
        resolve_source_secret({"grafana-prod": "s"}, source="nope")
    with pytest.raises(HMACAuthError, match="unknown"):
        resolve_source_secret({"grafana-prod": "s"}, source=None)


def test_resolve_ok():
    assert resolve_source_secret({"manual": "abc"}, source="manual") == "abc"


def test_b1_hmac_normalize_fingerprint_hot_path():
    """B1: HMAC verify + normalize + fingerprint hot path >= 200 req/s, p99 < 150 ms.

    In-process micro-benchmark of the crypto front of the alert-storm door
    (design.md Section 14.4). Full 5x-burst HTTP+PG k6 profile is M6.
    """
    body = b'{"source":"grafana-prod","platform_key":"presto-us1","error_summary":"Worker OOM killed"}'
    secret = "s3cr3t-for-b1-bench"
    sig = compute_signature(body, secret)
    platform_key = "presto-us1"
    summary = "Worker OOM killed"
    n = 500
    samples_ms: list[float] = []
    t0 = time.perf_counter()
    for _ in range(n):
        s = time.perf_counter()
        verify_signature(body, signature_header=sig, secret=secret)
        normalize_error_signature(summary)
        compute_fingerprint(platform_key, summary)
        samples_ms.append((time.perf_counter() - s) * 1000)
    elapsed = time.perf_counter() - t0
    rate = n / elapsed
    samples_ms.sort()
    p99 = samples_ms[int(0.99 * (n - 1))]
    assert rate >= 200.0, f"B1 FAILED: {rate:.1f} req/s (budget >= 200)"
    assert p99 < 150.0, f"B1 FAILED: p99={p99:.2f} ms (budget < 150 ms)"
