"""Alert fingerprint computation (design.md Section 4.1).

``fingerprint = hash(platform_key + normalized error signature)``.
Normalization lowercases, collapses whitespace, and strips leading/
trailing punctuation so trivial alert-text drift still correlates.
"""
from __future__ import annotations

import hashlib
import re

_WS_RE = re.compile(r"\s+")
_EDGE_PUNCT_RE = re.compile(r"^[\s\W_]+|[\s\W_]+$", re.UNICODE)


def normalize_error_signature(error_summary: str) -> str:
    text = (error_summary or "").strip().lower()
    text = _WS_RE.sub(" ", text)
    text = _EDGE_PUNCT_RE.sub("", text)
    return text


def compute_fingerprint(platform_key: str, error_summary: str) -> str:
    """SHA-256 hex digest of ``platform_key`` + newline + normalized summary."""
    signature = normalize_error_signature(error_summary)
    payload = f"{platform_key}\n{signature}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
