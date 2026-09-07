"""HMAC-SHA256 webhook authentication (design.md Section 4.1).

Header: ``X-Signature: hmac-sha256(body, shared_secret)`` (hex digest).
Secrets are configured per source; the source name is taken from the
JSON body field ``source`` (or the optional ``X-Alert-Source`` header).
"""
from __future__ import annotations

import hashlib
import hmac
from typing import Mapping


class HMACAuthError(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def compute_signature(body: bytes, secret: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return digest


def verify_signature(
    body: bytes,
    *,
    signature_header: str | None,
    secret: str,
) -> None:
    """Raise ``HMACAuthError`` when the signature is missing or invalid."""
    if not signature_header:
        raise HMACAuthError("missing X-Signature header")
    provided = signature_header.strip()
    # Accept bare hex or optional "sha256=" prefix.
    if provided.lower().startswith("sha256="):
        provided = provided.split("=", 1)[1].strip()
    expected = compute_signature(body, secret)
    if not hmac.compare_digest(provided, expected):
        raise HMACAuthError("invalid signature")


def resolve_source_secret(
    sources: Mapping[str, str],
    *,
    source: str | None,
) -> str:
    if not source:
        raise HMACAuthError("unknown source")
    secret = sources.get(source)
    if secret is None:
        raise HMACAuthError(f"unknown source: {source}")
    return secret
