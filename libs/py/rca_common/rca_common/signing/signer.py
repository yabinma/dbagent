"""Write-channel signing (design.md Section 9.3, D14).

MVP backend is a private key mounted on disk (K8s Secret / compose volume),
generated once by an idempotent pre-install job. The `Signer` protocol
abstracts the backend so Vault / AWS KMS implementations can be swapped in
later (Phase 2/3) without touching callers.

Canonicalization contract (this is the byte-for-byte contract the probe's Go
verifier -- built in M2 -- must reproduce exactly):

    message = sha256(
        execution_id.encode() + b"|" +
        playbook_id.encode() + b"|" +
        str(step_index).encode() + b"|" +
        op.encode() + b"|" +
        rfc8785_canonicalize(params)
    )
    signature = ed25519_sign(private_key, message)

`rfc8785_canonicalize` is RFC 8785 (JSON Canonicalization Scheme / JCS), so
both sides serialize `params` identically regardless of key ordering.
"""
from __future__ import annotations

import base64
import hashlib
import os
import stat
from pathlib import Path
from typing import Any, Protocol

import nacl.exceptions
import nacl.signing
import rfc8785


class Signer(Protocol):
    def sign(self, message: bytes) -> bytes:
        """Returns an ed25519 signature over `message`."""

    def public_key_bytes(self) -> bytes:
        """Returns the raw 32-byte ed25519 public key."""


def canonical_step_hash(
    execution_id: str,
    playbook_id: str,
    step_index: int,
    op: str,
    params: dict[str, Any],
) -> bytes:
    """sha256 digest of the canonical RemediationStep fields (see module
    docstring for the exact byte layout)."""
    canonical_params = rfc8785.dumps(params)
    parts = [
        execution_id.encode("utf-8"),
        playbook_id.encode("utf-8"),
        str(step_index).encode("utf-8"),
        op.encode("utf-8"),
        canonical_params,
    ]
    h = hashlib.sha256()
    for i, part in enumerate(parts):
        if i > 0:
            h.update(b"|")
        h.update(part)
    return h.digest()


class MountedEd25519Signer:
    """MVP `Signer` backend: ed25519 private key read from a mounted file
    path (design.md D14: 'private key in K8s Secret ... mounted by the
    worker')."""

    def __init__(self, signing_key: nacl.signing.SigningKey):
        self._signing_key = signing_key

    def sign(self, message: bytes) -> bytes:
        return self._signing_key.sign(message).signature

    def public_key_bytes(self) -> bytes:
        return bytes(self._signing_key.verify_key)

    @classmethod
    def load(cls, key_path: str) -> "MountedEd25519Signer":
        raw = Path(key_path).read_bytes()
        return cls(nacl.signing.SigningKey(raw))


def bootstrap_signing_key(key_path: str) -> MountedEd25519Signer:
    """Idempotent pre-install job (D14): generates an ed25519 key pair on
    first run; on subsequent runs (Secret/volume already populated) loads
    the existing key unchanged. Safe to call on every worker startup.

    Also (re-)writes a `{key_path}.pub` sidecar file: the raw public key,
    base64-encoded, with normal (0644) read permissions -- unlike the
    private key, the public key is not sensitive. This is how probe-gateway
    (Go, M2) obtains the control-plane's current signing public key to
    embed in `RegisterAck` (D14: "The public key reaches probes in
    RegisterAck") without ever needing read access to the private key
    itself: deploy manifests mount only `{key_path}.pub` (read-only) into
    probe-gateway, via a K8s Secret volume's per-key `items` mapping (or
    the compose-equivalent) -- an M6 deploy-manifest concern, not
    implemented here. The sidecar is refreshed on every call (including
    the existing-key path) so it stays in sync even if it didn't exist
    when this function was last extended."""
    path = Path(key_path)
    pub_path = path.with_name(path.name + ".pub")

    if path.exists():
        signer = MountedEd25519Signer.load(key_path)
        _write_public_key_sidecar(pub_path, signer.public_key_bytes())
        return signer

    path.parent.mkdir(parents=True, exist_ok=True)
    signing_key = nacl.signing.SigningKey.generate()

    # Write with restrictive permissions, atomically (write to temp then
    # rename) so a crash mid-write never leaves a partial key on disk.
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(bytes(signing_key))
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise
    os.chmod(tmp_path, stat.S_IRUSR | stat.S_IWUSR)
    os.replace(tmp_path, path)

    signer = MountedEd25519Signer(signing_key)
    _write_public_key_sidecar(pub_path, signer.public_key_bytes())
    return signer


def _write_public_key_sidecar(pub_path: Path, public_key_bytes: bytes) -> None:
    desired = base64.b64encode(public_key_bytes)
    # Read-only Secret mounts (K8s) already carry the .pub written by the
    # signing-key hook Job — do not attempt a write that would raise EROFS.
    # The *only* sanctioned reason to skip the write is a read that has
    # **proved** the sidecar already holds exactly these bytes: mere existence
    # is not proof.  A mismatched (or unreadable) sidecar that swallowed the
    # write error would leave probe-gateway verifying RegisterAck against a
    # different public key than the worker signs with, silently (code review
    # round 5, W2).
    if pub_path.exists():
        try:
            if pub_path.read_bytes() == desired:
                return
        except OSError:
            # Could not prove equality — fall through and write; any failure
            # from here on must surface to the caller.
            pass
    tmp_path = pub_path.with_suffix(pub_path.suffix + ".tmp")
    try:
        tmp_path.write_bytes(desired)
        os.chmod(tmp_path, 0o644)
        os.replace(tmp_path, pub_path)
    except OSError:
        tmp_path.unlink(missing_ok=True)
        raise


def verify(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
    """Reference verifier (mirrors what the Go probe implements in M2) --
    used by control-plane-side tests and by any control-plane pre-flight
    checks before dispatching a RemediationStep."""
    try:
        nacl.signing.VerifyKey(public_key_bytes).verify(message, signature)
        return True
    except nacl.exceptions.BadSignatureError:
        return False
