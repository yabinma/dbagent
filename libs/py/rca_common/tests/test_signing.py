import base64
import os
import stat

import nacl.signing
import pytest

from rca_common.signing.signer import (
    MountedEd25519Signer,
    bootstrap_signing_key,
    canonical_step_hash,
    verify,
)


def test_sign_verify_round_trip():
    signing_key = nacl.signing.SigningKey.generate()
    signer = MountedEd25519Signer(signing_key)
    message = canonical_step_hash("exec-1", "pb-1", 0, "restart_service", {"a": 1})
    signature = signer.sign(message)
    assert verify(signer.public_key_bytes(), message, signature) is True


def test_verify_rejects_tampered_message():
    signing_key = nacl.signing.SigningKey.generate()
    signer = MountedEd25519Signer(signing_key)
    message = canonical_step_hash("exec-1", "pb-1", 0, "restart_service", {"a": 1})
    signature = signer.sign(message)
    tampered = canonical_step_hash("exec-1", "pb-1", 1, "restart_service", {"a": 1})
    assert verify(signer.public_key_bytes(), tampered, signature) is False


def test_verify_rejects_wrong_key():
    signer_a = MountedEd25519Signer(nacl.signing.SigningKey.generate())
    signer_b = MountedEd25519Signer(nacl.signing.SigningKey.generate())
    message = canonical_step_hash("exec-1", "pb-1", 0, "op", {})
    signature = signer_a.sign(message)
    assert verify(signer_b.public_key_bytes(), message, signature) is False


def test_canonical_step_hash_is_key_order_independent():
    params_a = {"service": "presto", "node": "worker-1"}
    params_b = {"node": "worker-1", "service": "presto"}
    hash_a = canonical_step_hash("exec-1", "pb-1", 2, "restart_service", params_a)
    hash_b = canonical_step_hash("exec-1", "pb-1", 2, "restart_service", params_b)
    assert hash_a == hash_b


@pytest.mark.parametrize(
    "field,base_kwargs,changed_kwargs",
    [
        (
            "execution_id",
            dict(execution_id="exec-1", playbook_id="pb-1", step_index=0, op="op", params={}),
            dict(execution_id="exec-2", playbook_id="pb-1", step_index=0, op="op", params={}),
        ),
        (
            "playbook_id",
            dict(execution_id="exec-1", playbook_id="pb-1", step_index=0, op="op", params={}),
            dict(execution_id="exec-1", playbook_id="pb-2", step_index=0, op="op", params={}),
        ),
        (
            "step_index",
            dict(execution_id="exec-1", playbook_id="pb-1", step_index=0, op="op", params={}),
            dict(execution_id="exec-1", playbook_id="pb-1", step_index=1, op="op", params={}),
        ),
        (
            "op",
            dict(execution_id="exec-1", playbook_id="pb-1", step_index=0, op="op-a", params={}),
            dict(execution_id="exec-1", playbook_id="pb-1", step_index=0, op="op-b", params={}),
        ),
        (
            "params",
            dict(execution_id="exec-1", playbook_id="pb-1", step_index=0, op="op", params={"a": 1}),
            dict(execution_id="exec-1", playbook_id="pb-1", step_index=0, op="op", params={"a": 2}),
        ),
    ],
)
def test_canonical_step_hash_is_sensitive_to_every_field(field, base_kwargs, changed_kwargs):
    base_hash = canonical_step_hash(**base_kwargs)
    changed_hash = canonical_step_hash(**changed_kwargs)
    assert base_hash != changed_hash, f"hash did not change when {field} changed"


def test_bootstrap_signing_key_generates_new_key_with_0600_perms(tmp_path):
    key_path = tmp_path / "signing" / "ed25519.key"
    signer = bootstrap_signing_key(str(key_path))

    assert key_path.exists()
    mode = stat.S_IMODE(os.stat(key_path).st_mode)
    assert mode == 0o600
    assert isinstance(signer, MountedEd25519Signer)
    assert len(signer.public_key_bytes()) == 32


def test_bootstrap_signing_key_is_idempotent(tmp_path):
    key_path = tmp_path / "ed25519.key"
    signer_1 = bootstrap_signing_key(str(key_path))
    raw_1 = key_path.read_bytes()

    signer_2 = bootstrap_signing_key(str(key_path))
    raw_2 = key_path.read_bytes()

    assert raw_1 == raw_2
    assert signer_1.public_key_bytes() == signer_2.public_key_bytes()


def test_bootstrap_signing_key_loads_existing_key(tmp_path):
    key_path = tmp_path / "ed25519.key"
    original_signing_key = nacl.signing.SigningKey.generate()
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_bytes(bytes(original_signing_key))
    os.chmod(key_path, 0o600)

    loaded = bootstrap_signing_key(str(key_path))
    assert loaded.public_key_bytes() == bytes(original_signing_key.verify_key)


def test_bootstrap_signing_key_writes_public_key_sidecar(tmp_path):
    key_path = tmp_path / "ed25519.key"
    signer = bootstrap_signing_key(str(key_path))

    pub_path = tmp_path / "ed25519.key.pub"
    assert pub_path.exists()
    mode = stat.S_IMODE(os.stat(pub_path).st_mode)
    assert mode == 0o644

    decoded = base64.b64decode(pub_path.read_bytes())
    assert decoded == signer.public_key_bytes()


def test_bootstrap_signing_key_refreshes_sidecar_on_existing_key_path(tmp_path):
    key_path = tmp_path / "ed25519.key"
    pub_path = tmp_path / "ed25519.key.pub"

    signer = bootstrap_signing_key(str(key_path))
    pub_path.unlink()  # simulate the sidecar not existing yet (pre-upgrade deployment)
    assert not pub_path.exists()

    signer_2 = bootstrap_signing_key(str(key_path))

    assert pub_path.exists()
    assert base64.b64decode(pub_path.read_bytes()) == signer_2.public_key_bytes()
    assert signer.public_key_bytes() == signer_2.public_key_bytes()


def test_mounted_signer_load_from_path(tmp_path):
    key_path = tmp_path / "ed25519.key"
    bootstrap_signing_key(str(key_path))
    loaded = MountedEd25519Signer.load(str(key_path))
    assert len(loaded.public_key_bytes()) == 32


def test_bootstrap_signing_key_cleans_up_tmp_file_on_write_failure(tmp_path, monkeypatch):
    key_path = tmp_path / "ed25519.key"

    def _boom(*args, **kwargs):
        raise OSError("disk full")

    import os as os_module

    real_fdopen = os_module.fdopen
    monkeypatch.setattr(os_module, "fdopen", _boom)

    with pytest.raises(OSError):
        bootstrap_signing_key(str(key_path))

    monkeypatch.setattr(os_module, "fdopen", real_fdopen)
    tmp_file = key_path.with_suffix(key_path.suffix + ".tmp")
    assert not tmp_file.exists()
    assert not key_path.exists()
