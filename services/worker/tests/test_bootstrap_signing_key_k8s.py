"""FP-M6-8: bootstrap_signing_key.py --k8s-secret mode against mocked K8s API."""
from __future__ import annotations

import base64
import importlib.util
from pathlib import Path

import httpx
import pytest
import respx

_SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "bootstrap_signing_key.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("bootstrap_signing_key_k8s", _SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


_mod = _load_module()
bootstrap_from_k8s_secret = _mod.bootstrap_from_k8s_secret
main = _mod.main


def _readable_ca() -> str:
    """A real, readable PEM bundle.

    The secrets API call carries the SA bearer token and can upload the
    private signing key, so the production path builds its client with
    ``verify=<ca path>`` and refuses to run at all when the CA is missing or
    unreadable (code review round 5, C7).  Tests therefore hand it a genuine
    CA file and mock the *transport*, never TLS verification itself.
    """
    import certifi

    return certifi.where()


@pytest.fixture
def key_path(tmp_path):
    return str(tmp_path / "ed25519.key")


@respx.mock
def test_k8s_secret_200_reuses_existing(key_path, tmp_path):
    from rca_common.signing.signer import bootstrap_signing_key

    # Pre-generate a key to put in the secret.
    bootstrap_signing_key(key_path)
    raw = Path(key_path).read_bytes()
    pub = Path(key_path + ".pub").read_bytes()
    Path(key_path).unlink()
    Path(key_path + ".pub").unlink(missing_ok=True)

    token = tmp_path / "token"
    token.write_text("tok", encoding="utf-8")
    secret_body = {
        "data": {
            "ed25519.key": base64.b64encode(raw).decode(),
            "ed25519.key.pub": base64.b64encode(pub).decode(),
        }
    }
    respx.get("https://k8s/api/v1/namespaces/ns/secrets/dbagent-signing-key").mock(
        return_value=httpx.Response(200, json=secret_body)
    )
    rc = bootstrap_from_k8s_secret(
        key_path,
        "dbagent-signing-key",
        "ns",
        token_path=str(token),
        ca_path=_readable_ca(),
        api_base="https://k8s",
    )
    assert rc == 0
    assert Path(key_path).read_bytes() == raw


@respx.mock
def test_k8s_secret_404_creates(key_path, tmp_path):
    token = tmp_path / "token"
    token.write_text("tok", encoding="utf-8")
    respx.get("https://k8s/api/v1/namespaces/ns/secrets/dbagent-signing-key").mock(
        return_value=httpx.Response(404, json={"reason": "NotFound"})
    )
    respx.post("https://k8s/api/v1/namespaces/ns/secrets").mock(
        return_value=httpx.Response(201, json={"metadata": {"name": "dbagent-signing-key"}})
    )
    rc = bootstrap_from_k8s_secret(
        key_path,
        "dbagent-signing-key",
        "ns",
        token_path=str(token),
        ca_path=_readable_ca(),
        api_base="https://k8s",
    )
    assert rc == 0
    assert Path(key_path).is_file()


@respx.mock
def test_k8s_secret_409_reread(key_path, tmp_path):
    from rca_common.signing.signer import bootstrap_signing_key

    bootstrap_signing_key(key_path)
    raw = Path(key_path).read_bytes()
    pub = Path(key_path + ".pub").read_bytes()
    # Delete local so create path runs, then 409 forces re-read.
    Path(key_path).unlink()
    Path(key_path + ".pub").unlink(missing_ok=True)

    token = tmp_path / "token"
    token.write_text("tok", encoding="utf-8")
    secret_body = {
        "data": {
            "ed25519.key": base64.b64encode(raw).decode(),
            "ed25519.key.pub": base64.b64encode(pub).decode(),
        }
    }
    respx.get("https://k8s/api/v1/namespaces/ns/secrets/dbagent-signing-key").mock(
        side_effect=[
            httpx.Response(404, json={}),
            httpx.Response(200, json=secret_body),
        ]
    )
    respx.post("https://k8s/api/v1/namespaces/ns/secrets").mock(
        return_value=httpx.Response(409, json={"reason": "AlreadyExists"})
    )
    rc = bootstrap_from_k8s_secret(
        key_path,
        "dbagent-signing-key",
        "ns",
        token_path=str(token),
        ca_path=_readable_ca(),
        api_base="https://k8s",
    )
    assert rc == 0
    assert Path(key_path).read_bytes() == raw


@respx.mock
def test_k8s_secret_missing_ca_fails_closed_without_calling_the_api(key_path, tmp_path):
    """C7: no CA → no request at all, rather than one with TLS off."""
    token = tmp_path / "token"
    token.write_text("tok", encoding="utf-8")
    route = respx.get(
        "https://k8s/api/v1/namespaces/ns/secrets/dbagent-signing-key"
    ).mock(return_value=httpx.Response(200, json={"data": {}}))

    rc = bootstrap_from_k8s_secret(
        key_path,
        "dbagent-signing-key",
        "ns",
        token_path=str(token),
        ca_path=str(tmp_path / "missing-ca"),
        api_base="https://k8s",
    )
    assert rc == 1
    assert not route.called, "the bearer token must never leave the pod unverified"
    assert not Path(key_path).exists()


@respx.mock
def test_k8s_secret_empty_or_unreadable_ca_fails_closed(key_path, tmp_path):
    """An existing-but-unusable CA file is the same failure as a missing one."""
    token = tmp_path / "token"
    token.write_text("tok", encoding="utf-8")
    empty_ca = tmp_path / "ca.crt"
    empty_ca.write_bytes(b"")
    route = respx.get(
        "https://k8s/api/v1/namespaces/ns/secrets/dbagent-signing-key"
    ).mock(return_value=httpx.Response(200, json={"data": {}}))

    rc = bootstrap_from_k8s_secret(
        key_path,
        "dbagent-signing-key",
        "ns",
        token_path=str(token),
        ca_path=str(empty_ca),
        api_base="https://k8s",
    )
    assert rc == 1
    assert not route.called


@respx.mock
def test_k8s_secret_injected_client_is_the_sanctioned_test_transport(key_path, tmp_path):
    """An explicitly injected client owns its own TLS policy; the CA gate
    applies to the client this module builds itself."""
    token = tmp_path / "token"
    token.write_text("tok", encoding="utf-8")
    respx.get("https://k8s/api/v1/namespaces/ns/secrets/dbagent-signing-key").mock(
        return_value=httpx.Response(404, json={})
    )
    respx.post("https://k8s/api/v1/namespaces/ns/secrets").mock(
        return_value=httpx.Response(201, json={})
    )
    import ssl

    ctx = ssl.create_default_context(cafile=_readable_ca())
    with httpx.Client(verify=ctx) as client:
        rc = bootstrap_from_k8s_secret(
            key_path,
            "dbagent-signing-key",
            "ns",
            token_path=str(token),
            ca_path=str(tmp_path / "missing-ca"),
            api_base="https://k8s",
            http_client=client,
        )
    assert rc == 0
    assert Path(key_path).is_file()


def test_ca_is_usable_matrix(tmp_path):
    good = tmp_path / "good.pem"
    good.write_bytes(b"-----BEGIN CERTIFICATE-----\n")
    assert _mod._ca_is_usable(str(good)) is True
    assert _mod._ca_is_usable(str(tmp_path / "nope.pem")) is False
    empty = tmp_path / "empty.pem"
    empty.write_bytes(b"")
    assert _mod._ca_is_usable(str(empty)) is False
    assert _mod._ca_is_usable(str(tmp_path)) is False  # a directory is not a CA


def test_k8s_secret_missing_token_hard_fail(key_path, tmp_path):
    rc = bootstrap_from_k8s_secret(
        key_path,
        "dbagent-signing-key",
        "ns",
        token_path=str(tmp_path / "no-token"),
        api_base="https://k8s",
    )
    assert rc == 1


@respx.mock
def test_k8s_secret_non_2xx_hard_fail(key_path, tmp_path):
    token = tmp_path / "token"
    token.write_text("tok", encoding="utf-8")
    respx.get("https://k8s/api/v1/namespaces/ns/secrets/dbagent-signing-key").mock(
        return_value=httpx.Response(500, text="boom")
    )
    rc = bootstrap_from_k8s_secret(
        key_path,
        "dbagent-signing-key",
        "ns",
        token_path=str(token),
        ca_path=_readable_ca(),
        api_base="https://k8s",
    )
    assert rc == 1


def test_cli_without_k8s_secret_still_works(tmp_path):
    key = tmp_path / "ed25519.key"
    assert main(["--key-path", str(key)]) == 0
    assert key.is_file()


@respx.mock
def test_main_dispatches_k8s_secret(tmp_path, monkeypatch):
    """CLI --k8s-secret path (the Helm signing-key hook Job wiring)."""
    key_path = tmp_path / "ed25519.key"
    token = tmp_path / "token"
    token.write_text("tok", encoding="utf-8")
    sa_ns = tmp_path / "namespace"
    sa_ns.write_text("from-sa\n", encoding="utf-8")
    monkeypatch.setattr(_mod, "_SA_TOKEN_PATH", str(token))
    monkeypatch.setattr(_mod, "_SA_NS_PATH", str(sa_ns))
    monkeypatch.setattr(_mod, "_SA_CA_PATH", _readable_ca())
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "k8s.test")
    monkeypatch.setenv("KUBERNETES_SERVICE_PORT", "443")

    respx.get("https://k8s.test:443/api/v1/namespaces/from-sa/secrets/hook-secret").mock(
        return_value=httpx.Response(404, json={"reason": "NotFound"})
    )
    respx.post("https://k8s.test:443/api/v1/namespaces/from-sa/secrets").mock(
        return_value=httpx.Response(201, json={"metadata": {"name": "hook-secret"}})
    )
    rc = main(
        [
            "--key-path",
            str(key_path),
            "--k8s-secret",
            "hook-secret",
            # namespace omitted → _read_sa_namespace from SA file
        ]
    )
    assert rc == 0
    assert key_path.is_file()


def test_read_sa_namespace_explicit_and_file(tmp_path, monkeypatch):
    assert _mod._read_sa_namespace("explicit-ns") == "explicit-ns"
    sa = tmp_path / "namespace"
    sa.write_text("pod-ns\n", encoding="utf-8")
    monkeypatch.setattr(_mod, "_SA_NS_PATH", str(sa))
    assert _mod._read_sa_namespace(None) == "pod-ns"
    monkeypatch.setattr(_mod, "_SA_NS_PATH", str(tmp_path / "missing"))
    try:
        _mod._read_sa_namespace(None)
        raise AssertionError("expected RuntimeError")
    except RuntimeError as exc:
        assert "namespace" in str(exc).lower()


@respx.mock
def test_create_secret_non_2xx_hard_fail(key_path, tmp_path):
    token = tmp_path / "token"
    token.write_text("tok", encoding="utf-8")
    respx.get("https://k8s/api/v1/namespaces/ns/secrets/dbagent-signing-key").mock(
        return_value=httpx.Response(404, json={})
    )
    respx.post("https://k8s/api/v1/namespaces/ns/secrets").mock(
        return_value=httpx.Response(500, text="create boom")
    )
    rc = bootstrap_from_k8s_secret(
        key_path,
        "dbagent-signing-key",
        "ns",
        token_path=str(token),
        ca_path=_readable_ca(),
        api_base="https://k8s",
    )
    assert rc == 1
