#!/usr/bin/env python3
"""Idempotent pre-install job entrypoint for the write-channel signing key
(design.md D14: "private key in K8s Secret / compose volume, generated
once by an idempotent pre-install job").

Intended to be wired as:
  - a Helm pre-install/pre-upgrade hook Job (`deploy/charts/dbagent`), or
  - an init container / one-shot service in `deploy/compose/control-plane.yml`,
  - or invoked directly by an operator before first start-up.

Safe to run on every deploy: if the key file already exists it is left
untouched (loaded to sanity-check it, and to print its public key for the
operator to compare against what the probe side expects); if it does not
exist, an ed25519 key pair is generated and written with 0600 permissions.

When ``--k8s-secret`` is set (FP-M6-8), the key is also persisted to (or
loaded from) a Kubernetes Secret via the in-pod ServiceAccount token and
plain httpx — so worker and probe-gateway Deployments on different nodes
share the same key without requiring RWX storage.

Exit code is always 0 on success (existing-key or newly-generated), non-zero
on any I/O error, so it composes as a Helm hook / compose `depends_on`
precondition without extra glue.
"""
from __future__ import annotations

import argparse
import base64
import logging
import os
import ssl
import sys
from pathlib import Path

from rca_common.envcompat import reject_legacy_env
from rca_common.signing.signer import bootstrap_signing_key

logger = logging.getLogger("bootstrap_signing_key")

_SA_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
_SA_CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
_SA_NS_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"


def _read_sa_namespace(explicit: str | None) -> str:
    if explicit:
        return explicit
    try:
        return Path(_SA_NS_PATH).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise RuntimeError(
            f"cannot determine k8s namespace (pass --k8s-namespace or mount SA): {exc}"
        ) from exc


def _ca_is_usable(ca_path: str) -> bool:
    """True only when the CA bundle exists and this process can read it.

    ``os.path.exists`` alone is not enough: an existing-but-unreadable CA is
    exactly the misconfiguration that used to silence TLS verification.
    """
    try:
        with open(ca_path, "rb") as fh:
            return bool(fh.read(1))
    except OSError:
        return False


def _k8s_api_base() -> str:
    host = os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
    port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
    return f"https://{host}:{port}"


def bootstrap_from_k8s_secret(
    key_path: str,
    secret_name: str,
    namespace: str | None = None,
    *,
    token_path: str | None = None,
    ca_path: str | None = None,
    api_base: str | None = None,
    http_client=None,
) -> int:
    """Load or create the signing key via the Kubernetes Secrets API.

    1. GET secret; on 200 decode ``ed25519.key``, write to key_path, refresh .pub.
    2. On 404 generate, POST secret; on 409 fall back to GET.
    3. Any other status / missing token / missing CA → hard failure.

    This request carries the ServiceAccount bearer token and, on the create
    path, uploads the private signing key.  It is therefore never made without
    TLS verification: a missing or unreadable ServiceAccount CA certificate is
    a hard failure, not a reason to fall back to ``verify=False`` (code review
    round 5, C7).  Tests exercise the transport by passing ``http_client``.
    """
    import httpx

    # Resolve defaults at call time so tests can monkeypatch the module constants
    # and so main()'s --k8s-secret dispatch uses the live SA mount paths.
    if token_path is None:
        token_path = _SA_TOKEN_PATH
    if ca_path is None:
        ca_path = _SA_CA_PATH

    if not os.path.exists(token_path):
        logger.error("k8s serviceaccount token not found at %s", token_path)
        return 1

    try:
        token = Path(token_path).read_text(encoding="utf-8").strip()
        ns = _read_sa_namespace(namespace)
    except (OSError, RuntimeError) as exc:
        logger.error("%s", exc)
        return 1

    base = (api_base or _k8s_api_base()).rstrip("/")
    url = f"{base}/api/v1/namespaces/{ns}/secrets/{secret_name}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    client = http_client
    owns_client = client is None
    if client is None:
        if not _ca_is_usable(ca_path):
            logger.error(
                "k8s serviceaccount CA certificate missing or unreadable at %s; "
                "refusing to call the secrets API without TLS verification "
                "(this request carries the SA bearer token and the private "
                "signing key)",
                ca_path,
            )
            return 1
        try:
            ssl_context = ssl.create_default_context(cafile=ca_path)
        except (OSError, ssl.SSLError) as exc:
            logger.error("k8s serviceaccount CA at %s is not a usable CA bundle: %s", ca_path, exc)
            return 1
        client = httpx.Client(verify=ssl_context, timeout=30.0)

    try:
        resp = client.get(url, headers=headers)
        if resp.status_code == 200:
            return _load_secret_to_path(resp.json(), key_path)
        if resp.status_code == 404:
            return _create_secret(
                client, url, headers, key_path, secret_name, ns
            )
        logger.error(
            "unexpected status %s from secrets API: %s",
            resp.status_code,
            resp.text[:500],
        )
        return 1
    except httpx.HTTPError as exc:
        logger.error("k8s secrets API request failed: %s", exc)
        return 1
    finally:
        if owns_client:
            client.close()


def _load_secret_to_path(secret_body: dict, key_path: str) -> int:
    data = secret_body.get("data") or {}
    raw_b64 = data.get("ed25519.key")
    if not raw_b64:
        logger.error("secret missing data.ed25519.key")
        return 1
    try:
        raw = base64.b64decode(raw_b64)
    except Exception as exc:  # noqa: BLE001
        logger.error("decode ed25519.key: %s", exc)
        return 1
    path = Path(key_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(0o600)
    # Also restore .pub sidecar if present in the Secret.
    pub_b64 = data.get("ed25519.key.pub")
    if pub_b64:
        try:
            pub_text = base64.b64decode(pub_b64)
            path.with_suffix(path.suffix + ".pub").write_bytes(pub_text)
        except Exception:  # noqa: BLE001
            pass
    try:
        signer = bootstrap_signing_key(key_path)
    except OSError as exc:
        logger.error("failed to load signing key at %s: %s", key_path, exc)
        return 1
    public_key_b64 = base64.b64encode(signer.public_key_bytes()).decode("ascii")
    logger.info("loaded existing ed25519 signing key from k8s secret at %s", key_path)
    logger.info("public key (base64): %s", public_key_b64)
    return 0


def _create_secret(client, url: str, headers: dict, key_path: str, secret_name: str, ns: str) -> int:
    try:
        signer = bootstrap_signing_key(key_path)
    except OSError as exc:
        logger.error("failed to generate signing key at %s: %s", key_path, exc)
        return 1
    raw = Path(key_path).read_bytes()
    pub_path = Path(key_path + ".pub")
    pub_bytes = pub_path.read_bytes() if pub_path.exists() else b""
    body = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": secret_name, "namespace": ns},
        "type": "Opaque",
        "data": {
            "ed25519.key": base64.b64encode(raw).decode("ascii"),
            "ed25519.key.pub": base64.b64encode(pub_bytes).decode("ascii"),
        },
    }
    resp = client.post(url.rsplit("/", 1)[0], headers=headers, json=body)
    if resp.status_code in (200, 201):
        public_key_b64 = base64.b64encode(signer.public_key_bytes()).decode("ascii")
        logger.info("generated new ed25519 signing key and created secret %s/%s", ns, secret_name)
        logger.info("public key (base64): %s", public_key_b64)
        return 0
    if resp.status_code == 409:
        # Concurrent hook — re-read the winner.
        get = client.get(url, headers=headers)
        if get.status_code == 200:
            return _load_secret_to_path(get.json(), key_path)
        logger.error("409 create but re-GET failed: %s", get.status_code)
        return 1
    logger.error("create secret failed %s: %s", resp.status_code, resp.text[:500])
    return 1


def main(argv: list[str] | None = None) -> int:
    reject_legacy_env()
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--key-path",
        default=os.environ.get("DBAGENT_SIGNING_KEY_PATH", "/etc/dbagent/signing/ed25519.key"),
        help="Mounted signing key file path (design.md Appendix E `signing.key_path`).",
    )
    parser.add_argument(
        "--k8s-secret",
        default=None,
        help="Kubernetes Secret name to load/create (FP-M6-8). When set, uses the in-pod SA token.",
    )
    parser.add_argument(
        "--k8s-namespace",
        default=None,
        help="Namespace for --k8s-secret (defaults to the pod's SA namespace).",
    )
    args = parser.parse_args(argv)

    if args.k8s_secret:
        return bootstrap_from_k8s_secret(
            args.key_path, args.k8s_secret, args.k8s_namespace
        )

    try:
        existed_before = os.path.exists(args.key_path)
        signer = bootstrap_signing_key(args.key_path)
    except OSError as exc:
        logger.error("failed to bootstrap signing key at %s: %s", args.key_path, exc)
        return 1

    public_key_b64 = base64.b64encode(signer.public_key_bytes()).decode("ascii")
    action = "loaded existing" if existed_before else "generated new"
    logger.info("%s ed25519 signing key at %s", action, args.key_path)
    logger.info("public key (base64): %s", public_key_b64)
    return 0


if __name__ == "__main__":
    sys.exit(main())
