#!/usr/bin/env python3
"""Idempotent pre-install job entrypoint for the write-channel signing key
(design.md D14: "private key in K8s Secret / compose volume, generated
once by an idempotent pre-install job").

Intended to be wired as:
  - a Helm pre-install/pre-upgrade hook Job (`deploy/charts/rca-agent`), or
  - an init container / one-shot service in `deploy/compose/control-plane.yml`,
  - or invoked directly by an operator before first start-up.

Safe to run on every deploy: if the key file already exists it is left
untouched (loaded to sanity-check it, and to print its public key for the
operator to compare against what the probe side expects); if it does not
exist, an ed25519 key pair is generated and written with 0600 permissions.

Exit code is always 0 on success (existing-key or newly-generated), non-zero
on any I/O error, so it composes as a Helm hook / compose `depends_on`
precondition without extra glue.
"""
from __future__ import annotations

import argparse
import base64
import logging
import os
import sys

from rca_common.signing.signer import bootstrap_signing_key

logger = logging.getLogger("bootstrap_signing_key")


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--key-path",
        default=os.environ.get("RCA_SIGNING_KEY_PATH", "/etc/rca-agent/signing/ed25519.key"),
        help="Mounted signing key file path (design.md Appendix E `signing.key_path`).",
    )
    args = parser.parse_args(argv)

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
