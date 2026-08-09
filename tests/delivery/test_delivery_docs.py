"""FP-M6-13/14: required docs, toolpack/config completeness, acceptance structure."""
from __future__ import annotations

import json
import re
from dataclasses import fields, is_dataclass
from pathlib import Path

import yaml

from delivery_helpers import DOCS, REPO_ROOT

REQUIRED_DOCS = [
    "README.md",
    "deployment/kubernetes.md",
    "deployment/compose.md",
    "deployment/swarm.md",
    "deployment/probe.md",
    "configuration.md",
    "notifications.md",
    "security.md",
    "toolpack-reference.md",
    "runbooks/signing-key-rotation.md",
    "runbooks/platform-credential-rotation.md",
    "runbooks/bootstrap-ca-rotation.md",
    "runbooks/upgrade-and-rollback.md",
    "runbooks/backup-restore.md",
    "acceptance/m6-real-cluster-walkthrough.md",
]


def test_required_docs_exist_and_links_resolve():
    for rel in REQUIRED_DOCS:
        p = DOCS / rel
        assert p.is_file(), rel

    # Relative markdown links inside docs/ resolve.
    link_re = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
    for md in DOCS.rglob("*.md"):
        text = md.read_text(encoding="utf-8")
        for _, target in link_re.findall(text):
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            # strip anchors
            path_part = target.split("#", 1)[0]
            if not path_part:
                continue
            resolved = (md.parent / path_part).resolve()
            assert resolved.is_file(), f"broken link {target} in {md}"

    # Production + dev install command blocks (design §11.1.3 item 9).
    k8s = (DOCS / "deployment/kubernetes.md").read_text(encoding="utf-8")
    assert "values-dev.yaml" in k8s
    assert "my-values.yaml" in k8s or "external" in k8s.lower()
    assert "Uninstall" in k8s or "uninstall" in k8s

    # Runbooks must be distinct procedures, not copies of signing-key rotation.
    runbook_bodies = {}
    for name in (
        "signing-key-rotation.md",
        "platform-credential-rotation.md",
        "bootstrap-ca-rotation.md",
        "upgrade-and-rollback.md",
        "backup-restore.md",
    ):
        text = (DOCS / "runbooks" / name).read_text(encoding="utf-8")
        # Drop the H1 so we compare procedure bodies.
        body = "\n".join(text.splitlines()[1:]).strip()
        runbook_bodies[name] = body
        assert len(body) > 200, f"{name} is too thin to be an ops runbook"
    bodies = list(runbook_bodies.values())
    assert len(set(bodies)) == len(bodies), "runbooks must not be verbatim copies"


def test_toolpack_tools_and_config_keys_are_documented():
    ref = (DOCS / "toolpack-reference.md").read_text(encoding="utf-8")
    # Toolpack tools from schemas.
    for schema in (REPO_ROOT / "probe/internal/toolpack/schemas").glob("*.schema.json"):
        data = json.loads(schema.read_text(encoding="utf-8"))
        tools = data.get("tools") or data.get("ops") or {}
        for name in tools:
            assert name in ref, f"tool {name} missing from toolpack-reference.md"

    # Control tools.
    for name in ["read_evidence", "fetch_source", "diff_versions", "search_commits"]:
        assert name in ref

    cfg_doc = (DOCS / "configuration.md").read_text(encoding="utf-8")
    # AppConfig recursive fields.
    import sys

    sys.path.insert(0, str(REPO_ROOT / "libs/py/rca_common"))
    from rca_common.config import load_config

    tmp = REPO_ROOT / "deploy/compose/config/rca-agent.yaml"
    # Use empty-ish load — compose sample has ${} which is fine.
    import os
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
        fh.write("{}\n")
        path = fh.name
    try:
        conf = load_config(path)
    finally:
        os.unlink(path)

    def walk(obj, prefix=""):
        for f in fields(obj):
            path = f"{prefix}.{f.name}" if prefix else f.name
            yield path
            val = getattr(obj, f.name)
            if is_dataclass(val):
                yield from walk(val, path)

    for path in walk(conf):
        # Field name must appear (leaf or parent).
        leaf = path.split(".")[-1]
        assert leaf in cfg_doc or path in cfg_doc, f"config field {path} not documented"

    # Probe keys derived from the Go struct yaml tags (not a hard-coded list).
    probe_go = (REPO_ROOT / "probe/internal/config/config.go").read_text(encoding="utf-8")
    probe_keys = re.findall(r'`yaml:"([a-z0-9_]+)"`', probe_go)
    assert probe_keys, "expected yaml tags on probe config.Probe"
    for key in probe_keys:
        assert key in cfg_doc, f"probe config key {key} not documented"
    # Secret-file convention used by Swarm stack (not a YAML field).
    assert "BOOTSTRAP_TOKEN_FILE" in cfg_doc

    # Probe-gateway keys (stable set; gateway has its own config package).
    for key in [
        "session_listen_addr",
        "bootstrap_listen_addr",
        "internal_listen_addr",
        "postgres_dsn",
        "signing_public_key_path",
    ]:
        assert key in cfg_doc, key


def test_acceptance_walkthrough_document_structure():
    text = (DOCS / "acceptance/m6-real-cluster-walkthrough.md").read_text(encoding="utf-8")
    assert "status:" in text
    assert "Kubernetes" in text or "k8s" in text.lower()
    assert "Swarm" in text or "swarm" in text.lower()
    assert "0.298" in text
    # Do NOT require signed-off — human gate.


def test_signing_key_rotation_runbook_documents_propagation_ordering():
    """FP-KR-25: runbook anchors + ready-condition + version-skew sentences."""
    text = (DOCS / "runbooks/signing-key-rotation.md").read_text(encoding="utf-8")
    lower = " ".join(text.lower().split())

    anchors = [
        "bootstrap_signing_key",
        "signing_key_poll_interval",
        "signing key propagated to all connected sessions",
        "signing key propagation incomplete",
        "rolling-restart",
    ]
    for a in anchors:
        assert a in lower, f"missing anchor {a!r}"

    i_regen = lower.index("bootstrap_signing_key")
    i_ready = lower.index("signing key propagated to all connected sessions")
    i_incomplete = lower.index("signing key propagation incomplete")
    i_restart = lower.index("rolling-restart")
    assert i_regen < i_ready < i_restart, (
        f"ordering: regen={i_regen} ready={i_ready} restart={i_restart}"
    )
    assert i_incomplete < i_restart, "not-ready meaning must be documented before restart"

    ready_sentence = (
        "a pass that logs `signing key propagation incomplete` means the fleet is "
        "not ready: at least one connected probe still holds the old key. wait for a "
        "later pass to log `signing key propagated to all connected sessions`, which "
        "is emitted only when no session was dropped, before restarting the workers."
    )
    # Collapse design line wrapping: compare without backticks sensitivity by
    # normalizing both sides (lower already collapsed whitespace).
    ready_norm = " ".join(ready_sentence.split())
    assert ready_norm in lower, "ready-condition sentence missing verbatim"

    skew_sentence = (
        "probes running a build older than the mid-session key-update feature "
        "(design.md section 9.6) do not receive a rotated key until they reconnect "
        "or are restarted."
    )
    skew_norm = " ".join(skew_sentence.split())
    assert skew_norm in lower, "version-skew sentence missing verbatim"
