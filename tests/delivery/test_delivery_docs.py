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

    tmp = REPO_ROOT / "deploy/compose/config/dbagent.yaml"
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

    # Probe-gateway keys: every yaml tag of services/probe-gateway/internal/config.Config.
    pgw_go = (
        REPO_ROOT / "services/probe-gateway/internal/config/config.go"
    ).read_text(encoding="utf-8")
    pgw_keys = re.findall(r'`yaml:"([a-z0-9_]+)"`', pgw_go)
    assert pgw_keys, "expected yaml tags on probe-gateway config.Config"
    for key in pgw_keys:
        assert key in cfg_doc, f"probe-gateway config key {key} not documented"


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


# --- FP-SW-11 (design.md §11.2.5): every probe key documented, and a Swarm
# reference that is sanitized by construction. ---

# The closed set of permitted angle-bracket tokens (§11.2.3 D).
PERMITTED_PLACEHOLDERS = {
    "<PLATFORM_KEY>",
    "<GATEWAY_HOST>",
    "<CONTROL_PLANE_IP>",
    "<PRESTO_OVERLAY_NETWORK>",
    "<COORDINATOR_SERVICE>",
    "<WORKER_SERVICE>",
    "<COORDINATOR_PORT>",
    "<IN_CONTAINER_CONFIG_DIR>",
    "<REGISTRY>",
    "<APP_VERSION>",
    "<64-HEX>",
}

# The closed set of documented fixed defaults that may appear as literals.
FIXED_DEFAULTS = {
    "probe-gateway:8443",
    "probe-gateway:8444",
    "/var/run/docker.sock",
    "unix:///var/run/docker.sock",
    "/var/lib/dbagent-probe",
    "/etc/dbagent-probe/config.yaml",
    "/etc/dbagent-probe/platform-credentials",
    False,
}

# Documented composite forms that are not a single placeholder token but are
# the exact sanctioned shapes in Appendix E.1 / docs/deployment/swarm.md.
# Positive closed set only — no partial/substring match against placeholders
# (review W2 / FP-SW-11).
APPROVED_COMPOSITES = {
    "<IN_CONTAINER_CONFIG_DIR>/config.properties",
    "<IN_CONTAINER_CONFIG_DIR>/jvm.config",
    "<IN_CONTAINER_CONFIG_DIR>/node.properties",
    "sha256:<64-HEX>",
    "<REGISTRY>/probe:<APP_VERSION>",
    "probe-gateway:<CONTROL_PLANE_IP>",
    "${BOOTSTRAP_TOKEN}",
}

_PLACEHOLDER_RE = re.compile(r"<[^<>\n]+>")
_FENCE_RE = re.compile(r"```([A-Za-z0-9]*)\n(.*?)```", re.DOTALL)


def _fenced_blocks(text: str, language: str | None = None) -> list[str]:
    return [
        body
        for lang, body in _FENCE_RE.findall(text)
        if language is None or lang == language
    ]


def _sanitized(value, *, allow_placeholder: bool = True) -> bool:
    """A site-specific field must equal an approved placeholder, composite, or fixed default.

    Positive closed-set match only (design.md §11.2.3 D / FP-SW-11): the whole
    value must be exactly one of the permitted tokens, one of the documented
    composite forms, or one of the fixed defaults. A string that merely
    *contains* a placeholder (e.g. ``<COORDINATOR_SERVICE>-live-prod``) is
    not sanitized.
    """
    # Identity for the bool default so integer 0 is not accepted (review S9:
    # `0 == False` is True in Python, so `value in FIXED_DEFAULTS` is unsafe).
    if value is False:
        return True
    if not isinstance(value, str):
        return False
    if not allow_placeholder:
        return False
    if value in PERMITTED_PLACEHOLDERS:
        return True
    if value in APPROVED_COMPOSITES:
        return True
    for fixed in FIXED_DEFAULTS:
        if fixed is False:
            continue
        if value == fixed:
            return True
    return False


def test_sanitized_rejects_placeholder_composites():
    """FP-SW-11 adversarial: composites containing a placeholder are not sanitized."""
    for bad in (
        "<COORDINATOR_SERVICE>-live-prod",
        "<COORDINATOR_PORT>9999",
        "<IN_CONTAINER_CONFIG_DIR>/real-site-secret/config.properties",
        0,  # must not equal False via Python's 0 == False (review S9)
    ):
        assert not _sanitized(bad), f"{bad!r} must be rejected (partial/composite match)"
    # Exact approved forms still pass.
    for good in (
        "<COORDINATOR_SERVICE>",
        "<COORDINATOR_PORT>",
        "<IN_CONTAINER_CONFIG_DIR>/config.properties",
        "probe-gateway:8443",
        "sha256:<64-HEX>",
        False,
    ):
        assert _sanitized(good), f"{good!r} must remain accepted"


def test_probe_config_keys_and_swarm_reference_documented():
    cfg_doc = (DOCS / "configuration.md").read_text(encoding="utf-8")

    # 1. Every YAML key of config.Probe is documented (extends FP-M6-14's rule
    #    to the new keys).
    probe_go = (REPO_ROOT / "probe/internal/config/config.go").read_text(encoding="utf-8")
    probe_keys = re.findall(r'`yaml:"([a-z0-9_]+)"`', probe_go)
    assert "config_paths" in probe_keys and "docker_api_base_url" in probe_keys
    for key in probe_keys:
        assert key in cfg_doc, f"probe config key {key} not documented"

    # 2. The documented example is a file that loads: byte-identical to the
    #    fixture a Go unit test feeds through config.Load (D4).
    fixture = (
        REPO_ROOT / "probe/internal/config/testdata/appendix-e-example.yaml"
    ).read_text(encoding="utf-8")
    yaml_blocks = _fenced_blocks(cfg_doc, "yaml")
    assert fixture in yaml_blocks, (
        "docs/configuration.md carries no block byte-identical to "
        "probe/internal/config/testdata/appendix-e-example.yaml"
    )
    example = yaml.safe_load(fixture)
    assert "probe" not in example, "the documented example must have no `probe:` wrapper key"
    assert example["platform_key"]

    # 3. docs/deployment/swarm.md: the mechanism, the escape hatch and its
    #    warning, config_paths, and the six-step deployment sequence.
    swarm = (DOCS / "deployment/swarm.md").read_text(encoding="utf-8")
    # Errata pass 9 ledger row 4: preamble (before first ##) enumerates 65532
    # among the permitted literals so the page's own "only literals are" claim
    # matches the UID/GID it uses later (ledger row 5 is the doc line itself).
    preamble = swarm.split("\n## ", 1)[0]
    assert "65532" in preamble, (
        "docs/deployment/swarm.md preamble must list 65532 among permitted literals"
    )
    lower = " ".join(swarm.lower().split())
    for anchor in [
        "unix:///var/run/docker.sock",
        "docker_api_base_url",
        "config_paths",
        "before** enrollment consumes the single-use bootstrap token",
    ]:
        assert anchor.lower() in lower, f"swarm.md missing {anchor!r}"
    assert "is not a security control" in lower, "the :ro-is-not-a-control warning is missing"
    assert "root-equivalent" in lower, "the proxy option ships without its warning"
    assert "endpoint-filtering" in lower and "dedicated" in lower

    numbered = re.findall(r"(?m)^(\d+)\. ", swarm)
    assert numbered.count("6") >= 1, "the six-step deployment sequence is missing"
    for step in [
        "--profile apps up -d",
        "change-password",
        "bootstrap_ca_pin",
        "docker secret create",
        "docker stack deploy",
        "online",
    ]:
        assert step.lower() in lower, f"deployment sequence step {step!r} missing"

    # 4. Sanitization, asserted positively. Every extracted angle-bracket token
    # in the whole document is compared against the closed set (FP-SW-11) —
    # including lower-case forms that earlier drafts filtered out as "prose".
    tokens = set(_PLACEHOLDER_RE.findall(swarm))
    unknown = tokens - PERMITTED_PLACEHOLDERS
    assert not unknown, f"placeholders outside the closed set: {sorted(unknown)}"

    blocks = _fenced_blocks(swarm, "yaml")
    probe_cfg = next(b for b in blocks if b.lstrip().startswith("platform_key:"))
    stack = next(b for b in blocks if "services:" in b)
    # Inside the reference blocks every bracket token must be approved,
    # whatever its case.
    for block in (probe_cfg, stack):
        for token in set(_PLACEHOLDER_RE.findall(block)):
            assert token in PERMITTED_PLACEHOLDERS, f"unapproved placeholder {token}"

    cfg = yaml.safe_load(probe_cfg)
    for key in ("platform_key", "coordinator_service", "worker_service", "coordinator_port"):
        assert _sanitized(cfg[key]), f"{key} = {cfg[key]!r} is neither placeholder nor default"
    assert cfg["bootstrap_ca_pin"] == "sha256:<64-HEX>", cfg["bootstrap_ca_pin"]
    assert not re.search(r"sha256:[0-9a-f]{64}", swarm), "a real fingerprint appears"
    for value in cfg["config_paths"].values():
        assert _sanitized(value), value
    for key in ("gateway_address", "bootstrap_address"):
        assert cfg[key] in FIXED_DEFAULTS, f"{key} = {cfg[key]!r} is not a documented default"
    assert cfg["write_enabled"] is False
    assert cfg["coordinator_https"] is False
    assert cfg["docker_api_base_url"] == "unix:///var/run/docker.sock"
    assert cfg["state_dir"] == "/var/lib/dbagent-probe"
    assert cfg["credentials_mount"] == "/etc/dbagent-probe/platform-credentials"

    stack_data = yaml.safe_load(stack)
    svc = stack_data["services"]["probe"]
    assert svc["image"] == "<REGISTRY>/probe:<APP_VERSION>", svc["image"]
    for host in svc["extra_hosts"]:
        assert host == "probe-gateway:<CONTROL_PLANE_IP>", host
    for network in svc["networks"]:
        assert network in PERMITTED_PLACEHOLDERS, network
    for network, spec in (stack_data.get("networks") or {}).items():
        assert network in PERMITTED_PLACEHOLDERS, network
        assert spec == {"external": True}
    for volume in svc["volumes"]:
        assert volume.startswith(("probe-state:/var/lib/dbagent-probe", "/var/run/docker.sock:"))

    # No credential-shaped literal anywhere on the page.
    assert not re.search(r"(?i)\bpassword\s*[:=]\s*\S", swarm)
    assert not re.search(r"(?i)\btoken\s*:\s*(?!\$\{|/run/secrets)\S", swarm)
    # No bare IPv4 literal.
    assert not re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", swarm)


# --- FP-SW-13 (design.md §11.2.5): the acceptance artifact cannot be signed
# off on a run that never witnessed the pending state. ---

# The seven steps of §11.2.3 E.1, matched by CONTENT rather than by numbering
# (the count is descriptive, not load bearing).
WALKTHROUGH_STEP_ANCHORS = [
    ("create the platform", ["create the platform"]),
    ("admissibility gate + issue", ["admissibility gate", "bootstrap token"]),
    ("hand the token to the operator", ["--token-out", "0600"]),
    ("deploy without credentials", ["without the platform credentials"]),
    ("poll to pending_credentials", ["pending_credentials"]),
    ("install the credentials", ["install the credentials"]),
    ("resume, poll to online, run every tool", ["resumes the artifact", "online"]),
]


def _walk_keys(obj):
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield key
            yield from _walk_keys(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from _walk_keys(value)


def test_acceptance_walkthrough_documents_two_phase_procedure():
    path = DOCS / "acceptance/m6-real-cluster-walkthrough.md"
    text = path.read_text(encoding="utf-8")
    lower = " ".join(text.lower().split())

    # 1. The seven steps are documented, in order, matched by content.
    cursor = 0
    for label, needles in WALKTHROUGH_STEP_ANCHORS:
        found = [lower.find(n.lower(), cursor) for n in needles]
        assert all(i >= 0 for i in found), (
            f"walkthrough step {label!r} is missing or documented out of order"
        )
        cursor = min(found)
    # Step 3's handoff and step 4's credential-less deploy are both required
    # in their own words.
    assert "--token-out" in text
    assert "without the platform credentials" in lower

    # 1b. Both documented phase invocations pass an admin password that matches
    #     the shipped Compose/Helm default (admin-change-me), not the driver's
    #     CLI default of "admin". Phase 2 must also document the effective-
    #     password handoff because the resume artifact carries no credential.
    bash_blocks = re.findall(r"```bash\n(.*?)```", text, re.DOTALL)
    phase_blocks = [
        b for b in bash_blocks if "real_cluster_walkthrough.py" in b and "--phase" in b
    ]
    assert len(phase_blocks) >= 2, (
        "walkthrough must document both phase-1 and phase-2 bash invocations"
    )
    pre = next((b for b in phase_blocks if "pre-credentials" in b), None)
    post = next((b for b in phase_blocks if "post-credentials" in b), None)
    assert pre is not None, "phase-1 (pre-credentials) invocation missing"
    assert post is not None, "phase-2 (post-credentials) invocation missing"
    for label, block in (("phase 1", pre), ("phase 2", post)):
        has_flag = "--admin-password" in block
        has_env = "E2E_ADMIN_PASS" in block or "ADMIN_INITIAL_PASSWORD" in block
        assert has_flag or has_env, (
            f"{label} invocation omits --admin-password / password env; "
            "copy-paste against a default deployment would authenticate as 'admin'"
        )
        assert "admin-change-me" in block, (
            f"{label} must document the shipped ADMIN_INITIAL_PASSWORD default "
            f"('admin-change-me'), not the driver's CLI default"
        )
    assert "effective" in lower and "password" in lower, (
        "walkthrough must document that phase 2 receives the effective password "
        "(resume artifact has no credential)"
    )

    # 2. Every fenced json block that is non-empty after stripping whitespace
    #    is parsed and must satisfy the gate. An empty block is the unfilled
    #    state of a human gate and is skipped WITHOUT being parsed (D6).
    blocks = re.findall(r"```json\n(.*?)```", text, re.DOTALL)
    assert len(blocks) >= 2, "each deployment needs its own fenced json report block"
    for index, block in enumerate(blocks):
        if not block.strip():
            continue
        report = json.loads(block)
        assert report.get("registration", {}).get("pending_credentials_witnessed") is True, (
            f"report block {index} was produced by a run that never witnessed "
            "the PENDING_CREDENTIALS state"
        )
        assert report.get("summary", {}).get("failures") == 0, f"report block {index} has failures"
        assert "bootstrap_token" not in set(_walk_keys(report)), (
            f"report block {index} carries a raw single-use bootstrap token into git"
        )
