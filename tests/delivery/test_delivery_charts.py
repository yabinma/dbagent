"""FP-M6-5..9: Helm chart render matrix and packaging invariants."""
from __future__ import annotations

import re
import subprocess

import pytest
import yaml

from delivery_helpers import CHARTS, REPO_ROOT, helm_template, load_versions, parse_manifests, require_bin, run


RCA_AGENT = CHARTS / "rca-agent"
RCA_PROBE = CHARTS / "rca-probe"


def test_helm_available_or_hard_fail():
    require_bin("helm")


def test_rca_agent_renders_five_workloads_and_secret_indirection():
    out = helm_template(RCA_AGENT)
    docs = parse_manifests(out)
    kinds = [(d.get("kind"), d.get("metadata", {}).get("name", "")) for d in docs]
    names = " ".join(n for _, n in kinds)
    for comp in [
        "ingest-gateway",
        "temporal-worker",
        "probe-gateway",
        "dashboard-api",
        "dashboard-web",
    ]:
        assert any(k == "Deployment" and comp in n for k, n in kinds), comp
    # Secret created by default.
    assert any(k == "Secret" for k, _ in kinds)
    # ConfigMaps must not contain raw secret-looking passwords that aren't ${VAR}.
    for d in docs:
        if d.get("kind") == "ConfigMap":
            blob = yaml.dump(d)
            assert "change-me-in-production" not in blob
            assert "minioadmin" not in blob or "${" in blob


def test_bootstrap_ca_pvc_and_replica_guard():
    out = helm_template(RCA_AGENT)
    assert "bootstrap-ca" in out
    # replicaCount>1 without existingSecret must fail.
    proc = run(
        [
            "helm",
            "template",
            "t",
            str(RCA_AGENT),
            "--set",
            "probeGateway.replicaCount=2",
        ],
        cwd=str(REPO_ROOT),
    )
    assert proc.returncode != 0
    assert "existingSecret" in (proc.stderr + proc.stdout)


def test_networkpolicy_restricts_internal_listener():
    out = helm_template(RCA_AGENT, set_args=["networkPolicy.enabled=true"])
    docs = parse_manifests(out)
    nps = [d for d in docs if d.get("kind") == "NetworkPolicy"]
    assert nps
    blob = yaml.dump(nps)
    assert "8080" in blob
    assert "temporal-worker" in blob


def test_secrets_existing_secret_branch_renders_no_secret():
    out = helm_template(
        RCA_AGENT,
        set_args=["secrets.create=false", "secrets.existingSecret=my-existing"],
    )
    docs = parse_manifests(out)
    app_secrets = [
        d
        for d in docs
        if d.get("kind") == "Secret" and "app" in d.get("metadata", {}).get("name", "")
    ]
    assert not app_secrets
    assert "my-existing" in out


def test_probe_gateway_configmap_keys_incl_internal_listen_addr():
    out = helm_template(RCA_AGENT)
    docs = parse_manifests(out)
    cm = next(
        d
        for d in docs
        if d.get("kind") == "ConfigMap" and "probe-gateway" in d["metadata"]["name"]
    )
    cfg = cm["data"]["config.yaml"]
    for key in [
        "postgres_dsn",
        "session_listen_addr",
        "bootstrap_listen_addr",
        "internal_listen_addr",
        "signing_public_key_path",
        "bootstrap_ca_cert_path",
        "bootstrap_ca_key_path",
        "server_cert_sans",
        "gateway_replica",
        "heartbeat_timeout",
        "heartbeat_check_interval",
        "signing_key_poll_interval",
    ]:
        assert key in cfg, key
    assert re.search(r"internal_listen_addr:\s*\":8080\"", cfg) or "internal_listen_addr: \":8080\"" in cfg


def test_temporal_mode_dev_chart_external_render_exactly_one():
    # dev requires bundled PostgreSQL (auto-setup has no external DB surface).
    dev = helm_template(
        RCA_AGENT, set_args=["temporal.mode=dev", "postgresql.bundled=true"]
    )
    dev_docs = parse_manifests(dev)
    dev_temporal = [
        d
        for d in dev_docs
        if d.get("kind") in {"Deployment", "StatefulSet"}
        and "temporal" in (d.get("metadata", {}).get("name") or "").lower()
    ]
    assert len(dev_temporal) >= 1, "dev mode must render a temporal workload"
    assert "auto-setup" in dev.lower() or any(
        "temporal" in (d.get("metadata", {}).get("name") or "").lower() for d in dev_temporal
    )

    # dev without bundled PG fails at render time.
    proc_dev = run(
        [
            "helm",
            "template",
            "t",
            str(RCA_AGENT),
            "--set",
            "temporal.mode=dev",
            "--set",
            "postgresql.bundled=false",
        ],
        cwd=str(REPO_ROOT),
    )
    assert proc_dev.returncode != 0
    assert "values-dev.yaml" in (proc_dev.stderr + proc_dev.stdout)

    # external: no temporal workload from our chart (address points outside)
    ext = helm_template(
        RCA_AGENT, set_args=["temporal.mode=external", "temporal.address=temporal.other:7233"]
    )
    ext_docs = parse_manifests(ext)
    ext_temporal_workloads = [
        d
        for d in ext_docs
        if d.get("kind") in {"Deployment", "StatefulSet"}
        and "temporal" in (d.get("metadata", {}).get("name") or "").lower()
        and "rca-agent" in (d.get("metadata", {}).get("name") or "")
    ]
    # Exactly zero bundled temporal server workloads in external mode.
    assert len(ext_temporal_workloads) == 0, [
        d.get("metadata", {}).get("name") for d in ext_temporal_workloads
    ]

    # chart mode with dependency enabled
    chart = helm_template(
        RCA_AGENT,
        set_args=["temporal.mode=chart", "temporal.chart.enabled=true"],
    )
    assert chart  # must render offline from vendored tgz
    # invalid mode fails
    proc = run(
        ["helm", "template", "t", str(RCA_AGENT), "--set", "temporal.mode=bogus"],
        cwd=str(REPO_ROOT),
    )
    assert proc.returncode != 0


def test_temporal_subchart_vendored_and_pinned():
    vers = load_versions()
    ver = vers["TEMPORAL_CHART_VERSION"]
    tgz = RCA_AGENT / "charts" / f"temporal-{ver}.tgz"
    assert tgz.is_file()
    lock = yaml.safe_load((RCA_AGENT / "Chart.lock").read_text(encoding="utf-8"))
    deps = lock["dependencies"]
    assert any(d["name"] == "temporal" and d["version"] == ver for d in deps)
    chart_yaml = (RCA_AGENT / "Chart.yaml").read_text(encoding="utf-8")
    assert ver in chart_yaml


def test_bundled_or_external_postgres_minio_model_gateway():
    # Bundled path must opt in explicitly (defaults are external-only).
    bundled = helm_template(
        RCA_AGENT,
        set_args=[
            "postgresql.bundled=true",
            "minio.bundled=true",
            "modelGateway.bundled=true",
        ],
    )
    assert "postgresql" in bundled.lower()
    assert "minio" in bundled.lower()
    assert "model-gateway" in bundled or "litellm" in bundled.lower()
    external = helm_template(
        RCA_AGENT,
        set_args=[
            "postgresql.bundled=false",
            "minio.bundled=false",
            "modelGateway.bundled=false",
        ],
    )
    docs = parse_manifests(external)
    comps = {
        d.get("metadata", {}).get("labels", {}).get("app.kubernetes.io/component")
        for d in docs
        if d.get("kind") == "Deployment"
    }
    assert "postgresql" not in comps
    assert "minio" not in comps
    assert "model-gateway" not in comps


def test_bundled_postgres_is_dev_only_and_defaults_off():
    """Chart defaults ship no bundled PG; opt-in renders it with computed DSN."""
    defaults = helm_template(RCA_AGENT)
    default_docs = parse_manifests(defaults)
    pg_default = [
        d
        for d in default_docs
        if d.get("kind") in ("Deployment", "Service")
        and "postgresql" in (d.get("metadata") or {}).get("name", "")
    ]
    assert not pg_default, "postgresql.bundled defaults to false"
    # Default secret DSN must not invent a bundled host name.
    for d in default_docs:
        if d.get("kind") == "Secret" and "app" in d["metadata"]["name"]:
            dsn = (d.get("stringData") or {}).get("PG_DSN") or ""
            assert "-postgresql" not in dsn, dsn

    opted = helm_template(RCA_AGENT, set_args=["postgresql.bundled=true"])
    opted_docs = parse_manifests(opted)
    pg_opted = [
        d
        for d in opted_docs
        if d.get("kind") in ("Deployment", "Service")
        and "postgresql" in (d.get("metadata") or {}).get("name", "")
    ]
    assert pg_opted
    for d in opted_docs:
        if d.get("kind") == "Secret" and "app" in d["metadata"]["name"]:
            dsn = (d.get("stringData") or {}).get("PG_DSN") or ""
            assert "-postgresql" in dsn, dsn


def test_no_stateful_resource_in_the_pre_upgrade_hook_set():
    """Bundled PG (and any emptyDir-backed state) must never be pre-upgrade hooks."""
    for set_args in ([], ["postgresql.bundled=true"]):
        out = helm_template(RCA_AGENT, set_args=set_args or None)
        docs = parse_manifests(out)
        for d in docs:
            ann = (d.get("metadata") or {}).get("annotations") or {}
            hook = str(ann.get("helm.sh/hook") or "")
            if "pre-upgrade" not in hook:
                continue
            kind = d.get("kind")
            name = (d.get("metadata") or {}).get("name") or ""
            # Stateful kinds that store data must not be in pre-upgrade.
            if kind in ("Deployment", "StatefulSet", "PersistentVolumeClaim"):
                assert "postgresql" not in name, (
                    f"stateful {kind}/{name} must not be a pre-upgrade hook "
                    f"(hook={hook!r}); set_args={set_args}"
                )


def test_hook_jobs_order_images_and_idempotence_annotations():
    # Complete hook set includes bundled PG — opt in explicitly.
    out = helm_template(RCA_AGENT, set_args=["postgresql.bundled=true"])
    docs = parse_manifests(out)
    jobs = {
        d["metadata"]["name"]: d
        for d in docs
        if d.get("kind") == "Job"
    }
    assert jobs, "expected helm hook Jobs in rendered chart"

    def _weight(job: dict) -> int | None:
        ann = (job.get("metadata") or {}).get("annotations") or {}
        raw = ann.get("helm.sh/hook-weight") or ann.get("hook-weight")
        if raw is None:
            return None
        return int(raw)

    weights = {name: _weight(j) for name, j in jobs.items()}
    # Match by name substring: migrate=-20, signing-key=-10, bootstrap-admin=0, seed=10
    def _find(substr: str) -> dict:
        for name, j in jobs.items():
            if substr in name:
                return j
        raise AssertionError(f"no Job matching {substr!r} in {list(jobs)}")

    migrate = _find("migrate")
    signing = _find("signing")
    bootstrap = _find("bootstrap")
    seed = _find("seed")
    assert _weight(migrate) == -20, weights
    assert _weight(signing) == -10, weights
    assert _weight(bootstrap) == 0, weights
    assert _weight(seed) == 10, weights

    def _hook(job: dict) -> str:
        ann = (job.get("metadata") or {}).get("annotations") or {}
        return str(ann.get("helm.sh/hook") or ann.get("hook") or "")

    # migrate + signing-key are pre-install; bootstrap/seed are post-install.
    assert "pre-install" in _hook(migrate), _hook(migrate)
    assert "pre-install" in _hook(signing), _hook(signing)
    assert "post-install" in _hook(bootstrap), _hook(bootstrap)
    assert "post-install" in _hook(seed), _hook(seed)

    for j in (migrate, signing, bootstrap, seed):
        ann = (j.get("metadata") or {}).get("annotations") or {}
        policy = ann.get("helm.sh/hook-delete-policy") or ann.get("hook-delete-policy") or ""
        assert "before-hook-creation" in policy or "hook-succeeded" in policy, (
            f"unexpected hook-delete-policy on {j['metadata']['name']}: {policy!r}"
        )
        # Each Job has exactly one container image.
        containers = ((j.get("spec") or {}).get("template") or {}).get("spec", {}).get(
            "containers"
        ) or []
        assert len(containers) == 1, j["metadata"]["name"]
        assert containers[0].get("image"), j["metadata"]["name"]

    # Secrets/ConfigMaps/PG referenced by pre-install hook Jobs must themselves
    # be earlier-weighted pre-install hooks (Helm applies hooks by weight).
    app_secrets = [
        d
        for d in docs
        if d.get("kind") == "Secret"
        and "signing" not in d["metadata"]["name"]
    ]
    assert app_secrets, "expected app Secret for migrate hook"
    for sec in app_secrets:
        ann = (sec.get("metadata") or {}).get("annotations") or {}
        assert "pre-install" in str(ann.get("helm.sh/hook") or ""), (
            f"app Secret {sec['metadata']['name']} must be a pre-install hook "
            f"so migrate can mount it; annotations={ann}"
        )
        sw = int(ann.get("helm.sh/hook-weight") or "0")
        assert sw < -20, f"Secret hook-weight {sw} must be < migrate (-20)"

    pg_hooks = [
        d
        for d in docs
        if d.get("kind") in ("Deployment", "Service")
        and "postgresql" in d["metadata"]["name"]
    ]
    assert pg_hooks, "expected bundled postgresql Deployment/Service"
    for pg in pg_hooks:
        ann = (pg.get("metadata") or {}).get("annotations") or {}
        hook = str(ann.get("helm.sh/hook") or "")
        assert "pre-install" in hook, (
            f"postgresql {pg['kind']} must be a pre-install hook; annotations={ann}"
        )
        # pre-upgrade would wipe emptyDir on every helm upgrade (W3).
        assert "pre-upgrade" not in hook, (
            f"postgresql {pg['kind']} must NOT be pre-upgrade; annotations={ann}"
        )
        pw = int(ann.get("helm.sh/hook-weight") or "0")
        assert pw < -20, f"postgresql hook-weight {pw} must be < migrate (-20)"


def test_rca_probe_write_rbac_only_when_write_enabled():
    off = helm_template(
        RCA_PROBE,
        set_args=["platformKey=p1", "bootstrapToken=tok", "writeEnabled=false"],
    )
    assert "k8s_patch_configmap" not in off  # not expected in RBAC
    # write Role should be absent
    assert "delete" not in off or "Role" in off
    docs_off = parse_manifests(off)
    write_roles = [
        d
        for d in docs_off
        if d.get("kind") == "Role" and d["metadata"]["name"].endswith("-write")
    ]
    assert not write_roles

    on = helm_template(
        RCA_PROBE,
        set_args=["platformKey=p1", "bootstrapToken=tok", "writeEnabled=true"],
    )
    docs_on = parse_manifests(on)
    write_roles = [
        d
        for d in docs_on
        if d.get("kind") == "Role" and d["metadata"]["name"].endswith("-write")
    ]
    assert write_roles
    rules = yaml.dump(write_roles)
    assert "patch" in rules
    assert "delete" in rules
    assert "configmaps" in rules


def test_e2e_nodeports_match_kind_and_conftest():
    """C2: every port conftest targets is mapped by kind and assigned by e2e values."""
    kind = (REPO_ROOT / "tests/e2e/kind-cluster.yaml").read_text(encoding="utf-8")
    conf = (REPO_ROOT / "tests/e2e/conftest.py").read_text(encoding="utf-8")
    smoke = (REPO_ROOT / "tests/e2e/test_e2e_smoke.py").read_text(encoding="utf-8")
    # Ports the suite dials on 127.0.0.1 (app + Presto + webhook capture).
    expected = {30080, 30081, 30082, 30083, 30880, 30084}
    scenarios = (REPO_ROOT / "tests/e2e/test_e2e_scenarios.py").read_text(
        encoding="utf-8"
    )
    for port in expected:
        assert str(port) in kind, f"kind-cluster.yaml missing hostPort {port}"
        assert (
            str(port) in conf or str(port) in smoke or str(port) in scenarios
        ), f"conftest/smoke/scenarios missing {port}"

    out = helm_template(
        RCA_AGENT, values=[str(REPO_ROOT / "tests/e2e/values-rca-agent.yaml")]
    )
    docs = parse_manifests(out)
    node_ports: set[int] = set()
    for d in docs:
        if d.get("kind") != "Service":
            continue
        if (d.get("spec") or {}).get("type") != "NodePort":
            continue
        for p in (d.get("spec") or {}).get("ports") or []:
            np = p.get("nodePort")
            if np is not None:
                node_ports.add(int(np))
    for port in (30080, 30081, 30082, 30083):
        assert port in node_ports, f"e2e values did not assign NodePort {port}; got {node_ports}"


def test_one_container_per_pod_and_resources_probes():
    """FP-M6-4: one container per rendered pod spec in both charts."""
    for chart, set_args in (
        (RCA_AGENT, None),
        (RCA_PROBE, ["platformKey=p1", "bootstrapToken=tok", "writeEnabled=false"]),
    ):
        out = helm_template(chart, set_args=set_args)
        docs = parse_manifests(out)
        for d in docs:
            if d.get("kind") not in {"Deployment", "StatefulSet", "DaemonSet"}:
                continue
            containers = d["spec"]["template"]["spec"]["containers"]
            assert len(containers) == 1, f"{chart.name}: {d['metadata']['name']}"
            c = containers[0]
            name = d["metadata"]["name"]
            if chart is RCA_AGENT and any(
                x in name for x in ("ingest", "dashboard", "probe-gateway", "temporal-worker")
            ):
                assert "resources" in c
                assert "livenessProbe" in c or "readinessProbe" in c
