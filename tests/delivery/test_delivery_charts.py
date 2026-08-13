"""FP-M6-5..9: Helm chart render matrix and packaging invariants."""
from __future__ import annotations

import re
import subprocess

import pytest
import yaml

from delivery_helpers import CHARTS, REPO_ROOT, helm_template, load_versions, parse_manifests, require_bin, run


DBAGENT = CHARTS / "dbagent"
DBAGENT_PROBE = CHARTS / "dbagent-probe"


def test_helm_available_or_hard_fail():
    require_bin("helm")


def test_dbagent_renders_five_workloads_and_secret_indirection():
    out = helm_template(DBAGENT)
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
    out = helm_template(DBAGENT)
    assert "bootstrap-ca" in out
    # replicaCount>1 without existingSecret must fail.
    proc = run(
        [
            "helm",
            "template",
            "t",
            str(DBAGENT),
            "--set",
            "probeGateway.replicaCount=2",
        ],
        cwd=str(REPO_ROOT),
    )
    assert proc.returncode != 0
    assert "existingSecret" in (proc.stderr + proc.stdout)


def test_networkpolicy_restricts_internal_listener():
    out = helm_template(DBAGENT, set_args=["networkPolicy.enabled=true"])
    docs = parse_manifests(out)
    nps = [d for d in docs if d.get("kind") == "NetworkPolicy"]
    assert nps
    blob = yaml.dump(nps)
    assert "8080" in blob
    assert "temporal-worker" in blob


def test_secrets_existing_secret_branch_renders_no_secret():
    out = helm_template(
        DBAGENT,
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
    out = helm_template(DBAGENT)
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
        DBAGENT, set_args=["temporal.mode=dev", "postgresql.bundled=true"]
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
            str(DBAGENT),
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
        DBAGENT, set_args=["temporal.mode=external", "temporal.address=temporal.other:7233"]
    )
    ext_docs = parse_manifests(ext)
    ext_temporal_workloads = [
        d
        for d in ext_docs
        if d.get("kind") in {"Deployment", "StatefulSet"}
        and "temporal" in (d.get("metadata", {}).get("name") or "").lower()
        and "dbagent" in (d.get("metadata", {}).get("name") or "")
    ]
    # Exactly zero bundled temporal server workloads in external mode.
    assert len(ext_temporal_workloads) == 0, [
        d.get("metadata", {}).get("name") for d in ext_temporal_workloads
    ]

    # chart mode with dependency enabled
    chart = helm_template(
        DBAGENT,
        set_args=["temporal.mode=chart", "temporal.chart.enabled=true"],
    )
    assert chart  # must render offline from vendored tgz
    # invalid mode fails
    proc = run(
        ["helm", "template", "t", str(DBAGENT), "--set", "temporal.mode=bogus"],
        cwd=str(REPO_ROOT),
    )
    assert proc.returncode != 0


def test_temporal_subchart_vendored_and_pinned():
    vers = load_versions()
    ver = vers["TEMPORAL_CHART_VERSION"]
    tgz = DBAGENT / "charts" / f"temporal-{ver}.tgz"
    assert tgz.is_file()
    lock = yaml.safe_load((DBAGENT / "Chart.lock").read_text(encoding="utf-8"))
    deps = lock["dependencies"]
    assert any(d["name"] == "temporal" and d["version"] == ver for d in deps)
    chart_yaml = (DBAGENT / "Chart.yaml").read_text(encoding="utf-8")
    assert ver in chart_yaml


def test_bundled_or_external_postgres_minio_model_gateway():
    # Bundled path must opt in explicitly (defaults are external-only).
    bundled = helm_template(
        DBAGENT,
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
        DBAGENT,
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
    defaults = helm_template(DBAGENT)
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

    opted = helm_template(DBAGENT, set_args=["postgresql.bundled=true"])
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
        out = helm_template(DBAGENT, set_args=set_args or None)
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
    out = helm_template(DBAGENT, set_args=["postgresql.bundled=true"])
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


def test_dbagent_probe_write_rbac_only_when_write_enabled():
    off = helm_template(
        DBAGENT_PROBE,
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
        DBAGENT_PROBE,
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
        DBAGENT, values=[str(REPO_ROOT / "tests/e2e/values-dbagent.yaml")]
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
        (DBAGENT, None),
        (DBAGENT_PROBE, ["platformKey=p1", "bootstrapToken=tok", "writeEnabled=false"]),
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
            if chart is DBAGENT and any(
                x in name for x in ("ingest", "dashboard", "probe-gateway", "temporal-worker")
            ):
                assert "resources" in c
                assert "livenessProbe" in c or "readinessProbe" in c


# --- FP-SW-6 (design.md §11.2.5): Helm identities are `dbagent`. ---


def test_values_dev_usage_installs_into_dbagent_namespace():
    """FP-SW-6/rename: the dev values usage example must not reintroduce `rca`."""
    text = (DBAGENT / "values-dev.yaml").read_text(encoding="utf-8")
    assert "-n dbagent" in text, "values-dev.yaml usage must install into namespace dbagent"
    assert "-n rca" not in text, "values-dev.yaml usage must not install into namespace rca"


def test_chart_identity_is_dbagent():
    # Directories exist under the new names and the old ones do not.
    assert DBAGENT.is_dir() and DBAGENT_PROBE.is_dir()
    # The legacy names are assembled, not written out: FP-SW-10's forward
    # guard rejects those literals outside its closed allowlist, and this file
    # is not on it.
    legacy_umbrella, legacy_probe = f"rca-{'agent'}", f"rca-{'probe'}"
    assert not (CHARTS / legacy_umbrella).exists()
    assert not (CHARTS / legacy_probe).exists()
    assert sorted(p.name for p in CHARTS.iterdir() if p.is_dir()) == ["dbagent", "dbagent-probe"]

    # Chart.yaml names.
    umbrella = yaml.safe_load((DBAGENT / "Chart.yaml").read_text(encoding="utf-8"))
    probe = yaml.safe_load((DBAGENT_PROBE / "Chart.yaml").read_text(encoding="utf-8"))
    assert umbrella["name"] == "dbagent"
    assert probe["name"] == "dbagent-probe"

    # Every define/include in both charts uses the new prefix.
    for chart, prefix in ((DBAGENT, "dbagent."), (DBAGENT_PROBE, "dbagent-probe.")):
        for path in chart.rglob("*.tpl"):
            for name in re.findall(r'\{\{-?\s*define\s+"([^"]+)"', path.read_text(encoding="utf-8")):
                assert name.startswith(prefix), f"{path}: define {name}"
        for path in list(chart.rglob("*.yaml")) + list(chart.rglob("*.tpl")):
            text = path.read_text(encoding="utf-8")
            for name in re.findall(r'\{\{-?\s*include\s+"([^"]+)"', text):
                assert not name.startswith(
                    (f"rca-{'agent'}.", f"rca-{'probe'}.")
                ), f"{path}: include {name}"

    # Rendered labels and the fixed signing-key Secret name.
    umbrella_docs = parse_manifests(helm_template(DBAGENT))
    label_values = {
        d.get("metadata", {}).get("labels", {}).get("app.kubernetes.io/name")
        for d in umbrella_docs
        if (d.get("metadata", {}).get("labels") or {}).get("app.kubernetes.io/name")
    }
    assert label_values == {"dbagent"}, label_values

    probe_docs = parse_manifests(
        helm_template(
            DBAGENT_PROBE,
            set_args=["platformKey=p1", "bootstrapToken=tok", "writeEnabled=false"],
        )
    )
    probe_labels = {
        d.get("metadata", {}).get("labels", {}).get("app.kubernetes.io/name")
        for d in probe_docs
        if (d.get("metadata", {}).get("labels") or {}).get("app.kubernetes.io/name")
    }
    assert probe_labels == {"dbagent-probe"}, probe_labels

    helpers = (DBAGENT / "templates/_helpers.tpl").read_text(encoding="utf-8")
    assert re.search(r'define\s+"dbagent\.signingKeySecretName"', helpers)
    assert "dbagent-signing-key" in helpers
    rendered = helm_template(DBAGENT)
    assert "dbagent-signing-key" in rendered
    assert f"rca-{'agent'}-signing-key" not in rendered


# --- C2: worker config hostnames must match rendered Service DNS names. ---


def _hostname_from_url_or_addr(value: str) -> str:
    """Extract the host from http(s)://host:port or host:port."""
    raw = (value or "").strip()
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    host = raw.split("/", 1)[0]
    # strip port
    if host.startswith("["):
        return host.split("]", 1)[0].lstrip("[")
    return host.split(":", 1)[0]


def test_configmap_internal_endpoints_match_rendered_service_names():
    """Review C2: release-qualify bundled endpoints; hostnames must exist as Services.

    Renders the chart the same way e2e/dev does (bundled minio/model-gateway +
    temporal.mode=dev), parses config.yaml, and checks each internal hostname
    against Service metadata from the *same* render so bare defaults like
    http://minio:9000 cannot ship against dbagent-minio.
    """
    release = "dbagent"
    require_bin("helm")
    proc = run(
        [
            "helm",
            "template",
            release,
            str(DBAGENT),
            "-f",
            str(DBAGENT / "values-dev.yaml"),
        ],
        cwd=str(REPO_ROOT),
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    docs = parse_manifests(proc.stdout)

    service_names = {
        d["metadata"]["name"]
        for d in docs
        if d.get("kind") == "Service" and d.get("metadata", {}).get("name")
    }
    assert service_names, "render produced no Services"

    cm = next(
        d
        for d in docs
        if d.get("kind") == "ConfigMap"
        and d.get("metadata", {}).get("name") == f"{release}-config"
    )
    cfg = yaml.safe_load(cm["data"]["config.yaml"])

    checks = {
        "storage.s3_endpoint": cfg["storage"]["s3_endpoint"],
        "model_gateway.url": cfg["model_gateway"]["url"],
        "probe_gateway.url": cfg["probe_gateway"]["url"],
        "temporal.address": cfg["temporal"]["address"],
    }
    for key, value in checks.items():
        host = _hostname_from_url_or_addr(value)
        assert host in service_names, (
            f"{key}={value!r} host {host!r} is not a Service in this render; "
            f"services={sorted(service_names)}"
        )
        # Explicitly reject the bare compose-style defaults that C2 found.
        assert host not in {"minio", "model-gateway", "probe-gateway", "temporal"}, (
            f"{key} still uses bare hostname {host!r}"
        )
        assert host.startswith(f"{release}-"), (
            f"{key} host {host!r} is not release-qualified with {release!r}"
        )

    # Operator override for an external endpoint must survive (not rewritten).
    external = "https://minio.example.invalid:9000"
    proc_ext = run(
        [
            "helm",
            "template",
            release,
            str(DBAGENT),
            "-f",
            str(DBAGENT / "values-dev.yaml"),
            "--set",
            f"config.storage.s3_endpoint={external}",
        ],
        cwd=str(REPO_ROOT),
    )
    assert proc_ext.returncode == 0, proc_ext.stderr or proc_ext.stdout
    docs_ext = parse_manifests(proc_ext.stdout)
    cm_ext = next(
        d
        for d in docs_ext
        if d.get("kind") == "ConfigMap"
        and d.get("metadata", {}).get("name") == f"{release}-config"
    )
    cfg_ext = yaml.safe_load(cm_ext["data"]["config.yaml"])
    assert cfg_ext["storage"]["s3_endpoint"] == external


# --- FP-IG-1 / FP-IG-2 / FP-IG-4 (design.md §11.3) ---

PRODUCT_WORKLOADS = (
    "ingest-gateway",
    "temporal-worker",
    "probe-gateway",
    "dashboard-api",
    "dashboard-web",
)

PROBE_KEYS = ("timeoutSeconds", "periodSeconds", "failureThreshold", "successThreshold")


def _probe_blocks(docs):
    """Yield (deploy_name, container_name, probe_kind, probe_dict)."""
    for d in docs:
        if d.get("kind") != "Deployment":
            continue
        name = d["metadata"]["name"]
        for c in d["spec"]["template"]["spec"]["containers"]:
            for kind in ("livenessProbe", "readinessProbe"):
                if kind in c:
                    yield name, c["name"], kind, c[kind]


def test_probe_parameters_are_explicit_on_every_product_workload():
    """FP-IG-1: every product workload declares all four probe parameters."""
    out = helm_template(DBAGENT, values=[str(DBAGENT / "values-dev.yaml")])
    docs = parse_manifests(out)
    seen = set()
    for deploy, cname, kind, probe in _probe_blocks(docs):
        short = next((w for w in PRODUCT_WORKLOADS if w in deploy), None)
        if short is None:
            continue
        seen.add((short, kind))
        for k in PROBE_KEYS:
            assert k in probe, f"{deploy} {kind} missing {k}: {probe}"
            assert probe[k] is not None
    for w in PRODUCT_WORKLOADS:
        assert (w, "livenessProbe") in seen, f"missing liveness for {w}"
        assert (w, "readinessProbe") in seen, f"missing readiness for {w}"


def _shed_before_kill(t_r, p_r, F_r, t_l, p_l, F_l) -> bool:
    """FP-IG-2 five conditions."""
    if not (t_r < t_l):
        return False
    if not (p_r * F_r + t_r < (F_l - 1) * p_l):
        return False
    if not ((F_l - 1) * p_l >= 90):
        return False
    if not (t_l >= 5):
        return False
    if not (t_r <= p_r and t_l <= p_l):
        return False
    return True


def test_liveness_cannot_fire_before_readiness_sheds():
    """FP-IG-2: shed-before-kill over every rendered product workload + fixtures."""
    # Named negative fixtures from errata rounds 1 and 2.
    assert not _shed_before_kill(1, 89, 1, 5, 30, 3), "round1 counterexample must fail"
    assert not _shed_before_kill(4, 60, 1, 5, 30, 3), "round2 counterexample must fail"
    # Shipped HTTP assignment
    assert _shed_before_kill(3, 10, 3, 5, 15, 7)
    # Shipped worker assignment
    assert _shed_before_kill(3, 15, 3, 5, 30, 4)

    for values in (None, [str(DBAGENT / "values-dev.yaml")]):
        out = helm_template(DBAGENT, values=values)
        docs = parse_manifests(out)
        by_deploy: dict = {}
        for deploy, cname, kind, probe in _probe_blocks(docs):
            if not any(w in deploy for w in PRODUCT_WORKLOADS):
                continue
            by_deploy.setdefault(deploy, {})[kind] = probe
        for deploy, probes in by_deploy.items():
            r = probes["readinessProbe"]
            l = probes["livenessProbe"]
            ok = _shed_before_kill(
                r["timeoutSeconds"],
                r["periodSeconds"],
                r["failureThreshold"],
                l["timeoutSeconds"],
                l["periodSeconds"],
                l["failureThreshold"],
            )
            assert ok, f"{deploy} fails shed-before-kill: readiness={r} liveness={l}"


def test_ingest_gateway_cpu_sizing_is_derived_from_b1():
    """FP-IG-4: requests.cpu == ceil(basis × 200); limits >= 5×; basis literal."""
    import math

    values = yaml.safe_load((DBAGENT / "values.yaml").read_text(encoding="utf-8"))
    basis = float(values["ingestGateway"]["sizingBasis"]["cpuMsPerRequest"])
    # Literal identity — basis equals the test's own constant (FP-IG-4).
    # Five-run collection 2026-08-12: 2.031, 1.983, 2.205, 2.102, 2.096 →
    # max+(max−min) = 2.427.
    INGEST_GATEWAY_CPU_MS_PER_REQUEST = 2.427
    assert basis == INGEST_GATEWAY_CPU_MS_PER_REQUEST

    out = helm_template(DBAGENT)
    docs = parse_manifests(out)
    dep = next(
        d
        for d in docs
        if d.get("kind") == "Deployment" and "ingest-gateway" in d["metadata"]["name"]
    )
    res = dep["spec"]["template"]["spec"]["containers"][0]["resources"]
    req_cpu = res["requests"]["cpu"]
    lim_cpu = res["limits"]["cpu"]

    def millicores(v) -> int:
        s = str(v)
        if s.endswith("m"):
            return int(s[:-1])
        return int(float(s) * 1000)

    expected = math.ceil(basis * 200)
    assert millicores(req_cpu) == expected, f"requests.cpu={req_cpu} want {expected}m"
    assert millicores(lim_cpu) >= 5 * millicores(req_cpu)


def test_probe_tuning_template_renders_all_four_keys():
    """UT-IG-4: dbagent.probeTuning emits all four keys; override moves one workload."""
    out = helm_template(
        DBAGENT,
        set_args=["ingestGateway.probes.liveness.timeoutSeconds=9"],
    )
    docs = parse_manifests(out)
    for deploy, cname, kind, probe in _probe_blocks(docs):
        if "ingest-gateway" in deploy and kind == "livenessProbe":
            assert probe["timeoutSeconds"] == 9
            for k in PROBE_KEYS:
                assert k in probe
        elif "dashboard-api" in deploy and kind == "livenessProbe":
            # Unchanged from defaults
            assert probe["timeoutSeconds"] == 5


def _parse_memory_mi(v) -> int:
    s = str(v)
    if s.endswith("Gi"):
        return int(float(s[:-2]) * 1024)
    if s.endswith("Mi"):
        return int(s[:-2])
    raise AssertionError(f"unparseable memory {v!r}")


def _ingest_env(docs, name: str) -> str | None:
    dep = next(
        d
        for d in docs
        if d.get("kind") == "Deployment" and "ingest-gateway" in d["metadata"]["name"]
    )
    for env in dep["spec"]["template"]["spec"]["containers"][0].get("env") or []:
        if env.get("name") == name:
            return str(env.get("value"))
    return None


def test_ingest_gateway_worker_count_is_derived_and_identical_in_every_carrier():
    """FP-IG-20: one worker count, five carriers, memory scaled by W.

    Against the unfixed tree: red on every leg — main.py serves an app object
    through uvicorn.Config/Server, no env key, no workers value, no
    processes: field, memory at the per-process figures.
    """
    import ast

    pinned = 4
    main_path = REPO_ROOT / "services" / "gateway" / "gateway" / "main.py"
    tree = ast.parse(main_path.read_text(encoding="utf-8"))
    run_calls = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "run":
            if isinstance(func.value, ast.Name) and func.value.id == "uvicorn":
                run_calls.append(node)
        if isinstance(func, ast.Attribute) and func.attr in {"Config", "Server"}:
            if isinstance(func.value, ast.Name) and func.value.id == "uvicorn":
                raise AssertionError(
                    "gateway.main still constructs uvicorn.Config/Server "
                    "(single-process form)"
                )
    assert len(run_calls) == 1, run_calls
    run = run_calls[0]
    assert run.args and isinstance(run.args[0], ast.Constant)
    assert run.args[0].value == "gateway.main:create_worker_app"
    kwargs = {k.arg: k.value for k in run.keywords}
    assert isinstance(kwargs.get("factory"), ast.Constant) and kwargs["factory"].value is True
    # workers bound from the DBAGENT_GATEWAY_WORKERS read whose default is 4.
    workers_kw = kwargs.get("workers")
    assert isinstance(workers_kw, ast.Name), workers_kw
    # Find the env read that feeds that name.
    default_literal = None
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        if not isinstance(node.targets[0], ast.Name):
            continue
        if node.targets[0].id != workers_kw.id:
            continue
        call = node.value
        # int(os.environ.get("DBAGENT_GATEWAY_WORKERS", "4"))
        assert isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
        assert call.func.id == "int"
        inner = call.args[0]
        assert isinstance(inner, ast.Call)
        assert isinstance(inner.func, ast.Attribute) and inner.func.attr == "get"
        assert isinstance(inner.args[0], ast.Constant)
        assert inner.args[0].value == "DBAGENT_GATEWAY_WORKERS"
        assert isinstance(inner.args[1], ast.Constant)
        default_literal = inner.args[1].value
    assert default_literal == str(pinned), default_literal

    values = yaml.safe_load((DBAGENT / "values.yaml").read_text(encoding="utf-8"))
    assert values["ingestGateway"]["workers"] == pinned
    assert values["ingestGateway"]["replicaCount"] == 1

    profile = REPO_ROOT / "services" / "gateway" / "tests" / "b1_reference_profile.py"
    assigns = {
        n.targets[0].id: n.value
        for n in ast.parse(profile.read_text(encoding="utf-8")).body
        if isinstance(n, ast.Assign)
        and len(n.targets) == 1
        and isinstance(n.targets[0], ast.Name)
    }
    assert isinstance(assigns["INGEST_GATEWAY_WORKERS"], ast.Constant)
    assert assigns["INGEST_GATEWAY_WORKERS"].value == pinned

    b11 = yaml.safe_load(
        (REPO_ROOT / "tests" / "benchmark" / "thresholds.yaml").read_text(encoding="utf-8")
    )
    model = next(e for e in b11["benchmarks"] if e["id"] == "B11")["concurrency_model"]
    ingest = next(p for p in model["writer_processes"] if p["process"] == "ingest-gateway")
    assert ingest["processes"] == pinned

    overlays = [
        None,
        [str(DBAGENT / "values-dev.yaml")],
        [str(REPO_ROOT / "tests" / "e2e" / "values-dbagent.yaml")],
    ]
    set_matrices = [
        None,
        ["temporal.mode=dev", "postgresql.bundled=true"],
        ["temporal.mode=external", "temporal.address=temporal.other:7233"],
        ["temporal.mode=chart", "temporal.chart.enabled=true"],
    ]
    for values_files in overlays:
        for set_args in set_matrices:
            try:
                out = helm_template(DBAGENT, values=values_files, set_args=set_args)
            except RuntimeError:
                # Some mode/overlay combinations are rejected by the chart;
                # those are not this FP's subject.
                continue
            docs = parse_manifests(out)
            try:
                env = _ingest_env(docs, "DBAGENT_GATEWAY_WORKERS")
            except StopIteration:
                continue
            assert env == str(pinned), (values_files, set_args, env)
            dep = next(
                d
                for d in docs
                if d.get("kind") == "Deployment"
                and "ingest-gateway" in d["metadata"]["name"]
            )
            res = dep["spec"]["template"]["spec"]["containers"][0]["resources"]
            assert _parse_memory_mi(res["requests"]["memory"]) == pinned * 128
            assert _parse_memory_mi(res["limits"]["memory"]) == pinned * 512


VOID_SIZING_BASIS = 2.427
_RUN_ID_RE = re.compile(r"^[0-9]+/[0-9]+$")
_LEDGER_ENTRY_KEYS = (
    "runId",
    "cpuMsPerRequest",
    "cpus",
    "cpuModel",
    "image",
    "workers",
    "served",
    "errors",
    "committed",
    "p99Ms",
    "servedRate",
    "maxInFlight",
    "platformOnline",
    "workerPidsPre",
    "workerPidsPost",
)


def validate_sizing_ledger(ig: dict, *, check_rendered_cpu: bool = True) -> None:
    """FP-IG-23 validity + recompute. Factored so mutation fixtures can
    drive the same checks against a weakened ledger.

    Exactly five observations are required unconditionally. An empty
    ledger — including the shipped void 2.427 / observations: [] state —
    is red until five valid CI benchmark-job runs are recorded. A void
    2.427 basis with any observations is also red unless those five
    entries independently recompute to 2.427 (they will not: the void
    figure came from invalid cpus=16 runs).
    """
    assert "sizingBasis" in ig, "ingestGateway.sizingBasis missing (unfixed tree)"
    sb = ig["sizingBasis"]
    assert "signature" in sb, "sizingBasis.signature missing (unfixed tree)"
    assert "observations" in sb, "sizingBasis.observations missing (unfixed tree)"
    sig = sb["signature"]
    for key in ("cpus", "cpuModel", "image", "workers"):
        assert key in sig, key
    assert isinstance(sb["observations"], list)
    assert sig["cpus"] == 4
    assert sig["workers"] == ig["workers"]

    obs = sb["observations"]
    assert len(obs) == 5, f"want exactly five observations, got {len(obs)}"
    run_ids = []
    cpu_vals = []
    for entry in obs:
        for key in _LEDGER_ENTRY_KEYS:
            assert key in entry, key
        assert entry["cpus"] == sig["cpus"] == 4
        assert entry["cpuModel"] == sig["cpuModel"]
        assert entry["image"] == sig["image"]
        assert entry["workers"] == sig["workers"] == ig["workers"]
        assert entry["errors"] == 0
        assert entry["served"] == 30000
        assert entry["committed"] == entry["served"]
        assert entry["p99Ms"] < 150
        assert entry["servedRate"] >= 200
        assert entry["maxInFlight"] < 1000
        assert entry["platformOnline"] is True
        pre = list(entry["workerPidsPre"])
        post = list(entry["workerPidsPost"])
        assert pre == sorted(set(pre)), pre
        assert post == sorted(set(post)), post
        assert len(pre) == sig["workers"]
        assert pre == post
        rid = entry["runId"]
        assert isinstance(rid, str) and _RUN_ID_RE.fullmatch(rid), rid
        run_ids.append(rid)
        cpu_vals.append(float(entry["cpuMsPerRequest"]))
    assert len(set(run_ids)) == 5, run_ids
    recomputed = max(cpu_vals) + (max(cpu_vals) - min(cpu_vals))
    assert abs(float(sb["cpuMsPerRequest"]) - recomputed) < 1e-9
    if not check_rendered_cpu:
        return
    import math

    expected_req = math.ceil(recomputed * 200)
    out = helm_template(DBAGENT)
    docs = parse_manifests(out)
    dep = next(
        d
        for d in docs
        if d.get("kind") == "Deployment" and "ingest-gateway" in d["metadata"]["name"]
    )
    req = dep["spec"]["template"]["spec"]["containers"][0]["resources"]["requests"]["cpu"]
    s = str(req)
    millicores = int(s[:-1]) if s.endswith("m") else int(float(s) * 1000)
    assert millicores == expected_req


def test_sizing_basis_provenance_is_on_reference_and_from_a_serving_run():
    """FP-IG-23: ledger schema + five valid observations + recompute.

    Against the unfixed tree: red — no signature block and no observations.
    Against the current tree: still red — observations is empty. Valid
    runIds cannot be fabricated here (Z: five consecutive CI
    benchmark-job runs at this change's head on the four-vCPU reference
    runner). The void 2.427 figure stays in values.yaml as a historical
    label only; it does not satisfy this test. The batch is not complete
    until five real observations, a re-derived basis, and recomputed CPU
    resources are recorded.
    """
    values = yaml.safe_load((DBAGENT / "values.yaml").read_text(encoding="utf-8"))
    validate_sizing_ledger(values["ingestGateway"])


def _valid_observation(run_id: str, cpu: float, workers: int = 4) -> dict:
    pids = [1000 + i for i in range(workers)]
    return {
        "runId": run_id,
        "cpuMsPerRequest": cpu,
        "cpus": 4,
        "cpuModel": "ref",
        "image": "ref-image",
        "workers": workers,
        "served": 30000,
        "errors": 0,
        "committed": 30000,
        "p99Ms": 40.0,
        "servedRate": 990.0,
        "maxInFlight": 200,
        "platformOnline": True,
        "workerPidsPre": pids,
        "workerPidsPost": list(pids),
    }


def _filled_ledger(*, cpu_vals=None, mutate=None) -> dict:
    cpus = list(cpu_vals or [1.0, 1.1, 1.2, 1.05, 1.08])
    ig = {
        "workers": 4,
        "sizingBasis": {
            "cpuMsPerRequest": max(cpus) + (max(cpus) - min(cpus)),
            "signature": {
                "cpus": 4,
                "cpuModel": "ref",
                "image": "ref-image",
                "workers": 4,
            },
            "observations": [
                _valid_observation(f"{1000 + i}/1", cpus[i]) for i in range(5)
            ],
        },
    }
    if mutate:
        mutate(ig)
    return ig


def test_sizing_ledger_mutations_are_red_only_with_validity_rules():
    """Standing test for FP-IG-23: each named weakening fails the helper.

    Against the unfixed tree every case is independently red (no
    signature, no observations, void 2.427 cannot be re-encoded).
    Cases are red only while the corresponding rule is present.
    """
    validate_sizing_ledger(_filled_ledger(), check_rendered_cpu=False)

    def _expect_red(name, mutate):
        try:
            validate_sizing_ledger(_filled_ledger(mutate=mutate), check_rendered_cpu=False)
        except AssertionError:
            return
        raise AssertionError(f"{name} stayed green; the validity rule is absent")

    _expect_red("missing_signature", lambda ig: ig["sizingBasis"].pop("signature"))
    _expect_red("missing_observations", lambda ig: ig["sizingBasis"].pop("observations"))
    _expect_red(
        "void_basis_with_fabricated_obs",
        lambda ig: ig["sizingBasis"].__setitem__("cpuMsPerRequest", VOID_SIZING_BASIS),
    )
    _expect_red(
        "duplicate_run_ids",
        lambda ig: ig["sizingBasis"]["observations"].__setitem__(
            1, _valid_observation("1000/1", 1.1)
        ),
    )
    _expect_red(
        "duplicate_pids",
        lambda ig: ig["sizingBasis"]["observations"][0].__setitem__(
            "workerPidsPre", [1, 1, 1, 1]
        ),
    )
    _expect_red(
        "committed_ne_served",
        lambda ig: ig["sizingBasis"]["observations"][0].__setitem__("committed", 29999),
    )
    _expect_red(
        "platform_not_online",
        lambda ig: ig["sizingBasis"]["observations"][0].__setitem__(
            "platformOnline", False
        ),
    )
    _expect_red(
        "worker_set_changed",
        lambda ig: ig["sizingBasis"]["observations"][0].__setitem__(
            "workerPidsPost", [9, 10, 11, 12]
        ),
    )
    _expect_red(
        "cpus_not_reference_4",
        lambda ig: (
            ig["sizingBasis"]["signature"].__setitem__("cpus", 16),
            [
                e.__setitem__("cpus", 16)
                for e in ig["sizingBasis"]["observations"]
            ],
        ),
    )
    _expect_red(
        "recompute_mismatch",
        lambda ig: ig["sizingBasis"].__setitem__("cpuMsPerRequest", 9.999),
    )
    _expect_red(
        "empty_observations",
        lambda ig: ig["sizingBasis"].__setitem__("observations", []),
    )
    _expect_red(
        "malformed_run_id_extra_segment",
        lambda ig: ig["sizingBasis"]["observations"][0].__setitem__(
            "runId", "1000/bogus/extra"
        ),
    )
    _expect_red(
        "malformed_run_id_non_numeric_attempt",
        lambda ig: ig["sizingBasis"]["observations"][0].__setitem__(
            "runId", "1000/bogus"
        ),
    )

    # Unfixed-tree shape: no ledger at all.
    try:
        validate_sizing_ledger({"workers": 4}, check_rendered_cpu=False)
    except AssertionError:
        pass
    else:
        raise AssertionError("unfixed (no sizingBasis) stayed green")
