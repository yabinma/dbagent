"""FP-M6-11/12: compose apps profile and probe/swarm files."""
from __future__ import annotations

import re

from delivery_helpers import COMPOSE, require_bin, run


def test_control_plane_apps_profile_services_and_jobs():
    require_bin("docker")
    yml = COMPOSE / "control-plane.yml"
    assert yml.is_file()
    proc = run(["docker", "compose", "-f", str(yml), "config", "-q"])
    assert proc.returncode == 0, proc.stderr

    import yaml

    data = yaml.safe_load(yml.read_text(encoding="utf-8"))
    services = data.get("services") or {}
    apps = [
        "ingest-gateway",
        "temporal-worker",
        "probe-gateway",
        "dashboard-api",
        "dashboard-web",
        "migrate",
        "signing-key",
        "bootstrap-admin",
        "seed-playbooks",
    ]
    for svc in apps:
        assert svc in services, svc
        profiles = services[svc].get("profiles") or []
        assert "apps" in profiles, f"{svc} must be in apps profile"

    # M1 infrastructure services are outside the apps profile.
    for infra in ("postgres", "minio", "temporal"):
        if infra in services:
            profiles = services[infra].get("profiles") or []
            assert "apps" not in profiles, f"{infra} must not be in apps profile"

    # Exactly one image and no multi-process command per product service.
    for svc in ("ingest-gateway", "temporal-worker", "probe-gateway", "dashboard-api", "dashboard-web"):
        s = services[svc]
        assert s.get("image"), svc
        cmd = s.get("command") or s.get("entrypoint")
        if isinstance(cmd, list):
            joined = " ".join(str(x) for x in cmd)
        else:
            joined = str(cmd or "")
        assert "&&" not in joined and ";" not in joined, f"multi-process command in {svc}"

    text = yml.read_text(encoding="utf-8")
    # No committed secret literals (placeholder ${VAR} form is fine).
    assert "change-me-in-production" not in text
    assert ":latest" not in text


def test_probe_compose_and_swarm_stack_secrets_and_placement():
    require_bin("docker")
    import os

    probe = COMPOSE / "probe.yml"
    swarm = COMPOSE / "probe-swarm-stack.yml"
    assert probe.is_file() and swarm.is_file()

    # DOCKER_SOCKET_GID is required (non-root probe + root:docker 0660 socket).
    env = {**os.environ, "DOCKER_SOCKET_GID": "999"}
    proc = run(["docker", "compose", "-f", str(probe), "config", "-q"], env=env)
    assert proc.returncode == 0, proc.stderr

    import re
    import yaml

    data = yaml.safe_load(swarm.read_text(encoding="utf-8"))
    svc = data["services"]["probe"]
    assert "node.role == manager" in str(svc.get("deploy", {}))
    assert "secrets" in svc or "secrets" in data
    assert "configs" in svc or "configs" in data

    # write_enabled false by default in the config the swarm stack mounts
    configs = data.get("configs") or {}
    cfg_file = (configs.get("probe_config") or {}).get("file")
    assert cfg_file, "swarm stack must declare configs.probe_config.file"
    cfg_path = (swarm.parent / cfg_file).resolve()
    assert cfg_path.is_file(), f"swarm mounted config missing: {cfg_path}"
    cfg = cfg_path.read_text(encoding="utf-8")
    assert "write_enabled: false" in cfg

    # Every ${VAR} in the mounted config must be supplied as env (or *_FILE).
    placeholders = set(re.findall(r"\$\{([A-Z0-9_]+)\}", cfg))
    env_block = svc.get("environment") or {}
    if isinstance(env_block, list):
        env_keys = {e.split("=", 1)[0] for e in env_block}
    else:
        env_keys = set(env_block)
    for var in placeholders:
        assert var in env_keys or f"{var}_FILE" in env_keys, (
            f"swarm stack missing env for config placeholder ${{{var}}}"
        )


def test_probe_compose_and_swarm_require_docker_socket_gid_group_add():
    """C1: non-root probe needs host docker GID; Compose uses group_add, Swarm user:."""
    import os
    import re
    import yaml

    require_bin("docker")

    probe = COMPOSE / "probe.yml"
    swarm = COMPOSE / "probe-swarm-stack.yml"
    probe_text = probe.read_text(encoding="utf-8")
    swarm_text = swarm.read_text(encoding="utf-8")

    # Compose keeps group_add (supported by compose schema).
    assert "group_add" in probe_text, "probe.yml missing group_add"
    assert re.search(r"\$\{DOCKER_SOCKET_GID:\?", probe_text), (
        "probe.yml must require DOCKER_SOCKET_GID via :? syntax"
    )
    probe_data = yaml.safe_load(probe_text)
    group_add = probe_data["services"]["probe"].get("group_add") or []
    assert "DOCKER_SOCKET_GID" in " ".join(str(g) for g in group_add), group_add

    # Swarm stack schema rejects group_add; user: "65532:${DOCKER_SOCKET_GID}" is
    # the supported form for socket group membership.
    assert re.search(r"\$\{DOCKER_SOCKET_GID:\?", swarm_text), (
        "probe-swarm-stack.yml must require DOCKER_SOCKET_GID via :? syntax"
    )
    swarm_data = yaml.safe_load(swarm_text)
    probe_svc = swarm_data["services"]["probe"]
    assert "group_add" not in probe_svc, (
        "probe-swarm-stack.yml must not declare group_add (Swarm stack schema rejects it)"
    )
    user = str(probe_svc.get("user") or "")
    assert "65532" in user and "DOCKER_SOCKET_GID" in user, f"swarm user={user!r}"

    # docker compose config: unset GID must fail; numeric GID must pass.
    env_no_gid = {k: v for k, v in os.environ.items() if k != "DOCKER_SOCKET_GID"}
    fail_compose = run(
        ["docker", "compose", "-f", str(probe), "config", "-q"], env=env_no_gid
    )
    assert fail_compose.returncode != 0, "compose config must fail without DOCKER_SOCKET_GID"
    assert "DOCKER_SOCKET_GID" in (fail_compose.stderr or fail_compose.stdout)

    ok_compose = run(
        ["docker", "compose", "-f", str(probe), "config", "-q"],
        env={**os.environ, "DOCKER_SOCKET_GID": "999"},
    )
    assert ok_compose.returncode == 0, ok_compose.stderr

    # docker stack config: unset GID must fail; numeric GID must pass and render user.
    fail_stack = run(
        ["docker", "stack", "config", "-c", str(swarm)], env=env_no_gid
    )
    assert fail_stack.returncode != 0, "stack config must fail without DOCKER_SOCKET_GID"
    assert "DOCKER_SOCKET_GID" in (fail_stack.stderr or fail_stack.stdout)

    ok_stack = run(
        ["docker", "stack", "config", "-c", str(swarm)],
        env={**os.environ, "DOCKER_SOCKET_GID": "999"},
    )
    assert ok_stack.returncode == 0, ok_stack.stderr or ok_stack.stdout
    rendered = ok_stack.stdout
    assert "group_add" not in rendered
    # docker stack config may quote as 65532:999 or "65532:999"
    assert re.search(r'user:\s*"?65532:999"?', rendered), (
        f"expected user 65532:999 in stack config output, got:\n{rendered[:2000]}"
    )


# --- FP-SW-4 (design.md §11.2.5): the shipped Swarm/compose artifacts express
# the direct-socket posture, and no shipped artifact defines a proxy. ---

# Compose volume options that may appear as the third short-form field.
_COMPOSE_MOUNT_OPTS = frozenset(
    {"ro", "rw", "z", "Z", "nocopy", "cached", "delegated", "consistent"}
)
_ENV_SPAN_RE = re.compile(r"\$\{([^}]+)\}")
_PROBE_CONFIG_DEFAULT = "/etc/dbagent-probe/config.yaml"


def _probe_service_names(data: dict) -> set[str]:
    return set((data.get("services") or {}).keys())


def _env_lookup(environment, name: str) -> str | None:
    """Read NAME from a compose/stack environment mapping or list."""
    if isinstance(environment, dict):
        val = environment.get(name)
        return None if val is None else str(val)
    if isinstance(environment, list):
        for entry in environment:
            s = str(entry)
            if s == name:
                return ""
            if s.startswith(name + "="):
                return s.split("=", 1)[1]
    return None


def _mask_env_spans(s: str) -> tuple[str, list[str]]:
    """Replace every ${…} span with a colon-free token; return (masked, spans)."""
    spans: list[str] = []

    def repl(m: re.Match) -> str:
        spans.append(m.group(0))
        return f"__ENV{len(spans) - 1}__"

    return _ENV_SPAN_RE.sub(repl, s), spans


def _unmask(s: str, spans: list[str]) -> str:
    out = s
    for i, span in enumerate(spans):
        out = out.replace(f"__ENV{i}__", span)
    return out


def _interp_default(source: str) -> str:
    """Resolve ${VAR:-x}/${VAR:=x} to x; fail if a span has no default."""

    def repl(m: re.Match) -> str:
        body = m.group(1)
        for sep in (":-", ":="):
            if sep in body:
                return body.split(sep, 1)[1]
        if ":" in body and not body.startswith(":"):
            # ${VAR:?msg} / ${VAR:+x} — no usable default for a path.
            raise AssertionError(
                f"config mount source {source!r} has ${{{body}}} with no default"
            )
        # ${VAR} with no default
        raise AssertionError(
            f"config mount source {source!r} has ${{{body}}} with no default"
        )

    return _ENV_SPAN_RE.sub(repl, source)


def _compose_volume_target_and_source(entry) -> tuple[str, str] | None:
    """Parse one volumes: entry → (target, source) or None if unparseable.

    design.md §11.2.5 FP-SW-4 (iii): mask ${…}, split, unmask; long-form uses
    the `target` key. Unparseable entries are skipped, not guessed.
    """
    if isinstance(entry, dict):
        target = entry.get("target") or entry.get("destination")
        source = entry.get("source") or entry.get("bind") or ""
        if not target:
            return None
        return str(target), str(source)

    raw = str(entry)
    masked, spans = _mask_env_spans(raw)
    parts = masked.split(":")
    if len(parts) == 1:
        target = _unmask(parts[0], spans)
        return target, ""
    if len(parts) == 2:
        source = _unmask(parts[0], spans)
        target = _unmask(parts[1], spans)
        if not target.startswith("/"):
            return None
        return target, source
    if len(parts) == 3:
        source = _unmask(parts[0], spans)
        target = _unmask(parts[1], spans)
        mode = _unmask(parts[2], spans)
        opts = {o.strip() for o in mode.split(",") if o.strip()}
        if not opts or not opts <= _COMPOSE_MOUNT_OPTS:
            return None
        if not target.startswith("/"):
            return None
        return target, source
    return None


def _resolve_probe_config_path_compose(compose_path, data: dict):
    """Compose half of FP-SW-4 (iii): config file is the volumes: mount source."""
    from pathlib import Path

    svc = data["services"]["probe"]
    probe_config = _env_lookup(svc.get("environment"), "PROBE_CONFIG") or _PROBE_CONFIG_DEFAULT
    volumes = svc.get("volumes") or []
    for entry in volumes:
        parsed = _compose_volume_target_and_source(entry)
        if parsed is None:
            continue
        target, source = parsed
        if target != probe_config:
            continue
        assert source, f"{compose_path.name}: config mount has empty source"
        resolved_src = _interp_default(source)
        path = Path(resolved_src)
        if not path.is_absolute():
            path = (compose_path.parent / path).resolve()
        assert path.is_file(), f"{compose_path.name}: mounted config missing: {path}"
        return path
    raise AssertionError(
        f"{compose_path.name}: no volumes: entry targets PROBE_CONFIG path "
        f"{probe_config!r} (compose half of FP-SW-4 config resolution)"
    )


def _resolve_probe_config_path_swarm(swarm_path, data: dict):
    """Swarm half of FP-SW-4 (iii): config file via configs: target → file."""
    from pathlib import Path

    svc = data["services"]["probe"]
    probe_config = _env_lookup(svc.get("environment"), "PROBE_CONFIG") or _PROBE_CONFIG_DEFAULT
    svc_configs = svc.get("configs") or []
    top_configs = data.get("configs") or {}
    for entry in svc_configs:
        if isinstance(entry, str):
            source_name, target = entry, f"/{entry}"
        else:
            source_name = entry.get("source")
            target = entry.get("target") or f"/{source_name}"
        if target != probe_config:
            continue
        assert source_name in top_configs, (
            f"{swarm_path.name}: configs. source {source_name!r} not declared"
        )
        cfg_file = (top_configs[source_name] or {}).get("file")
        assert cfg_file, f"{swarm_path.name}: configs.{source_name}.file missing"
        path = Path(cfg_file)
        if not path.is_absolute():
            path = (swarm_path.parent / path).resolve()
        assert path.is_file(), f"{swarm_path.name}: mounted config missing: {path}"
        return path
    raise AssertionError(
        f"{swarm_path.name}: no configs: entry targets PROBE_CONFIG path "
        f"{probe_config!r} (swarm half of FP-SW-4 config resolution)"
    )


def _assert_probe_config_shape(cfg: dict, *, require_bootstrap_ca_pin: bool = False) -> None:
    if "docker_api_base_url" in cfg:
        assert str(cfg["docker_api_base_url"]).startswith("unix://"), cfg["docker_api_base_url"]
        assert cfg["docker_api_base_url"] == "unix:///var/run/docker.sock"
    assert "volumes" not in cfg and "mounts" not in cfg
    if require_bootstrap_ca_pin:
        assert "bootstrap_ca_pin" in cfg, "swarm probe config must set bootstrap_ca_pin"


def test_probe_stack_uses_mounted_socket_and_declares_no_proxy():
    import yaml

    from delivery_helpers import CHARTS, helm_template, parse_manifests

    probe_yml = COMPOSE / "probe.yml"
    swarm_yml = COMPOSE / "probe-swarm-stack.yml"
    assert probe_yml.is_file() and swarm_yml.is_file()

    for path in (probe_yml, swarm_yml):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        services = _probe_service_names(data)
        # No service other than `probe` -- so no socket proxy ships.
        assert services == {"probe"}, f"{path.name} declares {sorted(services)}"
        volumes = (data["services"]["probe"].get("volumes") or [])
        joined = [str(v) for v in volumes]
        assert any(
            v.startswith("/var/run/docker.sock:/var/run/docker.sock") for v in joined
        ), f"{path.name} does not mount the docker socket: {joined}"
        # The one service is the product probe image, and nothing publishes a
        # Docker TCP port (structural, so a prose mention of the rejected
        # proxy option does not trip it).
        image = str(data["services"]["probe"].get("image") or "")
        assert image.endswith("/probe:${APP_VERSION:-0.1.0}"), image
        for port in data["services"]["probe"].get("ports") or []:
            assert "2375" not in str(port) and "2376" not in str(port), port

    # Compose half of config resolution (errata pass 9 ledger row 3): the
    # mounted file is whatever services.probe mounts at PROBE_CONFIG — not a
    # hard-coded path. Swarm half is separate (configs:, not volumes:).
    compose_data = yaml.safe_load(probe_yml.read_text(encoding="utf-8"))
    compose_cfg_path = _resolve_probe_config_path_compose(probe_yml, compose_data)
    compose_cfg = yaml.safe_load(compose_cfg_path.read_text(encoding="utf-8"))
    _assert_probe_config_shape(compose_cfg)

    # The Swarm stack carries the attachments the real deployment needed.
    swarm = yaml.safe_load(swarm_yml.read_text(encoding="utf-8"))
    svc = swarm["services"]["probe"]
    networks = swarm.get("networks") or {}
    assert networks, "swarm stack declares no network"
    attached = svc.get("networks") or []
    assert attached, "probe service attaches to no network"
    for name in attached:
        assert networks.get(name, {}).get("external") is True, (
            f"{name} must be the existing, EXTERNAL Presto overlay"
        )
    extra_hosts = [str(h) for h in (svc.get("extra_hosts") or [])]
    assert any(h.startswith("probe-gateway:") for h in extra_hosts), extra_hosts
    assert "node.role == manager" in str(svc.get("deploy", {}))

    # FP-SW-4 / review W2: the config the swarm stack mounts must use the same
    # host as every extra_hosts entry (otherwise extra_hosts is inert and
    # host.docker.internal fails on a Linux Swarm node).
    swarm_cfg_path = _resolve_probe_config_path_swarm(swarm_yml, swarm)
    swarm_cfg = yaml.safe_load(swarm_cfg_path.read_text(encoding="utf-8"))
    _assert_probe_config_shape(swarm_cfg, require_bootstrap_ca_pin=True)
    extra_host_names = {h.split(":", 1)[0] for h in extra_hosts if ":" in h}
    assert extra_host_names, extra_hosts
    for key in ("gateway_address", "bootstrap_address"):
        addr = str(swarm_cfg.get(key) or "")
        host = addr.rsplit(":", 1)[0] if addr else ""
        assert host in extra_host_names, (
            f"swarm config {key}={addr!r} host must match an extra_hosts "
            f"entry among {sorted(extra_host_names)}"
        )

    # The probe CHART is untouched by this FP: on Kubernetes the probe talks to
    # the API server, never to a Docker socket -- asserted as an absence, so a
    # later copy-paste from the compose files is caught (DW1 / errata pass 9).
    rendered = helm_template(
        CHARTS / "dbagent-probe",
        set_args=["platformKey=p1", "bootstrapToken=tok", "writeEnabled=false"],
    )
    # Ledger row 1: DOCKER_SOCKET_GID must not appear anywhere in the render
    # (text scan) nor as a container env name (structural).
    assert "DOCKER_SOCKET_GID" not in rendered, (
        "probe chart rendered output must not contain DOCKER_SOCKET_GID"
    )
    docs = parse_manifests(rendered)
    configmaps = [d for d in docs if d.get("kind") == "ConfigMap"]
    assert configmaps, "probe chart rendered no ConfigMap"
    for cm in configmaps:
        for key, value in (cm.get("data") or {}).items():
            assert "docker_api_base_url" not in value, f"{key} carries docker_api_base_url"
    deployments = [d for d in docs if d.get("kind") == "Deployment"]
    assert deployments, "probe chart rendered no Deployment"
    for dep in deployments:
        spec = dep["spec"]["template"]["spec"]
        # Ledger row 2: distroless-nonroot identity.
        sc = spec.get("securityContext") or {}
        assert sc.get("runAsUser") == 65532, f"runAsUser={sc.get('runAsUser')!r}"
        assert sc.get("fsGroup") == 65532, f"fsGroup={sc.get('fsGroup')!r}"
        for vol in spec.get("volumes") or []:
            host_path = (vol.get("hostPath") or {}).get("path", "")
            assert "docker.sock" not in host_path, f"probe Deployment mounts {host_path}"
        for container_key in ("containers", "initContainers"):
            for container in spec.get(container_key) or []:
                for env in container.get("env") or []:
                    assert env.get("name") != "DOCKER_SOCKET_GID", (
                        f"{container_key} env carries DOCKER_SOCKET_GID"
                    )
                for mount in container.get("volumeMounts") or []:
                    assert "docker.sock" not in mount.get("mountPath", "")


# --- FP-SW-9 (design.md §11.2.5): deployment-scoped identities are `dbagent`. ---


def test_project_names_volumes_and_datastore_defaults_are_dbagent():
    import sys

    import yaml

    from delivery_helpers import CHARTS, REPO_ROOT

    control_plane = yaml.safe_load((COMPOSE / "control-plane.yml").read_text(encoding="utf-8"))
    probe = yaml.safe_load((COMPOSE / "probe.yml").read_text(encoding="utf-8"))
    assert control_plane.get("name") == "dbagent-control-plane"
    assert probe.get("name") == "dbagent-probe"

    # Application datastore identities (C.4). The Temporal datastore keeps its
    # own `temporal` identity and is deliberately untouched.
    app_pg = control_plane["services"]["postgres"]["environment"]
    assert app_pg["POSTGRES_DB"] == "dbagent"
    assert app_pg["POSTGRES_USER"] == "dbagent"
    assert app_pg["POSTGRES_PASSWORD"] == "dbagent"

    text = (COMPOSE / "control-plane.yml").read_text(encoding="utf-8")
    dsn_defaults = re.findall(r"\$\{PG_DSN:-([^}]+)\}", text)
    assert dsn_defaults, "no ${PG_DSN:-...} default found"
    for dsn in dsn_defaults:
        assert dsn == "postgresql://dbagent:dbagent@postgres:5432/dbagent", dsn

    # Chart values and the compose app config.
    chart_values = yaml.safe_load((CHARTS / "dbagent" / "values.yaml").read_text(encoding="utf-8"))
    assert chart_values["config"]["storage"]["s3"]["bucket"] == "dbagent"
    assert chart_values["config"]["temporal"]["namespace"] == "dbagent"
    assert chart_values["postgresql"]["auth"]["database"] == "dbagent"
    assert chart_values["postgresql"]["auth"]["username"] == "dbagent"

    app_config = yaml.safe_load((COMPOSE / "config/dbagent.yaml").read_text(encoding="utf-8"))
    assert app_config["temporal"]["namespace"] == "dbagent"
    assert app_config["storage"]["s3"]["bucket"] == "dbagent"

    # rca_common.config's own dataclass defaults (the library keeps its name;
    # only the deployment-scoped values move -- C.5).
    sys.path.insert(0, str(REPO_ROOT / "libs/py/rca_common"))
    from rca_common.config import load_config

    import tempfile
    import os as _os

    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
        fh.write("{}\n")
        empty = fh.name
    try:
        conf = load_config(empty)
    finally:
        _os.unlink(empty)
    assert conf.temporal.namespace == "dbagent"
    assert conf.storage.s3_bucket == "dbagent"
    assert conf.signing.key_path == "/etc/dbagent/signing/ed25519.key"
