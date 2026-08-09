"""FP-M6-11/12: compose apps profile and probe/swarm files."""
from __future__ import annotations

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
    probe = COMPOSE / "probe.yml"
    swarm = COMPOSE / "probe-swarm-stack.yml"
    assert probe.is_file() and swarm.is_file()

    proc = run(["docker", "compose", "-f", str(probe), "config", "-q"])
    assert proc.returncode == 0, proc.stderr

    import re
    import yaml

    data = yaml.safe_load(swarm.read_text(encoding="utf-8"))
    svc = data["services"]["probe"]
    assert "node.role == manager" in str(svc.get("deploy", {}))
    assert "secrets" in svc or "secrets" in data
    assert "configs" in svc or "configs" in data

    # write_enabled false by default in sample probe config
    cfg = (COMPOSE / "config/probe.yaml").read_text(encoding="utf-8")
    assert "write_enabled: false" in cfg

    # Every ${VAR} in the mounted config must be supplied as env (or *_FILE).
    placeholders = set(re.findall(r"\$\{([A-Z0-9_]+)\}", cfg))
    env = svc.get("environment") or {}
    if isinstance(env, list):
        env_keys = {e.split("=", 1)[0] for e in env}
    else:
        env_keys = set(env)
    for var in placeholders:
        assert var in env_keys or f"{var}_FILE" in env_keys, (
            f"swarm stack missing env for config placeholder ${{{var}}}"
        )
