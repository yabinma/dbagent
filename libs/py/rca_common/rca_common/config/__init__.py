"""Config loader for the single YAML config (design.md Section 6, Appendix E).

Supports ``${ENV_VAR}`` interpolation and per-platform overrides. Platform
overrides are applied by callers (they live in ``platforms.config`` in
Postgres, not in the static file) -- this module only loads and validates the
deployment-wide defaults.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any

import yaml

_ENV_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class ConfigError(Exception):
    """Raised for structurally invalid or policy-violating configuration."""


def _interpolate(value: Any) -> Any:
    if isinstance(value, str):
        def _sub(match: re.Match[str]) -> str:
            name = match.group(1)
            return os.environ.get(name, "")

        return _ENV_VAR_RE.sub(_sub, value)
    if isinstance(value, dict):
        return {k: _interpolate(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_interpolate(v) for v in value]
    return value


_LOCAL_MODEL_PREFIXES = ("ollama/", "vllm/")


@dataclass
class ModelRoute:
    model: str
    max_tokens: int = 2000


@dataclass
class BudgetDefaults:
    max_rounds: int = 15
    max_cost_usd: float = 10.0
    max_wall_seconds: int = 1800


@dataclass
class TracingConfig:
    backend: str = "builtin"  # builtin | langfuse | both
    langfuse_host: str = ""
    langfuse_public_key: str = ""
    langfuse_secret_key: str = ""


@dataclass
class SigningConfig:
    backend: str = "mounted"  # mounted | vault | aws_kms
    key_path: str = "/etc/rca-agent/signing/ed25519.key"
    rotation_grace_seconds: int = 600


@dataclass
class StorageConfig:
    postgres_dsn: str = ""
    s3_endpoint: str = ""
    s3_bucket: str = "rca-agent"
    s3_access_key: str = ""
    s3_secret_key: str = ""


@dataclass
class ModelGatewayConfig:
    url: str = "http://model-gateway:4000"
    master_key: str = ""


@dataclass
class TemporalConfig:
    address: str = "localhost:7233"
    namespace: str = "default"


@dataclass
class IngestSource:
    name: str
    secret: str


@dataclass
class IngestConfig:
    sources: list[IngestSource] = field(default_factory=list)
    correlation_window_seconds: int = 1800


@dataclass
class RawCommandsConfig:
    policy: str = "approve"  # approve | validate_only
    timeout_seconds: int = 60
    max_output_bytes: int = 1048576


@dataclass
class ProbeGatewayConfig:
    """Worker → probe-gateway internal ExecuteTool client (Section 3.2)."""

    url: str = "http://probe-gateway:8080"
    timeout_seconds: int = 120


@dataclass
class DashboardConfig:
    """Dashboard-api settings (Appendix E ``dashboard:`` block / Section 10.2)."""

    jwt_secret: str = ""
    token_ttl_seconds: int = 43200  # 12 h
    password_min_length: int = 12
    cors_origins: list[str] = field(default_factory=list)
    bootstrap_ca_cert_path: str = ""


@dataclass
class AppConfig:
    models: dict[str, ModelRoute] = field(default_factory=dict)
    budget_defaults: BudgetDefaults = field(default_factory=BudgetDefaults)
    max_calls_per_round: int = 8
    rca_confidence_threshold: float = 0.85
    display_verbosity: str = "compact"
    data_egress_policy: str = "allow_remote"  # allow_remote | local_only
    tracing: TracingConfig = field(default_factory=TracingConfig)
    signing: SigningConfig = field(default_factory=SigningConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    model_gateway: ModelGatewayConfig = field(default_factory=ModelGatewayConfig)
    temporal: TemporalConfig = field(default_factory=TemporalConfig)
    ingest: IngestConfig = field(default_factory=IngestConfig)
    raw_commands: RawCommandsConfig = field(default_factory=RawCommandsConfig)
    probe_gateway: ProbeGatewayConfig = field(default_factory=ProbeGatewayConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    raw: dict[str, Any] = field(default_factory=dict)

    def validate_egress_policy(self) -> None:
        """local_only: startup validation fails unless every agent role
        routes to a local provider (ollama/, vllm/) -- Appendix E."""
        if self.data_egress_policy != "local_only":
            return
        for role, route in self.models.items():
            if not route.model.startswith(_LOCAL_MODEL_PREFIXES):
                raise ConfigError(
                    f"data_egress_policy=local_only but agent role '{role}' routes "
                    f"to non-local model '{route.model}'"
                )


def load_config(path: str) -> AppConfig:
    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}
    return parse_config(raw)


def parse_config(raw: dict[str, Any]) -> AppConfig:
    raw = _interpolate(raw)

    models = {
        role: ModelRoute(model=spec["model"], max_tokens=spec.get("max_tokens", 2000))
        for role, spec in (raw.get("models") or {}).items()
    }

    bd = raw.get("budget_defaults") or {}
    budget_defaults = BudgetDefaults(
        max_rounds=bd.get("max_rounds", 15),
        max_cost_usd=bd.get("max_cost_usd", 10.0),
        max_wall_seconds=bd.get("max_wall_seconds", 1800),
    )

    tr = raw.get("tracing") or {}
    lf = tr.get("langfuse") or {}
    tracing = TracingConfig(
        backend=tr.get("backend", "builtin"),
        langfuse_host=lf.get("host", ""),
        langfuse_public_key=lf.get("public_key", ""),
        langfuse_secret_key=lf.get("secret_key", ""),
    )

    sg = raw.get("signing") or {}
    signing = SigningConfig(
        backend=sg.get("backend", "mounted"),
        key_path=sg.get("key_path", "/etc/rca-agent/signing/ed25519.key"),
        rotation_grace_seconds=sg.get("rotation_grace_seconds", 600),
    )

    st = raw.get("storage") or {}
    s3 = st.get("s3") or {}
    storage = StorageConfig(
        postgres_dsn=st.get("postgres_dsn", ""),
        s3_endpoint=s3.get("endpoint", ""),
        s3_bucket=s3.get("bucket", "rca-agent"),
        s3_access_key=s3.get("access_key", ""),
        s3_secret_key=s3.get("secret_key", ""),
    )

    mg = raw.get("model_gateway") or {}
    model_gateway = ModelGatewayConfig(
        url=mg.get("url", "http://model-gateway:4000"),
        master_key=mg.get("master_key", ""),
    )

    tm = raw.get("temporal") or {}
    temporal = TemporalConfig(
        address=tm.get("address", "localhost:7233"),
        namespace=tm.get("namespace", "default"),
    )

    ig = raw.get("ingest") or {}
    ingest = IngestConfig(
        sources=[
            IngestSource(name=s["name"], secret=s.get("secret", ""))
            for s in (ig.get("sources") or [])
        ],
        correlation_window_seconds=ig.get("correlation_window_seconds", 1800),
    )

    rc = raw.get("raw_commands") or {}
    raw_commands = RawCommandsConfig(
        policy=rc.get("policy", "approve"),
        timeout_seconds=rc.get("timeout_seconds", 60),
        max_output_bytes=rc.get("max_output_bytes", 1048576),
    )

    pgw = raw.get("probe_gateway") or {}
    probe_gateway = ProbeGatewayConfig(
        url=pgw.get("url", "http://probe-gateway:8080"),
        timeout_seconds=pgw.get("timeout_seconds", 120),
    )

    db_cfg = raw.get("dashboard") or {}
    dashboard = DashboardConfig(
        jwt_secret=db_cfg.get("jwt_secret", ""),
        token_ttl_seconds=int(db_cfg.get("token_ttl_seconds", 43200)),
        password_min_length=int(db_cfg.get("password_min_length", 12)),
        cors_origins=list(db_cfg.get("cors_origins") or []),
        bootstrap_ca_cert_path=db_cfg.get("bootstrap_ca_cert_path", "") or "",
    )

    cfg = AppConfig(
        models=models,
        budget_defaults=budget_defaults,
        max_calls_per_round=raw.get("max_calls_per_round", 8),
        rca_confidence_threshold=raw.get("rca_confidence_threshold", 0.85),
        display_verbosity=raw.get("display_verbosity", "compact"),
        data_egress_policy=raw.get("data_egress_policy", "allow_remote"),
        tracing=tracing,
        signing=signing,
        storage=storage,
        model_gateway=model_gateway,
        temporal=temporal,
        ingest=ingest,
        raw_commands=raw_commands,
        probe_gateway=probe_gateway,
        dashboard=dashboard,
        raw=raw,
    )
    cfg.validate_egress_policy()
    return cfg
