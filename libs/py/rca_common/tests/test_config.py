import os

import pytest

from rca_common.config import ConfigError, parse_config


def test_env_var_interpolation(monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.example/abc")
    raw = {
        "notifications": {
            "outbound_webhooks": [{"name": "team-slack", "url": "${SLACK_WEBHOOK_URL}"}]
        }
    }
    cfg = parse_config(raw)
    assert (
        cfg.raw["notifications"]["outbound_webhooks"][0]["url"]
        == "https://hooks.example/abc"
    )


def test_missing_env_var_interpolates_empty():
    raw = {"storage": {"postgres_dsn": "${UNSET_VAR_XYZ}"}}
    cfg = parse_config(raw)
    assert cfg.storage.postgres_dsn == ""


def test_defaults_applied():
    cfg = parse_config({})
    assert cfg.budget_defaults.max_rounds == 15
    assert cfg.budget_defaults.max_cost_usd == 10.0
    assert cfg.budget_defaults.max_wall_seconds == 1800
    assert cfg.max_calls_per_round == 8
    assert cfg.rca_confidence_threshold == 0.85
    assert cfg.display_verbosity == "compact"
    assert cfg.data_egress_policy == "allow_remote"
    assert cfg.tracing.backend == "builtin"
    assert cfg.signing.backend == "mounted"
    assert cfg.temporal.address == "localhost:7233"
    assert cfg.temporal.namespace == "default"


def test_full_config_roundtrip():
    raw = {
        "models": {
            "planner": {"model": "ollama/qwen2.5:14b", "max_tokens": 2000},
            "rca": {"model": "bedrock/anthropic.claude-fable-5", "max_tokens": 8000},
        },
        "budget_defaults": {"max_rounds": 20, "max_cost_usd": 5.0, "max_wall_seconds": 900},
        "max_calls_per_round": 4,
        "rca_confidence_threshold": 0.9,
        "display_verbosity": "full",
        "data_egress_policy": "allow_remote",
        "tracing": {"backend": "both", "langfuse": {"host": "h", "public_key": "p", "secret_key": "s"}},
        "signing": {"backend": "mounted", "key_path": "/tmp/k", "rotation_grace_seconds": 60},
        "storage": {
            "postgres_dsn": "postgresql://x",
            "s3": {"endpoint": "http://minio:9000", "bucket": "b", "access_key": "a", "secret_key": "s"},
        },
        "model_gateway": {"url": "http://model-gateway:4000", "master_key": "mk"},
        "temporal": {"address": "temporal-frontend:7233", "namespace": "rca-agent"},
    }
    cfg = parse_config(raw)
    assert cfg.models["planner"].model == "ollama/qwen2.5:14b"
    assert cfg.models["rca"].max_tokens == 8000
    assert cfg.budget_defaults.max_rounds == 20
    assert cfg.tracing.backend == "both"
    assert cfg.tracing.langfuse_host == "h"
    assert cfg.signing.key_path == "/tmp/k"
    assert cfg.storage.s3_bucket == "b"
    assert cfg.model_gateway.master_key == "mk"
    assert cfg.temporal.address == "temporal-frontend:7233"
    assert cfg.temporal.namespace == "rca-agent"


def test_local_only_egress_policy_passes_with_local_models():
    raw = {
        "models": {
            "planner": {"model": "ollama/qwen2.5:14b"},
            "rca": {"model": "vllm/local-model"},
        },
        "data_egress_policy": "local_only",
    }
    cfg = parse_config(raw)
    assert cfg.data_egress_policy == "local_only"


def test_local_only_egress_policy_rejects_remote_model():
    raw = {
        "models": {
            "planner": {"model": "ollama/qwen2.5:14b"},
            "rca": {"model": "bedrock/anthropic.claude-fable-5"},
        },
        "data_egress_policy": "local_only",
    }
    with pytest.raises(ConfigError):
        parse_config(raw)


def test_load_config_from_file(tmp_path):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(
        "budget_defaults:\n  max_rounds: 7\n"
    )
    from rca_common.config import load_config

    cfg = load_config(str(cfg_file))
    assert cfg.budget_defaults.max_rounds == 7
