"""Unit tests for the shared mock LLM server itself (design.md Section
14.2/14.3: this is one of the "standard mocks, built once in M1 and
shared"). Exercised directly over real HTTP (loopback), since that is
exactly the contract every future functional test relies on.
"""
from __future__ import annotations

import httpx
import pytest

from tests.mocks.llm.mock_llm_server import CannedResponse, MockLLMServer


@pytest.mark.asyncio
async def test_default_response_used_when_no_role_specific_canned_response():
    with MockLLMServer() as server:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{server.base_url}/chat/completions",
                json={"model": "m", "messages": [], "metadata": {"agent_role": "unknown_role"}},
            )
    assert resp.status_code == 200
    body = resp.json()
    assert body["choices"][0]["message"]["content"] == '{"answer": "ok"}'
    assert resp.headers["x-litellm-response-cost"] == "0.001"


@pytest.mark.asyncio
async def test_role_specific_canned_response_takes_precedence():
    with MockLLMServer(
        responses={"rca": CannedResponse(content='{"root_cause": "oom"}', cost_usd=0.02)}
    ) as server:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{server.base_url}/chat/completions",
                json={"model": "m", "messages": [], "metadata": {"agent_role": "rca"}},
            )
    body = resp.json()
    assert body["choices"][0]["message"]["content"] == '{"root_cause": "oom"}'
    assert resp.headers["x-litellm-response-cost"] == "0.02"


@pytest.mark.asyncio
async def test_records_received_requests():
    with MockLLMServer() as server:
        async with httpx.AsyncClient() as client:
            await client.post(
                f"{server.base_url}/chat/completions",
                json={"model": "m", "messages": [{"role": "user", "content": "hi"}], "metadata": {}},
            )
    assert len(server.received_requests) == 1
    assert server.received_requests[0]["messages"][0]["content"] == "hi"


@pytest.mark.asyncio
async def test_unknown_path_returns_404():
    with MockLLMServer() as server:
        async with httpx.AsyncClient() as client:
            resp = await client.post(f"{server.base_url}/not-a-real-path", json={})
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_usage_and_token_counts_reflect_canned_response():
    with MockLLMServer(default_response=CannedResponse(content="x", input_tokens=42, output_tokens=8)) as server:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{server.base_url}/chat/completions",
                json={"model": "m", "messages": [], "metadata": {}},
            )
    usage = resp.json()["usage"]
    assert usage["prompt_tokens"] == 42
    assert usage["completion_tokens"] == 8
    assert usage["total_tokens"] == 50


def test_start_stop_without_context_manager():
    server = MockLLMServer()
    url = server.start()
    assert url.startswith("http://127.0.0.1:")


@pytest.mark.asyncio
async def test_role_resolved_from_response_format_schema_name_when_metadata_absent():
    """F4: litellm strips metadata; json_schema.name is what the backend sees.

    The pinned litellm image forwards only messages/model/response_format.
    A request that still carries metadata.agent_role is the functional-tier
    path and does not exercise this defect.
    """
    with MockLLMServer(
        responses={"planner": CannedResponse(content='{"tool_calls":[]}', cost_usd=0.02)}
    ) as server:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{server.base_url}/chat/completions",
                json={
                    "model": "mock",
                    "messages": [{"role": "user", "content": "plan"}],
                    "response_format": {
                        "type": "json_schema",
                        "json_schema": {"name": "planner", "schema": {}},
                    },
                },
            )
    assert resp.status_code == 200
    assert resp.json()["choices"][0]["message"]["content"] == '{"tool_calls":[]}'
    assert resp.headers["x-litellm-response-cost"] == "0.02"


@pytest.mark.asyncio
async def test_metadata_agent_role_wins_over_response_format_schema_name():
    """F4 companion: the functional tier still keys on metadata when present."""
    with MockLLMServer(
        responses={
            "planner": CannedResponse(content='{"from":"planner"}'),
            "rca": CannedResponse(content='{"from":"rca"}'),
        }
    ) as server:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{server.base_url}/chat/completions",
                json={
                    "model": "mock",
                    "messages": [],
                    "metadata": {"agent_role": "rca"},
                    "response_format": {
                        "type": "json_schema",
                        "json_schema": {"name": "planner", "schema": {}},
                    },
                },
            )
    assert resp.json()["choices"][0]["message"]["content"] == '{"from":"rca"}'


def test_fixture_rule_matches_response_format_schema_name_without_metadata(tmp_path):
    """F4 e2e path: fixture-manifest rules must match json_schema.name alone."""
    (tmp_path / "planner.json").write_text('{"tool_calls":[{"name":"x"}]}', encoding="utf-8")
    (tmp_path / "fixtures.yaml").write_text(
        """
- when: {agent_role: planner}
  respond: planner.json
  repeat: all
""",
        encoding="utf-8",
    )
    with MockLLMServer(
        fixture_set=tmp_path,
        default_response=CannedResponse(content='{"answer": "ok"}'),
    ) as server:
        resp = httpx.post(
            f"{server.base_url}/chat/completions",
            json={
                "model": "mock",
                "messages": [{"role": "user", "content": "plan"}],
                "response_format": {
                    "type": "json_schema",
                    "json_schema": {"name": "planner"},
                },
            },
        )
    assert resp.status_code == 200
    assert resp.json()["choices"][0]["message"]["content"] == '{"tool_calls":[{"name":"x"}]}'


def test_placeholders_are_filled_from_earlier_prompts_of_the_same_case(tmp_path):
    """FP-M6-17 / review round 5 C6: a fixture that names a run-time value.

    E4's remediation action must carry the id of the query the scenario really
    submitted; a literal `${query_id}` made the probe kill a query that never
    existed while verification happily reported success.
    """
    (tmp_path / "planner.json").write_text('{"tool_calls":[]}', encoding="utf-8")
    (tmp_path / "remediation.json").write_text(
        '{"proposed_actions":[{"playbook_params":{"query_id":"${query_id}"}}]}',
        encoding="utf-8",
    )
    (tmp_path / "fixtures.yaml").write_text(
        """
- when: {agent_role: planner}
  respond: planner.json
  repeat: all
- when: {agent_role: remediation}
  respond: remediation.json
  repeat: all
""",
        encoding="utf-8",
    )

    with MockLLMServer(fixture_set=tmp_path) as server:
        alert = '{"labels": {"query_id": "20260801_101010_00007_abcde"}}'
        planner = httpx.post(
            f"{server.base_url}/chat/completions",
            json={
                "model": "m",
                "messages": [{"role": "user", "content": f"Alert: {alert}"}],
                "metadata": {"agent_role": "planner", "investigation_id": "inv-1"},
            },
        )
        assert planner.status_code == 200

        # The remediation prompt itself never mentions the query id.
        remediation = httpx.post(
            f"{server.base_url}/chat/completions",
            json={
                "model": "m",
                "messages": [{"role": "user", "content": "Root cause: runaway"}],
                "metadata": {"agent_role": "remediation", "investigation_id": "inv-1"},
            },
        )
        assert remediation.status_code == 200
        content = remediation.json()["choices"][0]["message"]["content"]
        assert "${query_id}" not in content
        assert "20260801_101010_00007_abcde" in content

        # A different investigation must not inherit the value, and an
        # unresolved placeholder is an error rather than a literal.
        other = httpx.post(
            f"{server.base_url}/chat/completions",
            json={
                "model": "m",
                "messages": [{"role": "user", "content": "Root cause: runaway"}],
                "metadata": {"agent_role": "remediation", "investigation_id": "inv-2"},
            },
        )
        assert other.status_code == 400, other.text
        assert other.json()["error"]["type"] == "unresolved_placeholder"


def test_harvest_and_fill_helpers():
    from tests.mocks.llm.mock_llm_server import (
        UnresolvedPlaceholder,
        fill_placeholders,
        harvest_placeholder_values,
    )

    prompt = 'Alert: {"labels": {"query_id": "q-1"}, "error_summary": "runaway query q-1"}'
    assert harvest_placeholder_values(prompt, {"query_id"}) == {"query_id": "q-1"}
    # Prose alone never yields a value: only the exact JSON key/value form does.
    assert harvest_placeholder_values("runaway query q-1", {"query_id"}) == {}
    assert fill_placeholders("kill ${query_id}", {"query_id": "q-1"}) == "kill q-1"
    with pytest.raises(UnresolvedPlaceholder):
        fill_placeholders("kill ${query_id}", {})


def test_e2e_fixture_placeholders_are_all_resolvable_names():
    """Every `${...}` the shipped e2e fixtures use must be a name the ingest
    normalizer actually preserves into the prompt (`labels.*`)."""
    from pathlib import Path

    from tests.mocks.llm.mock_llm_server import PLACEHOLDER_RE, load_fixture_set

    import re

    fixtures = Path(__file__).resolve().parents[2] / "e2e" / "mockllm" / "fixtures"
    scenarios = Path(__file__).resolve().parents[2] / "e2e" / "test_e2e_scenarios.py"
    assert fixtures.is_dir() and scenarios.is_file()

    names: set[str] = set()
    for rule in load_fixture_set(fixtures):
        names.update(PLACEHOLDER_RE.findall(rule.content))
    assert names, "no e2e fixture uses a run-time placeholder any more"

    source = scenarios.read_text(encoding="utf-8")
    label_keys: set[str] = set()
    for block in re.findall(r'"labels":\s*\{([^}]*)\}', source):
        label_keys.update(re.findall(r'"([A-Za-z_][A-Za-z0-9_]*)"\s*:', block))
    for name in sorted(names):
        assert name in label_keys, (
            f"the e2e fixtures use ${{{name}}}, but no scenario puts {name!r} in "
            "the alert `labels` — the only alert field ingest normalization "
            f"preserves into the prompt. Label keys found: {sorted(label_keys)}"
        )


def test_fixture_manifest_matching(tmp_path):
    """FP-M6-17: fixture-manifest mode — role, prompt_contains, repeat, fallback."""
    from tests.mocks.llm.mock_llm_server import FixtureRule, load_fixture_set

    (tmp_path / "planner.json").write_text('{"tool_calls":[]}', encoding="utf-8")
    (tmp_path / "rca.json").write_text('{"status":"concluded"}', encoding="utf-8")
    (tmp_path / "fixtures.yaml").write_text(
        """
- when: {agent_role: planner}
  respond: planner.json
  repeat: 1
- when: {agent_role: rca, prompt_contains: OOM}
  respond: rca.json
  repeat: all
""",
        encoding="utf-8",
    )
    rules = load_fixture_set(tmp_path)
    assert len(rules) == 2
    assert rules[0].agent_role == "planner"
    assert "tool_calls" in rules[0].content

    with MockLLMServer(
        fixture_set=tmp_path,
        default_response=CannedResponse(content='{"fallback":true}'),
    ) as server:
        import httpx

        # First planner hit uses fixture.
        r1 = httpx.post(
            f"{server.base_url}/chat/completions",
            json={"model": "m", "messages": [{"role": "user", "content": "plan"}], "metadata": {"agent_role": "planner"}},
        )
        assert r1.json()["choices"][0]["message"]["content"] == '{"tool_calls":[]}'
        # Second planner exhausts repeat:1 → default.
        r2 = httpx.post(
            f"{server.base_url}/chat/completions",
            json={"model": "m", "messages": [{"role": "user", "content": "plan"}], "metadata": {"agent_role": "planner"}},
        )
        assert r2.json()["choices"][0]["message"]["content"] == '{"fallback":true}'
        # RCA with prompt_contains match.
        r3 = httpx.post(
            f"{server.base_url}/chat/completions",
            json={
                "model": "m",
                "messages": [{"role": "user", "content": "worker OOM killed"}],
                "metadata": {"agent_role": "rca"},
            },
        )
        assert r3.json()["choices"][0]["message"]["content"] == '{"status":"concluded"}'
        # RCA without prompt match → default.
        r4 = httpx.post(
            f"{server.base_url}/chat/completions",
            json={
                "model": "m",
                "messages": [{"role": "user", "content": "something else"}],
                "metadata": {"agent_role": "rca"},
            },
        )
        assert r4.json()["choices"][0]["message"]["content"] == '{"fallback":true}'

    # Backward compatibility: responses= constructor still works with fixtures absent.
    with MockLLMServer(responses={"planner": CannedResponse(content="legacy")}) as server:
        import httpx

        r = httpx.post(
            f"{server.base_url}/chat/completions",
            json={"model": "m", "messages": [], "metadata": {"agent_role": "planner"}},
        )
        assert r.json()["choices"][0]["message"]["content"] == "legacy"

    # Direct FixtureRule list constructor.
    rule = FixtureRule(agent_role="x", content='{"ok":1}', repeat="all")
    assert rule.matches("x", "p")
    assert not rule.matches("y", "p")

    server.stop()
