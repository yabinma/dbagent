"""In-process, OpenAI-compatible mock LLM server (design.md Section 14.3:
"a mock LLM server (serves canned structured outputs per agent role and
scenario)"). Built once in M1 and reused by every later milestone's
functional tests per Section 14.2's shared-mocks convention.

Implements only what `LiteLLMHTTPBackend` (`rca_common.llmclient.backend`)
needs: `POST /chat/completions`, returning an OpenAI-shaped
`ChatCompletion` body plus the `x-litellm-response-cost` header the
backend reads cost from. No third-party HTTP framework dependency -- built
on `http.server.ThreadingHTTPServer` so it can be embedded directly in a
test process (as a background thread) or run standalone for local/manual
use (`python -m tests.mocks.llm.mock_llm_server`).

Canned responses are keyed by `agent_role` (read from the request's
`metadata.agent_role`, which `LLMClient.generate()` always sends -- Section
7); a scenario without a specific canned response falls back to
`default_response`.

M6 (FP-M6-17) adds a fixture-manifest mode: ``fixture_set`` / ``--fixtures``
loads an ordered list of ``{when, respond, repeat}`` rules from
``fixtures.yaml`` so e2e scenarios ship agent outputs as files, not code.

A canned response may carry ``${name}`` placeholders for values that only
exist at run time -- E4's remediation action has to name the *real* runaway
query id.  Placeholders are filled from values seen in earlier prompts of the
same investigation; an unresolved placeholder is a 400, never a response that
sends a literal ``${query_id}`` downstream (code review round 5, C6: a
playbook that killed a query named ``${query_id}`` verified "successfully"
while the runaway query kept running).
"""
from __future__ import annotations

import argparse
import json
import re
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

PLACEHOLDER_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class UnresolvedPlaceholder(LookupError):
    """A canned response needs a run-time value no prompt has carried yet."""


def harvest_placeholder_values(prompt: str, names: set[str]) -> dict[str, str]:
    """Values for `names` as they appear in a prompt, JSON-encoded.

    Only the exact JSON form ``"name": "value"`` is accepted: prompts embed
    the normalized alert (and its ``labels``) verbatim, and a looser pattern
    would happily pick a value out of prose.
    """
    found: dict[str, str] = {}
    for name in names:
        match = re.search(rf'"{re.escape(name)}"\s*:\s*"([^"]+)"', prompt)
        if match:
            found[name] = match.group(1)
    return found


def fill_placeholders(content: str, values: dict[str, str]) -> str:
    def _replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in values:
            raise UnresolvedPlaceholder(name)
        return values[name]

    return PLACEHOLDER_RE.sub(_replace, content)


@dataclass
class CannedResponse:
    content: str
    input_tokens: int = 10
    output_tokens: int = 5
    cost_usd: float = 0.001


DEFAULT_RESPONSE = CannedResponse(content='{"answer": "ok"}')


@dataclass
class FixtureRule:
    """One fixtures.yaml rule (FP-M6-17)."""

    agent_role: str | None = None
    prompt_contains: str | None = None
    respond_path: str = ""
    content: str = ""
    repeat: int | str = "all"  # int N or "all"
    _hits: int = 0

    def matches(self, agent_role: str | None, prompt: str) -> bool:
        if self.agent_role is not None and self.agent_role != agent_role:
            return False
        if self.prompt_contains is not None and self.prompt_contains not in prompt:
            return False
        if self.repeat != "all":
            try:
                limit = int(self.repeat)
            except (TypeError, ValueError):
                limit = 0
            if self._hits >= limit:
                return False
        return True

    def consume(self) -> CannedResponse:
        self._hits += 1
        return CannedResponse(content=self.content)


def load_fixture_set(fixtures_dir: str | Path) -> list[FixtureRule]:
    """Load fixtures.yaml + response files from a directory."""
    import yaml

    root = Path(fixtures_dir)
    manifest = root / "fixtures.yaml"
    if not manifest.is_file():
        raise FileNotFoundError(f"fixtures.yaml not found in {root}")
    raw = yaml.safe_load(manifest.read_text(encoding="utf-8")) or {}
    rules_raw = raw if isinstance(raw, list) else raw.get("rules") or raw.get("fixtures") or []
    rules: list[FixtureRule] = []
    for entry in rules_raw:
        when = entry.get("when") or {}
        respond = entry.get("respond") or entry.get("response") or ""
        content = ""
        respond_path = ""
        if isinstance(respond, dict):
            content = json.dumps(respond)
        else:
            respond_path = str(respond)
            path = root / respond_path
            if not path.is_file():
                # Also try relative to fixtures/ subdirs.
                path = root / Path(respond_path).name
            if path.is_file():
                content = path.read_text(encoding="utf-8")
            else:
                content = str(respond)
        rules.append(
            FixtureRule(
                agent_role=when.get("agent_role"),
                prompt_contains=when.get("prompt_contains"),
                respond_path=respond_path,
                content=content,
                repeat=entry.get("repeat", "all"),
            )
        )
    return rules


class MockLLMServer:
    """Threaded OpenAI-compatible `/chat/completions` mock.

    Usage as a test fixture::

        server = MockLLMServer(responses={"planner": CannedResponse("...")})
        base_url = server.start()
        ...
        server.stop()

    or as a context manager::

        with MockLLMServer() as server:
            ...  # server.base_url is live

    Fixture-manifest mode (FP-M6-17)::

        with MockLLMServer(fixture_set="tests/e2e/mockllm/fixtures/e1") as server:
            ...
    """

    def __init__(
        self,
        responses: dict[str, CannedResponse] | None = None,
        default_response: CannedResponse = DEFAULT_RESPONSE,
        host: str = "127.0.0.1",
        port: int = 0,
        fixture_set: str | Path | list[FixtureRule] | None = None,
    ):
        self.responses = dict(responses or {})
        self.default_response = default_response
        self.received_requests: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._fixture_rules: list[FixtureRule] = []
        if fixture_set is not None:
            if isinstance(fixture_set, list):
                self._fixture_rules = list(fixture_set)
            else:
                self._fixture_rules = load_fixture_set(fixture_set)
        # Run-time values, per investigation, for the ${...} names the loaded
        # fixtures actually reference.
        self._placeholder_names: set[str] = set()
        for rule in self._fixture_rules:
            self._placeholder_names.update(PLACEHOLDER_RE.findall(rule.content))
        for canned in [*self.responses.values(), self.default_response]:
            self._placeholder_names.update(PLACEHOLDER_RE.findall(canned.content))
        self._seen_values: dict[str, dict[str, str]] = {}
        self._server = ThreadingHTTPServer((host, port), self._make_handler())

    def _resolve_canned(self, body: dict[str, Any]) -> CannedResponse:
        metadata = body.get("metadata") or {}
        agent_role = metadata.get("agent_role")
        messages = body.get("messages") or []
        prompt_parts: list[str] = []
        for m in messages:
            if isinstance(m, dict) and m.get("content"):
                prompt_parts.append(str(m["content"]))
        prompt = "\n".join(prompt_parts)

        if self._placeholder_names:
            key = str(metadata.get("investigation_id") or "")
            values = self._seen_values.setdefault(key, {})
            values.update(harvest_placeholder_values(prompt, self._placeholder_names))
        else:
            values = {}

        canned = self._pick_canned(agent_role, prompt)
        if not PLACEHOLDER_RE.search(canned.content):
            return canned
        return CannedResponse(
            content=fill_placeholders(canned.content, values),
            input_tokens=canned.input_tokens,
            output_tokens=canned.output_tokens,
            cost_usd=canned.cost_usd,
        )

    def _pick_canned(self, agent_role: str | None, prompt: str) -> CannedResponse:
        # Fixture-manifest rules first (ordered).
        for rule in self._fixture_rules:
            if rule.matches(agent_role, prompt):
                return rule.consume()

        # Backward-compatible role map.
        if agent_role in self.responses:
            return self.responses[agent_role]
        return self.default_response

    def _make_handler(self):
        mock_server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                pass  # silence default stdlib access logging

            def do_POST(self) -> None:  # noqa: N802 (stdlib API name)
                if self.path != "/chat/completions":
                    self.send_response(404)
                    self.end_headers()
                    return

                length = int(self.headers.get("Content-Length", 0))
                raw_body = self.rfile.read(length) if length else b"{}"
                body = json.loads(raw_body or b"{}")

                try:
                    with mock_server._lock:
                        mock_server.received_requests.append(body)
                        canned = mock_server._resolve_canned(body)
                except UnresolvedPlaceholder as exc:
                    # Fail loudly rather than sending `${name}` downstream as
                    # if it were a real value.
                    message = json.dumps(
                        {
                            "error": {
                                "message": (
                                    f"mock LLM: no run-time value for ${{{exc.args[0]}}}"
                                    " has appeared in this investigation's prompts"
                                ),
                                "type": "unresolved_placeholder",
                            }
                        }
                    ).encode("utf-8")
                    self.send_response(400)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(message)))
                    self.end_headers()
                    self.wfile.write(message)
                    return

                payload = {
                    "id": "mock-chatcmpl-0",
                    "object": "chat.completion",
                    "model": body.get("model", "mock"),
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": canned.content},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {
                        "prompt_tokens": canned.input_tokens,
                        "completion_tokens": canned.output_tokens,
                        "total_tokens": canned.input_tokens + canned.output_tokens,
                    },
                }
                data = json.dumps(payload).encode("utf-8")

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("x-litellm-response-cost", str(canned.cost_usd))
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        return Handler

    @property
    def base_url(self) -> str:
        host, port = self._server.server_address[:2]
        if host in ("0.0.0.0", "::"):
            host = "127.0.0.1"
        return f"http://{host}:{port}"

    def start(self) -> str:
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self.base_url

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def __enter__(self) -> "MockLLMServer":
        self.start()
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.stop()


def _main() -> None:
    parser = argparse.ArgumentParser(
        description="Standalone mock LLM server for local/manual testing."
    )
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument(
        "--fixtures",
        default=None,
        help="Directory containing fixtures.yaml + response files (FP-M6-17).",
    )
    args = parser.parse_args()

    server = MockLLMServer(host=args.host, port=args.port, fixture_set=args.fixtures)
    url = server.start()
    print(f"mock LLM server listening on {url} (Ctrl+C to stop)")
    stop_event = threading.Event()
    try:
        stop_event.wait()
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()


if __name__ == "__main__":
    _main()
