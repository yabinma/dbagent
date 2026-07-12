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
"""
from __future__ import annotations

import argparse
import json
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


@dataclass
class CannedResponse:
    content: str
    input_tokens: int = 10
    output_tokens: int = 5
    cost_usd: float = 0.001


DEFAULT_RESPONSE = CannedResponse(content='{"answer": "ok"}')


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
    """

    def __init__(
        self,
        responses: dict[str, CannedResponse] | None = None,
        default_response: CannedResponse = DEFAULT_RESPONSE,
        host: str = "127.0.0.1",
        port: int = 0,
    ):
        self.responses = dict(responses or {})
        self.default_response = default_response
        self.received_requests: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._server = ThreadingHTTPServer((host, port), self._make_handler())

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

                with mock_server._lock:
                    mock_server.received_requests.append(body)

                agent_role = (body.get("metadata") or {}).get("agent_role")
                canned = mock_server.responses.get(agent_role, mock_server.default_response)

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
    args = parser.parse_args()

    server = MockLLMServer(host=args.host, port=args.port)
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
