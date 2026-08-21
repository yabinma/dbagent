"""FP-IG-33: beyond-ceiling shed is legible and the in-budget population survives."""
from __future__ import annotations

import socket
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn
import yaml

from gateway.main import BACKLOG, build_app

REPO_ROOT = Path(__file__).resolve().parents[2]


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _write_gateway_config(path: Path) -> None:
    path.write_text(
        yaml.safe_dump(
            {
                "temporal": {
                    "address": "localhost:7233",
                    "namespace": "default",
                    "task_queue": "t",
                },
                "storage": {"postgres_dsn": "sqlite:///:memory:"},
                "model_gateway": {"url": "http://127.0.0.1:9", "master_key": "k"},
                "probe_gateway": {"url": "http://127.0.0.1:9"},
                "signing": {"key_path": "/tmp/nope", "rotation_grace_seconds": 600},
                "dashboard": {"jwt_secret": "j", "cors_origins": [], "bootstrap_ca_cert_path": ""},
                "notifications": {"outbound_webhooks": []},
                "ingest": {
                    "sources": [{"name": "manual", "secret": "s"}],
                    "correlation_window_seconds": 1800,
                },
                "budget_defaults": {
                    "max_rounds": 15,
                    "max_cost_usd": 10.0,
                    "max_wall_seconds": 1800,
                },
                "agents": {},
                "tracing": {"backend": "builtin"},
            }
        )
    )


def _build_test_app(config_path: str):
    app, _config, service = build_app(config_path)

    class Stub:
        async def start_investigation(self, event, investigation_id):
            return f"investigation-{investigation_id}"

    @app.on_event("startup")
    async def _attach_stub() -> None:
        service._workflow_starter = Stub()

    return app


def _http_exchange(sock: socket.socket, *, host: str, port: int, path: str = "/healthz") -> tuple[int, dict[str, str]]:
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
    )
    sock.sendall(req.encode("ascii"))
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    header_blob, _, rest = buf.partition(b"\r\n\r\n")
    lines = header_blob.split(b"\r\n")
    status = int(lines[0].split()[1])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if b":" in line:
            key, value = line.split(b":", 1)
            headers[key.decode().lower()] = value.strip().decode()
    body = rest
    if "content-length" in headers:
        need = int(headers["content-length"]) - len(body)
        while need > 0:
            chunk = sock.recv(need)
            if not chunk:
                break
            body += chunk
            need -= len(chunk)
    return status, headers


def _socket_closed(sock: socket.socket, *, timeout: float = 2.0) -> bool:
    sock.settimeout(timeout)
    try:
        return sock.recv(4096) == b""
    except (TimeoutError, socket.timeout):
        return False


def _wait_until_healthy(url: str, *, timeout: float = 15.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if httpx.get(url, timeout=1.0).status_code == 200:
                return
        except Exception:
            time.sleep(0.05)
    raise RuntimeError(f"server never became healthy at {url}")


@pytest.fixture
def gateway_ceiling_server(tmp_path, monkeypatch):
    cfg = tmp_path / "config.yaml"
    _write_gateway_config(cfg)
    monkeypatch.setenv("DBAGENT_GATEWAY_CONFIG", str(cfg))

    host = "127.0.0.1"
    port = _free_port()
    ceiling = 8
    keepalive_s = 1
    app = _build_test_app(str(cfg))
    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        workers=1,
        limit_concurrency=ceiling,
        timeout_keep_alive=keepalive_s,
        backlog=BACKLOG,
        log_level="warning",
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    health = f"http://{host}:{port}/healthz"
    _wait_until_healthy(health)
    yield host, port, ceiling, keepalive_s
    server.should_exit = True
    thread.join(timeout=5)


def test_beyond_ceiling_sheds_while_in_budget_connections_serve(gateway_ceiling_server):
    """FP-IG-33: N−1 held keepalives serve; census=N sheds; recovery by idle expiry."""
    host, port, ceiling, keepalive_s = gateway_ceiling_server
    held: list[socket.socket] = []
    refused: socket.socket | None = None
    try:
        for _ in range(ceiling - 1):
            sock = socket.create_connection((host, port))
            status, _headers = _http_exchange(sock, host=host, port=port)
            assert status == 200
            held.append(sock)

        refused = socket.create_connection((host, port))
        status, headers = _http_exchange(refused, host=host, port=port)
        assert status == 503, "census=N request must shed with 503"
        assert headers.get("connection", "").lower() == "close"
        assert _socket_closed(refused), "refused socket must close before in-budget probe"

        status, _headers = _http_exchange(held[0], host=host, port=port)
        assert status == 200, "in-budget held connection must still serve after shed"

        # Before idle expiry a fresh connection still hits the ceiling.
        pre_expiry = socket.create_connection((host, port))
        try:
            pre_status, _ = _http_exchange(pre_expiry, host=host, port=port)
            assert pre_status == 503
        finally:
            pre_expiry.close()

        time.sleep(keepalive_s + 0.5)
        recovered = socket.create_connection((host, port))
        try:
            rec_status, _ = _http_exchange(recovered, host=host, port=port)
            assert rec_status == 200, "idle expiry must drain the budget without restart"
        finally:
            recovered.close()
    finally:
        if refused is not None:
            refused.close()
        for sock in held:
            sock.close()
