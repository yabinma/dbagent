"""Unit tests for rca_common.notifications (FP-M5-10)."""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

import pytest

from rca_common.notifications import (
    REDACTION_PLACEHOLDER,
    format_generic,
    format_slack,
    sanitize_payload,
    sanitize_string,
    send_to_webhooks,
    severity_at_least,
)


def test_format_generic_shape():
    body = format_generic(
        "case_resolved",
        {
            "investigation_id": "i1",
            "platform_key": "p1",
            "severity": "high",
            "summary": "fixed",
            "digest": "playbook-x",
            "dashboard_url": "http://d/cases/i1",
        },
    )
    assert body["event"] == "case_resolved"
    assert body["platform_key"] == "p1"
    assert body["summary"] == "fixed"
    assert body["digest"] == "playbook-x"
    assert "occurred_at" in body


def test_sanitize_string_redacts_password_pairs_and_userinfo():
    """C3: marker-bearing subject digests must not leave the control plane."""
    raw = (
        "connection-url=jdbc:hive2://x?password=REDACT_SENTINEL_secret "
        "and scheme://user:hunter2@host/db"
    )
    out = sanitize_string(raw)
    assert "REDACT_SENTINEL_secret" not in out
    assert "hunter2" not in out
    assert REDACTION_PLACEHOLDER in out
    assert "password=" in out

    url = "jdbc:hive2://user:supersecret@host/db"
    red = sanitize_string(url)
    assert "supersecret" not in red
    assert REDACTION_PLACEHOLDER in red


def test_sanitize_payload_and_format_generic_carry_digest():
    payload = {
        "summary": "approval: password=s3cret",
        "digest": "password=SECRET_MARKER",
        "nested": {"token": "token=abc123"},
        "list": ["api_key=zz"],
    }
    out = sanitize_payload(payload)
    blob = json.dumps(out)
    assert "s3cret" not in blob
    assert "SECRET_MARKER" not in blob
    assert "abc123" not in blob
    assert "zz" not in blob
    assert blob.count(REDACTION_PLACEHOLDER) >= 3
    body = format_generic("approval_requested", out)
    assert body["digest"] == out["digest"]
    assert REDACTION_PLACEHOLDER in body["summary"]
    assert "SECRET_MARKER" not in json.dumps(body)


def test_format_slack_block_kit():
    body = format_slack(
        "approval_requested",
        {
            "platform_key": "p1",
            "severity": "critical",
            "summary": "need approve",
            "dashboard_url": "http://d/x",
        },
    )
    assert "blocks" in body
    assert body["blocks"][0]["type"] == "header"
    assert any(b.get("type") == "actions" for b in body["blocks"])


def test_severity_filter():
    assert severity_at_least("high", "low")
    assert not severity_at_least("low", "high")
    assert severity_at_least("critical", "high")


class _Handler(BaseHTTPRequestHandler):
    hits: list = []
    fail_times: int = 0

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        type(self).hits.append(body)
        if len(type(self).hits) <= type(self).fail_times:
            self.send_response(500)
            self.end_headers()
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):  # silence
        return


@pytest.mark.asyncio
async def test_send_to_webhooks_filters_and_retries():
    _Handler.hits = []
    _Handler.fail_times = 2  # first 2 fail → 3rd succeeds
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{port}/hook"
        webhooks = [
            {
                "name": "slack",
                "url": url,
                "format": "slack",
                "events": ["case_resolved", "approval_requested"],
                "min_severity": "medium",
            },
            {
                "name": "filtered-event",
                "url": url,
                "format": "generic",
                "events": ["case_rejected"],
                "min_severity": "low",
            },
            {
                "name": "filtered-sev",
                "url": url,
                "format": "generic",
                "events": ["case_resolved"],
                "min_severity": "critical",
            },
        ]
        results = await send_to_webhooks(
            webhooks,
            "case_resolved",
            {
                "investigation_id": "i1",
                "platform_key": "p1",
                "severity": "high",
                "summary": "done",
            },
            base_backoff_seconds=0.01,
        )
        assert results[0]["ok"] is True
        assert results[0]["attempts"] == 3
        assert results[1].get("skipped") is True
        assert results[2].get("skipped") is True
        assert len(_Handler.hits) == 3  # only slack, 3 attempts
    finally:
        server.shutdown()


@pytest.mark.asyncio
async def test_send_to_webhooks_sanitizes_marker_bearing_digest():
    """Round 7 C3: free-form digest with password= must be redacted in flight."""
    _Handler.hits = []
    _Handler.fail_times = 0
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        marker = "REDACT_SENTINEL_e2e_password_value"
        results = await send_to_webhooks(
            [
                {
                    "name": "generic",
                    "url": f"http://127.0.0.1:{port}/hook",
                    "format": "generic",
                    "events": ["approval_requested"],
                    "min_severity": "low",
                }
            ],
            "approval_requested",
            {
                "investigation_id": "inv-e2",
                "platform_key": "p1",
                "severity": "high",
                "summary": f"remediation approval requested: password={marker}",
                "digest": f"password={marker}",
            },
            base_backoff_seconds=0.01,
            max_attempts=1,
        )
        assert results[0]["ok"] is True
        assert len(_Handler.hits) == 1
        body = _Handler.hits[0].decode("utf-8")
        assert marker not in body
        assert REDACTION_PLACEHOLDER in body
        assert "inv-e2" in body
    finally:
        server.shutdown()
