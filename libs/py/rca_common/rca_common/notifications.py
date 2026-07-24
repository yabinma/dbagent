"""Outbound notifications (design.md Section 10.1 / 9.5.3).

Shared by the worker ``send_notifications`` Activity and the dashboard-api
``POST /api/v1/admin/notifications/test`` endpoint.

Formatters:
  * ``format_slack`` — Slack Block Kit
  * ``format_generic`` — Section 10.1 generic JSON

Sender:
  * ``send_to_webhooks`` — per-webhook ``events`` / ``min_severity`` filter,
    up to 3 attempts with exponential backoff, never raises.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# Section 9.5.3 event vocabulary (separate from audit-action enum).
NOTIFICATION_EVENTS = frozenset(
    {
        "approval_requested",
        "case_needs_human",
        "case_resolved",
        "case_rejected",
        "notification_test",  # dashboard test endpoint only
    }
)

_SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "unknown": 0,
}


def severity_at_least(actual: str | None, minimum: str | None) -> bool:
    """Return True if ``actual`` meets or exceeds ``minimum``."""
    a = _SEVERITY_RANK.get((actual or "unknown").lower(), 0)
    m = _SEVERITY_RANK.get((minimum or "low").lower(), 1)
    return a >= m


def format_generic(event: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Section 10.1 generic webhook body."""
    return {
        "event": event,
        "investigation_id": payload.get("investigation_id"),
        "platform_key": payload.get("platform_key"),
        "severity": payload.get("severity") or "unknown",
        "summary": payload.get("summary") or payload.get("rca_compact") or "",
        "dashboard_url": payload.get("dashboard_url") or "",
        "occurred_at": payload.get("occurred_at")
        or datetime.now(timezone.utc).isoformat(),
    }


def format_slack(event: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Slack Block Kit message (Section 10.1)."""
    platform = payload.get("platform_key") or "unknown"
    severity = payload.get("severity") or "unknown"
    title = f"{event} · {platform} · {severity}"
    body = (
        payload.get("summary")
        or payload.get("rca_compact")
        or payload.get("digest")
        or "(no summary)"
    )
    dashboard_url = payload.get("dashboard_url") or ""
    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": title[:150]},
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": str(body)[:3000]},
        },
    ]
    if dashboard_url:
        blocks.append(
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Open in dashboard"},
                        "url": dashboard_url,
                    }
                ],
            }
        )
    return {
        "text": title,
        "blocks": blocks,
    }


def format_payload(fmt: str, event: str, payload: dict[str, Any]) -> dict[str, Any]:
    if (fmt or "generic").lower() == "slack":
        return format_slack(event, payload)
    return format_generic(event, payload)


async def _post_once(
    client: httpx.AsyncClient, url: str, body: dict[str, Any]
) -> tuple[bool, str | None, int | None]:
    try:
        resp = await client.post(url, json=body)
        ok = 200 <= resp.status_code < 300
        return ok, None if ok else f"status {resp.status_code}", resp.status_code
    except Exception as exc:  # noqa: BLE001 — never raise to caller
        return False, str(exc), None


async def send_to_webhooks(
    webhooks: list[dict[str, Any]] | list[Any],
    event: str,
    payload: dict[str, Any],
    *,
    client: httpx.AsyncClient | None = None,
    max_attempts: int = 3,
    base_backoff_seconds: float = 0.05,
) -> list[dict[str, Any]]:
    """POST ``event`` to each matching webhook.

    Filters by ``events`` subscription and ``min_severity``. Retries each
    webhook up to ``max_attempts`` with exponential backoff. Never raises;
    returns a per-target result list.
    """
    owns = client is None
    if client is None:
        client = httpx.AsyncClient(timeout=10.0)
    results: list[dict[str, Any]] = []
    try:
        for wh in webhooks or []:
            if hasattr(wh, "__dict__") and not isinstance(wh, dict):
                # OutboundWebhook dataclass
                name = getattr(wh, "name", "") or getattr(wh, "url", "unknown")
                url = getattr(wh, "url", "") or ""
                fmt = getattr(wh, "format", "generic") or "generic"
                events = list(getattr(wh, "events", None) or [])
                min_sev = getattr(wh, "min_severity", "low") or "low"
            else:
                name = (wh.get("name") if isinstance(wh, dict) else None) or (
                    wh.get("url") if isinstance(wh, dict) else None
                ) or "unknown"
                url = (wh.get("url") if isinstance(wh, dict) else "") or ""
                fmt = (wh.get("format") if isinstance(wh, dict) else "generic") or "generic"
                events = list((wh.get("events") if isinstance(wh, dict) else None) or [])
                min_sev = (wh.get("min_severity") if isinstance(wh, dict) else "low") or "low"

            # Dashboard test event bypasses subscription filter when events empty
            # or when event is notification_test.
            subscribed = (
                not events
                or event in events
                or event == "notification_test"
            )
            sev_ok = severity_at_least(payload.get("severity"), min_sev)
            if not subscribed or not sev_ok:
                results.append(
                    {
                        "name": name,
                        "ok": False,
                        "skipped": True,
                        "reason": "filtered",
                    }
                )
                continue
            if not url:
                results.append({"name": name, "ok": False, "error": "empty url"})
                continue

            body = format_payload(fmt, event, payload)
            last_err: str | None = None
            last_status: int | None = None
            ok = False
            for attempt in range(max_attempts):
                ok, last_err, last_status = await _post_once(client, url, body)
                if ok:
                    break
                if attempt + 1 < max_attempts:
                    await asyncio.sleep(base_backoff_seconds * (2**attempt))
            results.append(
                {
                    "name": name,
                    "ok": ok,
                    "status_code": last_status,
                    "error": last_err,
                    "attempts": attempt + 1,
                }
            )
    finally:
        if owns:
            await client.aclose()
    return results
