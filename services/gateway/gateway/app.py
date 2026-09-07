"""FastAPI app for ingest-gateway (design.md Section 4.1)."""
from __future__ import annotations

import json
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request, Response

from gateway.hmac_auth import HMACAuthError, resolve_source_secret, verify_signature
from gateway.ingest import IngestService


def create_app(
    *,
    ingest_service: IngestService,
    source_secrets: dict[str, str],
) -> FastAPI:
    app = FastAPI(title="rca-ingest-gateway", version="0.1.0")
    app.state.ingest_service = ingest_service
    app.state.source_secrets = source_secrets

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/v1/events")
    async def post_events(
        request: Request,
        x_signature: str | None = Header(default=None, alias="X-Signature"),
        x_alert_source: str | None = Header(default=None, alias="X-Alert-Source"),
    ) -> Response:
        body = await request.body()
        try:
            raw: dict[str, Any] = json.loads(body.decode("utf-8") or "{}")
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=400, detail=f"invalid JSON: {exc}") from exc

        source = raw.get("source") or x_alert_source
        try:
            secret = resolve_source_secret(app.state.source_secrets, source=source)
            verify_signature(body, signature_header=x_signature, secret=secret)
        except HMACAuthError as exc:
            raise HTTPException(status_code=401, detail=exc.reason) from exc

        # Ensure source is present for normalization after header-only auth.
        if not raw.get("source") and source:
            raw = {**raw, "source": source}

        status_code, payload = await app.state.ingest_service.ingest(raw)
        return Response(
            content=json.dumps(payload),
            status_code=status_code,
            media_type="application/json",
        )

    return app
