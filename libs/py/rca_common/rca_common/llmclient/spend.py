"""Model-gateway spend accounting (design.md Section 7):
`GET /spend?investigation_id=` backs the workflow's pre-round budget check
(Section 5.2 `get_spend` Activity, built in M3). Exposed here so the
worker's future Activity is a thin call-through.
"""
from __future__ import annotations

import httpx


async def get_investigation_spend(
    *, base_url: str, master_key: str, investigation_id: str, client: httpx.AsyncClient | None = None
) -> float:
    owns_client = client is None
    client = client or httpx.AsyncClient()
    try:
        resp = await client.get(
            f"{base_url.rstrip('/')}/spend",
            params={"investigation_id": investigation_id},
            headers={"Authorization": f"Bearer {master_key}"},
            timeout=30.0,
        )
        resp.raise_for_status()
        data = resp.json()
        return float(data.get("spend", 0.0))
    finally:
        if owns_client:
            await client.aclose()
