from __future__ import annotations

import httpx

BASE = "https://api.hunter.io/v2"


async def verify_email(client: httpx.AsyncClient, api_key: str, email: str) -> dict:
    r = await client.get(
        f"{BASE}/email-verifier",
        params={"email": email, "api_key": api_key},
        timeout=30,
    )
    r.raise_for_status()
    data = r.json().get("data") or {}
    return {
        "hunter_result": data.get("result"),
        "hunter_score": data.get("score"),
        "disposable": data.get("disposable"),
        "webmail": data.get("webmail"),
        "mx_records": data.get("mx_records"),
    }
