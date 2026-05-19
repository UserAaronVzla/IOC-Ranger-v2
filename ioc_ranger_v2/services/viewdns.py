from __future__ import annotations

import httpx

BASE = "https://api.viewdns.info"


async def check_email(client: httpx.AsyncClient, api_key: str, email: str) -> dict:
    domain = email.split("@")[1]
    result: dict = {"viewdns_reputation": None, "viewdns_shared_mx": None}

    # Email Reputation
    try:
        r = await client.get(
            f"{BASE}/emailrep/",
            params={"domain": domain, "apikey": api_key, "output": "json"},
            timeout=30,
        )
        r.raise_for_status()
        rep = r.json().get("response") or {}
        result["viewdns_reputation"] = rep.get("result") or rep.get("reputation") or rep.get("score")
    except httpx.HTTPError:
        pass

    # MX Lookup → Reverse MX
    try:
        mx_r = await client.get(
            f"{BASE}/mxlookup/",
            params={"domain": domain, "apikey": api_key, "output": "json"},
            timeout=30,
        )
        mx_r.raise_for_status()
        mx_list = (mx_r.json().get("response") or {}).get("mx") or []
        if mx_list:
            mx_host = mx_list[0].get("name", "")
            if mx_host:
                rev_r = await client.get(
                    f"{BASE}/reversemx/",
                    params={"mx": mx_host, "apikey": api_key, "output": "json"},
                    timeout=30,
                )
                rev_r.raise_for_status()
                domains = (rev_r.json().get("response") or {}).get("domains") or []
                result["viewdns_shared_mx"] = len(domains)
    except httpx.HTTPError:
        pass

    return result
