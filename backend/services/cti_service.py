"""
backend/services/cti_service.py
==================================
CTI enrichment — VirusTotal + URLhaus.
Hard 400ms wall-clock timeout via asyncio.wait_for at the enrich() level.

Fix for Windows 17s issue:
  - WHOIS removed from this service entirely (too slow, blocks on Windows)
  - CTI_TIMEOUT raised to 3s per individual call but enrich() itself
    is wrapped in a 400ms wait_for in scan.py — so worst case is 400ms
  - If no VT API key, VT is skipped instantly (no network call at all)
  - URLhaus is the only live call when no VT key — it's fast (~100ms)
"""

import os
import base64
import asyncio
import httpx
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY  = os.getenv("VIRUSTOTAL_API_KEY", "")
VT_URL      = "https://www.virustotal.com/api/v3/urls"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/url/"

# Per-request timeout for individual HTTP calls
# The hard 400ms wall is enforced by asyncio.wait_for in enrich()
CTI_TIMEOUT = httpx.Timeout(connect=2.0, read=3.0, write=2.0, pool=1.0)

# Fast fallback results
_VT_SKIP    = {"source": "virustotal", "found": False, "positives": 0,
               "total": 0, "status": "no_api_key"}
_VT_TIMEOUT = {"source": "virustotal", "found": False, "positives": 0,
               "total": 0, "status": "timeout"}
_UH_TIMEOUT = {"source": "urlhaus", "found": False, "listed": False,
               "status": "timeout", "threat": None}
_UH_ERROR   = {"source": "urlhaus", "found": False, "listed": False,
               "status": "error", "threat": None}


async def _check_virustotal(url: str, client: httpx.AsyncClient) -> dict:
    if not VT_API_KEY:
        return _VT_SKIP
    try:
        url_id  = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VT_API_KEY}
        resp    = await client.get(f"{VT_URL}/{url_id}", headers=headers)

        if resp.status_code == 200:
            stats     = (resp.json().get("data", {})
                                    .get("attributes", {})
                                    .get("last_analysis_stats", {}))
            positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
            return {"source": "virustotal", "found": True,
                    "positives": positives, "total": sum(stats.values()),
                    "status": "flagged" if positives > 0 else "clean"}
        elif resp.status_code == 404:
            # Submit for scanning — don't wait for result
            try:
                await asyncio.wait_for(
                    client.post(VT_URL, headers=headers, data={"url": url}),
                    timeout=0.5
                )
            except Exception:
                pass
            return {"source": "virustotal", "found": False, "positives": 0,
                    "total": 0, "status": "submitted"}
        else:
            return {"source": "virustotal", "found": False, "positives": 0,
                    "total": 0, "status": f"http_{resp.status_code}"}

    except (httpx.TimeoutException, asyncio.TimeoutError):
        return _VT_TIMEOUT
    except Exception as e:
        return {"source": "virustotal", "found": False, "positives": 0,
                "total": 0, "status": f"error: {str(e)[:40]}"}


async def _check_urlhaus(url: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.post(URLHAUS_URL, data={"url": url})
        if resp.status_code == 200:
            data = resp.json()
            if data.get("query_status") == "is_listed":
                return {"source": "urlhaus", "found": True, "listed": True,
                        "status": data.get("url_status", "unknown"),
                        "threat": data.get("threat", "unknown")}
            return {"source": "urlhaus", "found": False, "listed": False,
                    "status": "not_listed", "threat": None}
        return {"source": "urlhaus", "found": False, "listed": False,
                "status": f"http_{resp.status_code}", "threat": None}

    except (httpx.TimeoutException, asyncio.TimeoutError):
        return _UH_TIMEOUT
    except Exception:
        return _UH_ERROR


async def enrich(url: str) -> dict:
    """
    Fires VT + URLhaus in parallel.
    Called from scan.py wrapped in asyncio.wait_for(enrich(), timeout=0.4)
    so worst case total time = 400ms regardless of network conditions.
    """
    try:
        async with httpx.AsyncClient(timeout=CTI_TIMEOUT) as client:
            vt_result, uh_result = await asyncio.gather(
                _check_virustotal(url, client),
                _check_urlhaus(url, client),
                return_exceptions=True,
            )

        if isinstance(vt_result, Exception):
            vt_result = _VT_TIMEOUT
        if isinstance(uh_result, Exception):
            uh_result = _UH_ERROR

        return {"virustotal": vt_result, "urlhaus": uh_result}

    except Exception:
        return {"virustotal": _VT_TIMEOUT, "urlhaus": _UH_TIMEOUT}