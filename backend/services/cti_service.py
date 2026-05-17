"""
backend/services/cti_service.py
==================================
Cyber Threat Intelligence enrichment.
Uses httpx (plan spec) with 400ms timeout.
VirusTotal + URLhaus fired in parallel via asyncio.gather().
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

# 400ms timeout as specified in the plan
CTI_TIMEOUT = 0.4


async def _check_virustotal(url: str, client: httpx.AsyncClient) -> dict:
    """
    VirusTotal v3 API.
    Returns number of engines that flagged the URL as malicious.
    Rate limit: 4 req/min on free tier.
    """
    if not VT_API_KEY:
        return {"source": "virustotal", "found": False, "positives": 0,
                "total": 0, "status": "no_api_key"}

    try:
        # VT v3: URL must be base64url-encoded without padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VT_API_KEY}

        resp = await client.get(f"{VT_URL}/{url_id}", headers=headers)

        if resp.status_code == 200:
            data  = resp.json()
            stats = (data.get("data", {})
                        .get("attributes", {})
                        .get("last_analysis_stats", {}))
            positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
            total     = sum(stats.values())
            return {
                "source":    "virustotal",
                "found":     True,
                "positives": positives,
                "total":     total,
                "status":    "flagged" if positives > 0 else "clean",
            }
        elif resp.status_code == 404:
            # URL not in VT yet — submit it (fire and forget)
            await client.post(VT_URL, headers=headers, data={"url": url})
            return {"source": "virustotal", "found": False, "positives": 0,
                    "total": 0, "status": "submitted"}
        else:
            return {"source": "virustotal", "found": False, "positives": 0,
                    "total": 0, "status": f"http_{resp.status_code}"}

    except httpx.TimeoutException:
        return {"source": "virustotal", "found": False, "positives": 0,
                "total": 0, "status": "timeout"}
    except Exception as e:
        return {"source": "virustotal", "found": False, "positives": 0,
                "total": 0, "status": f"error: {str(e)[:60]}"}


async def _check_urlhaus(url: str, client: httpx.AsyncClient) -> dict:
    """
    URLhaus API — free, no key needed.
    Checks if URL is in the malware/phishing database.
    """
    try:
        resp = await client.post(URLHAUS_URL, data={"url": url})

        if resp.status_code == 200:
            data         = resp.json()
            query_status = data.get("query_status", "")
            if query_status == "is_listed":
                return {
                    "source":  "urlhaus",
                    "found":   True,
                    "status":  data.get("url_status", "unknown"),
                    "threat":  data.get("threat", "unknown"),
                    "listed":  True,
                }
            else:
                return {"source": "urlhaus", "found": False,
                        "status": "not_listed", "threat": None, "listed": False}
        else:
            return {"source": "urlhaus", "found": False,
                    "status": f"http_{resp.status_code}", "threat": None, "listed": False}

    except httpx.TimeoutException:
        return {"source": "urlhaus", "found": False,
                "status": "timeout", "threat": None, "listed": False}
    except Exception as e:
        return {"source": "urlhaus", "found": False,
                "status": f"error: {str(e)[:60]}", "threat": None, "listed": False}


async def enrich(url: str) -> dict:
    """
    Main entry point. Fires VT + URLhaus in parallel.
    400ms hard timeout — falls back gracefully if APIs are slow.
    Returns merged CTI dict.
    """
    async with httpx.AsyncClient(timeout=CTI_TIMEOUT) as client:
        vt_task  = _check_virustotal(url, client)
        uh_task  = _check_urlhaus(url, client)
        results  = await asyncio.gather(vt_task, uh_task, return_exceptions=True)

    vt_result = results[0] if not isinstance(results[0], Exception) else {
        "source": "virustotal", "found": False, "positives": 0,
        "total": 0, "status": "exception"
    }
    uh_result = results[1] if not isinstance(results[1], Exception) else {
        "source": "urlhaus", "found": False, "status": "exception",
        "threat": None, "listed": False
    }

    return {
        "virustotal": vt_result,
        "urlhaus":    uh_result,
    }
