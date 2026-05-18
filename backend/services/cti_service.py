"""
backend/services/cti_service.py
==================================
CTI enrichment — VirusTotal + URLhaus + PhishTank.
Three sources, all fired in parallel.
Hard 400ms wall-clock limit enforced by asyncio.wait_for in scan.py.

Source priority / what each adds:
  VirusTotal  — ~90 AV engines + reputation DB. Best for malware/phishing.
  URLhaus     — Focused malware distribution URL DB. Real-time, reliable.
  PhishTank   — Human-verified phishing URL DB. ~30k new URLs/day.
                Uses local cache (O(1) lookup) → adds ~0ms latency.
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

CTI_TIMEOUT = httpx.Timeout(connect=2.0, read=3.0, write=2.0, pool=1.0)

# Fast fallback constants
_VT_SKIP    = {"source": "virustotal", "found": False, "positives": 0,
               "total": 0, "status": "no_api_key"}
_VT_TIMEOUT = {"source": "virustotal", "found": False, "positives": 0,
               "total": 0, "status": "timeout"}
_UH_TIMEOUT = {"source": "urlhaus", "found": False, "listed": False,
               "status": "timeout", "threat": None}
_UH_ERROR   = {"source": "urlhaus", "found": False, "listed": False,
               "status": "error",   "threat": None}


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
            return {
                "source":    "virustotal", "found": True,
                "positives": positives, "total": sum(stats.values()),
                "status":    "flagged" if positives > 0 else "clean",
            }
        elif resp.status_code == 404:
            try:
                await asyncio.wait_for(
                    client.post(VT_URL, headers=headers, data={"url": url}),
                    timeout=0.5,
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
                "total": 0, "status": f"error:{str(e)[:40]}"}


async def _check_urlhaus(url: str, client: httpx.AsyncClient) -> dict:
    try:
        resp = await client.post(URLHAUS_URL, data={"url": url})
        if resp.status_code == 200:
            data = resp.json()
            if data.get("query_status") == "is_listed":
                return {
                    "source": "urlhaus", "found": True, "listed": True,
                    "status": data.get("url_status", "unknown"),
                    "threat": data.get("threat", "unknown"),
                }
            return {"source": "urlhaus", "found": False, "listed": False,
                    "status": "not_listed", "threat": None}
        return {"source": "urlhaus", "found": False, "listed": False,
                "status": f"http_{resp.status_code}", "threat": None}

    except (httpx.TimeoutException, asyncio.TimeoutError):
        return _UH_TIMEOUT
    except Exception:
        return _UH_ERROR


async def _check_phishtank(url: str) -> dict:
    """
    PhishTank: local cache lookup (O(1), ~0ms) then API fallback.
    Never blocks even if cache is empty.
    """
    try:
        from services.phishtank_service import check_phishtank
        return await asyncio.wait_for(check_phishtank(url), timeout=0.5)
    except Exception:
        return {"source": "phishtank", "found": False, "verified": False,
                "status": "unavailable"}


async def enrich(url: str) -> dict:
    """
    Fires VirusTotal + URLhaus + PhishTank in parallel.
    Designed to be called from scan.py wrapped in asyncio.wait_for(enrich(), timeout=0.4)
    so total worst-case = 400ms regardless of network.
    """
    try:
        async with httpx.AsyncClient(timeout=CTI_TIMEOUT) as client:
            vt_result, uh_result, pt_result = await asyncio.gather(
                _check_virustotal(url, client),
                _check_urlhaus(url, client),
                _check_phishtank(url),
                return_exceptions=True,
            )

        if isinstance(vt_result, Exception): vt_result = _VT_TIMEOUT
        if isinstance(uh_result, Exception): uh_result = _UH_ERROR
        if isinstance(pt_result, Exception):
            pt_result = {"source": "phishtank", "found": False, "status": "error"}

        return {
            "virustotal": vt_result,
            "urlhaus":    uh_result,
            "phishtank":  pt_result,
        }

    except Exception:
        return {
            "virustotal": _VT_TIMEOUT,
            "urlhaus":    _UH_TIMEOUT,
            "phishtank":  {"source": "phishtank", "found": False, "status": "error"},
        }
