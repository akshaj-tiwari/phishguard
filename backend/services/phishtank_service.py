"""
backend/services/phishtank_service.py
=======================================
PhishTank live feed integration.

PhishTank maintains a verified, daily-updated database of phishing URLs.
This module provides two lookup mechanisms:

  1. Local cache (phishtank_db.json) — fast O(1) lookup, refreshed daily.
     File is ~15MB compressed. Download once, lookup thousands of times.

  2. Online API — direct lookup for real-time verification.
     Requires free API key from phishtank.org (anonymous = 20 req/min).

Usage:
  from services.phishtank_service import check_phishtank

  result = await check_phishtank("http://evil.tk/login")
  # {
  #   "source": "phishtank",
  #   "found": True,
  #   "verified": True,
  #   "phish_id": "8923741",
  #   "submission_time": "2024-01-15T10:22:00Z",
  #   "verified_at": "2024-01-15T10:45:00Z",
  #   "target": "PayPal",
  #   "status": "online",
  # }

Cache refresh:
  python -c "from services.phishtank_service import refresh_cache; import asyncio; asyncio.run(refresh_cache())"

Or it auto-refreshes in background every 24h when the API is running.
"""

import os
import json
import asyncio
import hashlib
import time
import logging
from datetime import datetime, timedelta
from typing import Optional

import httpx
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger("phishtank")

# ── Config ─────────────────────────────────────────────────────────────────
PT_API_KEY       = os.getenv("PHISHTANK_API_KEY", "")  # "" = anonymous (rate-limited)
PT_API_URL       = "https://checkurl.phishtank.com/checkurl/"
PT_FEED_URL      = "http://data.phishtank.com/data/{key}/online-valid.json.bz2"
PT_ANON_FEED_URL = "http://data.phishtank.com/data/online-valid.json.bz2"

BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE_PATH  = os.path.join(BASE_DIR, "models", "phishtank_db.json")
CACHE_META  = os.path.join(BASE_DIR, "models", "phishtank_meta.json")

CACHE_TTL_HOURS = 24     # Refresh the local cache every 24h
API_TIMEOUT     = 3.0    # Max 3s for a single API check
MAX_CACHE_URLS  = 500_000  # Cap memory usage

# In-memory cache: url_hash -> record dict
_url_cache: dict[str, dict] = {}
_cache_loaded_at: float     = 0.0


# ══════════════════════════════════════════════════════════════════════════
# CACHE MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════

def _url_hash(url: str) -> str:
    """Normalise and hash URL for O(1) lookup."""
    url = url.strip().lower().rstrip("/")
    return hashlib.sha256(url.encode()).hexdigest()


def load_cache() -> bool:
    """
    Loads the local PhishTank JSON cache into memory.
    Returns True if cache loaded successfully, False if missing/stale.
    """
    global _url_cache, _cache_loaded_at

    if not os.path.exists(CACHE_PATH):
        logger.info("PhishTank cache not found. Run refresh_cache() to download.")
        return False

    # Check if cache is stale
    if os.path.exists(CACHE_META):
        try:
            with open(CACHE_META) as f:
                meta = json.load(f)
            refreshed_at = datetime.fromisoformat(meta.get("refreshed_at", "2000-01-01"))
            age_hours    = (datetime.utcnow() - refreshed_at).total_seconds() / 3600
            if age_hours > CACHE_TTL_HOURS:
                logger.info(f"PhishTank cache is {age_hours:.1f}h old (TTL={CACHE_TTL_HOURS}h). Will refresh.")
        except Exception:
            pass

    try:
        with open(CACHE_PATH) as f:
            data = json.load(f)

        _url_cache = {}
        for entry in data[:MAX_CACHE_URLS]:
            url   = entry.get("url", "")
            if not url:
                continue
            h = _url_hash(url)
            _url_cache[h] = {
                "phish_id":        entry.get("phish_id", ""),
                "submission_time": entry.get("submission_time", ""),
                "verified":        entry.get("verified", False),
                "verified_at":     entry.get("verified_at"),
                "target":          entry.get("target", ""),
                "url_status":      entry.get("url_status", ""),
            }

        _cache_loaded_at = time.time()
        logger.info(f"PhishTank cache loaded: {len(_url_cache):,} URLs")
        return True

    except Exception as e:
        logger.error(f"PhishTank cache load failed: {e}")
        return False


async def refresh_cache():
    """
    Downloads the latest PhishTank verified phishing URL database.
    Saves to CACHE_PATH. Runs in ~20s depending on connection speed.
    Call this once a day (auto-scheduled in main.py startup).
    """
    import bz2

    url = PT_FEED_URL.format(key=PT_API_KEY) if PT_API_KEY else PT_ANON_FEED_URL
    logger.info(f"Refreshing PhishTank cache from {url}")

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(60.0)) as client:
            resp = await client.get(url)
            resp.raise_for_status()

        # Decompress bz2 and parse JSON
        raw_json = bz2.decompress(resp.content).decode("utf-8", errors="replace")
        entries  = json.loads(raw_json)

        # Save raw JSON (not bz2) for fast loading next time
        with open(CACHE_PATH, "w") as f:
            json.dump(entries, f)

        with open(CACHE_META, "w") as f:
            json.dump({
                "refreshed_at": datetime.utcnow().isoformat(),
                "count":        len(entries),
                "source":       url,
            }, f)

        load_cache()
        logger.info(f"PhishTank cache refreshed: {len(entries):,} phishing URLs")
        return True

    except Exception as e:
        logger.error(f"PhishTank cache refresh failed: {e}")
        return False


# ══════════════════════════════════════════════════════════════════════════
# LOOKUP
# ══════════════════════════════════════════════════════════════════════════

_NOT_FOUND = {
    "source": "phishtank", "found": False, "verified": False,
    "phish_id": None, "submission_time": None, "verified_at": None,
    "target": None, "status": "not_listed",
}
_TIMEOUT   = {**_NOT_FOUND, "status": "timeout"}
_ERROR     = {**_NOT_FOUND, "status": "error"}


def _cache_lookup(url: str) -> Optional[dict]:
    """O(1) local cache lookup. Returns None if not found."""
    if not _url_cache:
        return None
    h = _url_hash(url)
    record = _url_cache.get(h)
    if not record:
        return None
    return {
        "source":          "phishtank",
        "found":           True,
        "verified":        record.get("verified", False),
        "phish_id":        record.get("phish_id"),
        "submission_time": record.get("submission_time"),
        "verified_at":     record.get("verified_at"),
        "target":          record.get("target"),
        "status":          record.get("url_status", "listed"),
    }


async def _api_lookup(url: str) -> dict:
    """
    Direct PhishTank API lookup for URLs not in local cache.
    Rate limits: anonymous=20/min, registered key=unlimited.
    """
    if not PT_API_KEY:
        # Anonymous lookups are severely rate-limited — skip to avoid 429s
        return _NOT_FOUND

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(API_TIMEOUT)) as client:
            resp = await client.post(PT_API_URL, data={
                "url":    url,
                "format": "json",
                "app_key": PT_API_KEY,
            })

        if resp.status_code == 200:
            data    = resp.json()
            results = data.get("results", {})
            in_db   = results.get("in_database", False)
            if in_db:
                entry = results.get("phish_detail", {}) or results
                return {
                    "source":          "phishtank",
                    "found":           True,
                    "verified":        results.get("verified", False),
                    "phish_id":        results.get("phish_id"),
                    "submission_time": entry.get("submission_time"),
                    "verified_at":     entry.get("verification_time"),
                    "target":          entry.get("target"),
                    "status":          "online" if results.get("valid") else "offline",
                }
            return _NOT_FOUND
        return _NOT_FOUND

    except (httpx.TimeoutException, asyncio.TimeoutError):
        return _TIMEOUT
    except Exception:
        return _ERROR


async def check_phishtank(url: str) -> dict:
    """
    Main entry point. Checks local cache first (fast), falls back to API.
    Designed to be called from cti_service.enrich() with a timeout wrapper.
    """
    # 1. Try local cache (microseconds)
    cached = _cache_lookup(url)
    if cached is not None:
        return cached

    # 2. Try online API (slower, rate-limited)
    return await _api_lookup(url)


# ══════════════════════════════════════════════════════════════════════════
# AUTO-REFRESH SCHEDULER
# ══════════════════════════════════════════════════════════════════════════

async def schedule_daily_refresh():
    """
    Background task that refreshes the PhishTank cache every 24h.
    Called from main.py startup as asyncio.create_task().
    """
    # Initial load from disk (fast)
    load_cache()

    while True:
        await asyncio.sleep(CACHE_TTL_HOURS * 3600)
        logger.info("Scheduled PhishTank cache refresh starting...")
        await refresh_cache()
