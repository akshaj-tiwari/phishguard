"""
backend/routers/scan.py
=========================
POST /scan  — main analysis endpoint
GET  /history — paginated scan history
GET  /stats   — dashboard aggregate stats

Fix for Windows 17s response time:
  - WHOIS removed from the hot path (it's a blocking call that ignores
    asyncio cancellation on Windows). WHOIS data still saved if available
    from a background best-effort call.
  - CTI wrapped in asyncio.wait_for with 400ms hard wall clock limit.
  - DNS A record lookup also capped at 400ms.
  - ML inference is synchronous but takes <10ms so it's fine inline.
"""

import asyncio
import time
from datetime import datetime
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from db.database import get_db
from db import crud
from db.schemas import (
    ScanRequest, ScanResponse, HistoryResponse, StatsResponse,
    ScanSummary, CTIResult, WHOISResult, VirusTotalResult,
    URLhausResult, FeatureInfo,
)
from services.feature_extractor import FeatureExtractor
from services.model_service import predict
from services import cti_service, dns_service

router     = APIRouter()
_extractor = FeatureExtractor()

# Disable live DNS/WHOIS in feature extractor (training already did this;
# re-patching here avoids a 15s WHOIS call inside feature extraction too)
_extractor._get_domain_age = lambda domain: -1
_extractor._has_mx_record  = lambda domain: False


def _parse_domain(url: str) -> str:
    try:
        return urlparse(url).netloc.split(":")[0]
    except Exception:
        return ""


# ── Fallback CTI result when timeout hits ─────────────────────────────────
_CTI_FALLBACK = {
    "virustotal": {"source": "virustotal", "found": False,
                   "positives": 0, "total": 0, "status": "timeout"},
    "urlhaus":    {"source": "urlhaus", "found": False,
                   "listed": False, "status": "timeout", "threat": None},
}


@router.post("/scan", response_model=ScanResponse, tags=["Scanning"])
async def scan_url(body: ScanRequest, db: Session = Depends(get_db)):
    """
    Full phishing analysis pipeline. Target: <500ms.

    Pipeline:
      1. Normalise + validate URL
      2. Feature extraction (~1ms)
      3. ML inference (~5ms)
      4. CTI: VirusTotal + URLhaus in parallel (capped at 400ms)
      5. DNS A record lookup (capped at 400ms, runs parallel with CTI)
      6. Merge + persist to DB
      7. Return threat report

    WHOIS is intentionally excluded from the hot path — it's a blocking
    synchronous call that takes 5-15s and cannot be reliably cancelled
    on Windows. The dashboard report page can show WHOIS data separately.
    """
    start = time.perf_counter()

    # ── 1. Normalise URL ───────────────────────────────────────────────────
    url = body.url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    if len(url) > 2000:
        raise HTTPException(status_code=422, detail="URL too long (max 2000 chars)")

    domain = _parse_domain(url)
    if not domain:
        raise HTTPException(status_code=422, detail="Could not parse domain from URL")

    # ── 2. Feature extraction ─────────────────────────────────────────────
    try:
        features = _extractor.extract(url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Feature extraction failed: {e}")

    t_features = (time.perf_counter() - start) * 1000

    # ── 3. ML inference ───────────────────────────────────────────────────
    try:
        ml_result = predict(url, features)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Model inference failed: {e}")

    risk_score = ml_result["risk_score"]
    verdict    = ml_result["verdict"]
    t_ml       = (time.perf_counter() - start) * 1000

    # ── 4+5. CTI + DNS in parallel, both capped at 400ms ──────────────────

    async def run_cti():
        try:
            return await asyncio.wait_for(cti_service.enrich(url), timeout=0.4)
        except (asyncio.TimeoutError, Exception):
            return _CTI_FALLBACK

    async def run_dns_a():
        loop = asyncio.get_event_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, dns_service.get_a_records, domain),
                timeout=0.4,
            )
        except (asyncio.TimeoutError, Exception):
            return []

    cti_raw, a_records = await asyncio.gather(run_cti(), run_dns_a())

    t_cti = (time.perf_counter() - start) * 1000

    # ── 5. Boost score if CTI confirms threat ─────────────────────────────
    if cti_raw:
        vt_hits   = cti_raw.get("virustotal", {}).get("positives", 0)
        uh_listed = cti_raw.get("urlhaus", {}).get("listed", False)
        if vt_hits > 5:
            risk_score = min(100.0, risk_score + 15.0)
        if uh_listed:
            risk_score = min(100.0, risk_score + 10.0)
        if risk_score >= 70:
            verdict = "phishing"
        elif risk_score >= 30:
            verdict = "suspicious"

    # ── 6. Build response objects ──────────────────────────────────────────
    cti_response = None
    if cti_raw:
        vt = cti_raw.get("virustotal", {})
        uh = cti_raw.get("urlhaus", {})
        cti_response = CTIResult(
            virustotal=VirusTotalResult(
                found     = vt.get("found", False),
                positives = vt.get("positives", 0),
                total     = vt.get("total", 0),
                status    = vt.get("status", "unknown"),
            ),
            urlhaus=URLhausResult(
                found  = uh.get("found", False),
                listed = uh.get("listed", False),
                status = uh.get("status", "unknown"),
                threat = uh.get("threat"),
            ),
        )

    # WHOIS placeholder — not fetched in hot path (too slow on Windows)
    whois_response = WHOISResult(
        domain_age_days = None,
        registrar       = None,
        country         = None,
        creation_date   = None,
        is_new_domain   = False,
        a_records       = a_records or [],
        has_mx_record   = False,
    )

    top_features = [FeatureInfo(**f) for f in ml_result.get("top_features", [])]

    # ── 7. Persist to DB ──────────────────────────────────────────────────
    scan = crud.create_scan(
        db           = db,
        url          = url,
        verdict      = verdict,
        risk_score   = round(risk_score, 2),
        features     = features,
        cti_result   = cti_raw or {},
        whois_result = {"a_records": a_records or []},
    )

    elapsed = (time.perf_counter() - start) * 1000
    print(f"[{elapsed:.0f}ms total | feat={t_features:.0f}ms ml={t_ml:.0f}ms cti={t_cti:.0f}ms] "
          f"{verdict.upper()} ({risk_score:.1f}) — {url[:70]}")

    return ScanResponse(
        scan_id      = str(scan.id),
        url          = url,
        verdict      = verdict,
        risk_score   = round(risk_score, 2),
        top_features = top_features,
        cti          = cti_response,
        whois        = whois_response,
        timestamp    = scan.created_at.isoformat(),
    )


@router.get("/history", response_model=HistoryResponse, tags=["History"])
def get_history(
    page:    int        = Query(1, ge=1),
    limit:   int        = Query(50, le=200),
    verdict: str | None = Query(None, description="phishing|suspicious|benign"),
    db:      Session    = Depends(get_db),
):
    scans, total = crud.get_history(db, page=page, limit=limit, verdict=verdict)
    return HistoryResponse(
        total = total,
        page  = page,
        limit = limit,
        scans = [
            ScanSummary(
                scan_id    = str(s.id),
                url        = s.url,
                verdict    = s.verdict or "unknown",
                risk_score = s.risk_score or 0.0,
                timestamp  = s.created_at.isoformat() if s.created_at else "",
            )
            for s in scans
        ],
    )


@router.get("/stats", response_model=StatsResponse, tags=["Stats"])
def get_stats(db: Session = Depends(get_db)):
    return StatsResponse(**crud.get_stats(db))