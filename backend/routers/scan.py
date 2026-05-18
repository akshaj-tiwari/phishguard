"""
backend/routers/scan.py
=========================
POST /scan        — full phishing analysis pipeline
GET  /scan/{id}   — detailed single scan lookup (NEW)
GET  /history     — paginated scan history with verdict filter
GET  /stats       — dashboard aggregate stats

Pipeline timing targets:
  Feature extraction : ~1ms
  ML inference       : ~5ms
  CTI (VT+URLhaus)   : capped at 400ms
  DNS A record       : capped at 400ms (parallel with CTI)
  WHOIS              : background task (NOT in hot path — too slow)
  Total              : <500ms
"""

import asyncio
import time
from datetime import datetime
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
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

# Disable live DNS/WHOIS in feature extractor for speed
# The DNS service is called separately with timeout caps
_extractor._get_domain_age = lambda domain: -1
_extractor._has_mx_record  = lambda domain: False


def _parse_domain(url: str) -> str:
    try:
        return urlparse(url).netloc.split(":")[0]
    except Exception:
        return ""


_CTI_FALLBACK = {
    "virustotal": {"source": "virustotal", "found": False,
                   "positives": 0, "total": 0, "status": "timeout"},
    "urlhaus":    {"source": "urlhaus", "found": False,
                   "listed": False, "status": "timeout", "threat": None},
}


# ── Background task: enrich WHOIS after response is sent ─────────────────
def _update_whois_background(scan_id: str, domain: str, db_factory):
    """
    Runs AFTER the response is sent. Does a full WHOIS lookup and updates
    the whois_result column. The report endpoint will then have full data.
    Uses its own DB session (background thread).
    """
    try:
        db = db_factory()
        try:
            whois_data = dns_service.get_whois_info(domain)
            dns_data   = dns_service.get_all_dns_info(domain)
            merged     = {**whois_data, **dns_data}
            crud.update_whois(db, scan_id, merged)
        finally:
            db.close()
    except Exception:
        pass   # best-effort — never crash the server


# ── POST /scan ────────────────────────────────────────────────────────────
@router.post("/scan", response_model=ScanResponse, tags=["Scanning"])
async def scan_url(
    body: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """
    Full phishing analysis. Target: <500ms response.

    Steps:
      1. Normalise + validate URL
      2. Feature extraction (pure Python, ~1ms)
      3. ML inference (~5ms)
      4. CTI (VirusTotal + URLhaus) — parallel, capped 400ms
      5. DNS A records — parallel with CTI, capped 400ms
      6. Score boosting from CTI confirmation
      7. Persist to DB
      8. WHOIS enrichment runs as background task after response
    """
    start = time.perf_counter()

    # ── 1. Normalise ───────────────────────────────────────────────────────
    url = body.url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    if len(url) > 2000:
        raise HTTPException(422, "URL too long (max 2000 chars)")

    domain = _parse_domain(url)
    if not domain:
        raise HTTPException(422, "Could not parse domain from URL")

    # ── 2. Feature extraction ──────────────────────────────────────────────
    try:
        features = _extractor.extract(url)
    except Exception as e:
        raise HTTPException(500, f"Feature extraction failed: {e}")

    t_features = (time.perf_counter() - start) * 1000

    # ── 3. ML inference ────────────────────────────────────────────────────
    try:
        ml_result = predict(url, features)
    except Exception as e:
        raise HTTPException(500, f"Model inference failed: {e}")

    risk_score = ml_result["risk_score"]
    verdict    = ml_result["verdict"]
    t_ml       = (time.perf_counter() - start) * 1000

    # ── 4+5. CTI + DNS in parallel, both capped 400ms ─────────────────────
    async def run_cti():
        try:
            return await asyncio.wait_for(cti_service.enrich(url), timeout=0.4)
        except Exception:
            return _CTI_FALLBACK

    async def run_dns_a():
        loop = asyncio.get_event_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, dns_service.get_a_records, domain),
                timeout=0.4,
            )
        except Exception:
            return []

    cti_raw, a_records = await asyncio.gather(run_cti(), run_dns_a())
    t_cti = (time.perf_counter() - start) * 1000

    # ── 6. CTI score boosting ─────────────────────────────────────────────
    # If live CTI feeds confirm the URL is malicious, boost the score.
    # Additive boosts ensure ML-clean-but-CTI-listed URLs are caught.
    if cti_raw:
        vt_hits   = cti_raw.get("virustotal", {}).get("positives", 0)
        uh_listed = cti_raw.get("urlhaus", {}).get("listed", False)
        if vt_hits > 10:
            risk_score = min(100.0, risk_score + 20.0)
        elif vt_hits > 5:
            risk_score = min(100.0, risk_score + 10.0)
        elif vt_hits > 1:
            risk_score = min(100.0, risk_score + 5.0)
        if uh_listed:
            risk_score = min(100.0, risk_score + 10.0)

        # Re-evaluate verdict after CTI boost
        if risk_score >= 70:
            verdict = "phishing"
        elif risk_score >= 30:
            verdict = "suspicious"
        else:
            verdict = "benign"

    # ── 7. Build response ─────────────────────────────────────────────────
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

    # WHOIS placeholder — filled by background task after response
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

    # ── 8. Persist ────────────────────────────────────────────────────────
    from db.database import SessionLocal
    scan = crud.create_scan(
        db           = db,
        url          = url,
        verdict      = verdict,
        risk_score   = round(risk_score, 2),
        features     = features,
        cti_result   = cti_raw or {},
        whois_result = {"a_records": a_records or [], "whois_status": "pending"},
    )
    scan_id = str(scan.id)

    # ── Background WHOIS (fires after response sent) ──────────────────────
    background_tasks.add_task(
        _update_whois_background, scan_id, domain, SessionLocal
    )

    elapsed = (time.perf_counter() - start) * 1000
    print(
        f"[{elapsed:.0f}ms | feat={t_features:.0f} ml={t_ml:.0f} cti={t_cti:.0f}] "
        f"{verdict.upper()} ({risk_score:.1f}) — {url[:70]}"
    )

    return ScanResponse(
        scan_id      = scan_id,
        url          = url,
        verdict      = verdict,
        risk_score   = round(risk_score, 2),
        top_features = top_features,
        cti          = cti_response,
        whois        = whois_response,
        timestamp    = scan.created_at.isoformat(),
    )


# ── GET /scan/{scan_id} ───────────────────────────────────────────────────
@router.get("/scan/{scan_id}", tags=["Scanning"])
def get_scan_detail(scan_id: str, db: Session = Depends(get_db)):
    """
    Returns complete scan details including features, CTI, and WHOIS.
    WHOIS may be populated if background task has completed.
    Used by the dashboard's ThreatReportModal.
    """
    scan = crud.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(404, f"Scan '{scan_id}' not found")

    return {
        "scan_id":     str(scan.id),
        "url":         scan.url,
        "verdict":     scan.verdict,
        "risk_score":  scan.risk_score,
        "features":    scan.features   or {},
        "cti":         scan.cti_result  or {},
        "whois":       scan.whois_result or {},
        "timestamp":   scan.created_at.isoformat() if scan.created_at else None,
    }


# ── GET /history ──────────────────────────────────────────────────────────
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


# ── GET /stats ────────────────────────────────────────────────────────────
@router.get("/stats", response_model=StatsResponse, tags=["Stats"])
def get_stats(db: Session = Depends(get_db)):
    return StatsResponse(**crud.get_stats(db))
