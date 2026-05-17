"""
backend/routers/scan.py
=========================
POST /scan  — main analysis endpoint
GET  /history — paginated scan history
GET  /stats   — dashboard aggregate stats
"""

import asyncio
import time
from datetime import datetime
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from db.database import get_db
from db import crud
from db.schemas import (
    ScanRequest, ScanResponse, HistoryResponse, StatsResponse,
    ScanSummary, CTIResult, WHOISResult, VirusTotalResult,
    URLhausResult, FeatureInfo
)
from services.feature_extractor import FeatureExtractor
from services.model_service import predict
from services import cti_service, dns_service

router = APIRouter()

# One FeatureExtractor instance (thread-safe, stateless)
_extractor = FeatureExtractor()


def _parse_domain(url: str) -> str:
    try:
        return urlparse(url).netloc.split(":")[0]
    except Exception:
        return ""


@router.post("/scan", response_model=ScanResponse, tags=["Scanning"])
async def scan_url(body: ScanRequest, request: Request, db: Session = Depends(get_db)):
    """
    Main endpoint — full phishing analysis pipeline.

    Logic (per plan):
      1. Parse + validate URL
      2. FeatureExtractor.extract(url)
      3. model.predict_proba -> risk_score (0-100)
      4. Async CTI: VirusTotal + URLhaus (400ms timeout)
      5. Async DNS/WHOIS (400ms timeout)
      6. Merge into threat report
      7. Persist to PostgreSQL
      8. Return threat report

    Verdict thresholds (plan spec):
      < 30  -> benign
      30-69 -> suspicious
      >= 70 -> phishing
    """
    start = time.time()

    # ── 1. Normalise URL ───────────────────────────────────────────────────
    url = body.url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    domain = _parse_domain(url)
    if not domain:
        raise HTTPException(status_code=422, detail="Could not parse domain from URL")

    # ── 2. Feature extraction ──────────────────────────────────────────────
    try:
        features = _extractor.extract(url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Feature extraction failed: {e}")

    # ── 3. ML inference ───────────────────────────────────────────────────
    try:
        ml_result = predict(url, features)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Model inference failed: {e}")

    risk_score = ml_result["risk_score"]
    verdict    = ml_result["verdict"]

    # ── 4. CTI + DNS/WHOIS in parallel (400ms timeout) ────────────────────
    cti_raw   = None
    whois_raw = None

    loop = asyncio.get_event_loop()

    async def run_cti():
        try:
            return await asyncio.wait_for(cti_service.enrich(url), timeout=0.4)
        except asyncio.TimeoutError:
            return {"virustotal": {"found": False, "positives": 0, "total": 0,
                                   "status": "timeout"},
                    "urlhaus":    {"found": False, "listed": False,
                                   "status": "timeout", "threat": None}}
        except Exception:
            return None

    async def run_dns():
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, dns_service.get_whois_info, domain),
                timeout=0.4
            )
        except (asyncio.TimeoutError, Exception):
            return None

    async def run_a_records():
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(None, dns_service.get_a_records, domain),
                timeout=0.4
            )
        except (asyncio.TimeoutError, Exception):
            return []

    cti_raw, whois_raw, a_records = await asyncio.gather(
        run_cti(), run_dns(), run_a_records()
    )

    # ── 5. Boost risk score if CTI confirms phishing ───────────────────────
    if cti_raw:
        vt_hits      = cti_raw.get("virustotal", {}).get("positives", 0)
        uh_listed    = cti_raw.get("urlhaus", {}).get("listed", False)
        if vt_hits > 5:
            risk_score = min(100.0, risk_score + 15.0)
        if uh_listed:
            risk_score = min(100.0, risk_score + 10.0)
        # Re-calculate verdict with boosted score
        if risk_score >= 70:
            verdict = "phishing"
        elif risk_score >= 30:
            verdict = "suspicious"

    # ── 6. Build structured response objects ──────────────────────────────
    cti_response   = None
    whois_response = None

    if cti_raw:
        vt = cti_raw.get("virustotal", {})
        uh = cti_raw.get("urlhaus", {})
        cti_response = CTIResult(
            virustotal=VirusTotalResult(
                found=vt.get("found", False),
                positives=vt.get("positives", 0),
                total=vt.get("total", 0),
                status=vt.get("status", "unknown"),
            ),
            urlhaus=URLhausResult(
                found=uh.get("found", False),
                listed=uh.get("listed", False),
                status=uh.get("status", "unknown"),
                threat=uh.get("threat"),
            ),
        )

    if whois_raw:
        whois_response = WHOISResult(
            domain_age_days=whois_raw.get("domain_age_days"),
            registrar=whois_raw.get("registrar"),
            country=whois_raw.get("country"),
            creation_date=whois_raw.get("creation_date"),
            is_new_domain=whois_raw.get("is_new_domain", False),
            a_records=a_records or [],
            has_mx_record=features.get("has_mx_record", 0) == 1,
        )

    top_features = [
        FeatureInfo(**f) for f in ml_result.get("top_features", [])
    ]

    # ── 7. Persist to database ─────────────────────────────────────────────
    scan = crud.create_scan(
        db=db,
        url=url,
        verdict=verdict,
        risk_score=round(risk_score, 2),
        features=features,
        cti_result=cti_raw or {},
        whois_result={**(whois_raw or {}), "a_records": a_records or []},
    )

    elapsed_ms = round((time.time() - start) * 1000, 1)
    print(f"[{elapsed_ms}ms] {verdict.upper()} ({risk_score:.1f}) — {url[:80]}")

    # ── 8. Return threat report ────────────────────────────────────────────
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
    page:    int            = Query(1, ge=1),
    limit:   int            = Query(50, le=200),
    verdict: str | None     = Query(None, description="Filter: phishing|suspicious|benign"),
    db:      Session        = Depends(get_db),
):
    """
    GET /history?page=1&limit=50&verdict=phishing
    Returns paginated scan history ordered by created_at DESC.
    """
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
    """
    GET /stats — aggregate statistics for the dashboard overview cards.
    """
    data = crud.get_stats(db)
    return StatsResponse(**data)
