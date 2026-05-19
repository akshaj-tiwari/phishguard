"""
backend/db/crud.py
====================
Database CRUD helpers. Business logic stays in routers — crud.py only touches DB.
"""

import uuid
from datetime import datetime, timedelta
from typing import Optional
from sqlalchemy.orm import Session
from sqlalchemy import desc, func

from .database import Scan


def create_scan(
    db: Session,
    url: str,
    verdict: str,
    risk_score: float,
    features: dict,
    cti_result: dict,
    whois_result: dict,
) -> Scan:
    """Persists a new scan. Returns the saved record."""
    scan = Scan(
        id           = str(uuid.uuid4()),
        url          = url,
        verdict      = verdict,
        risk_score   = risk_score,
        features     = features,
        cti_result   = cti_result,
        whois_result = whois_result,
        created_at   = datetime.utcnow(),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def get_scan(db: Session, scan_id: str) -> Optional[Scan]:
    """Returns a single scan by UUID or None."""
    return db.query(Scan).filter(Scan.id == scan_id).first()


def update_whois(db: Session, scan_id: str, whois_data: dict) -> bool:
    """
    Updates whois_result for a scan. Called by the background WHOIS task.
    Returns True if scan found and updated.
    """
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return False
    scan.whois_result = whois_data
    db.commit()
    return True


def get_history(
    db: Session,
    page: int = 1,
    limit: int = 50,
    verdict: Optional[str] = None,
    days: Optional[int] = None,
) -> tuple[list[Scan], int]:
    """
    Paginated scan history ordered by created_at DESC.
    Supports optional verdict and date range filters.
    """
    query = db.query(Scan).order_by(desc(Scan.created_at))

    if verdict:
        query = query.filter(Scan.verdict == verdict.lower())

    if days:
        cutoff = datetime.utcnow() - timedelta(days=days)
        query  = query.filter(Scan.created_at >= cutoff)

    total  = query.count()
    offset = (page - 1) * limit
    scans  = query.offset(offset).limit(limit).all()

    return scans, total


def get_stats(db: Session) -> dict:
    """
    Aggregate stats for the dashboard overview cards.
    Returns: total, phishing_count, suspicious_count, benign_count,
             avg_risk, top_flagged_domains, hourly_breakdown (last 24h).
    """
    from urllib.parse import urlparse

    total = db.query(func.count(Scan.id)).scalar() or 0

    by_verdict = (
        db.query(Scan.verdict, func.count(Scan.id))
        .group_by(Scan.verdict)
        .all()
    )
    counts = {v: c for v, c in by_verdict}
    avg_risk = db.query(func.avg(Scan.risk_score)).scalar() or 0.0

    # Top 10 flagged domains from recent 500 scans
    recent = db.query(Scan).order_by(desc(Scan.created_at)).limit(500).all()
    domain_counts: dict[str, int] = {}
    for s in recent:
        try:
            d = urlparse(s.url).netloc.split(":")[0]
            if d and s.verdict in ("phishing", "suspicious"):
                domain_counts[d] = domain_counts.get(d, 0) + 1
        except Exception:
            pass
    top_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    # Hourly scan counts for last 24h (for the area chart)
    cutoff_24h = datetime.utcnow() - timedelta(hours=24)
    recent_24h = (
        db.query(Scan)
        .filter(Scan.created_at >= cutoff_24h)
        .order_by(Scan.created_at)
        .all()
    )

    hourly: dict[int, dict] = {}
    for s in recent_24h:
        h = s.created_at.hour if s.created_at else 0
        if h not in hourly:
            hourly[h] = {"hour": h, "scans": 0, "malicious": 0}
        hourly[h]["scans"] += 1
        if s.verdict == "phishing":
            hourly[h]["malicious"] += 1
    hourly_breakdown = list(hourly.values())

    return {
        "total_scans":        total,
        "phishing_count":     counts.get("phishing", 0),
        "suspicious_count":   counts.get("suspicious", 0),
        "benign_count":       counts.get("benign", 0),
        "avg_risk_score":     round(float(avg_risk), 2),
        "top_flagged_domains": [{"domain": d, "count": c} for d, c in top_domains],
        "hourly_breakdown":   hourly_breakdown,
    }
