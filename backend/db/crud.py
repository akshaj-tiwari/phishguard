"""
backend/db/crud.py
====================
Database read/write helpers (CRUD operations).
All business logic stays in routes — crud.py only touches the DB.
"""

import uuid
from datetime import datetime
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
    """Persists a completed scan to the database. Returns the saved record."""
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
    """Returns a single scan by UUID, or None."""
    return db.query(Scan).filter(Scan.id == scan_id).first()


def get_history(
    db: Session,
    page: int = 1,
    limit: int = 50,
    verdict: Optional[str] = None,
) -> tuple[list[Scan], int]:
    """
    Returns paginated scan history ordered by created_at DESC.
    Matches GET /history?page=1&limit=50&verdict=phishing
    """
    query = db.query(Scan).order_by(desc(Scan.created_at))

    if verdict:
        query = query.filter(Scan.verdict == verdict.lower())

    total  = query.count()
    offset = (page - 1) * limit
    scans  = query.offset(offset).limit(limit).all()

    return scans, total


def get_stats(db: Session) -> dict:
    """
    Aggregate statistics for the dashboard overview cards.
    Returns: total, phishing_count, suspicious_count, benign_count, avg_risk.
    """
    total = db.query(func.count(Scan.id)).scalar() or 0

    by_verdict = (
        db.query(Scan.verdict, func.count(Scan.id))
        .group_by(Scan.verdict)
        .all()
    )
    counts = {v: c for v, c in by_verdict}

    avg_risk = db.query(func.avg(Scan.risk_score)).scalar() or 0.0

    # Top 10 most-scanned domains
    from sqlalchemy import cast, String
    recent = db.query(Scan).order_by(desc(Scan.created_at)).limit(500).all()
    domain_counts: dict[str, int] = {}
    for s in recent:
        try:
            from urllib.parse import urlparse
            d = urlparse(s.url).netloc.split(":")[0]
            if d:
                domain_counts[d] = domain_counts.get(d, 0) + 1
        except Exception:
            pass
    top_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        "total_scans":       total,
        "phishing_count":    counts.get("phishing", 0),
        "suspicious_count":  counts.get("suspicious", 0),
        "benign_count":      counts.get("benign", 0),
        "avg_risk_score":    round(float(avg_risk), 2),
        "top_flagged_domains": [{"domain": d, "count": c} for d, c in top_domains],
    }
