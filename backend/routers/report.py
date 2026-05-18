"""
backend/routers/report.py
===========================
GET /report/{scan_id} — returns full threat report for a single scan.
Used by the dashboard's ThreatReportModal when "View Report" is clicked.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from db.database import get_db
from db import crud

router = APIRouter()


@router.get("/report/{scan_id}", tags=["Reports"])
def get_report(scan_id: str, db: Session = Depends(get_db)):
    """
    Returns the full persisted threat report for a scan.
    Includes features JSONB, cti_result JSONB, whois_result JSONB.
    The dashboard uses this to populate the ThreatReportModal.
    """
    scan = crud.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found")

    return {
        "scan_id":     str(scan.id),
        "url":         scan.url,
        "verdict":     scan.verdict,
        "risk_score":  scan.risk_score,
        "features":    scan.features or {},
        "cti":         scan.cti_result or {},
        "whois":       scan.whois_result or {},
        "timestamp":   scan.created_at.isoformat() if scan.created_at else None,
    }
