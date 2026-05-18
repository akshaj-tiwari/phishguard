"""
backend/routers/report.py
===========================
GET  /report/{scan_id}         — full structured IoC threat report
GET  /export/csv               — download scan history as CSV
GET  /export/ioc/{scan_id}     — structured IoC JSON report (downloadable)
POST /export/csv/filtered      — filtered CSV export (verdict, date range)

These endpoints fulfill the deliverable:
  "Analyst Dashboard: downloadable structured IoC reports"
"""

import csv
import io
import json
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse, JSONResponse
from sqlalchemy.orm import Session

from db.database import get_db
from db import crud

router = APIRouter()


# ── GET /report/{scan_id} ─────────────────────────────────────────────────
@router.get("/report/{scan_id}", tags=["Reports"])
def get_report(scan_id: str, db: Session = Depends(get_db)):
    """
    Full structured threat report for a single scan.
    Includes ML features, CTI intelligence, and WHOIS/DNS forensics.
    Used by the dashboard ThreatReportModal.
    """
    scan = crud.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(404, f"Scan '{scan_id}' not found")

    whois  = scan.whois_result or {}
    cti    = scan.cti_result   or {}
    feats  = scan.features     or {}

    # Derive top risk indicators for the report
    risk_indicators = _derive_risk_indicators(feats, cti)

    return {
        "scan_id":     str(scan.id),
        "url":         scan.url,
        "verdict":     scan.verdict,
        "risk_score":  scan.risk_score,
        "timestamp":   scan.created_at.isoformat() if scan.created_at else None,

        # ML features breakdown
        "features": feats,

        # CTI intelligence
        "cti": {
            "virustotal": cti.get("virustotal", {}),
            "urlhaus":    cti.get("urlhaus", {}),
        },

        # WHOIS & DNS forensics
        "forensics": {
            "domain":          _extract_domain(scan.url),
            "a_records":       whois.get("a_records", []),
            "has_mx_record":   whois.get("has_mx_record", False),
            "registrar":       whois.get("registrar"),
            "country":         whois.get("country"),
            "creation_date":   whois.get("creation_date"),
            "domain_age_days": whois.get("domain_age_days"),
            "is_new_domain":   whois.get("is_new_domain", False),
            "whois_status":    whois.get("whois_status", "completed"),
        },

        # Structured IoC indicators (for analyst consumption)
        "ioc": {
            "url":        scan.url,
            "domain":     _extract_domain(scan.url),
            "ip_address": whois.get("a_records", [None])[0] if whois.get("a_records") else None,
            "threat_type": _derive_threat_type(scan.verdict, cti),
            "confidence":  _verdict_to_confidence(scan.risk_score),
            "tags":        risk_indicators,
            "first_seen":  scan.created_at.isoformat() if scan.created_at else None,
        },
    }


# ── GET /export/ioc/{scan_id} ─────────────────────────────────────────────
@router.get("/export/ioc/{scan_id}", tags=["Export"])
def export_ioc_report(scan_id: str, db: Session = Depends(get_db)):
    """
    Downloads a structured IoC JSON report for a single scan.
    Suitable for import into SIEM, threat intel platforms, or filing.
    Response: application/json with Content-Disposition attachment header.
    """
    scan = crud.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(404, f"Scan '{scan_id}' not found")

    whois = scan.whois_result or {}
    cti   = scan.cti_result   or {}
    feats = scan.features     or {}
    domain = _extract_domain(scan.url)

    report = {
        "report_type":    "phishguard_ioc_v1",
        "generated_at":   datetime.utcnow().isoformat() + "Z",
        "scan_id":        str(scan.id),

        # Primary IoC
        "ioc": {
            "type":       "url",
            "value":      scan.url,
            "domain":     domain,
            "ip_address": whois.get("a_records", [None])[0] if whois.get("a_records") else None,
            "verdict":    scan.verdict,
            "risk_score": scan.risk_score,
            "threat_type":_derive_threat_type(scan.verdict, cti),
            "confidence": _verdict_to_confidence(scan.risk_score),
            "first_seen": scan.created_at.isoformat() if scan.created_at else None,
            "tags":       _derive_risk_indicators(feats, cti),
        },

        # CTI sources
        "threat_intelligence": {
            "virustotal": cti.get("virustotal", {}),
            "urlhaus":    cti.get("urlhaus", {}),
        },

        # WHOIS/DNS forensics
        "forensics": {
            "domain":          domain,
            "registrar":       whois.get("registrar"),
            "country":         whois.get("country"),
            "creation_date":   whois.get("creation_date"),
            "domain_age_days": whois.get("domain_age_days"),
            "is_new_domain":   whois.get("is_new_domain", False),
            "a_records":       whois.get("a_records", []),
            "has_mx_record":   whois.get("has_mx_record", False),
        },

        # Top ML signals
        "ml_signals": _top_features_for_report(feats),

        # Mitre ATT&CK mapping
        "mitre_attack": _mitre_mapping(scan.verdict, feats, cti),
    }

    content   = json.dumps(report, indent=2)
    safe_id   = scan_id.replace("-", "")[:12]
    filename  = f"phishguard_ioc_{safe_id}.json"

    return StreamingResponse(
        io.StringIO(content),
        media_type  = "application/json",
        headers     = {"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── GET /export/csv ───────────────────────────────────────────────────────
@router.get("/export/csv", tags=["Export"])
def export_csv(
    verdict:    Optional[str] = Query(None, description="phishing|suspicious|benign"),
    days:       Optional[int] = Query(None, description="Export last N days"),
    limit:      int           = Query(10000, le=50000),
    db:         Session       = Depends(get_db),
):
    """
    Exports scan history as a downloadable CSV file.

    Query params:
      verdict : filter by verdict (phishing|suspicious|benign)
      days    : only export last N days (default: all)
      limit   : max rows (default 10000, max 50000)
    """
    scans, _ = crud.get_history(
        db,
        page=1,
        limit=limit,
        verdict=verdict,
        days=days,
    )

    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        "scan_id", "url", "domain", "verdict", "risk_score",
        "vt_positives", "vt_total", "urlhaus_listed", "urlhaus_threat",
        "domain_age_days", "registrar", "country", "a_records",
        "is_new_domain", "timestamp",
    ])

    for s in scans:
        cti   = s.cti_result   or {}
        whois = s.whois_result or {}
        vt    = cti.get("virustotal", {})
        uh    = cti.get("urlhaus", {})
        ips   = "; ".join(whois.get("a_records", []))

        writer.writerow([
            str(s.id),
            s.url,
            _extract_domain(s.url),
            s.verdict,
            s.risk_score,
            vt.get("positives", ""),
            vt.get("total", ""),
            uh.get("listed", ""),
            uh.get("threat", ""),
            whois.get("domain_age_days", ""),
            whois.get("registrar", ""),
            whois.get("country", ""),
            ips,
            whois.get("is_new_domain", ""),
            s.created_at.isoformat() if s.created_at else "",
        ])

    output.seek(0)
    now      = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    suffix   = f"_{verdict}" if verdict else ""
    filename = f"phishguard_export{suffix}_{now}.csv"

    return StreamingResponse(
        output,
        media_type  = "text/csv",
        headers     = {"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Helpers ───────────────────────────────────────────────────────────────

def _extract_domain(url: str) -> str:
    try:
        from urllib.parse import urlparse
        return urlparse(url).netloc.split(":")[0]
    except Exception:
        return ""


def _derive_threat_type(verdict: str, cti: dict) -> str:
    if verdict == "benign":
        return "none"
    uh = cti.get("urlhaus", {})
    if uh.get("threat"):
        return uh["threat"]
    vt = cti.get("virustotal", {})
    if vt.get("positives", 0) > 5:
        return "malware_distribution"
    return "phishing"


def _verdict_to_confidence(risk_score: float) -> str:
    if risk_score >= 90:
        return "high"
    elif risk_score >= 70:
        return "medium-high"
    elif risk_score >= 50:
        return "medium"
    elif risk_score >= 30:
        return "low-medium"
    return "low"


def _derive_risk_indicators(features: dict, cti: dict) -> list:
    """Returns list of human-readable risk tag strings."""
    tags = []

    if features.get("has_ip_address"):
        tags.append("ip-address-as-host")
    if features.get("suspicious_tld"):
        tags.append("suspicious-tld")
    if features.get("is_brand_impersonation"):
        tags.append("brand-impersonation")
    if features.get("tld_in_subdomain"):
        tags.append("tld-in-subdomain")
    if features.get("https_in_domain"):
        tags.append("https-in-domain-name")
    if features.get("phishing_keyword_count", 0) > 2:
        tags.append("multiple-phishing-keywords")
    elif features.get("has_phishing_keyword"):
        tags.append("phishing-keyword-present")
    if features.get("has_malicious_ext"):
        tags.append("malicious-file-extension")
    if features.get("is_url_shortened"):
        tags.append("url-shortened")
    if features.get("domain_age_days", 1) == 0:
        tags.append("newly-registered-domain")
    elif 0 < features.get("domain_age_days", 999) < 30:
        tags.append("new-domain-under-30d")
    if features.get("domain_entropy", 0) > 3.8:
        tags.append("high-entropy-domain")
    if features.get("consecutive_consonants", 0) > 5:
        tags.append("dga-like-domain")
    if features.get("punycode_in_url"):
        tags.append("homograph-attack")

    vt = cti.get("virustotal", {})
    uh = cti.get("urlhaus", {})
    if vt.get("positives", 0) > 0:
        tags.append(f"virustotal-{vt['positives']}-detections")
    if uh.get("listed"):
        tags.append("urlhaus-listed")

    return tags


def _top_features_for_report(features: dict) -> list:
    """Returns the most suspicious feature values for the analyst report."""
    interesting = [
        "url_length", "num_dots", "num_hyphens", "has_ip_address",
        "suspicious_tld", "is_brand_impersonation", "tld_in_subdomain",
        "https_in_domain", "phishing_keyword_count", "has_phishing_keyword",
        "domain_entropy", "vowel_ratio", "has_malicious_ext",
        "path_entropy", "domain_age_days", "has_mx_record",
        "consecutive_consonants", "has_tld_abuse", "domain_digit_ratio",
        "punycode_in_url",
    ]
    return [
        {"feature": k, "value": features[k]}
        for k in interesting
        if k in features
    ]


def _mitre_mapping(verdict: str, features: dict, cti: dict) -> list:
    """
    Maps detected signals to MITRE ATT&CK techniques.
    Technique IDs from https://attack.mitre.org/
    """
    if verdict == "benign":
        return []

    techniques = []

    # T1566.002 — Spearphishing Link
    techniques.append({
        "technique_id": "T1566.002",
        "technique":    "Spearphishing Link",
        "tactic":       "Initial Access",
    })

    # T1036 — Masquerading (brand impersonation / typosquatting)
    if features.get("is_brand_impersonation") or features.get("tld_in_subdomain"):
        techniques.append({
            "technique_id": "T1036",
            "technique":    "Masquerading",
            "tactic":       "Defense Evasion",
        })

    # T1027 — Obfuscated Files or Information
    if features.get("has_hex_encoding") or features.get("has_base64_like") \
       or features.get("punycode_in_url") or features.get("is_url_shortened"):
        techniques.append({
            "technique_id": "T1027",
            "technique":    "Obfuscated Files or Information",
            "tactic":       "Defense Evasion",
        })

    # T1583.001 — Acquire Infrastructure: Domains
    if features.get("suspicious_tld") or features.get("has_tld_abuse"):
        techniques.append({
            "technique_id": "T1583.001",
            "technique":    "Acquire Infrastructure: Domains",
            "tactic":       "Resource Development",
        })

    # T1598.003 — Phishing for Information: Spearphishing Link
    if features.get("has_phishing_keyword"):
        techniques.append({
            "technique_id": "T1598.003",
            "technique":    "Phishing for Information: Spearphishing Link",
            "tactic":       "Reconnaissance",
        })

    return techniques
