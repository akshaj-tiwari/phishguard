"""
backend/db/schemas.py
=======================
Pydantic models for request validation and response serialization.
Response shape matches the plan spec exactly.
"""

from pydantic import BaseModel, field_validator
from typing import Optional, List, Any
from datetime import datetime


# ── Request ────────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def url_must_be_non_empty(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("URL cannot be empty")
        if len(v) > 2000:
            raise ValueError("URL too long (max 2000 chars)")
        return v

    model_config = {
        "json_schema_extra": {
            "example": {"url": "http://paypal-secure-login.tk/verify?account=victim"}
        }
    }


# ── Response pieces ────────────────────────────────────────────────────────

class VirusTotalResult(BaseModel):
    found:     bool
    positives: int
    total:     int
    status:    str


class URLhausResult(BaseModel):
    found:  bool
    listed: bool
    status: str
    threat: Optional[str] = None


class CTIResult(BaseModel):
    virustotal: VirusTotalResult
    urlhaus:    URLhausResult


class WHOISResult(BaseModel):
    domain_age_days: Optional[int] = None
    registrar:       Optional[str] = None
    country:         Optional[str] = None
    creation_date:   Optional[str] = None
    is_new_domain:   bool = False
    a_records:       List[str] = []
    has_mx_record:   bool = False


class FeatureInfo(BaseModel):
    feature:      str
    value:        Any
    importance:   float
    contribution: float


# ── Main scan response (plan spec shape) ──────────────────────────────────

class ScanResponse(BaseModel):
    """
    Matches the plan spec response body for POST /scan:
      scan_id, url, verdict, risk_score, top_features, cti, whois, timestamp
    """
    scan_id:      str
    url:          str
    verdict:      str                       # benign | suspicious | phishing
    risk_score:   float                     # 0.0–100.0
    top_features: List[FeatureInfo]
    cti:          Optional[CTIResult] = None
    whois:        Optional[WHOISResult] = None
    timestamp:    str                       # ISO8601


# ── History / stats ────────────────────────────────────────────────────────

class ScanSummary(BaseModel):
    scan_id:    str
    url:        str
    verdict:    str
    risk_score: float
    timestamp:  str


class HistoryResponse(BaseModel):
    total:  int
    page:   int
    limit:  int
    scans:  List[ScanSummary]


class StatsResponse(BaseModel):
    total_scans:     int
    phishing_count:  int
    suspicious_count: int
    benign_count:    int
    avg_risk_score:  float
    top_flagged_domains: List[dict]
