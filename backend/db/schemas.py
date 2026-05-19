"""
backend/db/schemas.py
=======================
Pydantic v2 models for request validation and response serialization.
"""

from pydantic import BaseModel, field_validator
from typing import Optional, List, Any


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


# ── CTI Response pieces ────────────────────────────────────────────────────

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


class PhishTankResult(BaseModel):
    found:           bool
    verified:        bool  = False
    phish_id:        Optional[str] = None
    submission_time: Optional[str] = None
    verified_at:     Optional[str] = None
    target:          Optional[str] = None
    status:          str           = "unknown"


class CTIResult(BaseModel):
    virustotal: VirusTotalResult
    urlhaus:    URLhausResult
    phishtank:  Optional[PhishTankResult] = None


# ── WHOIS / DNS ────────────────────────────────────────────────────────────

class WHOISResult(BaseModel):
    domain_age_days: Optional[int] = None
    registrar:       Optional[str] = None
    country:         Optional[str] = None
    creation_date:   Optional[str] = None
    is_new_domain:   bool          = False
    a_records:       List[str]     = []
    has_mx_record:   bool          = False


# ── Feature info ───────────────────────────────────────────────────────────

class FeatureInfo(BaseModel):
    feature:      str
    value:        Any
    importance:   float
    contribution: float


# ── Main scan response ─────────────────────────────────────────────────────

class ScanResponse(BaseModel):
    scan_id:      str
    url:          str
    verdict:      str         # benign | suspicious | phishing
    risk_score:   float       # 0.0–100.0
    top_features: List[FeatureInfo]
    cti:          Optional[CTIResult]   = None
    whois:        Optional[WHOISResult] = None
    timestamp:    str                   # ISO8601


# ── History / Stats ────────────────────────────────────────────────────────

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


class HourlyBucket(BaseModel):
    hour:      int
    scans:     int
    malicious: int


class TopDomain(BaseModel):
    domain: str
    count:  int


class StatsResponse(BaseModel):
    total_scans:         int
    phishing_count:      int
    suspicious_count:    int
    benign_count:        int
    avg_risk_score:      float
    top_flagged_domains: List[dict]
    hourly_breakdown:    List[dict]  = []
