"""
backend/main.py
================
FastAPI entry point for PhishGuard API.

Run:
    cd backend/
    uvicorn main:app --host 0.0.0.0 --port 8000 --reload

Swagger UI : http://localhost:8000/docs
ReDoc      : http://localhost:8000/redoc
Health     : http://localhost:8000/health

Endpoints:
  POST /scan                   — analyse a URL (full pipeline)
  GET  /scan/{id}              — get scan details by ID
  GET  /history                — paginated scan history
  GET  /stats                  — dashboard aggregate stats
  GET  /report/{id}            — full structured threat report
  GET  /export/csv             — download scan history as CSV
  GET  /export/ioc/{id}        — download IoC JSON report
  GET  /health                 — health check
"""

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routers import scan, report
from db.database import init_db
from services.model_service import load_model
from services.phishtank_service import load_cache as load_phishtank_cache
from services.phishtank_service import schedule_daily_refresh


# ── Lifespan (replaces deprecated @app.on_event) ───────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Startup:
      1. Create DB tables
      2. Load ML model into memory
      3. Load PhishTank local cache (non-blocking)
      4. Schedule daily PhishTank cache refresh
    Shutdown: (nothing needed — connections auto-close)
    """
    # 1. Database
    init_db()

    # 2. ML model
    load_model()

    # 3. PhishTank cache (from disk, fast)
    load_phishtank_cache()

    # 4. Background auto-refresh task
    refresh_task = asyncio.create_task(schedule_daily_refresh())

    print("✓ PhishGuard API ready")
    print("✓ Docs: http://localhost:8000/docs")

    yield   # ← app runs here

    # Shutdown
    refresh_task.cancel()
    try:
        await refresh_task
    except asyncio.CancelledError:
        pass


# ── App ─────────────────────────────────────────────────────────────────────
app = FastAPI(
    title       = "PhishGuard API",
    description = (
        "ML-Powered Phishing URL Detection with Cyber Threat Intelligence.\n\n"
        "**Pipeline**: Feature extraction → XGB+LGBM+RF Ensemble → "
        "VirusTotal + URLhaus + PhishTank CTI → SQLite/PostgreSQL persistence\n\n"
        "**Target**: ≥95% accuracy, <500ms response time."
    ),
    version     = "3.0.0",
    docs_url    = "/docs",
    redoc_url   = "/redoc",
    lifespan    = lifespan,
)

# CORS — allows Chrome extension + React dashboard
# In production: replace "*" with ["chrome-extension://<ID>", "https://yourdomain.com"]
app.add_middleware(
    CORSMiddleware,
    allow_origins  = ["*"],
    allow_methods  = ["*"],
    allow_headers  = ["*"],
)

# ── Routers ──────────────────────────────────────────────────────────────────
app.include_router(scan.router)
app.include_router(report.router)


# ── Health ───────────────────────────────────────────────────────────────────
@app.get("/health", tags=["Meta"])
def health():
    from services.model_service import _pipeline, _feature_names
    return {
        "status":           "ok",
        "service":          "PhishGuard API v3",
        "model_loaded":     _pipeline is not None,
        "feature_count":    len(_feature_names) if _feature_names else 0,
        "model_version":    "v3_ensemble_stack",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
