"""
backend/main.py
================
FastAPI app entry point. Matches the plan spec exactly.

Run:
    cd backend/
    uvicorn main:app --host 0.0.0.0 --port 8000 --reload

Swagger UI: http://localhost:8000/docs
ReDoc:      http://localhost:8000/redoc
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from routers import scan, report
from db.database import engine, Base, init_db
from services.model_service import load_model

# ── App ────────────────────────────────────────────────────────────────────
app = FastAPI(
    title       = "PhishGuard API",
    description = "ML-Powered Phishing URL Detection with Cyber Threat Intelligence",
    version     = "1.0.0",
    docs_url    = "/docs",
    redoc_url   = "/redoc",
)

# CORS — allows Chrome extension + React dashboard to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins  = ["*"],   # dev: allow all. prod: ["chrome-extension://ID", "http://localhost:3000"]
    allow_methods  = ["*"],
    allow_headers  = ["*"],
)


# ── Startup ────────────────────────────────────────────────────────────────
@app.on_event("startup")
def startup():
    """Runs once when the server starts."""
    init_db()          # create tables if not exist
    load_model()       # load phishguard_v1.pkl into memory
    print("✓ PhishGuard API ready")
    print("✓ Docs: http://localhost:8000/docs")


# ── Routers ────────────────────────────────────────────────────────────────
app.include_router(scan.router)
app.include_router(report.router)


# ── Health check ───────────────────────────────────────────────────────────
@app.get("/health", tags=["Meta"])
def health():
    return {"status": "ok", "service": "PhishGuard API v1.0"}


# ── Dev entrypoint ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
