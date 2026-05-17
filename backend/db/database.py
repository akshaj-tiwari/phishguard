"""
backend/db/database.py
========================
SQLAlchemy setup for PostgreSQL (plan spec).
Falls back to SQLite for local development if DATABASE_URL is not set.

Schema matches plan spec:
  Table: scans
    id           UUID PRIMARY KEY
    url          TEXT
    verdict      VARCHAR(20)
    risk_score   FLOAT
    features     JSONB
    cti_result   JSONB
    whois_result JSONB
    created_at   TIMESTAMP

Index on created_at DESC for fast history queries.
"""

import os
from sqlalchemy import (
    create_engine, Column, Float, String, Text,
    DateTime, Index
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.types import JSON          # fallback for SQLite
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import uuid
from dotenv import load_dotenv

load_dotenv()

# ── Database URL ───────────────────────────────────────────────────────────
# Production:  set DATABASE_URL=postgresql://user:pass@localhost/phishguard in .env
# Development: falls back to SQLite (no setup needed)
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    f"sqlite:///{os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'phishguard_dev.db')}"
)

IS_POSTGRES = DATABASE_URL.startswith("postgresql")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if not IS_POSTGRES else {},
    echo=False,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# ── ORM Model ──────────────────────────────────────────────────────────────

class Scan(Base):
    """
    Matches the PostgreSQL schema from the implementation plan.
    Uses JSONB for features/cti_result/whois_result on Postgres,
    falls back to JSON (stored as text) on SQLite.
    """
    __tablename__ = "scans"

    # UUID primary key (plan spec)
    id = Column(
        UUID(as_uuid=True) if IS_POSTGRES else String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    url          = Column(Text, nullable=False)
    verdict      = Column(String(20))           # benign | suspicious | phishing
    risk_score   = Column(Float)                # 0.0–100.0
    features     = Column(JSONB if IS_POSTGRES else JSON)   # full feature dict
    cti_result   = Column(JSONB if IS_POSTGRES else JSON)   # VT + URLhaus
    whois_result = Column(JSONB if IS_POSTGRES else JSON)   # WHOIS + DNS
    created_at   = Column(DateTime, default=datetime.utcnow)

    # Index on created_at DESC (plan spec: fast history queries)
    __table_args__ = (
        Index("ix_scans_created_at", "created_at"),
    )


def init_db():
    """Creates all tables. Called once at app startup."""
    Base.metadata.create_all(bind=engine)
    db_type = "PostgreSQL" if IS_POSTGRES else "SQLite (dev)"
    print(f"✓ Database ready ({db_type}): {DATABASE_URL[:60]}...")


def get_db():
    """
    FastAPI dependency injection.
    Usage in a route:
        from db.database import get_db
        def my_route(db: Session = Depends(get_db)): ...
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
