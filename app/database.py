import json
import os
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from .models_db import Base, Investigation


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = BASE_DIR / "investigations.db"
DEFAULT_DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DEFAULT_DB_PATH}")


def get_engine(database_url: str | None = None) -> Engine:
    """Create a SQLAlchemy engine for the configured database URL."""
    resolved_url = database_url or DEFAULT_DATABASE_URL
    connect_args = {"check_same_thread": False} if resolved_url.startswith("sqlite") else {}
    return create_engine(resolved_url, connect_args=connect_args)


engine = get_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def init_db(database_url: str | None = None) -> Engine:
    """Create database tables for the current models and refresh the shared engine."""
    global engine, SessionLocal
    resolved_engine = get_engine(database_url)
    Base.metadata.create_all(bind=resolved_engine)
    engine = resolved_engine
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    return resolved_engine


def get_db():
    """Yield a database session for FastAPI request lifecycle management."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _generate_case_id(db: Session) -> str:
    """Generate a unique case ID in the format CASE-000001."""
    latest = db.query(Investigation).order_by(Investigation.id.desc()).first()
    if latest is None:
        return "CASE-000001"

    try:
        suffix = int(latest.case_id.split("-")[-1])
    except (AttributeError, ValueError):
        suffix = 0

    return f"CASE-{suffix + 1:06d}"


def create_investigation_record(db: Session, *, submitted_text: str, result: dict[str, Any]) -> Investigation:
    """Create a persisted investigation record from a completed analysis result."""
    init_db()
    analyst_report = result.get("analyst_report") or {}
    investigation = Investigation(
        case_id=_generate_case_id(db),
        title=f"Phishing investigation from {result.get('sender') or 'unknown sender'}",
        submitted_text=submitted_text,
        sender=result.get("sender") or "",
        urls=json.dumps(result.get("urls", [])),
        phishing_score=int(result.get("score", 0)),
        confidence=int(result.get("confidence", 0)),
        threat_level=str(analyst_report.get("threat_level", "MINIMAL")),
        analyst_report=json.dumps(analyst_report),
        analyst_notes="",
        status="Open",
    )
    db.add(investigation)
    db.commit()
    db.refresh(investigation)
    return investigation
