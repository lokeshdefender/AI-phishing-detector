import json
import os
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from .models_db import Base, Investigation, ThreatIntelIndicator, ThreatIntelCache


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


def _ensure_schema_columns(engine: Engine) -> None:
    """Add new columns for existing databases without forcing a destructive migration."""
    inspector = inspect(engine)
    existing_columns = {column["name"] for column in inspector.get_columns("investigations")}
    required_columns = {
        "investigation_type": "ALTER TABLE investigations ADD COLUMN investigation_type VARCHAR(50) DEFAULT 'email'",
        "pipeline_stage": "ALTER TABLE investigations ADD COLUMN pipeline_stage VARCHAR(30) DEFAULT 'New'",
        "timeline": "ALTER TABLE investigations ADD COLUMN timeline TEXT DEFAULT '[]'",
        "graph": "ALTER TABLE investigations ADD COLUMN graph TEXT DEFAULT '[]'",
        "summary": "ALTER TABLE investigations ADD COLUMN summary TEXT DEFAULT ''",
        "evidence": "ALTER TABLE investigations ADD COLUMN evidence TEXT DEFAULT '[]'",
        "assigned_to": "ALTER TABLE investigations ADD COLUMN assigned_to VARCHAR(255) DEFAULT ''",
        "tags": "ALTER TABLE investigations ADD COLUMN tags TEXT DEFAULT '[]'",
    }

    with engine.begin() as connection:
        for column_name, ddl in required_columns.items():
            if column_name not in existing_columns:
                connection.execute(text(ddl))


def init_db(database_url: str | None = None) -> Engine:
    """Create database tables for the current models and refresh the shared engine."""
    global engine, SessionLocal
    resolved_engine = get_engine(database_url)
    Base.metadata.create_all(bind=resolved_engine)
    _ensure_schema_columns(resolved_engine)
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


def _coerce_json_string(value: Any) -> str:
    """Convert a JSON-compatible object into a string payload for storage."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value)


def _derive_summary(result: dict[str, Any], analyst_report: Any) -> str:
    """Build a human-readable summary for the record from the analysis result."""
    if isinstance(analyst_report, dict):
        for key in ("summary", "executive_summary", "finding"):
            value = analyst_report.get(key)
            if value:
                return str(value)
    if isinstance(result.get("summary"), str) and result.get("summary").strip():
        return result["summary"]
    return "Phishing investigation recorded."


def create_investigation_record(db: Session, *, submitted_text: str, result: dict[str, Any]) -> Investigation:
    """Create a persisted investigation record from a completed analysis result."""
    init_db()
    analyst_report = result.get("analyst_report") or {}
    if isinstance(analyst_report, str):
        try:
            analyst_report = json.loads(analyst_report)
        except json.JSONDecodeError:
            analyst_report = {}

    evidence = result.get("evidence") or result.get("urls") or []
    tags = result.get("tags") or []

    investigation = Investigation(
        case_id=_generate_case_id(db),
        title=f"Phishing investigation from {result.get('sender') or 'unknown sender'}",
        submitted_text=submitted_text,
        sender=result.get("sender") or "",
        urls=json.dumps(result.get("urls", [])),
        phishing_score=int(result.get("score", 0)),
        confidence=int(result.get("confidence", 0)),
        threat_level=str(analyst_report.get("threat_level", "MINIMAL")) if isinstance(analyst_report, dict) else "MINIMAL",
        analyst_report=_coerce_json_string(analyst_report),
        analyst_notes="",
        investigation_type=str(result.get("investigation_type") or "email"),
        pipeline_stage=str(result.get("pipeline_stage") or "New"),
        timeline=json.dumps(result.get("timeline") or []),
        graph=json.dumps(result.get("graph") or []),
        summary=_derive_summary(result, analyst_report),
        evidence=json.dumps(evidence),
        assigned_to="",
        tags=json.dumps(tags),
        status="Open",
    )
    db.add(investigation)
    db.commit()
    db.refresh(investigation)
    return investigation
