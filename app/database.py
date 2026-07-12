import json
import os
from pathlib import Path
from typing import Any, List

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from .models_db import (
    Base,
    Investigation,
    InvestigationChatMessage,
    InvestigationComment,
    InvestigationTimeline,
    Organization,
    ThreatIntelCache,
    ThreatIntelIndicator,
    User,
)


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
        "organization_id": "ALTER TABLE investigations ADD COLUMN organization_id INTEGER",
        "creator_user_id": "ALTER TABLE investigations ADD COLUMN creator_user_id INTEGER",
        "subject": "ALTER TABLE investigations ADD COLUMN subject VARCHAR(512)",
        "recipients": "ALTER TABLE investigations ADD COLUMN recipients TEXT DEFAULT '[]'",
        "message_id": "ALTER TABLE investigations ADD COLUMN message_id VARCHAR(512)",
        "attachment_count": "ALTER TABLE investigations ADD COLUMN attachment_count INTEGER DEFAULT 0",
        "investigation_type": "ALTER TABLE investigations ADD COLUMN investigation_type VARCHAR(50) DEFAULT 'email'",
        "pipeline_stage": "ALTER TABLE investigations ADD COLUMN pipeline_stage VARCHAR(30) DEFAULT 'New'",
        "timeline": "ALTER TABLE investigations ADD COLUMN timeline TEXT DEFAULT '[]'",
        "graph": "ALTER TABLE investigations ADD COLUMN graph TEXT DEFAULT '[]'",
        "summary": "ALTER TABLE investigations ADD COLUMN summary TEXT DEFAULT ''",
        "evidence": "ALTER TABLE investigations ADD COLUMN evidence TEXT DEFAULT '[]'",
        "mitre_mappings": "ALTER TABLE investigations ADD COLUMN mitre_mappings TEXT DEFAULT '{}'",
        "assigned_to": "ALTER TABLE investigations ADD COLUMN assigned_to VARCHAR(255) DEFAULT ''",
        "assigned_user_id": "ALTER TABLE investigations ADD COLUMN assigned_user_id INTEGER",
        "assigned_at": "ALTER TABLE investigations ADD COLUMN assigned_at DATETIME",
        "assigned_by": "ALTER TABLE investigations ADD COLUMN assigned_by INTEGER",
        "tags": "ALTER TABLE investigations ADD COLUMN tags TEXT DEFAULT '[]'",
    }

    with engine.begin() as connection:
        for column_name, ddl in required_columns.items():
            if column_name not in existing_columns:
                connection.execute(text(ddl))


def get_or_create_organization(db: Session, name: str) -> Organization:
    """Fetch an organization by name, creating it when missing."""
    normalized_name = (name or "").strip() or "Default Organization"
    existing = db.query(Organization).filter(Organization.name == normalized_name).first()
    if existing:
        return existing

    org = Organization(name=normalized_name)
    db.add(org)
    db.commit()
    db.refresh(org)
    return org


def get_or_create_default_organization(db: Session) -> Organization:
    """Return the default single-tenant org for backward compatibility."""
    return get_or_create_organization(db, "Default Organization")


def get_user_by_email(db: Session, email: str) -> User | None:
    """Fetch a user by email address."""
    normalized = (email or "").strip().lower()
    if not normalized:
        return None
    return db.query(User).filter(User.email == normalized).first()


def create_user(
    db: Session,
    *,
    email: str,
    password_hash: str,
    full_name: str | None = None,
    role: str = "viewer",
    organization_id: int,
) -> User:
    """Create and persist a new platform user."""
    user = User(
        email=(email or "").strip().lower(),
        full_name=(full_name or "").strip() or None,
        password_hash=password_hash,
        role=(role or "viewer").strip().lower(),
        organization_id=organization_id,
        is_active=1,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def get_or_create_default_user(db: Session) -> User:
    """Return a default analyst user used for legacy flows and existing tests."""
    email = "default-analyst@local"
    user = get_user_by_email(db, email)
    if user:
        return user

    org = get_or_create_default_organization(db)
    user = User(
        email=email,
        full_name="Default Analyst",
        password_hash="!",
        role="admin",
        organization_id=org.id,
        is_active=1,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


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


def create_investigation_record(
    db: Session,
    *,
    submitted_text: str,
    result: dict[str, Any],
    organization_id: int | None = None,
    creator_user_id: int | None = None,
) -> Investigation:
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

    resolved_org_id = organization_id
    resolved_creator_id = creator_user_id

    if resolved_org_id is None or resolved_creator_id is None:
        default_user = get_or_create_default_user(db)
        resolved_org_id = resolved_org_id or default_user.organization_id
        resolved_creator_id = resolved_creator_id or default_user.id

    investigation = Investigation(
        case_id=_generate_case_id(db),
        organization_id=resolved_org_id,
        creator_user_id=resolved_creator_id,
        title=f"Phishing investigation from {result.get('sender') or 'unknown sender'}",
        submitted_text=submitted_text,
        sender=result.get("sender") or "",
        subject=(result.get("metadata") or {}).get("subject", "") if isinstance(result.get("metadata"), dict) else "",
        recipients=json.dumps((result.get("metadata") or {}).get("recipients", [])) if isinstance(result.get("metadata"), dict) else "[]",
        message_id=(result.get("metadata") or {}).get("message_id", "") if isinstance(result.get("metadata"), dict) else "",
        attachment_count=int((result.get("metadata") or {}).get("attachment_count", 0)) if isinstance(result.get("metadata"), dict) else 0,
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

    # Build and cache relationship graph for the case.
    try:
        from .investigation_graph import refresh_investigation_graph

        refresh_investigation_graph(db, investigation, force=False)
        db.commit()
        db.refresh(investigation)
    except Exception:
        # non-fatal: graph generation should not break case creation
        pass

    # Build and cache MITRE mappings for the case.
    try:
        from .mitre_mapping import refresh_investigation_mitre

        refresh_investigation_mitre(db, investigation, force=False)
        db.commit()
        db.refresh(investigation)
    except Exception:
        # non-fatal: mapping generation should not break case creation
        pass

    # Append immutable timeline event for case creation
    try:
        from .models_db import InvestigationTimeline
        import uuid

        event = InvestigationTimeline(
            event_id=str(uuid.uuid4()),
            investigation_id=investigation.id,
            event_type="case_created",
            title="Case created",
            description=f"Investigation {investigation.case_id} created.",
            source="system",
            metadata_json=json.dumps({"submitted_text": submitted_text}),
        )
        db.add(event)
        db.commit()
    except Exception:
        # non-fatal: timeline persistence should not break creation
        pass
    return investigation


def list_organization_users(db: Session, organization_id: int) -> list[User]:
    """Return active users for an organization ordered by name/email."""
    users = (
        db.query(User)
        .filter(User.organization_id == organization_id)
        .filter(User.is_active == 1)
        .order_by(User.full_name.asc(), User.email.asc())
        .all()
    )
    return users


def append_comment(
    investigation: Investigation,
    *,
    author_id: int,
    message: str,
    session: Session,
    comment_id: str | None = None,
) -> dict:
    """Persist a collaboration comment for an investigation."""
    import uuid as _uuid

    cid = comment_id or str(_uuid.uuid4())
    record = InvestigationComment(
        comment_id=cid,
        case_id=investigation.case_id,
        investigation_id=investigation.id,
        author_id=author_id,
        message=message,
    )
    session.add(record)
    session.commit()
    session.refresh(record)

    author = session.query(User).filter(User.id == record.author_id).first()
    return {
        "comment_id": record.comment_id,
        "case_id": record.case_id,
        "author_id": record.author_id,
        "author_name": (author.full_name or author.email) if author else "Unknown",
        "message": record.message,
        "timestamp": record.created_at.isoformat() if record.created_at else None,
    }


def get_comments(
    investigation_id: int,
    *,
    order: str = "asc",
    limit: int | None = None,
    offset: int | None = None,
) -> List[dict]:
    """Return comments for an investigation."""
    with SessionLocal() as session:
        q = (
            session.query(InvestigationComment)
            .filter(InvestigationComment.investigation_id == investigation_id)
        )

        if order == "desc":
            q = q.order_by(InvestigationComment.created_at.desc(), InvestigationComment.id.desc())
        else:
            q = q.order_by(InvestigationComment.created_at.asc(), InvestigationComment.id.asc())

        if offset:
            q = q.offset(offset)
        if limit:
            q = q.limit(limit)

        comments = q.all()
        results = []
        for comment in comments:
            author = session.query(User).filter(User.id == comment.author_id).first()
            results.append(
                {
                    "comment_id": comment.comment_id,
                    "case_id": comment.case_id,
                    "author_id": comment.author_id,
                    "author_name": (author.full_name or author.email) if author else "Unknown",
                    "message": comment.message,
                    "timestamp": comment.created_at.isoformat() if comment.created_at else None,
                }
            )
    return results


def get_dashboard_summary(*, organization_id: int, user_id: int, recent_limit: int = 10) -> dict:
    """Return collaboration dashboard counters and recent activity."""
    with SessionLocal() as session:
        my_open_cases = (
            session.query(Investigation)
            .filter(Investigation.organization_id == organization_id)
            .filter(Investigation.creator_user_id == user_id)
            .filter(Investigation.status != "Closed")
            .count()
        )
        assigned_to_me = (
            session.query(Investigation)
            .filter(Investigation.organization_id == organization_id)
            .filter(Investigation.assigned_user_id == user_id)
            .count()
        )

        events = (
            session.query(InvestigationTimeline, Investigation.case_id)
            .join(Investigation, Investigation.id == InvestigationTimeline.investigation_id)
            .filter(Investigation.organization_id == organization_id)
            .order_by(InvestigationTimeline.created_at.desc(), InvestigationTimeline.id.desc())
            .limit(recent_limit)
            .all()
        )

        recent_activity = []
        for event, case_id in events:
            recent_activity.append(
                {
                    "event_id": event.event_id,
                    "case_id": case_id,
                    "event_type": event.event_type,
                    "title": event.title,
                    "description": event.description,
                    "source": event.source,
                    "metadata": json.loads(event.metadata_json) if event.metadata_json else None,
                    "timestamp": event.created_at.isoformat() if event.created_at else None,
                }
            )

        return {
            "my_open_cases": my_open_cases,
            "assigned_to_me": assigned_to_me,
            "recent_team_activity": recent_activity,
        }


def append_timeline_event(
    investigation_id: int,
    *,
    event_type: str,
    title: str | None = None,
    description: str | None = None,
    source: str | None = "system",
    metadata: Any = None,
    timestamp: Any = None,
    session: Session | None = None,
) -> dict:
    """Append an immutable timeline event for an investigation.

    Attempts to deduplicate identical consecutive events.
    Returns the created event as a dict.
    """
    import uuid as _uuid

    owned_session = False
    if session is None:
        session = SessionLocal()
        owned_session = True

    try:
        # serialize metadata
        meta_json = None
        if metadata is not None:
            try:
                meta_json = json.dumps(metadata)
            except Exception:
                meta_json = str(metadata)

        # check last event for deduplication
        try:
            last = (
                session.query(InvestigationTimeline)
                .filter(InvestigationTimeline.investigation_id == investigation_id)
                .order_by(InvestigationTimeline.created_at.desc(), InvestigationTimeline.id.desc())
                .first()
            )
        except Exception:
            last = None

        if last is not None:
            last_meta = last.metadata_json or None
            if last.event_type == event_type and last.title == (title or last.title) and last.description == (description or last.description) and (last_meta == meta_json):
                # duplicate of last event — return existing
                return {
                    "event_id": last.event_id,
                    "investigation_id": last.investigation_id,
                    "event_type": last.event_type,
                    "title": last.title,
                    "description": last.description,
                    "source": last.source,
                    "metadata": json.loads(last_meta) if last_meta else None,
                    "timestamp": last.created_at.isoformat() if last.created_at else None,
                }

        # create new event
        eid = str(_uuid.uuid4())
        ev = InvestigationTimeline(
            event_id=eid,
            investigation_id=investigation_id,
            event_type=event_type,
            title=title,
            description=description,
            source=source,
            metadata_json=meta_json,
        )
        session.add(ev)
        session.commit()
        session.refresh(ev)

        return {
            "event_id": ev.event_id,
            "investigation_id": ev.investigation_id,
            "event_type": ev.event_type,
            "title": ev.title,
            "description": ev.description,
            "source": ev.source,
            "metadata": json.loads(ev.metadata_json) if ev.metadata_json else None,
            "timestamp": ev.created_at.isoformat() if ev.created_at else None,
        }
    finally:
        if owned_session:
            session.close()


def get_timeline_events(investigation_id: int, order: str = "desc", limit: int | None = None, offset: int | None = None) -> List[dict]:
    """Retrieve timeline events for an investigation."""
    with SessionLocal() as session:
        q = (
            session.query(InvestigationTimeline, Investigation.case_id)
            .join(Investigation, Investigation.id == InvestigationTimeline.investigation_id)
            .filter(InvestigationTimeline.investigation_id == investigation_id)
        )
        if order == "asc":
            q = q.order_by(InvestigationTimeline.created_at.asc(), InvestigationTimeline.id.asc())
        else:
            q = q.order_by(InvestigationTimeline.created_at.desc(), InvestigationTimeline.id.desc())
        if offset:
            q = q.offset(offset)
        if limit:
            q = q.limit(limit)

        results = []
        for ev, case_id in q.all():
            results.append(
                {
                    "event_id": ev.event_id,
                    "case_id": case_id,
                    "investigation_id": ev.investigation_id,
                    "event_type": ev.event_type,
                    "title": ev.title,
                    "description": ev.description,
                    "source": ev.source,
                    "metadata": json.loads(ev.metadata_json) if ev.metadata_json else None,
                    "timestamp": ev.created_at.isoformat() if ev.created_at else None,
                }
            )
        return results


def append_chat_message(
    investigation: Investigation,
    *,
    role: str,
    message: str,
    session: Session,
    message_id: str | None = None,
) -> dict:
    """Persist a single copilot chat message for an investigation."""
    import uuid as _uuid

    mid = message_id or str(_uuid.uuid4())
    record = InvestigationChatMessage(
        message_id=mid,
        case_id=investigation.case_id,
        investigation_id=investigation.id,
        role=role,
        message=message,
    )
    session.add(record)
    session.commit()
    session.refresh(record)
    return {
        "message_id": record.message_id,
        "case_id": record.case_id,
        "role": record.role,
        "message": record.message,
        "timestamp": record.created_at.isoformat() if record.created_at else None,
    }


def get_chat_messages(investigation_id: int, *, order: str = "asc", limit: int | None = None, offset: int | None = None) -> List[dict]:
    """Retrieve persisted chat messages for an investigation."""
    q = (
        SessionLocal()
        .query(InvestigationChatMessage)
        .filter(InvestigationChatMessage.investigation_id == investigation_id)
    )

    if order == "desc":
        q = q.order_by(InvestigationChatMessage.created_at.desc(), InvestigationChatMessage.id.desc())
    else:
        q = q.order_by(InvestigationChatMessage.created_at.asc(), InvestigationChatMessage.id.asc())

    if offset:
        q = q.offset(offset)
    if limit:
        q = q.limit(limit)

    results = []
    for msg in q.all():
        results.append(
            {
                "message_id": msg.message_id,
                "case_id": msg.case_id,
                "role": msg.role,
                "message": msg.message,
                "timestamp": msg.created_at.isoformat() if msg.created_at else None,
            }
        )
    return results


def clear_chat_messages(investigation_id: int, *, session: Session | None = None) -> int:
    """Delete all copilot chat messages for an investigation."""
    owned = False
    if session is None:
        session = SessionLocal()
        owned = True
    try:
        count = (
            session.query(InvestigationChatMessage)
            .filter(InvestigationChatMessage.investigation_id == investigation_id)
            .delete(synchronize_session=False)
        )
        session.commit()
        return int(count)
    finally:
        if owned:
            session.close()
