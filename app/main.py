import json
import threading
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import Depends, FastAPI, File, HTTPException, Request, Response, UploadFile, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
from sqlalchemy import or_
from app import auth as auth_module
from app import database as database_module
from app.analyzer import analyze_email
from app.copilot import QUICK_ACTIONS, build_investigation_context, generate_copilot_response
from app.investigation_graph import parse_cached_graph, refresh_investigation_graph
from app.mitre_mapping import parse_cached_mitre, refresh_investigation_mitre
from app.ioc_analyzer import analyze_ioc
from app.investigation_pipeline import process_investigation_input
from app.models_db import Investigation, ThreatIntelIndicator, User
from app.security import (
    ROLE_ADMIN,
    ROLE_ANALYST,
    ROLE_VIEWER,
    create_access_token,
    get_current_user,
    require_min_role,
)
from app.threat_intel import process_investigation_enrichment
from app.utils import parse_eml_file

app = FastAPI(title="Phishing Analyzer MVP")


@app.on_event("startup")
def startup_event():
    """Initialize the database when the FastAPI application starts."""
    database_module.init_db()


# ─────────────────────────────────────────────
#  CORS — required for browser clients
# ─────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # tighten to your domain after deployment
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve static frontend
app.mount("/static", StaticFiles(directory="app/static"), name="static")


# ─────────────────────────────────────────────
#  MODELS
# ─────────────────────────────────────────────
class AnalyzeRequest(BaseModel):
    email_text: str

    @field_validator("email_text")
    @classmethod
    def validate_email_text(cls, v):
        if not v or not v.strip():
            raise ValueError("email_text cannot be empty")
        if len(v) > 100_000:  # 100KB limit
            raise ValueError("email_text too large (max 100KB)")
        return v


class InvestigationUpdateRequest(BaseModel):
    title: Optional[str] = None
    status: Optional[str] = None
    threat_level: Optional[str] = None
    analyst_notes: Optional[str] = None
    analyst_report: Optional[Any] = None
    summary: Optional[str] = None
    assigned_to: Optional[str] = None
    tags: Optional[list[str]] = None
    evidence: Optional[list[str]] = None
    sender: Optional[str] = None
    phishing_score: Optional[int] = None
    confidence: Optional[int] = None
    submitted_text: Optional[str] = None
    urls: Optional[list[str]] = None


class InvestigationAssignmentRequest(BaseModel):
    assigned_user_id: Optional[int] = None


class InvestigationCommentRequest(BaseModel):
    message: str

    @field_validator("message")
    @classmethod
    def validate_message(cls, v):
        value = (v or "").strip()
        if not value:
            raise ValueError("message is required")
        if len(value) > 10_000:
            raise ValueError("message too large (max 10KB)")
        return value


class InvestigateRequest(BaseModel):
    input_text: str
    source_type: Optional[str] = None

    @field_validator("input_text")
    @classmethod
    def validate_input_text(cls, v):
        if not v or not v.strip():
            raise ValueError("input_text cannot be empty")
        if len(v) > 100_000:
            raise ValueError("input_text too large (max 100KB)")
        return v


class IocAnalyzeRequest(BaseModel):
    ioc_value: str
    context: Optional[str] = None

    @field_validator("ioc_value")
    @classmethod
    def validate_ioc_value(cls, v):
        if not v or not v.strip():
            raise ValueError("ioc_value cannot be empty")
        return v


class InvestigationChatRequest(BaseModel):
    message: str
    quick_action: Optional[str] = None

    @field_validator("message")
    @classmethod
    def validate_message(cls, v):
        if not isinstance(v, str):
            raise ValueError("message must be a string")
        if len(v) > 20_000:
            raise ValueError("message too large (max 20KB)")
        return v

    @field_validator("quick_action")
    @classmethod
    def validate_quick_action(cls, v):
        if v is None:
            return v
        if v not in QUICK_ACTIONS:
            raise ValueError("Unsupported quick_action")
        return v


class RegisterRequest(BaseModel):
    email: str
    password: str
    full_name: Optional[str] = None
    organization_name: str
    role: Optional[str] = None

    @field_validator("email")
    @classmethod
    def validate_email(cls, v):
        value = (v or "").strip()
        if not value or "@" not in value:
            raise ValueError("valid email is required")
        return value

    @field_validator("password")
    @classmethod
    def validate_password(cls, v):
        if not v or len(v) < 8:
            raise ValueError("password must be at least 8 characters")
        return v

    @field_validator("organization_name")
    @classmethod
    def validate_organization_name(cls, v):
        if not v or not v.strip():
            raise ValueError("organization_name is required")
        return v.strip()


class LoginRequest(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def validate_email(cls, v):
        value = (v or "").strip()
        if not value or "@" not in value:
            raise ValueError("valid email is required")
        return value

    @field_validator("password")
    @classmethod
    def validate_password(cls, v):
        if not v:
            raise ValueError("password is required")
        return v


def _enqueue_threat_intel_processing(investigation_id: int) -> None:
    """Run enrichment work in a background thread so the UI stays responsive."""
    thread = threading.Thread(target=process_investigation_enrichment, args=(investigation_id,), daemon=True)
    thread.start()


def _persist_analysis(submitted_text: str, result: dict, current_user: User) -> str:
    """Save a completed analysis as a permanent investigation record."""
    with database_module.SessionLocal() as db:
        investigation = database_module.create_investigation_record(
            db,
            submitted_text=submitted_text,
            result=result,
            organization_id=current_user.organization_id,
            creator_user_id=current_user.id,
        )
        case_id = investigation.case_id
        # record phishing analysis completed event
        try:
            database_module.append_timeline_event(
                investigation.id,
                event_type="phishing_analysis_completed",
                title="Phishing analysis completed",
                description=f"Phishing analysis completed with score {result.get('score') or result.get('phishing_score')}",
                source="system",
                metadata={"score": result.get("score") or result.get("phishing_score")},
                session=db,
            )
        except Exception:
            pass

        _enqueue_threat_intel_processing(investigation.id)
        return case_id


def _persist_ioc_analysis(ioc_value: str, result: dict, current_user: User) -> str:
    """Persist an IOC analysis result as an investigation case."""
    with database_module.SessionLocal() as db:
        investigation = database_module.create_investigation_record(
            db,
            submitted_text=f"IOC analysis for {result['ioc_type']}: {ioc_value}",
            result={
                "sender": "",
                "urls": [ioc_value] if result["ioc_type"] in {"URL", "Domain"} else [],
                "score": result["reputation_score"],
                "confidence": min(100, result["reputation_score"] + 10),
                "analyst_report": result["analyst_report"],
                "summary": result["summary"],
                "tags": [result["ioc_type"], "ioc"],
                "evidence": [ioc_value],
            },
            organization_id=current_user.organization_id,
            creator_user_id=current_user.id,
        )
        _enqueue_threat_intel_processing(investigation.id)
        # record IOC analysis completed
        try:
            database_module.append_timeline_event(
                investigation.id,
                event_type="ioc_analysis_completed",
                title="IOC analysis completed",
                description=f"IOC analysis for {result['ioc_type']} {ioc_value} completed.",
                source="system",
                metadata={"ioc_value": ioc_value, "ioc_type": result.get("ioc_type")},
                session=db,
            )
        except Exception:
            pass
        return investigation.case_id


def _serialize_investigation(investigation: Investigation) -> dict:
    """Convert a database record into a JSON-safe payload for the history API."""
    created_at = investigation.created_at.isoformat() if investigation.created_at else ""
    return {
        "id": investigation.id,
        "case_id": investigation.case_id,
        "title": investigation.title,
        "sender": investigation.sender or "Unknown",
        "threat_level": investigation.threat_level or "MINIMAL",
        "status": investigation.status or "Open",
        "created_at": created_at,
        "organization_id": investigation.organization_id,
        "creator_user_id": investigation.creator_user_id,
        "assigned_user_id": investigation.assigned_user_id,
        "assigned_at": investigation.assigned_at.isoformat() if investigation.assigned_at else None,
        "assigned_by": investigation.assigned_by,
    }


def _set_auth_cookie(response: Response, token: str) -> None:
    """Set auth cookie for browser clients."""
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=60 * 60 * 8,
        path="/",
    )


def _clear_auth_cookie(response: Response) -> None:
    """Clear auth cookie for browser logout."""
    response.delete_cookie("access_token", path="/")


def _investigation_query_for_user(db, case_id: str, current_user: User):
    return (
        db.query(Investigation)
        .filter(Investigation.case_id == case_id)
        .filter(
            or_(
                Investigation.organization_id == current_user.organization_id,
                Investigation.organization_id.is_(None),
            )
        )
    )


def _coerce_json_list(value: Any) -> list[str]:
    """Normalize stored JSON values into a list for the API payload."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                return parsed
            return [parsed]
        except (TypeError, json.JSONDecodeError):
            return [value]
    return [str(value)]


def _serialize_graph_payload(value: Any) -> dict:
    """Normalize graph storage into the canonical nodes/edges API shape."""
    parsed = parse_cached_graph(value)
    if parsed:
        return parsed

    legacy_edges: list[Any] = []
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                legacy_edges = parsed
        except (TypeError, json.JSONDecodeError):
            legacy_edges = []
    elif isinstance(value, list):
        legacy_edges = value

    edges = []
    for item in legacy_edges:
        if isinstance(item, dict) and item.get("source") and item.get("target"):
            source = str(item.get("source"))
            target = str(item.get("target"))
            edges.append(
                {
                    "source": source,
                    "target": target,
                    "relationship": item.get("relationship", "related_to"),
                    "metadata": item.get("metadata", {}),
                }
            )

    return {
        "nodes": [],
        "edges": edges,
        "metadata": {"legacy": True},
    }


def _serialize_mitre_payload(value: Any) -> dict:
    """Normalize MITRE mapping storage into a stable API payload."""
    parsed = parse_cached_mitre(value)
    if parsed:
        return parsed
    return {"mappings": [], "metadata": {"unavailable": True}}


def _serialize_investigation_detail(investigation: Investigation) -> dict:
    """Create a richer payload for the investigation details view."""
    detail = _serialize_investigation(investigation)
    detail.update(
        {
            "submitted_text": investigation.submitted_text or "",
            "urls": _coerce_json_list(investigation.urls),
            "phishing_score": investigation.phishing_score,
            "confidence": investigation.confidence,
            "analyst_report": investigation.analyst_report or "",
            "analyst_notes": investigation.analyst_notes or "",
            "investigation_type": investigation.investigation_type or "email",
            "pipeline_stage": investigation.pipeline_stage or "New",
            "timeline": _coerce_json_list(investigation.timeline),
            "graph": _serialize_graph_payload(investigation.graph),
            "mitre": _serialize_mitre_payload(investigation.mitre_mappings),
            "summary": investigation.summary or "",
            "evidence": _coerce_json_list(investigation.evidence),
            "assigned_to": investigation.assigned_to or "",
            "assigned_user_id": investigation.assigned_user_id,
            "assigned_at": investigation.assigned_at.isoformat() if investigation.assigned_at else None,
            "assigned_by": investigation.assigned_by,
            "tags": _coerce_json_list(investigation.tags),
            "updated_at": investigation.updated_at.isoformat() if investigation.updated_at else "",
        }
    )
    return detail


# ─────────────────────────────────────────────
#  ROUTES
# ─────────────────────────────────────────────
@app.get("/health")
def health():
    """Health check endpoint for deployment platforms."""
    return {"status": "ok"}


@app.post("/register")
def register(payload: RegisterRequest, response: Response):
    """Register a new user and issue a session token."""
    database_module.init_db()
    with database_module.SessionLocal() as db:
        user = auth_module.register_user(
            db,
            email=payload.email,
            password=payload.password,
            full_name=payload.full_name,
            organization_name=payload.organization_name,
            role=payload.role,
        )
        token = create_access_token(
            str(user.id),
            extra={
                "org_id": user.organization_id,
                "role": user.role,
                "email": user.email,
            },
        )
        _set_auth_cookie(response, token)
        return {"user": auth_module.serialize_user(user), "access_token": token, "token_type": "bearer"}


@app.post("/login")
def login(payload: LoginRequest, response: Response):
    """Authenticate a user and issue a session token."""
    database_module.init_db()
    with database_module.SessionLocal() as db:
        user = auth_module.authenticate_user(db, email=payload.email, password=payload.password)
        token = create_access_token(
            str(user.id),
            extra={
                "org_id": user.organization_id,
                "role": user.role,
                "email": user.email,
            },
        )
        _set_auth_cookie(response, token)
        return {"user": auth_module.serialize_user(user), "access_token": token, "token_type": "bearer"}


@app.post("/logout")
def logout(response: Response):
    """Logout browser/API session by removing auth cookie."""
    _clear_auth_cookie(response)
    return {"ok": True}


@app.get("/me")
def me(current_user: User = Depends(get_current_user)):
    """Return the authenticated user profile."""
    return {"user": auth_module.serialize_user(current_user)}


@app.get("/users")
def list_users(current_user: User = Depends(get_current_user)):
    """List active users in the current organization for assignment workflows."""
    with database_module.SessionLocal() as db:
        users = database_module.list_organization_users(db, current_user.organization_id)
        return {
            "users": [
                {
                    "id": user.id,
                    "email": user.email,
                    "full_name": user.full_name or "",
                    "role": (user.role or "viewer").lower(),
                }
                for user in users
            ]
        }


@app.get("/dashboard/summary")
def dashboard_summary(current_user: User = Depends(get_current_user)):
    """Return collaboration dashboard metrics for the signed-in user."""
    return database_module.get_dashboard_summary(
        organization_id=current_user.organization_id,
        user_id=current_user.id,
    )


@app.post("/analyze")
def analyze(request: AnalyzeRequest, current_user: User = Depends(require_min_role(ROLE_ANALYST))):
    """Analyze pasted email text and return URLs, risk score and explanations."""
    try:
        result = analyze_email(request.email_text)
        case_id = _persist_analysis(request.email_text, result, current_user)
        result["case_id"] = case_id
        return result
    except Exception:
        raise HTTPException(status_code=500, detail="Analysis failed. Please try again.")


@app.post("/investigate")
def investigate(request: InvestigateRequest, current_user: User = Depends(require_min_role(ROLE_ANALYST))):
    """Run the unified investigation pipeline for mixed investigation inputs."""
    try:
        result = process_investigation_input(request.input_text, source_type=request.source_type)
        case_id = _persist_analysis(request.input_text, result, current_user)
        result["case_id"] = case_id
        return result
    except Exception:
        raise HTTPException(status_code=500, detail="Investigation failed. Please try again.")


@app.post("/analyze-eml")
async def analyze_eml(
    file: UploadFile = File(...),
    current_user: User = Depends(require_min_role(ROLE_ANALYST)),
):
    """Upload and analyze .eml email file."""
    try:
        # File size limit: 1MB
        content = await file.read(1_000_000)
        if len(content) >= 1_000_000:
            raise HTTPException(status_code=413, detail="File too large (max 1MB)")

        metadata = parse_eml_file(content)

        if metadata.get("error"):
            raise HTTPException(status_code=422, detail=f"Could not parse .eml file: {metadata['error']}")

        result = analyze_email(metadata["full_text"])

        result["metadata"] = {
            "sender": metadata["sender"],
            "subject": metadata["subject"],
            "body_preview": metadata["body"][:200] + "..." if len(metadata["body"]) > 200 else metadata["body"],
        }

        case_id = _persist_analysis(metadata["full_text"], result, current_user)
        result["case_id"] = case_id

        return result

    except HTTPException:
        raise  # re-raise our own clean errors
    except Exception:
        raise HTTPException(status_code=500, detail="EML analysis failed. Please try again.")


@app.get("/investigations")
def list_investigations(
    filter_by: Optional[str] = None,
    current_user: User = Depends(get_current_user),
):
    """Return investigation history sorted newest-first."""
    with database_module.SessionLocal() as db:
        query = (
            db.query(Investigation)
            .filter(
                or_(
                    Investigation.organization_id == current_user.organization_id,
                    Investigation.organization_id.is_(None),
                )
            )
        )

        selected_filter = (filter_by or "").strip().lower()
        if selected_filter == "my_investigations":
            query = query.filter(Investigation.creator_user_id == current_user.id)
        elif selected_filter == "assigned_to_me":
            query = query.filter(Investigation.assigned_user_id == current_user.id)
        elif selected_filter == "open":
            query = query.filter(Investigation.status != "Closed")
        elif selected_filter == "closed":
            query = query.filter(Investigation.status == "Closed")
        elif selected_filter == "high_risk":
            query = query.filter(Investigation.threat_level.in_(["HIGH", "CRITICAL"]))
        elif selected_filter == "unassigned":
            query = query.filter(Investigation.assigned_user_id.is_(None))

        investigations = query.order_by(Investigation.created_at.desc(), Investigation.id.desc()).all()
        return [_serialize_investigation(item) for item in investigations]


@app.get("/investigations/{case_id}")
def investigation_detail(case_id: str, request: Request, current_user: User = Depends(get_current_user)):
    """Serve the details page for browser navigation, or return the stored investigation JSON for API clients."""
    accept_header = request.headers.get("accept", "")
    if "text/html" in accept_header.lower():
        return FileResponse("app/static/investigation-details.html")

    with database_module.SessionLocal() as db:
        investigation = _investigation_query_for_user(db, case_id, current_user).first()
        if not investigation:
            raise HTTPException(status_code=404, detail="Investigation not found")
        return _serialize_investigation_detail(investigation)


@app.get("/investigations/{case_id}/graph")
def investigation_graph(case_id: str, current_user: User = Depends(get_current_user)):
    """Return a relationship graph for the selected investigation."""
    with database_module.SessionLocal() as db:
        investigation = _investigation_query_for_user(db, case_id, current_user).first()
        if not investigation:
            raise HTTPException(status_code=404, detail="Investigation not found")

        try:
            graph = refresh_investigation_graph(db, investigation, force=False)
            db.commit()
            return graph
        except Exception:
            cached = parse_cached_graph(investigation.graph)
            if cached:
                return cached
            return {"nodes": [], "edges": [], "metadata": {"case_id": case_id, "error": "graph_unavailable"}}


@app.get("/investigations/{case_id}/mitre")
def investigation_mitre(case_id: str, current_user: User = Depends(get_current_user)):
    """Return MITRE ATT&CK mappings for an investigation."""
    with database_module.SessionLocal() as db:
        investigation = _investigation_query_for_user(db, case_id, current_user).first()
        if not investigation:
            raise HTTPException(status_code=404, detail="Investigation not found")

        try:
            payload = refresh_investigation_mitre(db, investigation, force=False)
            db.commit()
            return payload
        except Exception:
            cached = parse_cached_mitre(investigation.mitre_mappings)
            if cached:
                return cached
            return {"mappings": [], "metadata": {"case_id": case_id, "error": "mitre_unavailable"}}


@app.get("/investigations/{case_id}/intel")
def investigation_intel(case_id: str, current_user: User = Depends(get_current_user)):
    """Return enrichment results for an investigation's extracted IOCs."""
    with database_module.SessionLocal() as db:
        investigation = _investigation_query_for_user(db, case_id, current_user).first()
        if not investigation:
            raise HTTPException(status_code=404, detail="Investigation not found")

        indicators = (
            db.query(ThreatIntelIndicator)
            .filter(ThreatIntelIndicator.investigation_id == investigation.id)
            .order_by(ThreatIntelIndicator.risk_score.desc(), ThreatIntelIndicator.created_at.desc())
            .all()
        )

        return [
            {
                "ioc_value": indicator.ioc_value,
                "ioc_type": indicator.ioc_type,
                "source_providers": json.loads(indicator.source_providers or "[]"),
                "reputation": indicator.reputation,
                "confidence": indicator.confidence,
                "risk_score": indicator.risk_score,
                "detection_summary": indicator.detection_summary,
                "evidence": json.loads(indicator.evidence or "[]"),
                "provider_results": json.loads(indicator.provider_responses or "{}"),
            }
            for indicator in indicators
        ]



@app.get("/investigations/{case_id}/timeline")
def investigation_timeline(
    case_id: str,
    order: str = "desc",
    limit: int | None = None,
    offset: int | None = None,
    current_user: User = Depends(get_current_user),
):
    """Return timeline events for an investigation."""
    with database_module.SessionLocal() as db:
        investigation = _investigation_query_for_user(db, case_id, current_user).first()
        if not investigation:
            raise HTTPException(status_code=404, detail="Investigation not found")
        events = database_module.get_timeline_events(investigation.id, order=order, limit=limit, offset=offset)
        return events


@app.post("/investigations/{case_id}/timeline")
def add_timeline_event(
    case_id: str,
    payload: dict,
    current_user: User = Depends(require_min_role(ROLE_ANALYST)),
):
    """Append a manual timeline event for an investigation."""
    with database_module.SessionLocal() as db:
        investigation = _investigation_query_for_user(db, case_id, current_user).first()
        if not investigation:
            raise HTTPException(status_code=404, detail="Investigation not found")
        try:
            event_type = payload.get("event_type")
            if not event_type:
                raise HTTPException(status_code=422, detail="event_type is required")
            ev = database_module.append_timeline_event(
                investigation.id,
                event_type=str(event_type),
                title=payload.get("title"),
                description=payload.get("description"),
                source=payload.get("source", "analyst"),
                metadata=payload.get("metadata"),
            )
            return ev
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))


@app.patch("/investigations/{case_id}/assignment")
def update_assignment(
    case_id: str,
    payload: InvestigationAssignmentRequest,
    current_user: User = Depends(require_min_role(ROLE_ANALYST)),
):
    """Assign or unassign an investigation to an organization user."""
    with database_module.SessionLocal() as db:
        investigation = _investigation_query_for_user(db, case_id, current_user).first()
        if not investigation:
            raise HTTPException(status_code=404, detail="Investigation not found")

        target_user = None
        target_id = payload.assigned_user_id
        if target_id is not None:
            target_user = db.query(User).filter(User.id == target_id).first()
            if not target_user or target_user.organization_id != current_user.organization_id:
                raise HTTPException(status_code=404, detail="Assignee not found")

        previous_assignee = investigation.assigned_user_id

        investigation.assigned_user_id = target_user.id if target_user else None
        investigation.assigned_to = (target_user.full_name or target_user.email) if target_user else ""
        investigation.assigned_by = current_user.id if target_user else None
        investigation.assigned_at = datetime.now(timezone.utc) if target_user else None
        investigation.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(investigation)

        try:
            database_module.append_timeline_event(
                investigation.id,
                event_type="assignment_changed",
                title="Assignment changed",
                description=(
                    f"Assigned to {(target_user.full_name or target_user.email)}"
                    if target_user
                    else "Case unassigned"
                ),
                source="analyst",
                metadata={
                    "from": previous_assignee,
                    "to": investigation.assigned_user_id,
                    "changed_by": current_user.id,
                },
                session=db,
            )
        except Exception:
            pass

        return {
            "case_id": investigation.case_id,
            "assigned_user_id": investigation.assigned_user_id,
            "assigned_to": investigation.assigned_to,
            "assigned_at": investigation.assigned_at.isoformat() if investigation.assigned_at else None,
            "assigned_by": investigation.assigned_by,
        }


@app.get("/investigations/{case_id}/comments")
def list_comments(
    case_id: str,
    order: str = "asc",
    limit: int | None = None,
    offset: int | None = None,
    current_user: User = Depends(get_current_user),
):
    """Return collaboration comments for an investigation."""
    with database_module.SessionLocal() as db:
        investigation = _investigation_query_for_user(db, case_id, current_user).first()
        if not investigation:
            raise HTTPException(status_code=404, detail="Investigation not found")
        comments = database_module.get_comments(
            investigation.id,
            order=order,
            limit=limit,
            offset=offset,
        )
        return {"case_id": case_id, "comments": comments}


@app.post("/investigations/{case_id}/comments")
def add_comment(
    case_id: str,
    payload: InvestigationCommentRequest,
    current_user: User = Depends(get_current_user),
):
    """Add collaboration comment to an investigation."""
    with database_module.SessionLocal() as db:
        investigation = _investigation_query_for_user(db, case_id, current_user).first()
        if not investigation:
            raise HTTPException(status_code=404, detail="Investigation not found")

        comment = database_module.append_comment(
            investigation,
            author_id=current_user.id,
            message=payload.message.strip(),
            session=db,
        )

        try:
            database_module.append_timeline_event(
                investigation.id,
                event_type="comment_added",
                title="Comment added",
                description=payload.message.strip()[:200],
                source="analyst",
                metadata={"author_id": current_user.id, "comment_id": comment["comment_id"]},
                session=db,
            )
        except Exception:
            pass

        return comment


@app.get("/investigations/{case_id}/activity")
def investigation_activity(
    case_id: str,
    order: str = "desc",
    limit: int | None = None,
    offset: int | None = None,
    current_user: User = Depends(get_current_user),
):
    """Return collaboration activity log for an investigation."""
    with database_module.SessionLocal() as db:
        investigation = _investigation_query_for_user(db, case_id, current_user).first()
        if not investigation:
            raise HTTPException(status_code=404, detail="Investigation not found")
        events = database_module.get_timeline_events(investigation.id, order=order, limit=limit, offset=offset)
        return {"case_id": case_id, "activity": events}


@app.post("/investigations/{case_id}/chat")
def investigation_chat(case_id: str, payload: InvestigationChatRequest, current_user: User = Depends(get_current_user)):
    """Generate and persist an investigation-scoped copilot response."""
    with database_module.SessionLocal() as db:
        investigation = _investigation_query_for_user(db, case_id, current_user).first()
        if not investigation:
            raise HTTPException(status_code=404, detail="Investigation not found")

        user_message = (payload.message or "").strip()
        if not user_message and not payload.quick_action:
            raise HTTPException(status_code=422, detail="message cannot be empty")

        try:
            context = build_investigation_context(db, investigation)
            effective_message = user_message or QUICK_ACTIONS.get(payload.quick_action or "", "")
            assistant_message = generate_copilot_response(
                context,
                effective_message,
                quick_action=payload.quick_action,
            )

            user_record = database_module.append_chat_message(
                investigation,
                role="user",
                message=effective_message,
                session=db,
            )
            assistant_record = database_module.append_chat_message(
                investigation,
                role="assistant",
                message=assistant_message,
                session=db,
            )

            return {
                "case_id": case_id,
                "quick_action": payload.quick_action,
                "messages": [user_record, assistant_record],
                "response": assistant_record,
            }
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Copilot chat failed: {str(exc)}")


@app.get("/investigations/{case_id}/chat")
def investigation_chat_history(
    case_id: str,
    order: str = "asc",
    limit: int | None = None,
    offset: int | None = None,
    current_user: User = Depends(get_current_user),
):
    """Return persisted copilot conversation history for an investigation."""
    with database_module.SessionLocal() as db:
        investigation = _investigation_query_for_user(db, case_id, current_user).first()
        if not investigation:
            raise HTTPException(status_code=404, detail="Investigation not found")
        messages = database_module.get_chat_messages(
            investigation.id,
            order=order,
            limit=limit,
            offset=offset,
        )
        return {"case_id": case_id, "messages": messages}


@app.delete("/investigations/{case_id}/chat")
def investigation_chat_clear(case_id: str, current_user: User = Depends(get_current_user)):
    """Delete all persisted copilot messages for an investigation."""
    with database_module.SessionLocal() as db:
        investigation = _investigation_query_for_user(db, case_id, current_user).first()
        if not investigation:
            raise HTTPException(status_code=404, detail="Investigation not found")
        deleted = database_module.clear_chat_messages(investigation.id, session=db)
        return {"case_id": case_id, "deleted": deleted}


@app.patch("/investigations/{case_id}")
@app.put("/investigations/{case_id}")
def update_investigation(
    case_id: str,
    payload: InvestigationUpdateRequest,
    current_user: User = Depends(require_min_role(ROLE_ANALYST)),
):
    """Update an existing investigation with analyst workflow changes."""
    with database_module.SessionLocal() as db:
        investigation = _investigation_query_for_user(db, case_id, current_user).first()
        if not investigation:
            raise HTTPException(status_code=404, detail="Investigation not found")

        # capture original values for change events
        orig_status = investigation.status
        orig_notes = investigation.analyst_notes
        graph_inputs_changed = False

        if payload.title is not None:
            investigation.title = payload.title
            graph_inputs_changed = True
        if payload.status is not None:
            investigation.status = payload.status
            graph_inputs_changed = True
        if payload.threat_level is not None:
            investigation.threat_level = payload.threat_level
            graph_inputs_changed = True
        if payload.analyst_notes is not None:
            investigation.analyst_notes = payload.analyst_notes
            graph_inputs_changed = True
        if payload.analyst_report is not None:
            investigation.analyst_report = json.dumps(payload.analyst_report) if not isinstance(payload.analyst_report, str) else payload.analyst_report
            graph_inputs_changed = True
        if payload.summary is not None:
            investigation.summary = payload.summary
        if payload.assigned_to is not None:
            investigation.assigned_to = payload.assigned_to
        if payload.tags is not None:
            investigation.tags = json.dumps(payload.tags)
        if payload.evidence is not None:
            investigation.evidence = json.dumps(payload.evidence)
            graph_inputs_changed = True
        if payload.sender is not None:
            investigation.sender = payload.sender
            graph_inputs_changed = True
        if payload.phishing_score is not None:
            investigation.phishing_score = payload.phishing_score
        if payload.confidence is not None:
            investigation.confidence = payload.confidence
        if payload.submitted_text is not None:
            investigation.submitted_text = payload.submitted_text
            graph_inputs_changed = True
        if payload.urls is not None:
            investigation.urls = json.dumps(payload.urls)
            graph_inputs_changed = True

        if graph_inputs_changed:
            try:
                refresh_investigation_graph(db, investigation, force=False)
            except Exception:
                pass
            try:
                refresh_investigation_mitre(db, investigation, force=False)
            except Exception:
                pass

        investigation.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(investigation)

        # emit status changed event
        try:
            if payload.status is not None and payload.status != orig_status:
                database_module.append_timeline_event(
                    investigation.id,
                    event_type="status_changed",
                    title="Status changed",
                    description=f"Status changed from {orig_status} to {payload.status}",
                    source="analyst",
                    metadata={"from": orig_status, "to": payload.status, "changed_by": current_user.email},
                    session=db,
                )
                # if closed, also emit investigation_closed
                if payload.status == "Closed":
                    database_module.append_timeline_event(
                        investigation.id,
                        event_type="investigation_closed",
                        title="Investigation closed",
                        description="Case closed by analyst",
                        source="analyst",
                        metadata={},
                        session=db,
                    )
        except Exception:
            pass

        # emit analyst note events
        try:
            if payload.analyst_notes is not None and payload.analyst_notes != orig_notes:
                event_type = "analyst_note_added" if not orig_notes else "analyst_note_updated"
                database_module.append_timeline_event(
                    investigation.id,
                    event_type=event_type,
                    title="Analyst notes updated" if event_type == "analyst_note_updated" else "Analyst notes added",
                    description=(payload.analyst_notes or ""),
                    source="analyst",
                    metadata={"changed_by": current_user.email},
                    session=db,
                )
        except Exception:
            pass

        return _serialize_investigation_detail(investigation)


@app.get("/ioc-analyzer")
def ioc_analyzer_page(request: Request):
    """Serve the dedicated IOC analyzer page."""
    token = request.cookies.get("access_token")
    if not token:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    return FileResponse("app/static/ioc-analyzer.html")


@app.post("/ioc-analyze")
def analyze_ioc_endpoint(request: IocAnalyzeRequest, current_user: User = Depends(require_min_role(ROLE_ANALYST))):
    """Analyze an IOC, enrich it, and save it as an investigation case."""
    try:
        result = analyze_ioc(request.ioc_value)
        case_id = _persist_ioc_analysis(request.ioc_value, result, current_user)
        result["case_id"] = case_id
        return result
    except Exception:
        raise HTTPException(status_code=500, detail="IOC analysis failed. Please try again.")


@app.get("/history")
def history_page(request: Request):
    """Serve the investigation history page."""
    token = request.cookies.get("access_token")
    if not token:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    return FileResponse("app/static/history.html")


@app.get("/login")
def login_page(request: Request):
    """Serve login page or redirect active sessions to analyzer."""
    token = request.cookies.get("access_token")
    if token:
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    return FileResponse("app/static/login.html")


@app.get("/register")
def register_page(request: Request):
    """Serve registration page or redirect active sessions to analyzer."""
    token = request.cookies.get("access_token")
    if token:
        return RedirectResponse(url="/", status_code=status.HTTP_302_FOUND)
    return FileResponse("app/static/register.html")


@app.get("/")
def root(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    return FileResponse("app/static/index.html")