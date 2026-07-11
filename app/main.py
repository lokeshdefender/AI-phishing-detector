import json
import threading
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
from app import database as database_module
from app.analyzer import analyze_email
from app.ioc_analyzer import analyze_ioc
from app.investigation_pipeline import process_investigation_input
from app.models_db import Investigation, ThreatIntelIndicator
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


def _enqueue_threat_intel_processing(investigation_id: int) -> None:
    """Run enrichment work in a background thread so the UI stays responsive."""
    thread = threading.Thread(target=process_investigation_enrichment, args=(investigation_id,), daemon=True)
    thread.start()


def _persist_analysis(submitted_text: str, result: dict) -> str:
    """Save a completed analysis as a permanent investigation record."""
    with database_module.SessionLocal() as db:
        investigation = database_module.create_investigation_record(
            db,
            submitted_text=submitted_text,
            result=result,
        )
        _enqueue_threat_intel_processing(investigation.id)
        return investigation.case_id


def _persist_ioc_analysis(ioc_value: str, result: dict) -> str:
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
        )
        _enqueue_threat_intel_processing(investigation.id)
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
    }


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
            "graph": _coerce_json_list(investigation.graph),
            "summary": investigation.summary or "",
            "evidence": _coerce_json_list(investigation.evidence),
            "assigned_to": investigation.assigned_to or "",
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


@app.post("/analyze")
def analyze(request: AnalyzeRequest):
    """Analyze pasted email text and return URLs, risk score and explanations."""
    try:
        result = analyze_email(request.email_text)
        case_id = _persist_analysis(request.email_text, result)
        result["case_id"] = case_id
        return result
    except Exception:
        raise HTTPException(status_code=500, detail="Analysis failed. Please try again.")


@app.post("/investigate")
def investigate(request: InvestigateRequest):
    """Run the unified investigation pipeline for mixed investigation inputs."""
    try:
        result = process_investigation_input(request.input_text, source_type=request.source_type)
        case_id = _persist_analysis(request.input_text, result)
        result["case_id"] = case_id
        return result
    except Exception:
        raise HTTPException(status_code=500, detail="Investigation failed. Please try again.")


@app.post("/analyze-eml")
async def analyze_eml(file: UploadFile = File(...)):
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

        case_id = _persist_analysis(metadata["full_text"], result)
        result["case_id"] = case_id

        return result

    except HTTPException:
        raise  # re-raise our own clean errors
    except Exception:
        raise HTTPException(status_code=500, detail="EML analysis failed. Please try again.")


@app.get("/investigations")
def list_investigations():
    """Return investigation history sorted newest-first."""
    with database_module.SessionLocal() as db:
        investigations = (
            db.query(Investigation)
            .order_by(Investigation.created_at.desc(), Investigation.id.desc())
            .all()
        )
        return [_serialize_investigation(item) for item in investigations]


@app.get("/investigations/{case_id}")
def investigation_detail(case_id: str, request: Request):
    """Serve the details page for browser navigation, or return the stored investigation JSON for API clients."""
    accept_header = request.headers.get("accept", "")
    if "text/html" in accept_header.lower():
        return FileResponse("app/static/investigation-details.html")

    with database_module.SessionLocal() as db:
        investigation = db.query(Investigation).filter(Investigation.case_id == case_id).first()
        if not investigation:
            raise HTTPException(status_code=404, detail="Investigation not found")
        return _serialize_investigation_detail(investigation)


@app.get("/investigations/{case_id}/intel")
def investigation_intel(case_id: str):
    """Return enrichment results for an investigation's extracted IOCs."""
    with database_module.SessionLocal() as db:
        investigation = db.query(Investigation).filter(Investigation.case_id == case_id).first()
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


@app.patch("/investigations/{case_id}")
@app.put("/investigations/{case_id}")
def update_investigation(case_id: str, payload: InvestigationUpdateRequest):
    """Update an existing investigation with analyst workflow changes."""
    with database_module.SessionLocal() as db:
        investigation = db.query(Investigation).filter(Investigation.case_id == case_id).first()
        if not investigation:
            raise HTTPException(status_code=404, detail="Investigation not found")

        if payload.title is not None:
            investigation.title = payload.title
        if payload.status is not None:
            investigation.status = payload.status
        if payload.threat_level is not None:
            investigation.threat_level = payload.threat_level
        if payload.analyst_notes is not None:
            investigation.analyst_notes = payload.analyst_notes
        if payload.analyst_report is not None:
            investigation.analyst_report = json.dumps(payload.analyst_report) if not isinstance(payload.analyst_report, str) else payload.analyst_report
        if payload.summary is not None:
            investigation.summary = payload.summary
        if payload.assigned_to is not None:
            investigation.assigned_to = payload.assigned_to
        if payload.tags is not None:
            investigation.tags = json.dumps(payload.tags)
        if payload.evidence is not None:
            investigation.evidence = json.dumps(payload.evidence)
        if payload.sender is not None:
            investigation.sender = payload.sender
        if payload.phishing_score is not None:
            investigation.phishing_score = payload.phishing_score
        if payload.confidence is not None:
            investigation.confidence = payload.confidence
        if payload.submitted_text is not None:
            investigation.submitted_text = payload.submitted_text
        if payload.urls is not None:
            investigation.urls = json.dumps(payload.urls)

        investigation.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(investigation)
        return _serialize_investigation_detail(investigation)


@app.get("/ioc-analyzer")
def ioc_analyzer_page():
    """Serve the dedicated IOC analyzer page."""
    return FileResponse("app/static/ioc-analyzer.html")


@app.post("/ioc-analyze")
def analyze_ioc_endpoint(request: IocAnalyzeRequest):
    """Analyze an IOC, enrich it, and save it as an investigation case."""
    try:
        result = analyze_ioc(request.ioc_value)
        case_id = _persist_ioc_analysis(request.ioc_value, result)
        result["case_id"] = case_id
        return result
    except Exception:
        raise HTTPException(status_code=500, detail="IOC analysis failed. Please try again.")


@app.get("/history")
def history_page():
    """Serve the investigation history page."""
    return FileResponse("app/static/history.html")


@app.get("/")
def root():
    return FileResponse("app/static/index.html")