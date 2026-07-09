from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
from app.analyzer import analyze_email
from app.database import init_db
from app.utils import parse_eml_file

app = FastAPI(title="Phishing Analyzer MVP")


@app.on_event("startup")
def startup_event():
    """Initialize the database when the FastAPI application starts."""
    init_db()


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
        return result
    except Exception:
        raise HTTPException(status_code=500, detail="Analysis failed. Please try again.")


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

        return result

    except HTTPException:
        raise  # re-raise our own clean errors
    except Exception:
        raise HTTPException(status_code=500, detail="EML analysis failed. Please try again.")


@app.get("/")
def root():
    return FileResponse("app/static/index.html")