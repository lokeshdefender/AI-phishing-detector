from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from app.analyzer import analyze_email

app = FastAPI(title="Phishing Analyzer MVP")

# Serve static frontend from /static and the root index
app.mount("/static", StaticFiles(directory="app/static"), name="static")


class AnalyzeRequest(BaseModel):
    email_text: str


@app.post("/analyze")
def analyze(request: AnalyzeRequest):
    """Analyze pasted email text and return URLs, risk score and explanations."""
    result = analyze_email(request.email_text)
    return result


@app.get("/")
def root():
    return FileResponse("app/static/index.html")
