from fastapi import FastAPI, UploadFile, File
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from app.analyzer import analyze_email
from app.utils import parse_eml_file

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


@app.post("/analyze-eml")
async def analyze_eml(file: UploadFile = File(...)):
    """Upload and analyze .eml email file."""
    try:
        content = await file.read()
        metadata = parse_eml_file(content)
        
        if metadata.get('error'):
            return {"error": metadata['error']}
        
        # Analyze the full email text
        result = analyze_email(metadata['full_text'])
        
        # Add metadata to result
        result['metadata'] = {
            'sender': metadata['sender'],
            'subject': metadata['subject'],
            'body_preview': metadata['body'][:200] + '...' if len(metadata['body']) > 200 else metadata['body']
        }
        
        return result
    except Exception as e:
        return {"error": str(e)}


@app.get("/")
def root():
    return FileResponse("app/static/index.html")
