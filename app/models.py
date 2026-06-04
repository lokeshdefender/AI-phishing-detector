from pydantic import BaseModel
from typing import List, Dict, Optional

class AnalyzeResponse(BaseModel):
    urls: List[str]
    score: int
    confidence: int
    indicators: List[Dict]
    explanation: str
    sender: str


class EmailMetadata(BaseModel):
    sender: str
    subject: str
    body_preview: str


class AnalyzeEMLResponse(AnalyzeResponse):
    metadata: Optional[EmailMetadata] = None
