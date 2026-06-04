from pydantic import BaseModel
from typing import List, Dict

class AnalyzeResponse(BaseModel):
    urls: List[str]
    score: int
    confidence: int
    indicators: List[Dict]
    explanation: str
    sender: str
