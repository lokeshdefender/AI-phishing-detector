from pydantic import BaseModel
from typing import List, Dict, Optional


class AnalystReport(BaseModel):
    threat_level: str
    executive_summary: str
    threat_assessment: str
    key_indicators: List[Dict]
    detection_rationale: str
    remediation_recommendations: List[str]
    confidence_percentage: int


class AnalyzeResponse(BaseModel):
    urls: List[str]
    score: int
    confidence: int
    indicators: List[Dict]
    explanation: str
    sender: str
    analyst_report: AnalystReport
    case_id: Optional[str] = None


class EmailMetadata(BaseModel):
    sender: str
    subject: str
    body_preview: str


class AnalyzeEMLResponse(AnalyzeResponse):
    metadata: Optional[EmailMetadata] = None
