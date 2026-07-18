from pydantic import BaseModel
from typing import List, Optional

class ScanRequest(BaseModel):
    path: str
    project_id: str

class Finding(BaseModel):
    rule_id: str
    description: str
    severity: str
    location: str
    score: Optional[float] = None

class AnalysisResult(BaseModel):
    project_id: str
    files_analyzed: int
    findings: List[Finding]
    status: str
