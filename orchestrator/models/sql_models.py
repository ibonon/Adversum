from typing import Optional, List
from datetime import datetime
from sqlmodel import SQLModel, Field, Relationship
from enum import Enum

class JobStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

class Job(SQLModel, table=True):
    __table_args__ = {'extend_existing': True}
    
    id: Optional[int] = Field(default=None, primary_key=True)
    project_path: str = Field(index=True)
    status: JobStatus = Field(default=JobStatus.PENDING, index=True)
    created_at: datetime = Field(default_factory=datetime.utcnow, index=True)  # Added index for sorting
    completed_at: Optional[datetime] = Field(None, index=True)  # FIX: Added index for filtering/sorting
    summary: Optional[str] = None # Generated AI summary
    error_message: Optional[str] = None
    robustness_score: float = Field(default=1.0) # Global ARS
    
    findings: List["FindingModel"] = Relationship(back_populates="job")

class FindingModel(SQLModel, table=True):
    __table_args__ = {'extend_existing': True}
    
    id: Optional[int] = Field(default=None, primary_key=True)
    job_id: Optional[int] = Field(default=None, foreign_key="job.id", index=True)
    job: Optional[Job] = Relationship(back_populates="findings")
    
    # Raw Data
    rule_id: str = Field(index=True) # External rule reference
    message: str
    severity: str = Field(index=True)
    file_path: str = Field(index=True)
    line: int
    snippet: Optional[str] = None
    
    # Validation Data
    validation_status: str = Field(index=True)
    ai_confidence: float
    reasoning_notes: str
    remediation_suggestion: Optional[str] = None
    
    # Auto-Remediation Data
    fix_description: Optional[str] = None
    fix_code: Optional[str] = None
    proof_anchor: Optional[str] = Field(None, index=True)
    is_fixed: bool = Field(default=False, index=True)

class AuditLog(SQLModel, table=True):
    __table_args__ = {'extend_existing': True}
    
    id: Optional[int] = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    action: str
    target: str
    user_identifier: Optional[str] = "system" # Future: User ID
    status: str
    details: Optional[str] = None

class FileHash(SQLModel, table=True):
    __table_args__ = {'extend_existing': True}
    
    id: Optional[int] = Field(default=None, primary_key=True)
    file_path: str = Field(index=True, unique=True)
    xxh3_hash: str
    last_scanned_at: datetime = Field(default_factory=datetime.utcnow)
    
class CachedFinding(SQLModel, table=True):
    __table_args__ = {'extend_existing': True}
    
    id: Optional[int] = Field(default=None, primary_key=True)
    file_path: str = Field(index=True)
    finding_data_json: str # Store the serialized RawFinding
