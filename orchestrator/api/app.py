from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from sqlmodel import Session, select
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional

from ..config.settings import settings
from ..config.security import get_api_key
from ..config.limiter import limiter, setup_limiter
from ..services.db import create_db_and_tables, get_session
from ..models.sql_models import Job, JobStatus, FindingModel
from ..services.audit import log_audit
from ..middleware.headers import SecureHeadersMiddleware
from ..middleware.size_limit import LimitUploadSize
from ..services.integrity import verify_system_integrity
from ..services.crypto import decrypt_data
import os
import logging

from pydantic import BaseModel

# Setup Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("adversum.api")

# Define API Application
app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Orchestrator API (Paranoid Mode)",
    docs_url=None, 
    redoc_url=None,
    openapi_url=None # Hide OpenAPI schema completely
)

# --- MIDDLEWARE STACK (Order Matters) ---
# 1. Secure Headers (First applied)
app.add_middleware(SecureHeadersMiddleware)

# 2. Trusted Host
app.add_middleware(
    TrustedHostMiddleware, 
    allowed_hosts=["localhost", "127.0.0.1", "testserver", settings.API_HOST]
)

# 3. Size Limit (Reject big payloads early)
app.add_middleware(LimitUploadSize)

# 4. Strict CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["X-API-KEY", "Content-Type"],
)

# 5. Rate Limiting
setup_limiter(app)


# --- EXCEPTION HANDLERS ---
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Internal Server Error: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal System Error"},
    )

@app.on_event("startup")
def on_startup():
    create_db_and_tables()
    # Run Self-Integrity Check
    verify_system_integrity(os.path.dirname(os.path.dirname(__file__)))


# --- HONEYPOT ENDPOINTS ---
@app.get("/admin")
@app.get("/phpmyadmin")
@app.get("/config")
def honeypot(request: Request, background_tasks: BackgroundTasks):
    """
    Trap for scanners. Logs a CRITICAL security alert.
    """
    ip = request.client.host
    logger.critical(f"HONEYPOT TRIGGERED by {ip} on {request.url.path}")
    background_tasks.add_task(log_audit, "HONEYPOT_TRIGGER", ip, "BLOCKED", f"Attempted access to {request.url.path}")
    
    # Return a generic 404 to not give hints, or a 403.
    # A smart honeypot might hang the connection, but let's just 404.
    raise HTTPException(status_code=404, detail="Not Found")

# API DTOs
class JobRequest(BaseModel):
    project_path: str

class JobResponse(BaseModel):
    job_id: int
    status: str
    project_path: str

class JobDetailResponse(JobResponse):
    findings_count: int
    findings: List[dict] # Simplified for brevity, normally FindingModel schema
    error: Optional[str] = None

@app.get("/health")
def health_check():
    return {"status": "ok", "version": settings.VERSION}

from ..utils.validation import validate_project_path
from ..services.audit import log_audit

async def run_analysis_job(job_id: int):
    """Executes an analysis job asynchronously in background."""
    try:
        from ..pipeline.analysis_pipeline import AnalysisPipeline
        from ..services.db import engine
        from sqlalchemy.ext.asyncio import AsyncSession
        async with AsyncSession(engine, expire_on_commit=False) as session:
            job = await session.get(Job, job_id)
            if not job:
                return
            job.status = JobStatus.RUNNING
            session.add(job)
            await session.commit()
            
            pipeline = AnalysisPipeline()
            result = await pipeline.run(job.project_path)
            
            job.status = JobStatus.COMPLETED
            job.robustness_score = result.get("robustness_score", 1.0)
            job.summary = result.get("summary", "")
            session.add(job)
            await session.commit()
    except Exception as e:
        logger.error(f"Job {job_id} failed: {e}", exc_info=True)


@app.post("/analyze", response_model=JobResponse, dependencies=[Depends(get_api_key)])
@limiter.limit(settings.RATE_LIMIT_ANALYZE)
async def submit_analysis(
    request: Request, # Required for limiter
    job_request: JobRequest, # Renamed to avoid collision
    background_tasks: BackgroundTasks, 
    session: AsyncSession = Depends(get_session)
):
    """
    Submits an analysis job to the queue. Returns immediately.
    Protected by API Key.
    Rate Limited.
    """
    # 1. Security Validation
    safe_path = validate_project_path(job_request.project_path)
    
    # Audit Log (Attempt)
    background_tasks.add_task(log_audit, "SUBMIT_ANALYSIS", safe_path, "SUCCESS")

    # Create Job Record
    job = Job(project_path=safe_path, status=JobStatus.PENDING)
    session.add(job)
    await session.commit()
    await session.refresh(job)
    
    # Trigger Background Task
    background_tasks.add_task(run_analysis_job, job.id)
    
    return JobResponse(job_id=job.id, status=job.status, project_path=job.project_path)

@app.get("/jobs/{job_id}", response_model=JobDetailResponse, dependencies=[Depends(get_api_key)])
async def get_job_status(job_id: int, session: AsyncSession = Depends(get_session)):
    """
    Poll this endpoint to get job status and results.
    """
    job = await session.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
        
    findings_data = []
    if job.status == JobStatus.COMPLETED:
        stmt = select(FindingModel).where(FindingModel.job_id == job_id)
        findings_res = await session.execute(stmt)
        findings_list = findings_res.scalars().all()
        findings_data = [
            {
                "rule_id": f.rule_id,
                "description": decrypt_data(f.description) if f.description else "",
                "severity": f.severity,
                "file": f"{f.file_path}:{f.line_number}",
                "snippet": decrypt_data(f.snippet) if f.snippet else "",
                "ai_status": f.validation_status,
                "remediation": f.remediation_suggestion
            } for f in findings_list
        ]
    
    return JobDetailResponse(
        job_id=job.id,
        status=job.status,
        project_path=job.project_path,
        findings_count=len(findings_data),
        findings=findings_data,
        error=job.error_message
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("adversum.orchestrator.api.app:app", host=settings.API_HOST, port=settings.API_PORT, reload=True)
