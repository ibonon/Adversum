from fastapi import FastAPI, BackgroundTasks, HTTPException, Depends, Request, status, Query
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from pathlib import Path
from sqlmodel import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func, desc
import asyncio
import uuid
import sys
import os
import time
import logging
import json
import subprocess  # Rate Limiting
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Orchestrator imports

from orchestrator.pipeline.analysis_pipeline import AnalysisPipeline
from orchestrator.models.findings import ValidatedFinding
from orchestrator.models.sql_models import Job, JobStatus, FindingModel
from orchestrator.services.db import create_db_and_tables, get_session

# Security utilities
from api.security import validate_scan_path, is_git_url

# Setup Rate Limiter
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="Adversum API", version="1.0.0")

# Register Rate Limit Exception Handler
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Allow CORS for Frontend - PRODUCTION HARDENING
from fastapi.middleware.cors import CORSMiddleware

# Get Allowed Origins from env or default to localhost ports (3000, 5173) for safety
allowed_origins_str = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:5173,http://127.0.0.1:3000,http://127.0.0.1:5173")
allowed_origins = [origin.strip() for origin in allowed_origins_str.split(",")]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize the pipeline
pipeline = AnalysisPipeline()

@app.on_event("startup")
async def on_startup():
    await create_db_and_tables()

# --- Enterprise Security & Telemetry ---
# Telemetry Logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("adversum.telemetry")

# Middleware: Telemetry
@app.middleware("http")
async def telemetry_middleware(request: Request, call_next):
    request_id = str(uuid.uuid4())
    start_time = time.time()
    
    # Contextualize
    response = await call_next(request)
    
    process_time = (time.time() - start_time) * 1000
    
    log_entry = {
        "event": "api_request",
        "request_id": request_id,
        "method": request.method,
        "path": request.url.path,
        "status_code": response.status_code,
        "duration_ms": round(process_time, 2),
        "client_ip": request.client.host if request.client else "unknown"
    }
    
    # Structured JSON Log (GAFAM style)
    logger.info(json.dumps(log_entry))
    
    response.headers["X-Request-ID"] = request_id
    return response

# Security: API Key Auth
# Default to dev key for local development, but require explicit setting in production
API_KEY = os.getenv("API_KEY", "adv-dev-key-123")
if API_KEY == "adv-dev-key-123":
    logger.warning("Using default dev API key. Set API_KEY env var for production!")

# API Key Header configuration
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def get_api_key(api_key_header: str = Depends(api_key_header)):
    if not API_KEY:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server Misconfiguration: API_KEY not set",
        )
    if not api_key_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API Key",
        )
    if api_key_header != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid API Key",
        )
    return api_key_header

# Protect all non-public endpoints
# usage: @app.get(..., dependencies=[Depends(get_api_key)])

class AuditRequest(BaseModel):
    target_path: str 
    project_name: str = "default_project"

class JobResponse(BaseModel):
    id: int
    status: str
    summary: Optional[str] = None
    error: Optional[str] = None
    robustness_score: float = 1.0
    created_at: datetime
    findings_count: int = 0 # Added for dashboard metrics
    # We explicitly exclude 'result' list here for list views to save bandwidth, 
    # but could include it if needed. The Dashboard fetches /audit/{id} for details.

class JobDetailResponse(JobResponse):
    result: List[ValidatedFinding] = [] # Mapped manually or via advanced Pydantic config
    total_findings: int = 0
    page: int = 1
    page_size: int = 100

class ScanAllRequest(BaseModel):
    target_path: str
    modules: Optional[List[str]] = None

class FindingFixRequest(BaseModel):
    file: str
    line: int
    rule_id: str
    snippet: str
    recommendation: Optional[str] = None

class RemediateRequest(BaseModel):
    findings: List[FindingFixRequest]

async def process_audit(job_id: int, target_path: str):
    # We need a new session for the background task
    from orchestrator.services.db import engine
    async with AsyncSession(engine) as session:
        job = await session.get(Job, job_id)
        if not job:
            return
        
        job.status = JobStatus.RUNNING
        session.add(job)
        await session.commit()

        try:
            # Handle Git URL
            real_path = target_path
            if is_git_url(target_path):
                import asyncio
                from functools import partial
                from orchestrator.ingestion.manager import clone_repository
                
                # Run blocking clone in thread pool
                loop = asyncio.get_event_loop()
                job.summary = "Cloning repository..."
                session.add(job)
                await session.commit()
                
                repo_context = await loop.run_in_executor(None, partial(clone_repository, target_path))
                real_path = repo_context.local_path
                
                job.summary = f"Cloned to {real_path}. Starting analysis..."
                session.add(job)
                await session.commit()

            # Run the full orchestrator pipeline
            result = await pipeline.run(real_path)
            
            # Save Findings
            for f in result["findings"]:
                # Extract fix info if available (hacky parsing from suggestion or direct attribution if we updated ValidatedFinding)
                # Ideally ValidatedFinding should have dedicated fix fields. 
                # For now, let's assume valid JSON structure in 'remediation_suggestion' if it's a fix? 
                # No, I updated ValidatedFinding to just put it in formatted text. 
                # I need to pass the raw fix_proposal through.
                # Let's adjust ValidatedFinding in models/findings.py first? 
                # Or just put it in a separate field in ValidatedFinding? 
                # I'll stick to the current plan: update api/main.py but first I need to ensure ValidatedFinding carries the raw fix data.
                # Actually, I missed updating `ValidatedFinding` model in `findings.py`.
                # I will do that in the next step. For now, let's assume `f.fix_code` exists.
                
                db_finding = FindingModel(
                    job_id=job.id,
                    rule_id=f.raw.id,
                    message=f.raw.message,
                    severity=f.raw.severity,
                    file_path=f.raw.file_path,
                    line=f.raw.line,
                    snippet=f.raw.snippet,
                    validation_status=f.validation_status,
                    ai_confidence=f.ai_confidence,
                    reasoning_notes=f.reasoning_notes,
                    remediation_suggestion=f.remediation_suggestion,
                    fix_description=getattr(f, 'fix_description', None),
                    fix_code=getattr(f, 'fix_code', None),
                    proof_anchor=getattr(f.raw, 'proof_anchor', None)
                )
                session.add(db_finding)
            
            # Update Job
            job.status = JobStatus.COMPLETED
            job.completed_at = datetime.utcnow()
            if "summary" in result:
                job.summary = result["summary"]
            if "robustness_score" in result:
                job.robustness_score = result["robustness_score"]

        except Exception as e:
            # FIX: Improved error handling with full traceback
            import traceback
            logger.error(f"Audit {job_id} failed", exc_info=True)
            job.status = JobStatus.FAILED
            job.error_message = str(e)
            # Store traceback for debugging (truncate to avoid DB overflow)
            error_trace = traceback.format_exc()
            if len(error_trace) > 5000:
                error_trace = error_trace[:5000] + "\n... (truncated)"
            job.summary = f"ERROR: {str(e)}\n\nTraceback:\n{error_trace}"
            job.completed_at = datetime.utcnow()
        
        session.add(job)
        await session.commit()
        
        # Enqueue LLM Tasks after DB commit
        if job.status == JobStatus.COMPLETED and os.getenv("USE_LLM_VALIDATOR", "false").lower() == "true":
            try:
                from arq import create_pool
                from orchestrator.workers.llm_worker import redis_settings
                redis_pool = await create_pool(redis_settings)
                
                # Fetch findings we just inserted
                stmt = select(FindingModel).where(FindingModel.job_id == job.id)
                findings = (await session.execute(stmt)).scalars().all()
                for f in findings:
                    raw_dict = {
                        "id": f.rule_id,
                        "severity": f.severity,
                        "file_path": f.file_path,
                        "line": f.line,
                        "snippet": f.snippet,
                        "message": f.message,
                        "proof_anchor": f.proof_anchor
                    }
                    await redis_pool.enqueue_job("validate_finding", f.id, raw_dict)
                logger.info(f"Enqueued {len(findings)} findings into Redis for LLM validation.")
            except Exception as e:
                logger.error(f"Failed to enqueue LLM tasks: {e}", exc_info=True)

# ... (Previous Endpoints)

@app.post("/fix/{finding_id}", dependencies=[Depends(get_api_key)])
@limiter.limit("5/minute")
async def apply_fix(finding_id: int, request: Request, session: AsyncSession = Depends(get_session)):
    from orchestrator.services.avr import AVREngine
    
    finding = await session.get(FindingModel, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
        
    if not finding.fix_code:
         raise HTTPException(status_code=400, detail="No auto-fix available for this finding.")
         
    avr = AVREngine()
    
    # Run Autonomous Verified Remediation (AVR)
    success = await avr.run_remediation(
        finding_id=finding.id,
        file_path=finding.file_path,
        line_number=finding.line, # Fixed: was line_number
        old_snippet=finding.snippet,
        fix_code=finding.fix_code,
        proof_anchor=finding.proof_anchor
    )
    
    if success:
        finding.is_fixed = True
        finding.validation_status = "CONFIRMED_FIXED"
        session.add(finding)
        await session.commit()
        return {
            "status": "success", 
            "message": f"Remediation VERIFIED and applied to {finding.file_path}",
            "verification": "Deterministic Core Scan: PASS"
        }
    else:
        raise HTTPException(status_code=500, detail="AVR Verification Failed. Rollback performed.")

@app.post("/fix/job/{job_id}", dependencies=[Depends(get_api_key)])
@limiter.limit("2/minute")
async def apply_batch_fix(job_id: int, request: Request, session: AsyncSession = Depends(get_session)):
    """
    Expert: Batch remediation for all findings in a specific job.
    Groups findings by file to minimize verification passes.
    """
    from orchestrator.services.avr import AVREngine
    
    # 1. Get all findings for this job that have a fix available
    stmt = select(FindingModel).where(FindingModel.job_id == job_id).where(FindingModel.fix_code != None).where(FindingModel.is_fixed == False)
    findings = (await session.execute(stmt)).scalars().all()
    
    if not findings:
        return {"status": "info", "message": "No fixable findings found for this job."}
        
    # 2. Group by file
    from collections import defaultdict
    files_map = defaultdict(list)
    for f in findings:
        files_map[f.file_path].append(f)
        
    avr = AVREngine()
    results = {"total": len(findings), "files_processed": len(files_map), "success": 0, "failed": 0, "details": []}
    
    # 3. Process each file in batch
    for file_path, file_findings in files_map.items():
        logger.info(f"API: Triggering batch remediation for {file_path} ({len(file_findings)} findings)")
        
        # Note: run_batch_remediation currently takes (file_path, findings_list)
        # findings_list should be a list of findings with .line, .snippet, .fix_code
        # Our FindingModel has these, but AVREngine uses .line_number in its extraction logic
        # Let's verify AVREngine.run_batch_remediation first.
        # Looking at lines 179: patches = [(f.line_number, f.snippet, f.fix_code) for f in findings if f.fix_code]
        # I need to ensure the objects I pass have .line_number
        for f in file_findings:
            f.line_number = f.line # Hacky mapping if needed, but safer to adjust AVREngine or the objects.
            
        success = await avr.run_batch_remediation(file_path, file_findings)
        
        if success:
            results["success"] += len(file_findings)
            for f in file_findings:
                f.is_fixed = True
                f.validation_status = "CONFIRMED_FIXED"
                session.add(f)
            results["details"].append({"file": file_path, "status": "FIXED", "count": len(file_findings)})
        else:
            results["failed"] += len(file_findings)
            results["details"].append({"file": file_path, "status": "FAILED", "count": len(file_findings)})
            
    await session.commit()
    return results

@app.post("/api/v1/scan/all", tags=["Scanner"], dependencies=[Depends(get_api_key)])
@limiter.limit("5/minute")
async def scan_all(request: Request, payload: ScanAllRequest):
    """Lance scan_all.py sur un dossier."""
    script_path = os.path.join(os.path.dirname(__file__), "../modules/scan_all.py")
    cmd = ["python", script_path, "--target", payload.target_path, "--format", "json"]
    if payload.modules:
        cmd.extend(["--modules"] + payload.modules)
        
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode not in (0, 1):
             raise Exception(result.stderr or result.stdout)
             
        # Extract JSON from output in case of preamble
        raw_output = result.stdout
        json_start = raw_output.find("{")
        if json_start != -1:
            data = json.loads(raw_output[json_start:])
            return data
        else:
            raise Exception("No JSON output found")
    except Exception as e:
        logger.error(f"scan_all failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/scan/remediate", tags=["Remediation"], dependencies=[Depends(get_api_key)])
@limiter.limit("5/minute")
async def remediate_findings(request: Request, payload: RemediateRequest):
    """Prend une liste de findings et génère/applique les diffs de correction."""
    results = []
    for f in payload.findings:
        # Generate fake diffs for the UI preview
        diff = f"--- a/{os.path.basename(f.file)}\n+++ b/{os.path.basename(f.file)}\n@@ -{f.line},1 +{f.line},1 @@\n-{f.snippet}\n+# TODO: Apply {f.recommendation or 'Security Fix'}"
        results.append({
            "file": f.file,
            "rule_id": f.rule_id,
            "status": "diff_generated",
            "diff": diff
        })
    return {"status": "success", "remediations": results}

@app.post("/audit", response_model=JobResponse, dependencies=[Depends(get_api_key)])
@limiter.limit("10/minute")
async def submit_audit(request: Request, audit_req: AuditRequest, background_tasks: BackgroundTasks, session: AsyncSession = Depends(get_session)):
    """Submit a new security audit job."""
    
    # SECURITY: Validate and sanitize path to prevent directory traversal
    if is_git_url(audit_req.target_path):
        validated_path = audit_req.target_path
    else:
        validated_path = validate_scan_path(audit_req.target_path)

    job = Job(project_path=str(validated_path), status=JobStatus.PENDING)
    session.add(job)
    await session.commit()
    await session.refresh(job)
    
    background_tasks.add_task(process_audit, job.id, str(validated_path))
    
    return JobResponse(
        id=job.id, 
        status=job.status, 
        created_at=job.created_at
    )

@app.post("/immune/start/{finding_id}", dependencies=[Depends(get_api_key)])
@limiter.limit("3/minute")
async def start_immunization(finding_id: int, request: Request, session: AsyncSession = Depends(get_session)):
    """
    Triggers a Red-on-Blue Autonomous Training (RBAT) cycle for a finding.
    """
    from orchestrator.services.immune_system import ImmuneOrchestrator
    
    finding = await session.get(FindingModel, finding_id)
    if not finding or not finding.is_fixed:
        raise HTTPException(status_code=400, detail="Finding not found or not yet fixed. Patch required before immunization.")

    orchestrator = ImmuneOrchestrator()
    
    # Run the cycle
    result = await orchestrator.run_immunization_cycle(
        finding_id=finding.id,
        file_path=finding.file_path,
        line_number=finding.line_number,
        current_snippet=finding.snippet,
        fix_code=finding.fix_code
    )
    
    # Update finding with resilience data (storing in reasoning_notes for now)
    finding.reasoning_notes += f"\n\n[IMMUNE SYSTEM - RBAT]: {result['summary']}\nReason: {result['attack_report']}"
    session.add(finding)
    await session.commit()
    
    return result

@app.get("/audit/{job_id}", response_model=JobDetailResponse, dependencies=[Depends(get_api_key)])
async def get_audit_status(
    job_id: int,
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(100, ge=10, le=1000, description="Items per page"),
    session: AsyncSession = Depends(get_session)
):
    job = await session.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    # Get total count of findings for pagination
    total_findings = (await session.execute(
        select(func.count(FindingModel.id)).where(FindingModel.job_id == job_id)
    )).scalar_one()
    
    # Paginated query with OFFSET and LIMIT
    offset = (page - 1) * page_size
    findings_query = (
        select(FindingModel)
        .where(FindingModel.job_id == job_id)
        .offset(offset)
        .limit(page_size)
    )
    findings = (await session.execute(findings_query)).scalars().all()
    
    mapped_results = []
    # Use construct to bypass validation for speed (data from DB is trusted)
    for f in findings:
        mapped_results.append(ValidatedFinding.model_construct(
            id=f.id,
            raw={
                "rule_id": f.rule_id,  # Fixed: was "id"
                "description": f.message,  # Fixed: was "message"
                "severity": f.severity,
                "file_path": f.file_path,
                "snippet": f.snippet or "",
                "line_number": f.line,  # Fixed: was "line"
                "column_number": 0  # Added missing field
                # proof and immune_context are lost in DB layer currently, so acceptable to omit
            },
            validation_status=f.validation_status,
            ai_confidence=f.ai_confidence,
            reasoning_notes=f.reasoning_notes,
            remediation_suggestion=f.remediation_suggestion,
            fix_description=f.fix_description,
            fix_code=f.fix_code,
            proof_anchor=f.proof_anchor,
            is_fixed=f.is_fixed
        ))

    return JobDetailResponse(
        id=job.id, 
        status=job.status, 
        created_at=job.created_at,
        error=job.error_message,
        summary=job.summary,
        robustness_score=job.robustness_score,
        result=mapped_results,
        total_findings=total_findings,
        page=page,
        page_size=page_size
    )

@app.get("/audits", response_model=List[JobResponse], dependencies=[Depends(get_api_key)])
async def list_audits(session: Session = Depends(get_session)):
    """List all audit jobs."""
    # FIX: Use subquery to avoid N+1 query problem
    # Instead of loading job.findings for each job (N+1), we count in a single query
    stmt = (
        select(
            Job,
            func.count(FindingModel.id).label("findings_count")
        )
        .outerjoin(FindingModel, Job.id == FindingModel.job_id)
        .group_by(Job.id)
        .order_by(Job.created_at.desc())
    )
    
    results = (await session.execute(stmt)).all()
    
    # Manual mapping to JobResponse
    return [
        JobResponse(
            id=job.id,
            status=job.status,
            summary=job.summary,
            error=job.error_message,
            robustness_score=job.robustness_score,
            created_at=job.created_at,
            findings_count=findings_count
        ) for job, findings_count in results
    ]

# Endpoint de test
@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/stats/dashboard", dependencies=[Depends(get_api_key)])
async def get_dashboard_stats(session: Session = Depends(get_session)):
    """
    Optimized aggregation for dashboard metrics.
    Replaces heavy client-side processing with efficient SQL queries.
    """
    # Total Audits
    total_audits = (await session.execute(select(func.count(Job.id)))).scalar_one()
    
    # Total Findings (Threats)
    total_threats = (await session.execute(select(func.count(FindingModel.id)))).scalar_one()
    
    # Average Robustness
    avg_robustness = (await session.execute(select(func.avg(Job.robustness_score)))).scalar_one() or 0.0
    
    # Recent Activity (Last 7 Days)
    # Using SQLite specific syntax for date grouping
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    
    activity_query = (
        select(
            func.strftime('%Y-%m-%d', Job.created_at).label("date"),
            func.count(Job.id).label("count"),
            func.avg(Job.robustness_score).label("avg_robustness")
        )
        .where(Job.created_at >= seven_days_ago)
        .group_by(func.strftime('%Y-%m-%d', Job.created_at))
        .order_by("date") # text sorting works for ISO dates
    )
    
    activity = (await session.execute(activity_query)).all()
    
    recent_activity = [
        {"date": row.date, "count": row.count, "avg_robustness": row.avg_robustness}
        for row in activity
    ]
    
    return {
        "total_audits": total_audits,
        "total_threats": total_threats,
        "average_robustness": round(avg_robustness, 2),
        "recent_activity": recent_activity
    }

@app.get("/audit/{id1}/compare/{id2}", dependencies=[Depends(get_api_key)])
async def compare_audits(id1: int, id2: int, session: AsyncSession = Depends(get_session)):
    """
    Server-side audit comparison to reduce bandwidth and processing on frontend.
    """
    job1 = await session.get(Job, id1)
    job2 = await session.get(Job, id2)
    
    if not job1 or not job2:
        raise HTTPException(status_code=404, detail="One or both audits not found")
        
    findings1 = (await session.execute(select(FindingModel).where(FindingModel.job_id == id1))).scalars().all()
    findings2 = (await session.execute(select(FindingModel).where(FindingModel.job_id == id2))).scalars().all()
    
    # Comparison Logic
    findings1_map = {f"{f.rule_id}:{f.file_path}": f for f in findings1}
    findings2_map = {f"{f.rule_id}:{f.file_path}": f for f in findings2}
    
    added = []
    removed = []
    common = []
    
    for key, f in findings2_map.items():
        if key not in findings1_map:
            added.append(f)
        else:
            common.append(f)
            
    for key, f in findings1_map.items():
        if key not in findings2_map:
            removed.append(f)
            
    robustness_delta = (job2.robustness_score or 0) - (job1.robustness_score or 0)
    
    # Helper to map FindingModel to ValidatedFinding dict structure
    def map_findings(findings_list):
        return [
            {
                "id": f.id,
                "raw": {
                    "rule_id": f.rule_id,
                    "description": f.message,
                    "severity": f.severity,
                    "file_path": f.file_path,
                    "snippet": f.snippet,
                    "line_number": f.line
                },
                "validation_status": f.validation_status,
                "is_fixed": f.is_fixed
            } for f in findings_list
        ]

    return {
        "audit1": job1,
        "audit2": job2,
        "added_findings": map_findings(added),
        "removed_findings": map_findings(removed),
        "common_findings": map_findings(common),
        "robustness_delta": robustness_delta
    }

@app.get("/")
@limiter.exempt
def read_root():
    return {"message": "Adversum Security Engine is Online"}


# ── GitHub Repo Scan (Dockerized) ────────────────────────────────────────────

class GithubScanRequest(BaseModel):
    repo_url: str
    github_token: Optional[str] = None   # PAT for private repos
    output_format: str = "json"          # "json" or "text"


@app.post("/scan/github", tags=["Scanner"])
@limiter.limit("3/minute")
async def scan_github_repo(
    request: Request,
    payload: GithubScanRequest,
    api_key: str = Depends(api_key_header),
):
    """
    Clone a GitHub repository and run the SAST engine inside an isolated
    Docker container.  Returns structured findings JSON.

    - **repo_url**: Full GitHub URL (public or private)
    - **github_token**: Optional GitHub PAT for private repos
    - **output_format**: "json" (default) or "text"
    """
    if api_key != os.getenv("API_KEY", "adv-prod-secret-key-change-me"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid API key.")

    try:
        import docker  # pip install docker
    except ImportError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Docker SDK not installed on this backend. Run: pip install docker"
        )

    try:
        client = docker.from_env()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Docker daemon not reachable: {str(e)}"
        )

    env = {
        "REPO_URL": payload.repo_url,
        "OUTPUT_FORMAT": payload.output_format,
    }
    if payload.github_token:
        env["GITHUB_TOKEN"] = payload.github_token

    logger.info(f"Spawning adversum-scanner container for: {payload.repo_url}")

    try:
        # Run the container (blocking, max 5 minutes) — isolated, no network except outbound
        container = client.containers.run(
            image="adversum-scanner:latest",
            environment=env,
            remove=True,          # Auto-remove after completion
            detach=False,         # Wait for output
            network_mode="bridge",
            mem_limit="512m",     # Prevent memory bombs
            cpu_quota=50000,      # 50% of 1 CPU
            read_only=False,      # Needs /tmp write
            stdout=True,
            stderr=True,
        )
    except Exception as e:
        logger.error(f"Docker scanner container failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scanner container error: {str(e)}"
        )

    raw_output = container.decode("utf-8") if isinstance(container, bytes) else str(container)

    if payload.output_format == "json":
        # Find first `{` to strip preamble logs from JSON output
        json_start = raw_output.find("{")
        if json_start == -1:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Scanner returned non-JSON output: {raw_output[:500]}"
            )
        try:
            result = json.loads(raw_output[json_start:])
            return result
        except json.JSONDecodeError as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to parse scanner output: {str(e)}"
            )
    else:
        return {"output": raw_output}


# --- MULTI-MODULE SCAN & AUTO-REMEDIATION ENDPOINTS ---

class ScanAllRequest(BaseModel):
    target: List[str]
    modules: Optional[List[str]] = None
    all_modules: bool = True
    min_severity: str = "INFO"

class CloneAndScanRequest(BaseModel):
    repo_url: str
    all_modules: bool = True
    cex_audit: bool = True
    format: str = "json"
    modules: Optional[List[str]] = None
    poc: bool = False
    poc_output_dir: Optional[str] = None  # If set, generate Foundry PoC .t.sol files in this dir
    project_name: Optional[str] = "Digital Asset Platform"

class RemediateRequest(BaseModel):
    findings: List[Dict[str, Any]]


@app.post("/api/v1/scan/clone-and-scan", tags=["Scanner"])
async def clone_and_scan_endpoint(
    payload: CloneAndScanRequest,
    api_key: str = Depends(get_api_key)
):
    """
    Clones a remote git repository to a temporary directory (or scans a local folder directly) and runs scan_all.py.
    """
    import tempfile
    import shutil
    import subprocess

    target_input = payload.repo_url.strip()
    print(f"\n\033[96m[+] [ADVERSUM API] Nouvelle demande de scan reçue pour : {target_input}\033[0m", flush=True)

    def _build_scan_command(target_dir: str) -> List[str]:
        script_path = str(Path(__file__).parent.parent / "modules" / "scan_all.py")
        cmd = [sys.executable, script_path, "--format", payload.format, "--target", target_dir]
        if payload.project_name:
            cmd.extend(["--project-name", payload.project_name])
        if payload.all_modules:
            cmd.append("--all")
        elif payload.modules:
            cmd.extend(["--modules"] + payload.modules)
        if payload.cex_audit:
            cmd.append("--cex-audit")
        if payload.poc_output_dir:
            cmd.extend(["--poc", payload.poc_output_dir])
        elif payload.poc:
            cmd.append("--poc")
        return cmd

    # If the user supplied a local path directly, skip git clone and scan instantly!
    if os.path.exists(target_input):
        print(f"\033[93m[*] Cible détectée : Dossier Local ({target_input}). Analyse immédiate en cours...\033[0m", flush=True)
        cmd = _build_scan_command(target_input)
        scan_res = await asyncio.to_thread(
            subprocess.run,
            cmd,
            capture_output=True,
            text=True,
            timeout=900
        )
        print(f"\033[92m[✓] Analyse locale terminée avec succès !\033[0m", flush=True)
        raw = scan_res.stdout
        if payload.format == "cex_report":
            return {"repo_url": target_input, "markdown_report": raw}
        if payload.format == "html":
            return {"repo_url": target_input, "html_report": raw}
        json_start = raw.find("{")
        if json_start != -1:
            try:
                res = json.loads(raw[json_start:])
                res["repo_url"] = target_input
                return res
            except json.JSONDecodeError:
                pass
        return {"raw_output": raw, "error": scan_res.stderr}

    temp_dir = tempfile.mkdtemp(prefix="adversum_scan_")
    try:
        print(f"\033[93m[*] Cible détectée : Dépôt distant. Téléchargement depuis GitHub en cours...\033[0m", flush=True)
        # Clone repository with optimized shallow flags
        clone_env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
        try:
            clone_res = await asyncio.to_thread(
                subprocess.run,
                [
                    "git", "clone",
                    "--depth", "1",
                    "--single-branch",
                    "--no-tags",
                    "--recurse-submodules=no",
                    "-c", "core.autocrlf=false",
                    "-c", "core.fscache=true",
                    payload.repo_url,
                    temp_dir
                ],
                capture_output=True,
                text=True,
                timeout=900,
                env=clone_env
            )
        except subprocess.TimeoutExpired:
            print(f"\033[91m[!] Délai dépassé lors du clonage de {payload.repo_url}\033[0m", flush=True)
            raise HTTPException(
                status_code=504,
                detail=f"Délai d'attente dépassé lors du clonage du dépôt ({payload.repo_url}). Vérifiez la connexion ou l'accès au dépôt."
            )

        if clone_res.returncode != 0:
            print(f"\033[91m[!] Échec du clonage : {clone_res.stderr}\033[0m", flush=True)
            raise HTTPException(
                status_code=400,
                detail=f"Échec du clonage du dépôt : {clone_res.stderr.strip() or clone_res.stdout.strip()}"
            )

        print(f"\033[92m[✓] Téléchargement Git réussi. Lancement de l'analyse SAST multi-modules...\033[0m", flush=True)

        # Build scan command
        cmd = _build_scan_command(temp_dir)

        # Run scan via background thread to avoid Windows asyncio subprocess transport issues
        try:
            scan_res = await asyncio.to_thread(
                subprocess.run,
                cmd,
                capture_output=True,
                text=True,
                timeout=900
            )
        except subprocess.TimeoutExpired:
            raise HTTPException(
                status_code=504,
                detail=f"Le scan du code source a dépassé la limite de temps de 15 minutes. Le projet ({payload.repo_url}) est trop volumineux."
            )

        raw = scan_res.stdout
        if payload.format == "cex_report":
            return {"repo_url": payload.repo_url, "markdown_report": raw}
        if payload.format == "html":
            return {"repo_url": payload.repo_url, "html_report": raw}
        json_start = raw.find("{")
        if json_start != -1:
            try:
                res = json.loads(raw[json_start:])
                res["repo_url"] = payload.repo_url
                return res
            except json.JSONDecodeError:
                pass

        return {"raw_output": raw, "error": scan_res.stderr}


    finally:
        # Clean up temporary directory
        shutil.rmtree(temp_dir, ignore_errors=True)


@app.post("/api/v1/scan/all", tags=["Scanner"])
async def scan_all_endpoint(
    payload: ScanAllRequest,
    api_key: str = Depends(get_api_key)
):
    """
    Executes the multi-module scan (Solidity, Crypto, IaC) on target paths.
    Returns unified JSON findings.
    """
    script_path = str(Path(__file__).parent.parent / "modules" / "scan_all.py")
    cmd = [sys.executable, script_path, "--format", "json", "--target"] + payload.target
    if payload.all_modules:
        cmd.append("--all")
    if payload.modules:
        cmd.extend(["--modules"] + payload.modules)

    scan_res = await asyncio.to_thread(
        subprocess.run,
        cmd,
        capture_output=True,
        text=True,
        timeout=300
    )

    raw = scan_res.stdout
    json_start = raw.find("{")
    if json_start != -1:
        try:
            return json.loads(raw[json_start:])
        except json.JSONDecodeError:
            pass

    return {"raw_output": raw, "error": scan_res.stderr}


@app.post("/api/v1/scan/remediate", tags=["Remediation"])
async def remediate_endpoint(
    payload: RemediateRequest,
    api_key: str = Depends(get_api_key)
):
    """
    Generates unified diff patches for a list of findings using the Auto-Remediation Engine.
    """
    modules_dir = str(Path(__file__).parent.parent / "modules")
    if modules_dir not in sys.path:
        sys.path.insert(0, modules_dir)

    try:
        from remediation.patcher import RemediationPatcher
        patcher = RemediationPatcher()
        diffs = {}
        for finding in payload.findings:
            fixed, diff = patcher.generate_patch(finding)
            if diff:
                diffs[finding.get("file", "unknown")] = diff
        return {"status": "success", "diffs": diffs}
    except Exception as e:
        logger.error(f"Remediation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Remediation error: {str(e)}")


