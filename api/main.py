import sys
import os
from pathlib import Path

# Automatically ensure project root is in sys.path for both CMD and PowerShell
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

try:
    from dotenv import load_dotenv
    load_dotenv(Path(_PROJECT_ROOT) / ".env")
except ImportError:
    pass

from fastapi import FastAPI, BackgroundTasks, HTTPException, Depends, Request, status, Query
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta, timezone
from sqlmodel import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func, desc
import asyncio
import uuid
import time
import logging
import json
import subprocess  # Rate Limiting
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# -- Prometheus Metrics --------------------------------------------------------
try:
    from prometheus_client import (
        Counter, Histogram,
        generate_latest, CONTENT_TYPE_LATEST, CollectorRegistry,
    )
    _PROMETHEUS_AVAILABLE = True
except ImportError:
    _PROMETHEUS_AVAILABLE = False

_metrics_registry = None

def _get_registry():
    global _metrics_registry
    if _metrics_registry is None:
        _metrics_registry = CollectorRegistry()
    return _metrics_registry

def _make_counter(name, doc, labels=()):
    if not _PROMETHEUS_AVAILABLE:
        return None
    try:
        return Counter(name, doc, labels, registry=_get_registry())
    except ValueError:
        return None

def _make_histogram(name, doc, labels=(), buckets=None):
    if not _PROMETHEUS_AVAILABLE:
        return None
    kwargs = {"registry": _get_registry()}
    if buckets:
        kwargs["buckets"] = buckets
    try:
        return Histogram(name, doc, labels, **kwargs)
    except ValueError:
        return None

_http_requests_total   = _make_counter(  "adversum_http_requests_total",   "Total HTTP requests", ["method", "path", "status"])
_http_errors_total     = _make_counter(  "adversum_http_errors_total",      "Total HTTP 5xx errors", ["path"])
_http_duration_seconds = _make_histogram("adversum_http_duration_seconds",  "HTTP request latency seconds", ["method", "path"],
                                         buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0])
_scans_total           = _make_counter(  "adversum_scans_total",            "Total audit scans started")
_findings_total        = _make_counter(  "adversum_findings_total",         "Total security findings", ["severity"])

# Orchestrator imports

from orchestrator.pipeline.analysis_pipeline import AnalysisPipeline
from orchestrator.models.findings import ValidatedFinding
from orchestrator.models.sql_models import Job, JobStatus, FindingModel
from orchestrator.services.db import create_db_and_tables, get_session

# Security utilities
from api.security import validate_scan_path, is_git_url
from api.cache import api_cache

# ── Nebius (NVIDIA Nemotron) + Tavily integrations ─────────────────────────
# Lazy-imported so the API starts even without the keys configured.
# Set NEBIUS_API_KEY and TAVILY_API_KEY in the environment to activate them.
try:
    from orchestrator.services.nebius_llm import (
        validate_findings_batch,
        generate_executive_summary,
        generate_attack_graph_hypothesis,
        nebius_health_check,
        get_active_model,
        get_active_base_url,
        _is_available as _nebius_available,
    )
    _NEBIUS_LOADED = True
except Exception as _e:
    logger = logging.getLogger("adversum.api")
    logger.warning(f"[Nebius] Module not loaded: {_e}")
    _NEBIUS_LOADED = False

try:
    from orchestrator.services.threat_intel import (
        enrich_findings_batch,
        _is_available as _tavily_available,
    )
    _TAVILY_LOADED = True
except Exception as _e:
    logging.getLogger("adversum.api").warning(f"[Tavily] Module not loaded: {_e}")
    _TAVILY_LOADED = False

# ── Phase 1: Live Fork & Self-Healing Engines ──────────────────────────────
try:
    from modules.live_fork.engine import LiveForkEngine
    from orchestrator.services.self_healing import TriPartiteSelfHealingEngine
    _PHASE1_ENGINES_LOADED = True
except Exception as _e:
    logging.getLogger("adversum.api").warning(f"[Phase 1] Modules not loaded: {_e}")
    _PHASE1_ENGINES_LOADED = False

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
    from orchestrator.services.job_queue import job_queue
    await job_queue.start()

@app.on_event("shutdown")
async def on_shutdown():
    try:
        from orchestrator.services.job_queue import job_queue as jq
        await jq.stop()
    except Exception as e:
        logger.warning(f"Error stopping job queue: {e}")
    try:
        from orchestrator.services.db import close_db
        await close_db()
    except Exception as e:
        logger.warning(f"Error during shutdown: {e}")


# --- Enterprise Security & Telemetry ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("adversum.telemetry")

# Maximum allowed payload size: 25 MB
MAX_REQUEST_SIZE = int(os.getenv("MAX_REQUEST_BODY_BYTES", str(25 * 1024 * 1024)))

@app.middleware("http")
async def telemetry_middleware(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_REQUEST_SIZE:
        return JSONResponse(
            status_code=413,
            content={"error": "PayloadTooLarge", "detail": f"Request body exceeds maximum size limit of {MAX_REQUEST_SIZE // (1024 * 1024)} MB"}
        )

    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    start_time = time.time()
    
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
    
    logger.info(json.dumps(log_entry))

    # Prometheus counters
    if _PROMETHEUS_AVAILABLE and _http_requests_total:
        _http_requests_total.labels(
            method=request.method,
            path=request.url.path,
            status=str(response.status_code),
        ).inc()
    if _PROMETHEUS_AVAILABLE and _http_duration_seconds:
        _http_duration_seconds.labels(
            method=request.method,
            path=request.url.path,
        ).observe(process_time / 1000)
    if _PROMETHEUS_AVAILABLE and _http_errors_total and response.status_code >= 500:
        _http_errors_total.labels(path=request.url.path).inc()

    # OWASP Recommended Security Headers
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

from starlette.exceptions import HTTPException as StarletteHTTPException

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers=getattr(exc, "headers", None)
    )

@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    req_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    logger.error(f"[Unhandled Exception] req_id={req_id} path={request.url.path} error={exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "InternalServerError",
            "detail": f"An unexpected server error occurred. (ref: {req_id[:8]})",
            "request_id": req_id
        }
    )

# -- Prometheus /metrics endpoint ---------------------------------------------
@app.get("/metrics", include_in_schema=False)
async def prometheus_metrics():
    """Expose Prometheus metrics (text/plain Prometheus format)."""
    if not _PROMETHEUS_AVAILABLE:
        return JSONResponse(status_code=501, content={"detail": "prometheus_client not installed"})
    from fastapi.responses import Response
    return Response(content=generate_latest(_get_registry()), media_type=CONTENT_TYPE_LATEST)

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
    import secrets
    if not secrets.compare_digest(api_key_header, API_KEY):
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

    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    model_config = {"str_strip_whitespace": True}

    def model_post_init(self, __context: Any) -> None:
        # Block path-traversal attempts at the model layer
        if ".." in self.target_path:
            raise ValueError("target_path must not contain '..' (path traversal attempt)")
        if len(self.target_path) > 500:
            raise ValueError("target_path too long (max 500 chars)")
        if len(self.project_name) > 128:
            raise ValueError("project_name too long (max 128 chars)")

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
    target_path: Optional[str] = None
    target: Optional[List[str]] = None
    modules: Optional[List[str]] = None
    all_modules: bool = True
    min_severity: str = "INFO"

    def model_post_init(self, __context: Any) -> None:
        valid_severities = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
        if self.min_severity not in valid_severities:
            raise ValueError(f"min_severity must be one of {valid_severities}")
        if self.target_path and ".." in self.target_path:
            raise ValueError("target_path must not contain '..' (path traversal attempt)")

class FindingFixRequest(BaseModel):
    file: str
    line: int
    rule_id: str
    snippet: str
    recommendation: Optional[str] = None

    def model_post_init(self, __context: Any) -> None:
        if ".." in self.file:
            raise ValueError("file must not contain '..' (path traversal attempt)")
        if self.line < 1:
            raise ValueError("line must be >= 1")
        if len(self.rule_id) > 128:
            raise ValueError("rule_id too long")

class RemediateRequest(BaseModel):
    findings: List[Dict[str, Any]]

    def model_post_init(self, __context: Any) -> None:
        if len(self.findings) > 500:
            raise ValueError("findings list too large (max 500 items)")

class LiveForkRequest(BaseModel):
    finding: Dict[str, Any]
    initial_vault_eth: Optional[float] = 100.0
    network: Optional[str] = "ethereum-mainnet-fork"

    def model_post_init(self, __context: Any) -> None:
        if self.initial_vault_eth is not None and not (0 < self.initial_vault_eth <= 10_000):
            raise ValueError("initial_vault_eth must be between 0 and 10000")

class SelfHealingPRRequest(BaseModel):
    finding: Dict[str, Any]
    repo_url: Optional[str] = ""
    apply_to_disk: Optional[bool] = False

    def model_post_init(self, __context: Any) -> None:
        if self.repo_url:
            url = self.repo_url.strip()
            if not (url.startswith("https://github.com/") or url.startswith("https://gitlab.com/")):
                raise ValueError("repo_url must be a GitHub or GitLab HTTPS URL")

async def process_audit(job_id: int, target_path: str):
    # We need a new session for the background task
    from orchestrator.services.db import engine
    async with AsyncSession(engine, expire_on_commit=False) as session:
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

            # SOL-004 : audit Solidity spécifique (Nemotron -> ancrage -> Z3, repli regex).
            # Provenance et verdict Z3 sont portés par reasoning_notes/proof_anchor.
            try:
                from orchestrator.services.solidity_overflow_audit import audit_solidity_path as audit_overflow
                sol_overflow_findings = await audit_overflow(real_path)
            except Exception as e:
                logger.warning(f"[SOL-004] Solidity overflow pass skipped: {e}", exc_info=True)
                sol_overflow_findings = []

            # SOL-001 : audit Réentrance (Nemotron -> ancrage séquentiel -> Z3, repli regex).
            try:
                from orchestrator.services.solidity_reentrancy_audit import audit_solidity_path as audit_reentrancy
                sol_reentrancy_findings = await audit_reentrancy(real_path)
            except Exception as e:
                logger.warning(f"[SOL-001] Solidity reentrancy pass skipped: {e}", exc_info=True)
                sol_reentrancy_findings = []

            for sf in sol_overflow_findings + sol_reentrancy_findings:
                session.add(FindingModel(
                    job_id=job.id,
                    rule_id=sf["rule_id"],
                    message=sf["message"],
                    severity="HIGH" if sf.get("z3_verdict") == "SAT" else "MEDIUM",
                    file_path=sf["file_path"],
                    line=sf["line"] or 0,
                    snippet=sf["snippet"],
                    validation_status=sf["validation_status"],
                    ai_confidence=sf["ai_confidence"],
                    reasoning_notes=sf["reasoning_notes"],
                    proof_anchor=sf["proof_anchor"],
                    provenance=sf["provenance"],
                    nemotron_line=sf["nemotron_line"],
                    resolved_line=sf["resolved_line"],
                    anchor_status=sf["anchor_status"],
                    z3_verdict=sf["z3_verdict"],
                ))
            
            # Update Job
            job.status = JobStatus.COMPLETED
            job.completed_at = datetime.now(timezone.utc)
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
            job.completed_at = datetime.now(timezone.utc)
        
        is_completed = (job.status == JobStatus.COMPLETED)
        session.add(job)
        await session.commit()
        
        # Enqueue LLM Tasks after DB commit
        if is_completed and os.getenv("USE_LLM_VALIDATOR", "false").lower() == "true":
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
        line_number=finding.line,
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
            provenance=f.provenance,
            nemotron_line=f.nemotron_line,
            resolved_line=f.resolved_line,
            anchor_status=f.anchor_status,
            z3_verdict=f.z3_verdict,
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
async def list_audits(
    session: AsyncSession = Depends(get_session),
    since_id: Optional[int] = Query(None, description="Cursor for keyset pagination — returns only jobs with id > since_id"),
):
    """List all audit jobs. Use since_id for efficient cursor-based pagination."""
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

    if since_id is not None:
        stmt = stmt.where(Job.id > since_id)

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
async def get_dashboard_stats(session: AsyncSession = Depends(get_session)):
    """
    Optimized aggregation for dashboard metrics.
    Replaces heavy client-side processing with efficient SQL queries.
    Results are cached in-memory for 30 seconds (LRU cache).
    """
    cache_key = "dashboard:stats"
    cached = await api_cache.get(cache_key)
    if cached:
        return cached.value

    # Total Audits
    total_audits = (await session.execute(select(func.count(Job.id)))).scalar_one()

    # Total Findings (Threats)
    total_threats = (await session.execute(select(func.count(FindingModel.id)))).scalar_one()

    # Average Robustness
    avg_robustness = (await session.execute(select(func.avg(Job.robustness_score)))).scalar_one() or 0.0

    # Recent Activity (Last 7 Days)
    # Using SQLite specific syntax for date grouping
    seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)

    activity_query = (
        select(
            func.strftime('%Y-%m-%d', Job.created_at).label("date"),
            func.count(Job.id).label("count"),
            func.avg(Job.robustness_score).label("avg_robustness")
        )
        .where(Job.created_at >= seven_days_ago)
        .group_by(func.strftime('%Y-%m-%d', Job.created_at))
        .order_by("date")  # text sorting works for ISO dates
    )

    activity = (await session.execute(activity_query)).all()

    recent_activity = [
        {"date": row.date, "count": row.count, "avg_robustness": row.avg_robustness}
        for row in activity
    ]

    result = {
        "total_audits": total_audits,
        "total_threats": total_threats,
        "average_robustness": round(avg_robustness, 2),
        "recent_activity": recent_activity,
    }
    await api_cache.set(cache_key, result)
    return result


@app.get("/api/v1/cache/stats", include_in_schema=False)
async def cache_stats():
    """Internal monitoring endpoint — returns LRU cache hit/miss statistics."""
    return api_cache.stats

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
    api_key: str = Depends(get_api_key),
):
    """
    Clone a GitHub repository and run the SAST engine inside an isolated
    Docker container.  Returns structured findings JSON.

    - **repo_url**: Full GitHub URL (public or private)
    - **github_token**: Optional GitHub PAT for private repos
    - **output_format**: "json" (default) or "text"
    """

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



async def _ai_enrich_result(res: dict, repo_url: str = "", project_name: str = "") -> dict:
    """
    Post-process a scan result dict with:
      1. NVIDIA Nemotron (Nebius Token Factory) — finding validation & confidence scoring
      2. Tavily Search — CVE / exploit threat intelligence enrichment
      3. Nemotron executive summary generation

    All steps are optional and gracefully no-op when API keys are absent.
    """
    findings = res.get("findings", [])
    if not isinstance(findings, list):
        findings = []

    active_model = get_active_model() if (_NEBIUS_LOADED and _nebius_available()) else None
    active_infra = (
        "NVIDIA NIM API" if os.getenv("NEBIUS_API_KEY", "").startswith("nvapi-")
        else "Nebius Token Factory"
    ) if (_NEBIUS_LOADED and _nebius_available()) else None

    ai_metadata = {
        "nebius_enabled": _NEBIUS_LOADED and _nebius_available(),
        "tavily_enabled": _TAVILY_LOADED and _tavily_available(),
        "model": active_model,
        "infrastructure": active_infra,
    }

    if findings:
        # Step 1 — Tavily threat intel (fastest, run first)
        if _TAVILY_LOADED and _tavily_available():
            print("\033[96m[*] [Nebius/Tavily] Enrichissement threat-intel en cours...\033[0m", flush=True)
            findings = await enrich_findings_batch(findings, max_findings=5)

        # Step 2 — Nebius / NVIDIA Nemotron finding validation
        if _NEBIUS_LOADED and _nebius_available():
            print("\033[96m[*] [Nebius/Nemotron] Validation IA des findings en cours (NVIDIA Nemotron)...\033[0m", flush=True)
            findings = await validate_findings_batch(findings, max_findings=4)

        # Step 3 — Executive summary
        if _NEBIUS_LOADED and _nebius_available():
            stats = res.get("stats", {})
            summary = await generate_executive_summary(
                findings, stats,
                repo_url=repo_url,
                project_name=project_name or "Security Audit Target",
            )
            if summary:
                res["ai_executive_summary"] = summary
                print("\033[92m[✓] [Nebius/Nemotron] Résumé exécutif IA généré avec succès.\033[0m", flush=True)

        # Step 4 — Attack Graph Kill Chain Hypothesis (NVIDIA Nemotron Reasoning)
        if _NEBIUS_LOADED and _nebius_available():
            attack_graph = await generate_attack_graph_hypothesis(
                findings,
                repo_url=repo_url,
                project_name=project_name or "Target System",
            )
            if attack_graph:
                res["ai_attack_graph"] = attack_graph
                print("\033[92m[✓] [Nebius/Nemotron] Graphe d'Attaque Multi-Étapes IA synthétisé avec succès.\033[0m", flush=True)

    res["findings"] = findings
    res["ai_metadata"] = ai_metadata
    return res


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
                res = await _ai_enrich_result(res, repo_url=target_input, project_name=payload.project_name or "")
                return res
            except json.JSONDecodeError:
                pass
        return {"raw_output": raw, "error": scan_res.stderr, "findings": [], "ai_metadata": {"nebius_enabled": False, "tavily_enabled": False}}

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
                    "-c", "http.postBuffer=524288000",
                    "-c", "http.lowSpeedLimit=1000",
                    "-c", "http.lowSpeedTime=120",
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
                res = await _ai_enrich_result(res, repo_url=payload.repo_url, project_name=payload.project_name or "")
                return res
            except json.JSONDecodeError:
                pass

        return {"raw_output": raw, "error": scan_res.stderr, "findings": [], "ai_metadata": {"nebius_enabled": False, "tavily_enabled": False}}


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
    targets = payload.target or ([payload.target_path] if payload.target_path else ["./"])
    cmd = [sys.executable, script_path, "--format", "json", "--target"] + targets
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


# ═══════════════════════════════════════════════════════════════════════════
# PHASE 1 FLAGSHIP ENDPOINTS: LIVE FORK EXPLOIT & TRI-PARTITE SELF-HEALING PR
# ═══════════════════════════════════════════════════════════════════════════

@app.post("/api/v1/exploit/live-fork", tags=["Live Fork Exploitation"])
async def live_fork_exploit_endpoint(
    payload: LiveForkRequest,
    api_key: str = Depends(get_api_key)
):
    """
    Executes an empirical on-chain fork exploit simulation for a detected finding.
    Returns verified EVM call traces, gas metrics, and Proof of Exploit (PoE) certificate.
    """
    try:
        from modules.live_fork.engine import LiveForkEngine
        engine = LiveForkEngine()
        proof = engine.execute_live_exploit(
            finding=payload.finding,
            initial_vault_eth=payload.initial_vault_eth or 100.0,
            network=payload.network or "ethereum-mainnet-fork"
        )
        return proof.to_dict()
    except Exception as e:
        logger.error(f"Live fork exploit execution failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Live fork exploit failed: {str(e)}")


@app.post("/api/v1/remediation/self-healing-pr", tags=["Self-Healing PR"])
async def self_healing_pr_endpoint(
    payload: SelfHealingPRRequest,
    api_key: str = Depends(get_api_key)
):
    """
    Coordinates the Tri-Partite Security Committee (Attacker vs Defender vs Rust Judge)
    to generate a mathematically proven GitHub Pull Request package.
    """
    try:
        from orchestrator.services.self_healing import TriPartiteSelfHealingEngine
        engine = TriPartiteSelfHealingEngine()
        pr_package = engine.generate_verified_pr(
            finding=payload.finding,
            repo_url=payload.repo_url or "",
            apply_to_disk=bool(payload.apply_to_disk)
        )
        return pr_package.to_dict()
    except Exception as e:
        logger.error(f"Self-healing PR generation failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Self-healing PR failed: {str(e)}")





# ═══════════════════════════════════════════════════════════════════════════
# PHASE 2: AI-ASOC — WEBSOCKET, MEV, THREAT MODEL, COMPLIANCE
# ═══════════════════════════════════════════════════════════════════════════

from fastapi import WebSocket, WebSocketDisconnect


class MEVAnalysisRequest(BaseModel):
    transactions: List[Dict[str, Any]]
    chain: str = "ethereum"
    block_number: Optional[int] = None
    pool_liquidity_eth: float = 1000.0
    eth_price_usd: float = 2650.0


class ThreatModelRequest(BaseModel):
    source_code: str
    target: str = "Unknown Target"
    component_names: Optional[List[str]] = None


class ComplianceReportRequest(BaseModel):
    findings: List[Dict[str, Any]]
    target: str = "Unknown System"
    frameworks: List[str] = ["soc2", "iso27001", "sarif"]


# ── AI Intelligence Triage ──────────────────────────────────────────────────

@app.post("/api/v1/intelligence/triage", tags=["AI Intelligence"])
@limiter.limit("20/minute")
async def ai_triage_findings(request: Request, payload: RemediateRequest, _key: str = Depends(get_api_key)):
    """
    AI Triage Engine — Scores and prioritizes a batch of findings.
    Returns findings sorted by risk tier (P0_CRITICAL first).
    """
    from orchestrator.services.ai_triage import triage_engine
    results = triage_engine.triage_batch([dict(f) for f in payload.findings])
    return {
        "total": len(results),
        "triaged": [
            {
                "finding_id": r.finding_id,
                "risk_tier": r.risk_tier.value,
                "triage_score": r.triage_score,
                "original_severity": r.original_severity,
                "signals": r.signals,
                "recommended_action": r.recommended_action,
                "confidence": r.confidence,
            }
            for r in results
        ],
        "summary": {
            "P0": sum(1 for r in results if r.risk_tier.value == "P0_CRITICAL"),
            "P1": sum(1 for r in results if r.risk_tier.value == "P1_HIGH"),
            "P2": sum(1 for r in results if r.risk_tier.value == "P2_MEDIUM"),
            "P3": sum(1 for r in results if r.risk_tier.value == "P3_LOW"),
            "P4": sum(1 for r in results if r.risk_tier.value == "P4_INFORMATIONAL"),
        }
    }


# ── WebSocket Threat Stream ─────────────────────────────────────────────────

@app.websocket("/ws/threat-stream")
async def websocket_threat_stream(websocket: WebSocket):
    """
    Real-time WebSocket threat stream.
    Clients receive push notifications for all security events:
    findings, exploits, MEV attacks, CVE correlations, patches, compliance.
    """
    await websocket.accept()
    from orchestrator.services.threat_stream import get_event_bus
    bus = get_event_bus()
    sub_id = f"ws-{id(websocket)}"

    try:
        async with await bus.subscribe(sub_id) as ctx:
            logger.info("WebSocket client connected: %s", sub_id)
            history = bus.get_history(limit=20)
            await websocket.send_json({
                "type": "welcome",
                "subscriber_count": bus.subscriber_count,
                "recent_events": history,
                "stats": bus.get_stats(),
            })
            while True:
                event = await ctx.get(timeout=25.0)
                if event is not None:
                    await websocket.send_json(event.to_dict())
                else:
                    await websocket.send_json({
                        "type": "heartbeat",
                        "subscriber_count": bus.subscriber_count,
                        "stats": bus.get_stats(),
                    })
    except WebSocketDisconnect:
        logger.info("WebSocket client disconnected: %s", sub_id)
    except Exception as e:
        logger.error("WebSocket error for %s: %s", sub_id, e)
        try:
            await websocket.close(code=1011)
        except Exception:
            pass


@app.get("/api/v1/threat-stream/history", tags=["AI-ASOC Threat Stream"])
async def get_threat_history(
    limit: int = Query(default=50, le=200),
    severity: Optional[str] = None,
    api_key: str = Depends(get_api_key),
):
    """Returns recent threat events from the in-memory event history."""
    from orchestrator.services.threat_stream import get_event_bus
    bus = get_event_bus()
    return {"events": bus.get_history(limit=limit, severity=severity), "stats": bus.get_stats()}


@app.get("/api/v1/threat-stream/stats", tags=["AI-ASOC Threat Stream"])
async def get_threat_stream_stats(api_key: str = Depends(get_api_key)):
    """Returns WebSocket bus statistics."""
    from orchestrator.services.threat_stream import get_event_bus
    return get_event_bus().get_stats()


# ── MEV Intelligence ────────────────────────────────────────────────────────

@app.post("/api/v1/intelligence/mev-analyze", tags=["MEV Intelligence"])
async def mev_analyze_endpoint(
    payload: MEVAnalysisRequest,
    api_key: str = Depends(get_api_key),
):
    """
    Analyzes a block or mempool snapshot for MEV attack patterns.
    Detects Sandwich, Front-Running, Flash Loan, Rug Pull, Oracle Manipulation.
    """
    try:
        from modules.mev_intelligence.engine import (
            MEVIntelligenceEngine, MEVTransaction, MEVChain
        )
        engine = MEVIntelligenceEngine(eth_price_usd=payload.eth_price_usd)
        try:
            chain_enum = MEVChain(payload.chain.lower())
        except ValueError:
            chain_enum = MEVChain.ETHEREUM

        txs = [
            MEVTransaction(
                tx_hash      = tx.get("tx_hash", f"0x{i:064x}"),
                from_address = tx.get("from_address", "0x" + "0" * 40),
                to_address   = tx.get("to_address",   "0x" + "0" * 40),
                value_wei    = int(tx.get("value_wei", 0)),
                gas_price    = int(tx.get("gas_price", 30_000_000_000)),
                gas_limit    = int(tx.get("gas_limit", 200_000)),
                input_data   = tx.get("input_data", "0x"),
                position     = i,
            )
            for i, tx in enumerate(payload.transactions)
        ]

        result = await engine.analyze_block(
            transactions       = txs,
            chain              = chain_enum,
            block_number       = payload.block_number,
            pool_liquidity_eth = payload.pool_liquidity_eth,
        )

        if result.has_critical:
            from orchestrator.services.threat_stream import emit_mev_attack
            for pattern in result.patterns_found:
                if pattern.risk_level.value == "CRITICAL":
                    await emit_mev_attack(
                        attack_type       = pattern.attack_type.value,
                        chain             = pattern.chain.value,
                        value_at_risk_usd = pattern.value_at_risk_usd,
                        tx_hash           = pattern.tx_hashes[0] if pattern.tx_hashes else "0x",
                        payload           = pattern.to_dict(),
                    )

        return result.to_dict()

    except Exception as e:
        logger.error("MEV analysis failed: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"MEV analysis error: {str(e)}")


# ── Autonomous Threat Modeling ──────────────────────────────────────────────

@app.post("/api/v1/intelligence/threat-model", tags=["Autonomous Threat Modeling"])
async def threat_model_endpoint(
    payload: ThreatModelRequest,
    api_key: str = Depends(get_api_key),
):
    """
    Generates a complete STRIDE + PASTA + MITRE ATT&CK threat model from source code.
    Replaces 40h of manual consultant work with <60s autonomous analysis.
    """
    try:
        from modules.threat_model.autonomous_modeler import AutonomousThreatModeler
        modeler = AutonomousThreatModeler()
        report  = await modeler.analyze(
            source_code     = payload.source_code,
            target          = payload.target,
            component_names = payload.component_names,
        )

        from orchestrator.services.threat_stream import get_event_bus, ThreatEvent, ThreatEventType, ThreatSeverity
        bus = get_event_bus()
        sev_map = {"CRITICAL": ThreatSeverity.CRITICAL, "HIGH": ThreatSeverity.HIGH,
                   "MEDIUM": ThreatSeverity.MEDIUM, "LOW": ThreatSeverity.LOW}
        await bus.publish(ThreatEvent(
            event_type  = ThreatEventType.THREAT_MODEL_READY,
            severity    = sev_map.get(report.overall_risk, ThreatSeverity.HIGH),
            title       = f"Threat Model: {payload.target} ({report.overall_risk})",
            description = report.executive_summary,
            payload     = {"report_id": report.report_id, "threat_count": len(report.stride_threats)},
            source      = "threat-modeler",
        ))

        return report.to_dict()

    except Exception as e:
        logger.error("Threat modeling failed: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Threat model error: {str(e)}")


# ── Compliance Report Generation ────────────────────────────────────────────

@app.post("/api/v1/compliance/report", tags=["Compliance Engine"])
async def compliance_report_endpoint(
    payload: ComplianceReportRequest,
    api_key: str = Depends(get_api_key),
):
    """
    Generates SOC2 Type II, ISO 27001:2022, and SARIF 2.1 compliance reports.
    Produces audit-ready evidence artifacts from Adversum findings.
    """
    try:
        response: Dict[str, Any] = {"target": payload.target, "frameworks": {}}

        if "soc2" in payload.frameworks:
            from modules.compliance.soc2_mapper import SOC2Mapper
            response["frameworks"]["soc2"] = SOC2Mapper().generate_report(
                payload.findings, target=payload.target
            ).to_dict()

        if "iso27001" in payload.frameworks:
            from modules.compliance.iso27001_mapper import ISO27001Mapper
            response["frameworks"]["iso27001"] = ISO27001Mapper().generate_report(
                payload.findings, target=payload.target
            ).to_dict()

        if "sarif" in payload.frameworks:
            from modules.compliance.sarif_v2 import SARIFv2Exporter
            response["frameworks"]["sarif"] = SARIFv2Exporter().export(
                payload.findings, tool_name="Adversum Security Engine"
            ).to_sarif()

        from orchestrator.services.threat_stream import get_event_bus, ThreatEvent, ThreatEventType, ThreatSeverity
        bus = get_event_bus()
        soc2_score = response.get("frameworks", {}).get("soc2", {}).get("compliance_score", 100)
        await bus.publish(ThreatEvent(
            event_type  = ThreatEventType.COMPLIANCE_REPORT,
            severity    = ThreatSeverity.HIGH if soc2_score < 70 else ThreatSeverity.INFO,
            title       = f"Compliance Report: {payload.target}",
            description = f"SOC2 score: {soc2_score:.1f}% | {', '.join(payload.frameworks)}",
            payload     = {"target": payload.target, "soc2_score": soc2_score},
            source      = "compliance-engine",
        ))

        return response

    except Exception as e:
        logger.error("Compliance report failed: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Compliance report error: {str(e)}")


@app.get("/api/v1/compliance/sarif/{job_id}", tags=["Compliance Engine"])
async def export_sarif_for_job(
    job_id: int,
    api_key: str = Depends(get_api_key),
    session: AsyncSession = Depends(get_session),
):
    """Export SARIF 2.1 report for an existing audit job."""
    job = await session.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    stmt = select(FindingModel).where(FindingModel.job_id == job_id)
    findings_db = (await session.execute(stmt)).scalars().all()
    findings = [
        {
            "id": f"FINDING-{f.id}",
            "rule_id": f.rule_id,
            "message": f.message,
            "severity": f.severity,
            "file": f.file_path,
            "line": f.line,
            "snippet": f.snippet or "",
            "recommendation": f.remediation_suggestion or f.reasoning_notes or ""
        }
        for f in findings_db
    ]
    from modules.compliance.sarif_v2 import SARIFv2Exporter
    return SARIFv2Exporter().export(findings, tool_name="Adversum Security Engine").to_sarif()


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 3 — Cross-Protocol Attack Simulator & DeFi Risk Scorer
# ═══════════════════════════════════════════════════════════════════════════════

# Global executor instance (in-memory history)
from modules.attack_simulator.chain_executor import AttackChainExecutor
from modules.attack_simulator.risk_scorer import DeFiRiskScorer
from modules.attack_simulator.scenarios import SCENARIO_REGISTRY

_attack_executor = AttackChainExecutor()
_risk_scorer = DeFiRiskScorer()


class SimulatorRunRequest(BaseModel):
    scenario_id: str
    custom_params: Optional[Dict[str, Any]] = None


class RiskScoreRequest(BaseModel):
    protocol: str
    tvl_usd: Optional[float] = None
    custom_overrides: Optional[Dict[str, float]] = None


@app.post("/api/v1/simulator/run-attack", tags=["Attack Simulator"])
async def run_attack_simulation(
    payload: SimulatorRunRequest,
    api_key: str = Depends(get_api_key),
):
    """
    Run a named DeFi attack chain simulation.
    Available scenarios: euler_finance, ronin_bridge, mango_markets, wormhole, generic_flashloan_cascade
    """
    scenario_fn = SCENARIO_REGISTRY.get(payload.scenario_id)
    if scenario_fn is None:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown scenario '{payload.scenario_id}'. Available: {list(SCENARIO_REGISTRY.keys())}",
        )

    # Build chain — pass custom_params to configurable scenarios
    try:
        if payload.custom_params and payload.scenario_id == "generic_flashloan_cascade":
            chain = scenario_fn(**payload.custom_params)
        else:
            chain = scenario_fn()
    except (TypeError, ValueError) as e:
        raise HTTPException(status_code=422, detail=f"Invalid custom_params: {e}")

    result = _attack_executor.execute(chain)
    return result.to_dict()


@app.get("/api/v1/simulator/scenarios", tags=["Attack Simulator"])
async def list_scenarios(api_key: str = Depends(get_api_key)):
    """List all available attack simulation scenarios."""
    scenarios = []
    for sid, fn in SCENARIO_REGISTRY.items():
        chain = fn() if sid != "generic_flashloan_cascade" else fn()
        scenarios.append({
            "scenario_id":   sid,
            "name":          chain.name,
            "description":   chain.description,
            "loss_usd":      chain.loss_usd,
            "tags":          chain.tags,
            "steps":         len(chain.steps),
            "real_hack_ref": chain.real_hack_ref,
        })
    return {"scenarios": scenarios, "count": len(scenarios)}


@app.get("/api/v1/simulator/replay/{simulation_id}", tags=["Attack Simulator"])
async def get_simulation_replay(
    simulation_id: str,
    api_key: str = Depends(get_api_key),
):
    """Get step-by-step replay data for a completed simulation."""
    result = _attack_executor.get_by_id(simulation_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail=f"Simulation '{simulation_id}' not found. Run /api/v1/simulator/run-attack first.",
        )
    return result.to_dict()


@app.post("/api/v1/simulator/risk-score", tags=["Attack Simulator"])
async def get_risk_score(
    payload: RiskScoreRequest,
    api_key: str = Depends(get_api_key),
):
    """
    Get economic risk score for a DeFi protocol across 6 attack vectors.
    Known protocols: Euler Finance, Ronin Bridge, Mango Markets, Wormhole,
                     Compound, Aave, Curve Finance, Uniswap v3
    """
    score = _risk_scorer.score_protocol(
        protocol=payload.protocol,
        custom_overrides=payload.custom_overrides,
        tvl_usd=payload.tvl_usd,
    )
    return score.to_dict()


@app.get("/api/v1/simulator/history", tags=["Attack Simulator"])
async def get_simulation_history(api_key: str = Depends(get_api_key)):
    """Get all simulation results from the current session."""
    history = _attack_executor.get_history()
    return {
        "simulations": history,
        "count": len(history),
        "total_protocol_loss_usd": sum(h["protocol_loss_usd"] for h in history),
    }


@app.get("/api/v1/simulator/risk-matrix", tags=["Attack Simulator"])
async def get_risk_matrix(api_key: str = Depends(get_api_key)):
    """Get full DeFi risk matrix: protocol × attack vector scores."""
    matrix = _risk_scorer.risk_matrix()
    protocols = _risk_scorer.known_protocols()
    return {
        "matrix": matrix,
        "protocols": protocols,
        "vectors": list({
            "oracle_risk": "Oracle Manipulation",
            "flash_loan_risk": "Flash Loan Attack",
            "bridge_risk": "Cross-Chain Bridge",
            "governance_risk": "Governance Takeover",
            "liquidity_risk": "Liquidity Concentration",
            "smart_contract_risk": "Smart Contract Exploit",
        }.values()),
    }


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 4 — Autonomous Incident Response & Resilience Arena (AI-AIRA)
# ═══════════════════════════════════════════════════════════════════════════════

from modules.incident_response.circuit_breaker import (
    CircuitBreakerConfig, CircuitBreakerSynthesizer
)
from modules.incident_response.adversarial_evaluator import (
    AdversarialInvariantEvaluator
)
from modules.incident_response.resilience_arena import (
    ResilienceArena
)

_resilience_arena = ResilienceArena()
_breaker_synthesizer = CircuitBreakerSynthesizer()
_invariant_evaluator = AdversarialInvariantEvaluator()


class IncidentClashRequest(BaseModel):
    protocol: str = "Euler Finance"
    scenario_key: str = "flashloan_drain"
    custom_exposure_usd: Optional[float] = None


class CircuitBreakerSynthesisRequest(BaseModel):
    protocol_name: str = "DeFiProtocol"
    target_token: str = "USDC"
    max_tvl_outflow_pct_per_window: float = 5.0
    window_blocks: int = 10
    max_oracle_divergence_pct: float = 3.5
    enable_flash_loan_guard: bool = True
    emergency_multisig: str = "0x000000000000000000000000000000000000dEaD"


class InvariantEvaluationRequest(BaseModel):
    protocol_name: str = "TargetProtocol"
    source_code: str


@app.post("/api/v1/wargame/simulate-incident", tags=["Resilience Arena"])
async def simulate_incident_clash(
    payload: IncidentClashRequest,
    api_key: str = Depends(get_api_key),
):
    """
    Simulate an adversarial incident clash against active autonomous circuit breaker defense.
    Scenarios: flashloan_drain, oracle_desync, reentrancy_wave, bridge_forgery
    """
    result = _resilience_arena.simulate_clash(
        protocol=payload.protocol,
        scenario_key=payload.scenario_key,
        custom_exposure_usd=payload.custom_exposure_usd,
    )
    return result.to_dict()


@app.post("/api/v1/wargame/synthesize-circuit-breaker", tags=["Resilience Arena"])
async def synthesize_circuit_breaker(
    payload: CircuitBreakerSynthesisRequest,
    api_key: str = Depends(get_api_key),
):
    """
    Synthesize tailor-made on-chain Solidity CircuitBreakerGuard.sol
    and automated monitoring policies.
    """
    cfg = CircuitBreakerConfig(
        protocol_name=payload.protocol_name,
        target_token=payload.target_token,
        max_tvl_outflow_pct_per_window=payload.max_tvl_outflow_pct_per_window,
        window_blocks=payload.window_blocks,
        max_oracle_divergence_pct=payload.max_oracle_divergence_pct,
        enable_flash_loan_guard=payload.enable_flash_loan_guard,
        emergency_multisig=payload.emergency_multisig,
    )
    synth = _breaker_synthesizer.synthesize(cfg)
    return synth.to_dict()


@app.get("/api/v1/wargame/resilience-benchmark", tags=["Resilience Arena"])
async def get_resilience_benchmark(
    protocol: str = "Euler Finance",
    api_key: str = Depends(get_api_key),
):
    """
    Run full multi-scenario resilience benchmark (Flashloan, Oracle, Reentrancy, Bridge).
    """
    return _resilience_arena.run_benchmark(protocol=protocol)


@app.get("/api/v1/wargame/arena-history", tags=["Resilience Arena"])
async def get_arena_history(api_key: str = Depends(get_api_key)):
    """Retrieve history of all incident clash simulations."""
    history = _resilience_arena.get_history()
    return {
        "clashes": history,
        "count": len(history),
    }


@app.post("/api/v1/wargame/evaluate-invariants", tags=["Resilience Arena"])
async def evaluate_protocol_invariants(
    payload: InvariantEvaluationRequest,
    api_key: str = Depends(get_api_key),
):
    """
    Evaluates contract source code against 10 critical DeFi security invariants.
    """
    report = _invariant_evaluator.evaluate_code(
        source_code=payload.source_code,
        protocol_name=payload.protocol_name,
    )
    return report.to_dict()


# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 5 — Autonomous Threat Hunting Watchtower & Enterprise Readiness
# ═══════════════════════════════════════════════════════════════════════════════

from modules.threat_hunter.daemon import ThreatHuntingDaemon

_threat_hunter = ThreatHuntingDaemon(chain="ethereum")
try:
    from orchestrator.services.threat_stream import get_event_bus
    _threat_hunter.attach_event_bus(get_event_bus())
except Exception:
    pass


class HunterStartRequest(BaseModel):
    chain: str = "ethereum"


class HunterScanBlockRequest(BaseModel):
    block_number: Optional[int] = None


@app.post("/api/v1/hunter/start", tags=["Autonomous Threat Hunter"])
async def start_threat_hunter(
    payload: Optional[HunterStartRequest] = None,
    api_key: str = Depends(get_api_key),
):
    """Start the autonomous 24/7 background EVM threat hunter watchtower."""
    if payload and payload.chain:
        _threat_hunter.chain = payload.chain
    status = await _threat_hunter.start()
    return status.to_dict()


@app.post("/api/v1/hunter/stop", tags=["Autonomous Threat Hunter"])
async def stop_threat_hunter(api_key: str = Depends(get_api_key)):
    """Stop the autonomous background threat hunter watchtower."""
    status = await _threat_hunter.stop()
    return status.to_dict()


@app.get("/api/v1/hunter/status", tags=["Autonomous Threat Hunter"])
async def get_threat_hunter_status(api_key: str = Depends(get_api_key)):
    """Retrieve operational metrics and status of the Threat Hunter."""
    return _threat_hunter.status().to_dict()


@app.get("/api/v1/hunter/findings", tags=["Autonomous Threat Hunter"])
async def get_threat_hunter_findings(
    limit: int = 50,
    api_key: str = Depends(get_api_key),
):
    """Retrieve recent autonomous threat hunting detections."""
    return {
        "findings": _threat_hunter.get_findings(limit=limit),
        "count": len(_threat_hunter.get_findings(limit=limit)),
    }


@app.post("/api/v1/hunter/scan-block", tags=["Autonomous Threat Hunter"])
async def manual_scan_block(
    payload: Optional[HunterScanBlockRequest] = None,
    api_key: str = Depends(get_api_key),
):
    """Manually triggers triage on an individual block."""
    block_num = payload.block_number if payload else None
    findings = await _threat_hunter.scan_single_block(block_num=block_num)
    return {
        "block_number": _threat_hunter._current_block,
        "findings": [f.to_dict() for f in findings],
        "threats_count": len(findings),
    }


# ── Enterprise Healthcheck & Readiness Probes ────────────────────────────────

@app.get("/api/v1/queue/stats", include_in_schema=False)
async def queue_stats():
    """Internal: job queue stats for monitoring."""
    from orchestrator.services.job_queue import job_queue
    return job_queue.stats


# ── Threat Graph & Heuristics v2 ──────────────────────────────────────────────

@app.post("/api/v1/intelligence/threat-graph", tags=["AI Intelligence"])
@limiter.limit("10/minute")
async def build_threat_graph(
    request: Request,
    payload: RemediateRequest,
    _key: str = Depends(get_api_key),
):
    """Build a NetworkX threat dependency graph from findings. Returns nodes, edges, centrality."""
    from orchestrator.services.threat_graph import ThreatGraph
    graph = ThreatGraph()
    graph.build_from_findings([dict(f) for f in payload.findings])
    return graph.to_dict()


@app.post("/api/v1/intelligence/blast-radius", tags=["AI Intelligence"])
@limiter.limit("10/minute")
async def compute_blast_radius(
    request: Request,
    payload: RemediateRequest,
    root_node_id: str = Query(..., description="Node ID to compute blast radius from"),
    _key: str = Depends(get_api_key),
):
    """Compute blast radius from root_node_id: affected nodes, protocols, critical paths."""
    from orchestrator.services.threat_graph import ThreatGraph
    graph = ThreatGraph()
    graph.build_from_findings([dict(f) for f in payload.findings])
    result = graph.blast_radius(root_node_id)
    return {
        "root_node": result.root_node,
        "affected_nodes": result.affected_nodes,
        "affected_protocols": result.affected_protocols,
        "depth": result.depth,
        "total_value_at_risk_usd": result.total_value_at_risk_usd,
        "critical_paths": result.critical_paths,
    }


@app.post("/api/v1/intelligence/heuristics-scan", tags=["AI Intelligence"])
@limiter.limit("20/minute")
async def heuristics_v2_scan(
    request: Request,
    payload: RemediateRequest,
    _key: str = Depends(get_api_key),
):
    """Run 17-rule bytecode/source heuristics engine v2. Returns findings sorted CRITICAL first."""
    from modules.threat_hunter.heuristics_v2 import heuristics_v2
    files = [
        {
            "path": str(f.get("file", "")),
            "content": str(f.get("snippet", "")) + " " + str(f.get("description", "")),
        }
        for f in payload.findings
    ]
    results = heuristics_v2.scan_files(files)
    if _PROMETHEUS_AVAILABLE and _findings_total:
        for r in results:
            _findings_total.labels(severity=r.get("severity", "INFO")).inc()
    return {
        "rule_count": heuristics_v2.rule_count,
        "findings_count": len(results),
        "findings": results,
    }


@app.get("/health/live", tags=["Health & Readiness"])
async def liveness_probe():
    """Kubernetes / Docker container liveness probe."""
    return {"status": "alive", "timestamp": time.time()}


@app.get("/health/ready", tags=["Health & Readiness"])
async def readiness_probe(session: AsyncSession = Depends(get_session)):
    """Enterprise deep readiness probe checking database, event bus, and AI engine."""
    checks = {
        "api": "ok",
        "database": "unknown",
        "threat_stream_bus": "unknown",
        "threat_hunter": "active" if _threat_hunter.is_running else "idle",
    }

    # DB check
    try:
        from sqlmodel import text
        await session.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception as e:
        checks["database"] = f"unhealthy: {str(e)[:40]}"

    # Threat stream check
    try:
        from orchestrator.services.threat_stream import get_event_bus
        bus = get_event_bus()
        checks["threat_stream_bus"] = "ok"
    except Exception as e:
        checks["threat_stream_bus"] = "degraded"

    is_healthy = checks["database"] == "ok"
    status_code = 200 if is_healthy else 503

    return JSONResponse(
        status_code=status_code,
        content={
            "ready": is_healthy,
            "version": "5.0.0",
            "checks": checks,
            "timestamp": time.time(),
        },
    )
