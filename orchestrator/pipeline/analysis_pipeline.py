import logging
import time
import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict
from sqlmodel import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from ..services.db import engine
from ..models.sql_models import FileHash, CachedFinding
from ..scanner.project_scanner import ProjectScanner
from ..core_bridge.core_wrapper import CoreWrapper
from ..reasoning.ai_validator import AIValidator
from ..reasoning.deterministic_validator import DeterministicValidator
from ..reporting.report_generator import ReportGenerator
from ..scanner.fallback_engine import FallbackEngine
from ..services.shadow_discovery import ShadowDiscoveryMiner
from ..models.findings import ValidatedFinding, RawFinding
import os

# Use orjson for faster JSON serialization (5-10x faster than stdlib json)
try:
    import orjson
    def json_dumps(obj):
        return orjson.dumps(obj).decode('utf-8')
    def json_loads(s):
        return orjson.loads(s)
except ImportError:
    import json
    json_dumps = json.dumps
    json_loads = json.loads
    logging.getLogger(__name__).warning("orjson not available, using stdlib json (slower)")

logger = logging.getLogger(__name__)

class AnalysisPipeline:
    """
    Orchestrates the complete flow with Phase 4 Optimizations:
    1. Scan Project
    2. Incremental Analysis (XXH3 check)
    3. Analyze modified files (mmap + Pre-compiled queries)
    4. Deterministic Validation (for new/modified findings)
    5. Aggregate Results
    """
    
    def __init__(self):
        self.core = CoreWrapper()
        # Use deterministic validator by default (no LLM, 100% deterministic)
        # Set USE_LLM_VALIDATOR=true to use AIValidator (probabilistic)
        use_llm = os.getenv("USE_LLM_VALIDATOR", "false").lower() == "true"
        self.use_llm = use_llm
        if use_llm:
            logger.warning("Using AIValidator (probabilistic LLM). For deterministic results, use Rust Core Validator.")
            self.validator = AIValidator()
        else:
            if self.core.use_ffi:
                logger.info("Using Rust Core Validator (Deterministic - Parallel)")
                self.validator = None
            else:
                logger.warning("Rust Core NOT active. Using Python Fallback Validator (Deterministic - Slow)")
                self.validator = DeterministicValidator()
        self.reporter = ReportGenerator()
        self.fallback_engine = FallbackEngine()
        
        # [Shadow Discovery] Research Module
        self.researcher = ShadowDiscoveryMiner(
            ai_validator=self.validator if use_llm else None,
            core_wrapper=self.core
        )
        self.research_mode = os.getenv("RESEARCH_MODE", "false").lower() == "true"
        
        # Thread pool for running sync Rust validation without blocking event loop
        self.executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="rust_validator")

    async def run(self, project_path: str) -> dict:
        """
        Main entry point for analysis with Incremental Logic.
        """
        start_time = time.time()
        logger.info(f"Pipeline started for: {project_path}")

        # Step 1: Scan
        scanner = ProjectScanner(project_path)
        all_files = scanner.scan()
        if not all_files:
            logger.warning("No valid source files found.")
            return {"findings": [], "summary": "No source files found."}

        # Step 2: Incremental Check
        changed_files, cached_findings = await self._get_incremental_state(all_files)
        logger.info(f"Incremental State: {len(changed_files)} files modified, {len(cached_findings)} findings cached.")

        # Step 3: Core Analysis (Only for changed files)
        new_findings = []
        robustness_score = 1.0
        if changed_files:
            try:
                raw_findings, new_hashes, core_robustness = self.core.analyze(changed_files)
                new_findings = raw_findings
                robustness_score = core_robustness
            except Exception as e:
                logger.critical(f"RUST CORE CRASHED or unavailable: {e}. Switching to Fallback Engine (Beast Mode)!")
                raw_findings, new_hashes, core_robustness = self.fallback_engine.analyze(changed_files)
                new_findings = raw_findings
                robustness_score = core_robustness
                
            await self._update_incremental_state(new_hashes, raw_findings)
        else:
            logger.info("Universal optimization: No files changed. Skipping Core analysis.")

        # Step 4: Merge Findings
        # Note: In a real scenario, we might want to re-validate only new findings
        # but for now we'll combine all raw findings for validation if they are 'new'
        # or just use the cached results for others.
        
        # Combine all RawFindings
        all_raw_findings = new_findings + cached_findings

        # Step 5: Validation
        if all_raw_findings:
            if self.use_llm:
                logger.info(f"LLM offloaded mode: {len(all_raw_findings)} findings marked for background validation.")
                validated_findings = []
                for rf in all_raw_findings:
                    validated_findings.append(ValidatedFinding(
                        raw=rf,
                        validation_status="PENDING_LLM",
                        ai_confidence=0.0,
                        reasoning_notes="Scheduled for background LLM validation...",
                        remediation_suggestion="",
                        is_fixed=False
                    ))
            elif not self.use_llm and self.core.use_ffi:
                # FIX: Run Rust validation in thread pool to avoid blocking event loop
                logger.info(f"Validating {len(all_raw_findings)} findings using Rust Core Validator (async).")
                loop = asyncio.get_event_loop()
                validated_findings = await loop.run_in_executor(
                    self.executor,
                    self.core.validate_findings,
                    all_raw_findings
                )
            elif not self.use_llm and self.validator:
                logger.info(f"Validating {len(all_raw_findings)} findings using Python Fallback Validator.")
                validated_findings = await self.validator.validate(all_raw_findings)
            else:
                logger.warning("No validator available. Skipping validation.")
                validated_findings = []
        else:
            validated_findings = []

        # Step 5.5: Zero-Day Discovery Research (Optional)
        zero_days = []
        if self.research_mode:
            logger.info("Initiating Zero-Day Research Phase (Autonomous Discovery)...")
            zero_days = await self.researcher.mine(all_files) # Scan ALL files for anomalies
            if zero_days:
                logger.warning(f"ZeroDayMiner discovered {len(zero_days)} potential unknown vulnerabilities!")
        
        all_validated = validated_findings + zero_days

        # Step 6: Reporting
        summary = await self.reporter.generate_summary(all_validated)

        duration = time.time() - start_time
        logger.info(f"Pipeline finished in {duration:.2f}s (Optimized). Results: {len(all_validated)}")
        
        return {
            "findings": all_validated,
            "summary": summary,
            "robustness_score": robustness_score
        }

    async def _get_incremental_state(self, all_files: List[str]) -> tuple[List[str], List[RawFinding]]:
        """Determines which files need re-analysis and returns cached findings for others.
        
        FIX: Optimized to use batch queries instead of N+1 queries.
        """
        changed_files = []
        cached_findings = []
        
        current_hashes = self.core.get_hashes(all_files)
        
        async with AsyncSession(engine) as session:
            # FIX: Load ALL hashes in one query instead of N queries
            db_hashes_list = (await session.execute(select(FileHash))).scalars().all()
            db_hashes = {h.file_path: h.xxh3_hash for h in db_hashes_list}
            
            # Identify changed files
            for path in all_files:
                curr_hash = current_hashes.get(path)
                db_hash = db_hashes.get(path)
                
                if not db_hash or db_hash != curr_hash:
                    changed_files.append(path)
            
            # FIX: Delete old cached findings in ONE query using IN clause
            if changed_files:
                await session.execute(
                    delete(CachedFinding).where(CachedFinding.file_path.in_(changed_files))
                )
            
            # FIX: Load cached findings for unchanged files in ONE query
            unchanged_files = list(set(all_files) - set(changed_files))
            if unchanged_files:
                db_findings = (await session.execute(
                    select(CachedFinding).where(CachedFinding.file_path.in_(unchanged_files))
                )).scalars().all()
                
                for df in db_findings:
                    data = json_loads(df.finding_data_json)
                    cached_findings.append(RawFinding(**data))
            
            # Single commit at the end
            await session.commit()
        
        logger.debug(f"Incremental cache: {len(changed_files)} changed, {len(unchanged_files)} unchanged, {len(cached_findings)} cached findings")
        return changed_files, cached_findings

    async def _update_incremental_state(self, new_hashes: Dict[str, str], new_findings: List[RawFinding]):
        """Updates the database with new hashes and caches new findings.
        
        FIX: Optimized to use batch operations and faster JSON serialization.
        """
        async with AsyncSession(engine) as session:
            # FIX: Load all existing hashes in one query
            existing_hashes = {h.file_path: h for h in (await session.execute(select(FileHash))).scalars().all()}
            
            # Update or insert hashes
            for path, h in new_hashes.items():
                if path in existing_hashes:
                    existing_hashes[path].xxh3_hash = h
                else:
                    session.add(FileHash(file_path=path, xxh3_hash=h))
            
            # Cache findings (grouped by file)
            findings_by_file = {}
            for f in new_findings:
                findings_by_file.setdefault(f.file_path, []).append(f)
            
            # FIX: Use orjson for faster serialization
            for path, file_findings in findings_by_file.items():
                for f in file_findings:
                    session.add(CachedFinding(
                        file_path=path,
                        finding_data_json=json_dumps(f.model_dump())
                    ))
            
            # Single commit at the end
            await session.commit()
