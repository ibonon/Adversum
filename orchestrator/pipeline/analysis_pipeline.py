import logging
import time
import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import List, Dict, Optional
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

# SQLite builds before 3.32 cap a statement at 999 bound parameters. Every
# `IN (...)` below is chunked so a large repository cannot blow that limit.
_IN_CHUNK = 900


def _chunked(seq, size: int = _IN_CHUNK):
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


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
        changed_files, cached_findings = await self._get_incremental_state(all_files, project_path)
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
                
            await self._update_incremental_state(new_hashes, raw_findings, changed_files)
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

    async def _get_incremental_state(self, all_files: List[str], project_root: str = "") -> tuple[List[str], List[RawFinding]]:
        """Determines which files need re-analysis and returns cached findings for others.

        The hash table is GLOBAL (one row per path ever scanned). Loading it
        wholesale made the cost of every scan grow with total scan history; the
        query is now scoped to the current project subtree, and rows for files
        that no longer exist are purged so the table cannot grow forever.
        """
        changed_files = []
        cached_findings = []
        
        current_hashes = self.core.get_hashes(all_files)

        # `startswith(..., autoescape=True)` escapes LIKE wildcards, so a path
        # containing '_' or '%' cannot accidentally broaden the match.
        scope = project_root or ""
        file_set = set(all_files)
        
        async with AsyncSession(engine) as session:
            if scope:
                scope_stmt = select(FileHash).where(FileHash.file_path.startswith(scope, autoescape=True))
            else:
                scope_stmt = select(FileHash)
            rows = (await session.execute(scope_stmt)).scalars().all()
            db_hashes = {h.file_path: h.xxh3_hash for h in rows}
            
            # Identify changed files (new, modified, or hash unavailable)
            for path in all_files:
                curr_hash = current_hashes.get(path)
                db_hash = db_hashes.get(path)
                if not db_hash or (curr_hash is not None and db_hash != curr_hash):
                    changed_files.append(path)

            changed_set = set(changed_files)

            # Cache eviction: modified files (stale findings) + deleted files.
            stale_paths = [h.file_path for h in rows if h.file_path not in file_set]
            purge = list(changed_set) + stale_paths
            for chunk in _chunked(purge):
                await session.execute(delete(CachedFinding).where(CachedFinding.file_path.in_(chunk)))

            # Drop hashes for files that disappeared from the project.
            for chunk in _chunked(stale_paths):
                await session.execute(delete(FileHash).where(FileHash.file_path.in_(chunk)))
            
            # Load cached findings for unchanged files, in bounded batches.
            unchanged_files = [p for p in all_files if p not in changed_set]
            for chunk in _chunked(unchanged_files):
                db_findings = (await session.execute(
                    select(CachedFinding).where(CachedFinding.file_path.in_(chunk))
                )).scalars().all()
                
                for df in db_findings:
                    data = json_loads(df.finding_data_json)
                    cached_findings.append(RawFinding(**data))
            
            # Single commit at the end
            await session.commit()
        
        logger.debug(f"Incremental cache: {len(changed_files)} changed, {len(unchanged_files)} unchanged, "
                     f"{len(cached_findings)} cached findings, {len(stale_paths)} stale purged")
        return changed_files, cached_findings

    async def _update_incremental_state(
        self,
        new_hashes: Dict[str, str],
        new_findings: List[RawFinding],
        changed_files: Optional[List[str]] = None,
    ):
        """Persists hashes and per-file finding cache for the files just scanned.

        Only the changed files are touched: the previous version loaded the
        whole FileHash table to upsert, which made writes O(total history).
        """
        if changed_files is None:
            changed_files = list(new_hashes.keys())

        async with AsyncSession(engine) as session:
            existing: Dict[str, FileHash] = {}
            for chunk in _chunked(changed_files):
                rows = (await session.execute(
                    select(FileHash).where(FileHash.file_path.in_(chunk))
                )).scalars().all()
                existing.update({h.file_path: h for h in rows})
            
            now = datetime.now(timezone.utc)

            # Update or insert hashes
            for path, h in new_hashes.items():
                if path in existing:
                    existing[path].xxh3_hash = h
                    existing[path].last_scanned_at = now
                else:
                    session.add(FileHash(file_path=path, xxh3_hash=h, last_scanned_at=now))
            
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
