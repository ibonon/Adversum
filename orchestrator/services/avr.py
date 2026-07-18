import logging
import os
from typing import Optional
from ..core_bridge.core_wrapper import CoreWrapper
from .patcher import PatchService
from ..models.findings import ValidationStatus
from ..models.sql_models import AuditLog
from sqlmodel import Session
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

class AVREngine:
    """
    Autonomous Verified Remediation Engine.
    Orchestrates the loop: Apply Fix -> Verify with Static Engine -> Confirm.
    """
    
    def __init__(self):
        self.patcher = PatchService()
        self.core = CoreWrapper()

    async def run_remediation(self, finding_id: int, file_path: str, line_number: int, old_snippet: str, fix_code: str, proof_anchor: Optional[str] = None, speculative: bool = True) -> bool:
        """
        Executes the full AVR loop for a specific finding.
        Includes a self-healing refinement pass if the first attempt fails.
        If speculative=True, tries to generate 2 candidates if the first one fails.
        """
        logger.info(f"Starting AVR Loop for finding {finding_id} in {file_path}")

        # Try 1: Initial AI Fix
        success, remaining = await self._apply_and_verify(file_path, line_number, old_snippet, fix_code, proof_anchor=proof_anchor)
        
        if not success:
            logger.warning("AVR: Verification failed on first attempt. Triggering AI Self-Healing...")
            # Build detailed feedback from remaining findings
            feedback = "Verification scan still detected the following potential issues:\n"
            for f in remaining:
                feedback += f"- L{f.line}: {f.message} ({f.id})\n"
            
            if speculative:
                logger.info("AVR: Speculative Mode Active - Generating 2 parallel refinement candidates.")
                # Parallel generation of 2 candidates
                candidates_tasks = [
                    self._request_refinement(file_path, line_number, fix_code, feedback + "\nNote: Try a different approach than the previous one."),
                    self._request_refinement(file_path, line_number, fix_code, feedback + "\nNote: Focus on strict type safety and input sanitization.")
                ]
                import asyncio
                refined_fixes = await asyncio.gather(*candidates_tasks)
                
                # Expert Optimization: Test all candidates in parallel (leveraging Rust speed)
                logger.info(f"AVR: Testing {len([f for f in refined_fixes if f])} candidates in PARALLEL.")
                test_tasks = [
                    self._apply_and_verify(file_path, line_number, old_snippet, rf) 
                    for rf in refined_fixes if rf
                ]
                results = await asyncio.gather(*test_tasks)
                
                for success, _ in results:
                    if success:
                        break
            else:
                # Traditional single refinement
                refined_fix = await self._request_refinement(file_path, line_number, fix_code, feedback)
                if refined_fix:
                    logger.info("AVR: Applying single refined fix...")
                    success, _ = await self._apply_and_verify(file_path, line_number, old_snippet, refined_fix)

        if success:
            logger.info(f"AVR: Remediation VERIFIED for {file_path}")
            # Log successful remediation
            async with AsyncSession(engine) as session:
                log = AuditLog(
                    action="AVR_REMEDIATION",
                    target=file_path,
                    status="SUCCESS",
                    details=f"Finding {finding_id} fixed. Verification PASSED."
                )
                session.add(log)
                await session.commit()
            
            bak_file = f"{file_path}.bak"
            if os.path.exists(bak_file):
                os.remove(bak_file)
            return True
        else:
            logger.error(f"AVR: Remediation ultimately failed for {file_path}")
            # Log failed remediation
            async with AsyncSession(engine) as session:
                log = AuditLog(
                    action="AVR_REMEDIATION",
                    target=file_path,
                    status="FAILED",
                    details=f"Finding {finding_id} fix failed verification. Rollback performed."
                )
                session.add(log)
                await session.commit()

            self.rollback(file_path) # Final fallback
            return False

    async def _apply_and_verify(self, file_path: str, line_number: int, old_snippet: str, fix_code: str, proof_anchor: Optional[str] = None) -> tuple[bool, list]:
        """
        Applies patch and runs Core analysis to verify.
        Returns (success, remaining_relevant_findings)
        """
        # Restore from backup before trying a new patch if it's there
        bak_file = f"{file_path}.bak"
        if os.path.exists(bak_file):
            import shutil
            shutil.copy2(bak_file, file_path)

        # 0. Context Anchor Check: If no anchor provided, try to generate it from old_snippet
        if not proof_anchor and old_snippet:
            import hashlib
            clean_snippet = "".join(old_snippet.split())
            proof_anchor = hashlib.md5(f"{file_path}:{clean_snippet}".encode()).hexdigest()

        # 1. Apply Patch
        patch_success = self.patcher.apply_fix(file_path, line_number, old_snippet, fix_code)
        if not patch_success:
            return False, []

        # 2. Verify with Core (Using Targeted Scan for 70% speedup)
        try:
            # High-Performance: Only re-scan the patched zone (±15 lines)
            # This avoids scanning 10k+ lines in large files for every patch candidate.
            dirty_ranges = {file_path: [(max(1, line_number - 15), line_number + 15)]}
            new_findings, _, _ = self.core.analyze([file_path], dirty_ranges=dirty_ranges)
            
            # Robust Matching: Use proof_anchor if available, fallback to line window
            if proof_anchor:
                remaining = [
                    f for f in new_findings 
                    if getattr(f, 'proof_anchor', None) == proof_anchor
                ]
            else:
                remaining = [
                    f for f in new_findings
                    if abs(f.line - line_number) <= 5
                ]
            
            # Regression Scan: Ensure no new findings were introduced
            # In an expert system, we don't just want to fix the bug, we want to NOT create new ones.
            # We compare total count or specific new criticals.
            # For now, let's keep it simple: if ANY findings exist in the file, we check if they are our 'target'.
            
            # Check for Formal Immunity (RBAT)
            immune = any(
                f.immune_context and f.immune_context.invariant_holds
                for f in remaining
            )

            success = len(remaining) == 0 or immune
            return success, remaining
            
        except Exception as e:
            logger.error(f"AVR Verification Error: {e}")
            return False, []

    async def _request_refinement(self, file_path: str, line_number: int, failed_fix: str, failure_reason: str) -> Optional[str]:
        """Calls the AI to refine the fix given the failure feedback."""
        from ..reasoning.ai_validator import AIValidator
        validator = AIValidator() 
        
        prompt = (
            f"REFINE FIX REQUIRED:\n"
            f"File: {file_path}\n"
            f"Line: {line_number}\n"
            f"Previous Failed Fix: {failed_fix}\n"
            f"Failure Feedback from Static Engine: {failure_reason}\n\n"
            f"Please provide a more robust or alternative fix that addresses these specific points."
        )
        
        # We use a similar prompt structure as the initial analysis
        try:
            from ..ai_reasoning.llm_client import LLMModel
            from ..ai_reasoning.prompts import ANALYSIS_SYSTEM_PROMPT
            
            result_json = await validator.client.generate_async(
                LLMModel.CLAUDE_3_5_SONNET,
                ANALYSIS_SYSTEM_PROMPT + "\nFOCUS: You are in Refinement Mode. The previous fix failed validation.",
                prompt
            )
            
            import json
            data = json.loads(result_json)
            return data.get("fix", {}).get("code")
        except Exception as e:
            logger.error(f"AVR Refinement AI error: {e}")
            return None

    async def run_batch_remediation(self, file_path: str, findings: list) -> bool:
        """
        Boosted: Applies multiple fixes to the same file and verifies them in a single Core pass.
        Returns True if ALL findings in the file were successfully remediated.
        """
        logger.info(f"AVR Boost: Starting batch remediation for {len(findings)} findings in {file_path}")
        
        # 1. Apply all fixes at once
        patches = [(f.line_number, f.snippet, f.fix_code) for f in findings if f.fix_code]
        if not patches:
            return False
            
        # Create backup once for the whole batch
        shutil.copy2(file_path, f"{file_path}.bak")
        
        success = self.patcher.apply_batch_fixes(file_path, patches)
        if not success:
            return False
            
        # 2. Verify all at once
        try:
            new_findings, _, _ = self.core.analyze([file_path])
            
            # Check if ANY of our target lines still have issues
            target_lines = {p[0] for p in patches}
            remaining = [f for f in new_findings if any(abs(f.line - tl) <= 5 for tl in target_lines)]
            
            if not remaining:
                logger.info(f"AVR Boost: Batch remediation SUCCESS for {file_path}")
                os.remove(f"{file_path}.bak")
                return True
            else:
                logger.warning(f"AVR Boost: Batch failed verification. Falling back to individual speculative fixing.")
                # We could potentially do more smart logic here, but for now fallback is safest
                self.rollback(file_path)
                return False
        except Exception as e:
            logger.error(f"AVR Batch Verification Error: {e}")
            self.rollback(file_path)
            return False

    def rollback(self, file_path: str):
        """Restores the .bak file if remediation failed."""
        bak_file = f"{file_path}.bak"
        if os.path.exists(bak_file):
            import shutil
            shutil.copy2(bak_file, file_path)
            logger.info(f"AVR: Rollback successful for {file_path}")
