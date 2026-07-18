import logging
import os
import shutil
from typing import Optional
from ..core_bridge.core_wrapper import CoreWrapper
from .patcher import PatchService
from ..models.findings import ValidationStatus

logger = logging.getLogger(__name__)


class AVREngine:
    """
    Autonomous Verified Remediation Engine.
    Orchestrates the loop: Apply Fix -> Verify with Static Engine -> Confirm.
    """

    def __init__(self):
        self.patcher = PatchService()
        self.core = CoreWrapper()

    async def run_remediation(
        self,
        finding_id: int,
        file_path: str,
        line_number: int,
        old_snippet: str,
        fix_code: str,
        proof_anchor: Optional[str] = None,
        speculative: bool = True,
    ) -> bool:
        """
        Executes the full AVR loop for a specific finding.
        Includes a self-healing refinement pass if the first attempt fails.
        If speculative=True, tries to generate 2 candidates if the first one fails.
        """
        logger.info(f"Starting AVR Loop for finding {finding_id} in {file_path}")

        # Try 1: Initial AI Fix
        success, remaining = await self._apply_and_verify(
            file_path, line_number, old_snippet, fix_code, proof_anchor=proof_anchor
        )

        if not success:
            logger.warning(
                "AVR: Verification failed on first attempt. Triggering AI Self-Healing..."
            )
            feedback = "Verification scan still detected the following potential issues:\n"
            for f in remaining:
                line = getattr(f, "line", getattr(f, "line_number", "?"))
                msg = getattr(f, "message", "Unknown")
                rule = getattr(f, "id", getattr(f, "rule_id", "UNKNOWN"))
                feedback += f"- L{line}: {msg} ({rule})\n"

            if speculative:
                logger.info(
                    "AVR: Speculative Mode Active - Generating 2 parallel refinement candidates."
                )
                import asyncio

                candidates_tasks = [
                    self._request_refinement(
                        file_path,
                        line_number,
                        fix_code,
                        feedback
                        + "\nNote: Try a different approach than the previous one.",
                    ),
                    self._request_refinement(
                        file_path,
                        line_number,
                        fix_code,
                        feedback
                        + "\nNote: Focus on strict type safety and input sanitization.",
                    ),
                ]
                refined_fixes = await asyncio.gather(*candidates_tasks)

                logger.info(
                    f"AVR: Testing {len([f for f in refined_fixes if f])} candidates in PARALLEL."
                )
                test_tasks = [
                    self._apply_and_verify(file_path, line_number, old_snippet, rf)
                    for rf in refined_fixes
                    if rf
                ]
                results = await asyncio.gather(*test_tasks)

                for candidate_success, _ in results:
                    if candidate_success:
                        success = True
                        break
            else:
                refined_fix = await self._request_refinement(
                    file_path, line_number, fix_code, feedback
                )
                if refined_fix:
                    logger.info("AVR: Applying single refined fix...")
                    success, _ = await self._apply_and_verify(
                        file_path, line_number, old_snippet, refined_fix
                    )

        if success:
            logger.info(f"AVR: Remediation VERIFIED for {file_path}")
            await self._log_audit(
                file_path,
                "AVR_REMEDIATION",
                "SUCCESS",
                f"Finding {finding_id} fixed. Verification PASSED.",
            )
            bak_file = f"{file_path}.bak"
            if os.path.exists(bak_file):
                os.remove(bak_file)
            return True
        else:
            logger.error(f"AVR: Remediation ultimately failed for {file_path}")
            await self._log_audit(
                file_path,
                "AVR_REMEDIATION",
                "FAILED",
                f"Finding {finding_id} fix failed verification. Rollback performed.",
            )
            self.rollback(file_path)
            return False

    async def _log_audit(
        self, target: str, action: str, status: str, details: str
    ) -> None:
        """Logs an audit entry safely; skips if DB is not configured."""
        try:
            from sqlmodel import Session
            from sqlalchemy.ext.asyncio import AsyncSession
            from ..models.sql_models import AuditLog
            from ..services.db import get_engine

            engine = get_engine()
            if engine is None:
                return
            async with AsyncSession(engine) as session:
                log = AuditLog(
                    action=action, target=target, status=status, details=details
                )
                session.add(log)
                await session.commit()
        except Exception as e:
            logger.warning(f"AVR audit log skipped (no DB or import error): {e}")

    async def _apply_and_verify(
        self,
        file_path: str,
        line_number: int,
        old_snippet: str,
        fix_code: str,
        proof_anchor: Optional[str] = None,
    ) -> tuple[bool, list]:
        """
        Applies patch and runs Core analysis to verify.
        Returns (success, remaining_relevant_findings)
        """
        bak_file = f"{file_path}.bak"
        if os.path.exists(bak_file):
            shutil.copy2(bak_file, file_path)

        if not proof_anchor and old_snippet:
            import hashlib

            clean_snippet = "".join(old_snippet.split())
            proof_anchor = hashlib.md5(
                f"{file_path}:{clean_snippet}".encode()
            ).hexdigest()

        patch_success = self.patcher.apply_fix(
            file_path, line_number, old_snippet, fix_code
        )
        if not patch_success:
            return False, []

        try:
            dirty_ranges = {file_path: [(max(1, line_number - 15), line_number + 15)]}
            # core.analyze returns (findings, file_hashes, robustness_score)
            new_findings, _, _ = self.core.analyze(
                [file_path], dirty_ranges=dirty_ranges
            )

            if proof_anchor:
                remaining = [
                    f
                    for f in new_findings
                    if getattr(f, "proof_anchor", None) == proof_anchor
                ]
            else:
                remaining = [
                    f
                    for f in new_findings
                    if abs(getattr(f, "line", getattr(f, "line_number", 0)) - line_number) <= 5
                ]

            immune = any(
                getattr(f, "immune_context", None) is not None
                and getattr(getattr(f, "immune_context", None), "invariant_holds", False)
                for f in remaining
            )

            success = len(remaining) == 0 or immune
            return success, remaining

        except Exception as e:
            logger.error(f"AVR Verification Error: {e}")
            return False, []

    async def _request_refinement(
        self,
        file_path: str,
        line_number: int,
        failed_fix: str,
        failure_reason: str,
    ) -> Optional[str]:
        """Calls the AI to refine the fix given the failure feedback."""
        prompt = (
            f"REFINE FIX REQUIRED:\n"
            f"File: {file_path}\n"
            f"Line: {line_number}\n"
            f"Previous Failed Fix: {failed_fix}\n"
            f"Failure Feedback from Static Engine: {failure_reason}\n\n"
            f"Please provide a more robust or alternative fix that addresses these specific points."
        )

        try:
            from ..reasoning.ai_validator import AIValidator
            from ..ai_reasoning.llm_client import LLMModel
            from ..ai_reasoning.prompts import ANALYSIS_SYSTEM_PROMPT

            validator = AIValidator()
            result_json = await validator.client.generate_async(
                LLMModel.CLAUDE_3_5_SONNET,
                ANALYSIS_SYSTEM_PROMPT
                + "\nFOCUS: You are in Refinement Mode. The previous fix failed validation.",
                prompt,
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
        logger.info(
            f"AVR Boost: Starting batch remediation for {len(findings)} findings in {file_path}"
        )

        patches = [
            (
                getattr(f, "line_number", getattr(f, "line", 0)),
                getattr(f, "snippet", ""),
                getattr(f, "fix_code", ""),
            )
            for f in findings
            if getattr(f, "fix_code", None)
        ]
        if not patches:
            return False

        shutil.copy2(file_path, f"{file_path}.bak")

        success = self.patcher.apply_batch_fixes(file_path, patches)
        if not success:
            return False

        try:
            new_findings, _, _ = self.core.analyze([file_path])
            target_lines = {p[0] for p in patches}
            remaining = [
                f
                for f in new_findings
                if any(
                    abs(getattr(f, "line", getattr(f, "line_number", 0)) - tl) <= 5
                    for tl in target_lines
                )
            ]

            if not remaining:
                logger.info(f"AVR Boost: Batch remediation SUCCESS for {file_path}")
                os.remove(f"{file_path}.bak")
                return True
            else:
                logger.warning(
                    "AVR Boost: Batch failed verification. Falling back to individual speculative fixing."
                )
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
            shutil.copy2(bak_file, file_path)
            logger.info(f"AVR: Rollback successful for {file_path}")
