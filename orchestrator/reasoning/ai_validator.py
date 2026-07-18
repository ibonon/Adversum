import logging
import asyncio
import os
import json
from typing import List
from ..models.findings import RawFinding, ValidatedFinding, ValidationStatus, Severity
from ..ai_reasoning.llm_client import MockMultiModelClient, LLMModel
from ..ai_reasoning.prompts import ANALYSIS_SYSTEM_PROMPT, AUDIT_SYSTEM_PROMPT, ZERODAY_SYSTEM_PROMPT

logger = logging.getLogger(__name__)

class AIValidator:
    """
    Responsible for the 'Reasoning' phase using a Hybrid Multi-Model Strategy (Async).
    """
    
    def __init__(self):
        from ..ai_reasoning.llm_client import ProductionMultiModelClient
        self.client = ProductionMultiModelClient()
        self._concurrency_limit = asyncio.Semaphore(10) # Industrial best practice

    async def validate(self, findings: List[RawFinding]) -> List[ValidatedFinding]:
        logger.info(f"Validating {len(findings)} findings via Optimized Hybrid AI Strategy.")
        
        # Step 1: Pre-load file contents to avoid thrashing
        # Group findings by file_path to read each file exactly once
        unique_paths = list(set(f.file_path for f in findings))
        file_cache = {}
        for path in unique_paths:
            try:
                if os.path.exists(path):
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        file_cache[path] = f.read()
                else:
                    file_cache[path] = ""
            except Exception as e:
                logger.warning(f"Failed to pre-load {path}: {e}")
                file_cache[path] = ""

        # Step 2: Parallel Execution with shared context
        tasks = [self._validate_single(raw, file_cache.get(raw.file_path, "")) for raw in findings]
        validated_results = await asyncio.gather(*tasks)
            
        return validated_results

    async def _validate_single(self, raw: RawFinding, file_content: str) -> ValidatedFinding:
        async with self._concurrency_limit:
            # Step 0: Build rich G-ASR Context using pre-loaded content
            from ..ai_reasoning.context import ContextBuilder
            builder = ContextBuilder()
            
            ctx = builder.build_context(raw, file_content)

            # Step 1: Analyzer (DeepSeek R1 preferred for reasoning)
            logger.info(f"Requesting Async G-ASR Analysis for {raw.id} at {raw.file_path}:{raw.line}...")
            
            # Format a high-intelligence prompt including the Flow Path
            path_str = " -> ".join(ctx.flow_path) if ctx.flow_path else "Direct access (no complex CFG path)"
            
            analysis_prompt = (
                f"VULNERABILITY CONTEXT (G-ASR):\n"
                f"- File: {ctx.file_path}\n"
                f"- Rule: {ctx.vulnerability_type}\n"
                f"- Severity: {ctx.severity}\n"
                f"- Flow Path (CFG): {path_str}\n\n"
                f"CODE SNIPPET:\n{ctx.code_snippet}\n\n"
                f"SURROUNDING CONTEXT:\n{ctx.surrounding_code}\n\n"
                f"TASK: Analyze the impact of this vulnerability. Return ONLY a valid JSON object."
            )
            
            # Use specialized researcher prompt for Zero-Day candidates
            is_zeroday_research = raw.id == "ZERODAY_CANDIDATE_SINK"
            system_prompt = ZERODAY_SYSTEM_PROMPT if is_zeroday_research else ANALYSIS_SYSTEM_PROMPT
            
            # Hybrid Preference: Use DeepSeek R1 if Ollama is enabled
            if self.client.ollama_enabled:
                model = LLMModel.OLLAMA_DEEPSEEK_R1_DISTILL
            else:
                model = LLMModel.OPENAI_O1_PREVIEW if is_zeroday_research else LLMModel.CLAUDE_3_5_SONNET
            
            analysis_result = await self.client.generate_async(
                model, 
                system_prompt, 
                analysis_prompt
            )
            
            import json
            
            # Parse Thought and Answer from DeepSeek R1 or other models
            thought = ""
            if "<think>" in analysis_result and "</think>" in analysis_result:
                parts = analysis_result.split("</think>")
                thought = parts[0].replace("<think>", "").strip()
                final_answer = parts[1].strip()
            else:
                final_answer = analysis_result.strip()
            
            # Parse JSON from Answer
            try:
                # Basic cleanup in case of markdown blocks
                if "```json" in final_answer:
                    final_answer = final_answer.split("```json")[1].split("```")[0].strip()
                elif "```" in final_answer:
                    final_answer = final_answer.split("```")[1].split("```")[0].strip()
                
                analysis_data = json.loads(final_answer)
                status_label = "[Deep-Reasoning]" if not self.client.is_mock else "[Simulation-Mock]"
                notes = f"{status_label}: {analysis_data.get('analysis', 'Analysis unavailable.')}"
                if thought:
                    notes = f"[Chain of Thought]:\n{thought}\n\n{notes}"
                fix_proposal = analysis_data.get("fix")
            except json.JSONDecodeError:
                status_label = "[Analyzer (Parse Error)]" if not self.client.is_mock else "[Simulation-Mock (Fallback)]"
                notes = f"{status_label}: {final_answer}"
                if thought:
                    notes = f"[Chain of Thought]:\n{thought}\n\n{notes}"
                fix_proposal = None
            
            status = ValidationStatus.CONFIRMED
            confidence = 0.9
            
            # Step 2: Auditor (OpenAI o1) - Challenge mechanism
            if raw.severity in [Severity.HIGH, Severity.CRITICAL]:
                logger.info(f"Triggering Highly Intelligent Auditor (o1) for {raw.severity} finding...")
                audit_prompt = f"Previous Analysis: {analysis_result}\nOriginal Finding: {raw.message}\nSnippet: {raw.snippet}"
                
                # Prefer R1 for auditing too if enabled
                audit_model = LLMModel.OLLAMA_DEEPSEEK_R1_DISTILL if self.client.ollama_enabled else LLMModel.OPENAI_O1_PREVIEW

                audit_result = await self.client.generate_async(
                    audit_model,
                    AUDIT_SYSTEM_PROMPT,
                    audit_prompt
                )
                
                try:
                    audit_data = json.loads(audit_result)
                    notes += f"\n\n[Auditor]: {audit_data.get('reasoning', 'No reasoning provided.')}"
                    
                    if audit_data.get('conclusion') == "FALSE_POSITIVE":
                        status = ValidationStatus.REJECTED
                        confidence = 0.2
                        notes += "\n\n-> Auditor REJECTED this finding as a probable false positive."
                except json.JSONDecodeError:
                    notes += f"\n\n[Auditor (Parse Error)]: {audit_result}"

            suggestion = "Refer to analysis."
            if fix_proposal and fix_proposal.get("code"):
                suggestion = f"Suggested Fix: {fix_proposal['description']}\nCode: `{fix_proposal['code']}`"

            return ValidatedFinding(
                raw=raw,
                validation_status=status,
                ai_confidence=confidence,
                reasoning_notes=notes,
                remediation_suggestion=suggestion,
                fix_description=fix_proposal['description'] if fix_proposal else None,
                fix_code=fix_proposal['code'] if fix_proposal else None
            )
