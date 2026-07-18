import os
import asyncio
import logging
from typing import Dict, Any

from arq.connections import RedisSettings
from sqlalchemy.ext.asyncio import AsyncSession
from orchestrator.services.db import engine
from orchestrator.models.sql_models import FindingModel, Job
from orchestrator.models.findings import RawFinding
from orchestrator.reasoning.ai_validator import AIValidator

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("adversum.worker")

# Setup Redis connection settings for ARQ
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
# parse redis URL (arq uses a slightly different config model if not passed a complete URL)
if REDIS_URL.startswith("redis://"):
    host = REDIS_URL.split("redis://")[1].split(":")[0]
    port = int(REDIS_URL.split("redis://")[1].split(":")[1])
else:
    host = "localhost"
    port = 6379

redis_settings = RedisSettings(host=host, port=port)


async def validate_finding(ctx: Dict[Any, Any], finding_id: int, raw_finding_dict: dict) -> str:
    """
    Background Task: Validates a raw finding from the core engine using the AIValidator.
    """
    logger.info(f"Worker received validation task for finding ID: {finding_id}")
    validator = AIValidator()
    
    # Reconstruct RawFinding model
    raw_finding = RawFinding(**raw_finding_dict)
    
    try:
        # We pass a list of 1 to the validator, but AIValidator supports bulk.
        # To avoid rate limits, bulk was better, but individual validation gives more granular feedback
        # and parallelizes easily across workers.
        validated_findings = await validator.validate([raw_finding])
        
        if not validated_findings:
            logger.error(f"Validator returned no results for finding ID {finding_id}.")
            return "FAILED_NO_RESULT"

        validated = validated_findings[0]
        
        # Update database with the LLM results
        async with AsyncSession(engine) as session:
            db_finding = await session.get(FindingModel, finding_id)
            if db_finding:
                db_finding.validation_status = validated.validation_status
                db_finding.ai_confidence = validated.ai_confidence
                db_finding.reasoning_notes = validated.reasoning_notes
                db_finding.remediation_suggestion = validated.remediation_suggestion
                db_finding.fix_description = getattr(validated, 'fix_description', None)
                db_finding.fix_code = getattr(validated, 'fix_code', None)
                session.add(db_finding)
                await session.commit()
                logger.info(f"Background validation complete for finding {finding_id}: {validated.validation_status}.")
                return validated.validation_status
            else:
                logger.warning(f"Finding ID {finding_id} not found in DB during background validation.")
                return "FAILED_NOT_FOUND"
                
    except Exception as e:
        logger.error(f"Error during background validation for {finding_id}: {str(e)}", exc_info=True)
        # Update DB with error status
        async with AsyncSession(engine) as session:
            db_finding = await session.get(FindingModel, finding_id)
            if db_finding:
                db_finding.validation_status = "ERROR_LLM_TIMEOUT"
                session.add(db_finding)
                await session.commit()
        return "ERROR_LLM_TIMEOUT"

class WorkerSettings:
    """
    Settings for the `arq` CLI to launch the worker.
    Run via: `arq orchestrator.workers.llm_worker.WorkerSettings`
    """
    functions = [validate_finding]
    redis_settings = redis_settings
    max_jobs = 10
    job_timeout = 300 # 5 minutes max per validation to avoid hanging
    
    @staticmethod
    async def on_startup(ctx: Dict[Any, Any]):
        logger.info("ARQ Worker starting up. Subscribed to LLM Validation Queue.")

    @staticmethod
    async def on_shutdown(ctx: Dict[Any, Any]):
        logger.info("ARQ Worker shutting down.")
