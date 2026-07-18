
import asyncio
import os
import shutil
import logging
from sqlmodel import Session, select
from api.main import process_audit, Job, JobStatus, FindingModel
from orchestrator.services.db import engine, create_db_and_tables

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Use a test DB to avoid cluttering the real one
os.environ["DATABASE_URL"] = "sqlite:///./verify_audit.db"
TEST_REPO_URL = "https://github.com/navdeep-G/sample-python-project.git"

async def verify_real_audit():
    logger.info("Setting up database...")
    create_db_and_tables()
    
    # Clean up any previous attempts
    if os.path.exists("./tmp_repos"):
        shutil.rmtree("./tmp_repos", ignore_errors=True)
        os.makedirs("./tmp_repos")

    job_id = 0
    with Session(engine) as session:
        job = Job(project_path=TEST_REPO_URL, status=JobStatus.PENDING)
        session.add(job)
        session.commit()
        job_id = job.id
        logger.info(f"Created Job {job_id} for URL {TEST_REPO_URL}")

    logger.info("Starting process_audit...")
    try:
        await process_audit(job_id, TEST_REPO_URL)
    except Exception as e:
        logger.error(f"process_audit failed: {e}")
        # Print full trace if possible
        import traceback
        traceback.print_exc()

    with Session(engine) as session:
        job = session.get(Job, job_id)
        logger.info(f"Job Status: {job.status}")
        logger.info(f"Job Summary: {job.summary}")
        logger.info(f"Job Error: {job.error_message}")
        
        findings = session.exec(select(FindingModel).where(FindingModel.job_id == job_id)).all()
        logger.info(f"Findings found: {len(findings)}")
        for f in findings:
            logger.info(f" - {f.rule_id}: {f.message} ({f.file_path})")

        if job.status == JobStatus.COMPLETED:
            print("SUCCESS: Real audit completed.")
        else:
            print("FAILURE: Audit did not complete successfully.")

if __name__ == "__main__":
    if os.path.exists("./verify_audit.db"):
        os.remove("./verify_audit.db") # Clean start
    asyncio.run(verify_real_audit())
