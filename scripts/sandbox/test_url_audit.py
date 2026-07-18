
import asyncio
import os
import shutil
from unittest.mock import MagicMock, patch
from sqlmodel import Session, select
from api.main import process_audit, Job, JobStatus, FindingModel
from orchestrator.services.db import engine, create_db_and_tables
from orchestrator.ingestion.manager import RepoContext

# Setup test environment
TEST_DB_URL = "sqlite:///./test_url_audits.db"
os.environ["DATABASE_URL"] = TEST_DB_URL

# Dummy Repo Content
LOCAL_TEST_REPO = os.path.abspath("./temp_test_cloned_repo")

def setup_dummy_repo():
    if os.path.exists(LOCAL_TEST_REPO):
        shutil.rmtree(LOCAL_TEST_REPO)
    os.makedirs(LOCAL_TEST_REPO)
    with open(os.path.join(LOCAL_TEST_REPO, "vuln.py"), "w") as f:
        f.write("import os\n\ndef run(cmd):\n    os.system(cmd)\n")

async def test_url_audit():
    create_db_and_tables()
    setup_dummy_repo()
    
    # Mock clone_repository to avoid genuine network calls and git operations
    with patch("orchestrator.ingestion.manager.clone_repository") as mock_clone:
        # returns context pointing to our dummy local repo
        mock_clone.return_value = RepoContext(
            url="https://github.com/fake/repo.git",
            local_path=LOCAL_TEST_REPO,
            files=[]
        )
        
        # Create a Job
        with Session(engine) as session:
            job = Job(project_path="https://github.com/fake/repo.git", status=JobStatus.PENDING)
            session.add(job)
            session.commit()
            job_id = job.id
            print(f"Created Job {job_id} with URL {job.project_path}")

        # Run process_audit
        print("Running process_audit...")
        await process_audit(job_id, "https://github.com/fake/repo.git")
        
        # Verify
        with Session(engine) as session:
            job = session.get(Job, job_id)
            print(f"Job Status: {job.status}")
            print(f"Job Summary: {job.summary}")
            
            findings = session.exec(select(FindingModel).where(FindingModel.job_id == job_id)).all()
            print(f"Findings found: {len(findings)}")
            
            assert job.status == JobStatus.COMPLETED
            # We expect findings because vuln.py has os.system
            assert len(findings) > 0
            # Check mock was called
            mock_clone.assert_called_once()
            print("Test PASSED: URL was accepted, 'cloned', and scanned.")

if __name__ == "__main__":
    try:
        asyncio.run(test_url_audit())
    finally:
        # Cleanup
        if os.path.exists(LOCAL_TEST_REPO):
            shutil.rmtree(LOCAL_TEST_REPO)
        # We might want to keep the DB for inspection if it fails, but removing for clean rerun
        if os.path.exists("test_url_audits.db"):
            os.remove("test_url_audits.db")
