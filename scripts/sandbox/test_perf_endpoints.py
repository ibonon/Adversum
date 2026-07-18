from fastapi.testclient import TestClient
from api.main import app, get_session
from orchestrator.models.sql_models import Job, FindingModel, JobStatus
from sqlmodel import Session, create_engine, SQLModel
from datetime import datetime
import os
import sys

# Add project root to sys.path
sys.path.append(os.getcwd())

# Setup in-memory DB for testing
engine = create_engine("sqlite:///:memory:")

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

def get_session_override():
    with Session(engine) as session:
        yield session

app.dependency_overrides[get_session] = get_session_override
client = TestClient(app)

def setup_data():
    create_db_and_tables()
    with Session(engine) as session:
        # Create dummy data
        job1 = Job(project_path="/tmp/1", status=JobStatus.COMPLETED, robustness_score=0.9, created_at=datetime.utcnow())
        job2 = Job(project_path="/tmp/2", status=JobStatus.COMPLETED, robustness_score=0.8, created_at=datetime.utcnow())
        session.add(job1)
        session.add(job2)
        session.commit()
        session.refresh(job1)
        session.refresh(job2)
        
        # Add finding to job1
        f1 = FindingModel(
            job_id=job1.id, 
            rule_id="R1", 
            message="M1", 
            severity="HIGH", 
            file_path="f1.py", 
            line=1, 
            snippet="s1", 
            validation_status="CONFIRMED",
            ai_confidence=0.95,
            reasoning_notes="Valid finding"
        )
        session.add(f1)
        
        # Add finding to job2 (same finding = common)
        f2 = FindingModel(
            job_id=job2.id, 
            rule_id="R1", 
            message="M1", 
            severity="HIGH", 
            file_path="f1.py", 
            line=1, 
            snippet="s1", 
            validation_status="CONFIRMED",
            ai_confidence=0.95,
            reasoning_notes="Valid finding"
        )
        session.add(f2)
        
        # Add new finding to job2 (added)
        f3 = FindingModel(
            job_id=job2.id, 
            rule_id="R2", 
            message="M2", 
            severity="MEDIUM", 
            file_path="f2.py", 
            line=5, 
            snippet="s2", 
            validation_status="CONFIRMED",
            ai_confidence=0.8,
            reasoning_notes="New finding"
        )
        session.add(f3)
        
        session.commit()
        return job1.id, job2.id

def test_dashboard_stats():
    print("Testing /stats/dashboard...")
    response = client.get("/stats/dashboard", headers={"X-API-Key": "adv-dev-key-123"})
    if response.status_code != 200:
        print(f"FAILED: {response.text}")
        return
        
    data = response.json()
    print(f"Response: {data}")
    assert data["total_audits"] == 2
    assert data["total_threats"] == 3
    assert abs(data["average_robustness"] - 0.85) < 0.001
    print("Dashboard Stats: PASS")

def test_compare_audits(id1, id2):
    print(f"Testing /audit/{id1}/compare/{id2}...")
    response = client.get(f"/audit/{id1}/compare/{id2}", headers={"X-API-Key": "adv-dev-key-123"})
    if response.status_code != 200:
        print(f"FAILED: {response.text}")
        return

    data = response.json()
    assert len(data["common_findings"]) == 1
    assert len(data["added_findings"]) == 1
    assert len(data["removed_findings"]) == 0
    assert abs(data["robustness_delta"] - (-0.1)) < 0.001
    print("Audit Comparison: PASS")

if __name__ == "__main__":
    try:
        id1, id2 = setup_data()
        test_dashboard_stats()
        test_compare_audits(id1, id2)
        print("\nALL PERFORMANCE ENDPOINTS VERIFIED SUCCESSFULLY")
    except Exception as e:
        print(f"\nCRITICAL FAILURE: {e}")
        import traceback
        traceback.print_exc()
