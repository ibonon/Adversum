from sqlmodel import Session
from orchestrator.services.db import engine, create_db_and_tables
from orchestrator.models.sql_models import Job, FindingModel, JobStatus
from orchestrator.models.findings import RawFinding, ValidatedFinding, Severity, ValidationStatus

def test_db_persistence():
    print("Creating tables...")
    create_db_and_tables()
    
    with Session(engine) as session:
        print("Creating mock Job...")
        job = Job(project_path="test_project", status=JobStatus.COMPLETED)
        session.add(job)
        session.commit()
        session.refresh(job)
        
        print(f"Creating mock Finding for Job #{job.id}...")
        # Simulating what happens in api/main.py
        raw = RawFinding(
            id="RUST_CORE_001_DANGEROUS_EVAL",
            message="Test DB message",
            severity=Severity.HIGH,
            file_path="test.py",
            line=50,
            snippet="eval(x)",
            flow_path=["source", "sink"]
        )
        
        vf = ValidatedFinding(
            raw=raw,
            validation_status=ValidationStatus.CONFIRMED,
            ai_confidence=0.85,
            reasoning_notes="DB Persistence Test",
            remediation_suggestion="Fix it"
        )
        
        db_finding = FindingModel(
            job_id=job.id,
            rule_id=vf.raw.id, # matches the renamed field
            message=vf.raw.message,
            severity=vf.raw.severity,
            file_path=vf.raw.file_path,
            line=vf.raw.line,
            snippet=vf.raw.snippet,
            validation_status=vf.validation_status,
            ai_confidence=vf.ai_confidence,
            reasoning_notes=vf.reasoning_notes,
            remediation_suggestion=vf.remediation_suggestion
        )
        
        session.add(db_finding)
        session.commit()
        print("Finding saved successfully!")
        
        # Cleanup
        session.delete(db_finding)
        session.delete(job)
        session.commit()
        print("Cleanup complete.")

if __name__ == "__main__":
    test_db_persistence()
