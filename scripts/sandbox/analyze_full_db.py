from sqlmodel import Session, select, func
from orchestrator.services.db import engine
from orchestrator.models.sql_models import Job, FindingModel, AuditLog, FileHash, CachedFinding
import sys

def analyze():
    with Session(engine) as session:
        print("--- Database Analysis Report ---")
        
        # Jobs Analysis
        jobs = session.exec(select(Job)).all()
        print(f"\nTotal Jobs: {len(jobs)}")
        for job in jobs:
            print(f"  ID: {job.id} | Status: {job.status} | Created: {job.created_at} | Findings: {len(job.findings)}")

        # Findings Analysis
        findings_count = session.exec(select(func.count(FindingModel.id))).one()
        print(f"\nTotal Findings (Global): {findings_count}")
        
        if findings_count > 0:
            print("  Sample Findings (Last 3):")
            recent_findings = session.exec(select(FindingModel).order_by(FindingModel.id.desc()).limit(3)).all()
            for f in recent_findings:
                print(f"    ID: {f.id} | Rule: {f.rule_id} | File: {f.file_path} | Severity: {f.severity}")

        # Audit Logs
        logs = session.exec(select(AuditLog).order_by(AuditLog.id.desc()).limit(5)).all()
        print(f"\nRecent Audit Logs (Last 5):")
        for log in logs:
            print(f"  [{log.timestamp}] {log.action} - {log.target} ({log.status})")

        # Other stats
        file_hashes = session.exec(select(func.count(FileHash.id))).one()
        print(f"\nTotal File Hashes Cached: {file_hashes}")

if __name__ == "__main__":
    try:
        analyze()
    except Exception as e:
        print(f"Error analyzing database: {e}")
