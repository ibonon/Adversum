#!/usr/bin/env python3
"""Fix zombie audit #1 and launch a new test audit."""

from orchestrator.services.db import engine
from sqlmodel import Session
from orchestrator.models.sql_models import Job, JobStatus
from datetime import datetime

with Session(engine) as session:
    # Fix zombie audit #1
    job = session.get(Job, 1)
    if job and job.status == JobStatus.RUNNING:
        print(f"Fixing zombie audit #{job.id}...")
        job.status = JobStatus.FAILED
        job.error_message = "Server restarted while audit was running. Task was orphaned."
        job.completed_at = datetime.utcnow()
        session.add(job)
        session.commit()
        print(f"✓ Audit #{job.id} marked as FAILED")
    else:
        print(f"Audit #1 is not in RUNNING state or doesn't exist")

print("\nCurrent audits in database:")
from sqlmodel import select
jobs = session.exec(select(Job)).all()
for j in jobs:
    print(f"  - Audit #{j.id}: {j.status} (created: {j.created_at})")
