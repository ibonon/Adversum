#!/usr/bin/env python3
"""Quick script to check audit status in the database."""

from orchestrator.services.db import engine
from sqlmodel import Session, select
from orchestrator.models.sql_models import Job
import sys

with Session(engine) as session:
    # Get latest job
    stmt = select(Job).order_by(Job.id.desc()).limit(1)
    result = session.exec(stmt).first()
    
    if not result:
        print("No jobs found!")
        sys.exit(1)
    
    job = result
    
    print(f"Job ID: {job.id}")
    print(f"Status: {job.status}")
    print(f"Created: {job.created_at}")
    print(f"Completed: {job.completed_at}")
    print(f"Project Path: {job.project_path}")
    print(f"Error Message: {job.error_message}")
    print(f"Summary: {job.summary}")
    print(f"Robustness Score: {job.robustness_score}")
    print(f"Number of findings: {len(job.findings)}")
