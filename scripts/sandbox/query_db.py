from orchestrator.services.db import engine
from sqlmodel import Session, select
from orchestrator.models.sql_models import Job
import json

with Session(engine) as session:
    jobs = session.exec(select(Job)).all()
    results = []
    for j in jobs:
        results.append({
            "id": j.id,
            "status": j.status,
            "created_at": str(j.created_at),
            "completed_at": str(j.completed_at) if j.completed_at else None,
            "error": j.error_message
        })
    print(json.dumps(results, indent=2))
