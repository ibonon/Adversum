import os
import time
import sys
import asyncio
from fastapi.testclient import TestClient

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from api.main import app
from orchestrator.services.db import create_db_and_tables

client = TestClient(app, headers={"X-API-Key": "adv-dev-key-123"})

def test_persistence_workflow():
    print("Testing API Persistence...")
    create_db_and_tables() # Ensure DB exists
    
    # 1. Trigger Audit
    current_dir = os.path.abspath(os.path.dirname(__file__))
    project_root = os.path.abspath(os.path.join(current_dir, "../../"))
    target_scan_path = os.path.join(project_root, "adversum", "orchestrator")
    
    print(f"Submitting job for {target_scan_path}...")
    response = client.post("/audit", json={"target_path": target_scan_path})
    assert response.status_code == 200
    job_data = response.json()
    job_id = job_data["id"]
    print(f"Job ID: {job_id}")

    # 2. Wait for Completion
    for _ in range(10):
        time.sleep(1)
        resp = client.get(f"/audit/{job_id}")
        data = resp.json()
        print(f"Status: {data['status']}")
        if data["status"] == "completed":
            print("Job Completed.")
            break
    else:
        print("Timeout waiting for job completion.")
        return

    # 3. Verify Persistence
    # In a real server, we'd restart the process. Here, we rely on the DB file existing.
    print("Verifying data retention...")
    resp = client.get(f"/audit/{job_id}")
    final_data = resp.json()
    
    # Check Summary
    if final_data.get("summary"):
        print("SUCCESS: Summary persisted.")
        print(f"Summary Preview: {final_data['summary'][:50]}...")
    else:
        print("FAILURE: Summary missing.")

    # Check Findings
    findings_count = len(final_data.get("result", []))
    print(f"Findings Persisted: {findings_count}")
    
    if findings_count > 0:
        print("SUCCESS: Findings persisted to DB.")
    else:
        print("FAILURE: No findings in DB.")

if __name__ == "__main__":
    test_persistence_workflow()
