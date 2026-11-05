import os
import time
import sys
import asyncio

import pytest
from fastapi.testclient import TestClient

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import api.main as api_main
from api.main import app
from orchestrator.services.db import create_db_and_tables

# Key this module's client is pinned to. Deliberately different from the suite
# default (`adv-dev-key-123`) to prove that per-test isolation actually works.
MODULE_API_KEY = "test-secret-key"

client = TestClient(app, headers={"X-API-Key": MODULE_API_KEY})


@pytest.fixture(autouse=True)
def module_api_config(monkeypatch):
    """Apply this module's config per test instead of mutating os.environ at import.

    The previous module-level ``os.environ["API_KEY"] = "test-secret-key"`` ran
    during collection — i.e. before any test executed and before the other test
    modules were imported — and therefore leaked into the whole pytest session.
    ``api/test_api_persistence.py`` and ``api/test_auto_fix.py`` then sent a key
    that no longer matched ``api.main.API_KEY`` and failed with 403.

    ``monkeypatch`` restores both ``os.environ`` and ``api.main.API_KEY`` after
    each test, so the override cannot escape this module.
    """
    monkeypatch.setenv("API_KEY", MODULE_API_KEY)
    # Allow scanning of the project root for testing purposes.
    monkeypatch.setenv(
        "ALLOWED_SCAN_DIR",
        os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")),
    )
    monkeypatch.setattr(api_main, "API_KEY", MODULE_API_KEY)
    yield

def test_api_workflow():
    print("Testing API Workflow...")
    asyncio.run(create_db_and_tables())

    # 1. Check Root
    response = client.get("/")
    assert response.status_code == 200
    print(f"Root: {response.json()}")

    # 2. Submit Job (Scanning current directory)
    current_dir = os.path.abspath(os.path.dirname(__file__))
    project_root = os.path.abspath(os.path.join(current_dir, ".."))
    
    # Let's scan the 'orchestrator' folder to find some files
    target_scan_path = os.path.join(project_root, "orchestrator")
    
    print(f"Submitting audit for: {target_scan_path}")
    response = client.post("/audit", json={"target_path": target_scan_path, "project_name": "Test Run"})
    
    if response.status_code != 200:
        print(f"Failed to submit job: {response.text}")
        return

    job_data = response.json()
    job_id = job_data["id"]
    print(f"Job Queued: {job_id}")

    # 3. Poll for Status
    # Since we are using TestClient with BackgroundTasks, the tasks run synchronously after the request in some versions,
    # but strictly TestClient might not await background tasks automatically unless configured.
    # However, usually TestClient runs the view then triggers tasks. Let's see if it completes.
    
    timeout = 10
    start = time.time()
    
    while time.time() - start < timeout:
        status_resp = client.get(f"/audit/{job_id}")
        status_data = status_resp.json()
        status = status_data["status"]
        print(f"Job Status: {status}")
        
        if status.lower() in ["completed", "failed"]:
            print("Final Result:")
            if status_data.get("summary"):
                print(f"Summary: {status_data['summary']}")
            
            # Print first 2 findings to verify structure
            if status_data.get("result"):
                for f in status_data["result"][:2]:
                    print(f" - {f['raw']['rule_id']}: {f['validation_status']}")
            else:
                 print("No results found or error occurred.")
                 if status_data.get("error"):
                     print(f"Error: {status_data['error']}")
            return

        time.sleep(1)
    
    print("Test Timed Out")

if __name__ == "__main__":
    test_api_workflow()
