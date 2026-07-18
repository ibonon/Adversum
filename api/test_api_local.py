import os
import time
import sys
import asyncio
# Set API Key for testing BEFORE importing app
os.environ["API_KEY"] = "test-secret-key"
# Allow scanning of the project root for testing purposes
os.environ["ALLOWED_SCAN_DIR"] = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))

from fastapi.testclient import TestClient

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from api.main import app

client = TestClient(app, headers={"X-API-Key": "test-secret-key"})

def test_api_workflow():
    print("Testing API Workflow...")

    # 1. Check Root
    response = client.get("/")
    assert response.status_code == 200
    print(f"Root: {response.json()}")

    # 2. Submit Job (Scanning current directory)
    # We use the current directory '.' as the target
    current_dir = os.path.abspath(os.path.dirname(__file__))
    # Go up one level to 'api' then '..' to root
    project_root = os.path.abspath(os.path.join(current_dir, "../../"))
    
    # Let's scan the 'orchestrator' folder to find some files
    target_scan_path = os.path.join(project_root, "adversum", "orchestrator")
    
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
        
        if status in ["completed", "failed"]:
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
