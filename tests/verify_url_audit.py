import requests
import time
import sys

API_URL = "http://localhost:8080"
API_KEY = "adv-dev-key-123"
HEADERS = {"X-API-Key": API_KEY}
TEST_REPO = "https://github.com/psf/requests.git"

def check_health_url(url):
    try:
        r = requests.get(f"{url}/health", timeout=2)
        return r.status_code == 200
    except requests.exceptions.ConnectionError:
        return False

def check_health():
    global API_URL
    # Try 8080 first
    if check_health_url("http://localhost:8080"):
        API_URL = "http://localhost:8080"
        return True
    # Try 8000
    if check_health_url("http://localhost:8000"):
        API_URL = "http://localhost:8000"
        return True
    return False

def run_test():
    print(f"Checking API health at {API_URL}...")
    if not check_health():
        print("API is not running. Please start the Adversum API first.")
        sys.exit(1)
    
    print("API is online.")
    print(f"Submitting audit for {TEST_REPO}...")
    
    payload = {
        "target_path": TEST_REPO,
        "project_name": "requests_test_scan"
    }
    
    try:
        r = requests.post(f"{API_URL}/audit", json=payload, headers=HEADERS)
        r.raise_for_status()
        job = r.json()
        job_id = job["id"]
        print(f"Job submitted successfully. ID: {job_id}")
    except Exception as e:
        print(f"Failed to submit job: {e}")
        if 'r' in locals():
            print(f"Response: {r.text}")
        sys.exit(1)
        
    print("Polling for completion...")
    while True:
        r = requests.get(f"{API_URL}/audit/{job_id}", headers=HEADERS)
        if r.status_code != 200:
            print(f"Error polling job: {r.status_code}")
            break
            
        data = r.json()
        status = data["status"]
        print(f"Status: {status}")
        
        if status in ["COMPLETED", "FAILED"]:
            print("\nAudit Finished!")
            print(f"Final Status: {status}")
            print(f"Summary: {data.get('summary')}")
            print(f"Findings Count: {data.get('total_findings')}")
            break
            
        time.sleep(2)

if __name__ == "__main__":
    run_test()
