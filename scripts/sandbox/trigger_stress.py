import urllib.request
import json
import time

API_URL = "http://localhost:8080"
HEADERS = {
    "X-API-Key": "adv-dev-key-123",
    "Content-Type": "application/json"
}

TARGET_PATH = "f:/Adversum/adversum/stress_test_project_v2"

def post_json(endpoint, data):
    req = urllib.request.Request(f"{API_URL}{endpoint}", method="POST")
    for k, v in HEADERS.items():
        req.add_header(k, v)
    
    jsondata = json.dumps(data).encode('utf-8')
    with urllib.request.urlopen(req, data=jsondata) as response:
        return json.loads(response.read().decode())

def get_json(endpoint):
    req = urllib.request.Request(f"{API_URL}{endpoint}")
    req.add_header('X-API-Key', 'adv-dev-key-123')
    with urllib.request.urlopen(req) as response:
        return json.loads(response.read().decode())

try:
    print(f"Triggering STRESS TEST audit on {TARGET_PATH}...")
    start_time = time.time()
    
    resp = post_json("/audit", {
        "target_path": TARGET_PATH
    })
    job_id = resp['id']
    print(f"Audit triggered: Job ID {job_id}")
    
    # Poll
    while True:
        status_resp = get_json(f"/audit/{job_id}")
        status = status_resp['status']
        elapsed = time.time() - start_time
        print(f"[{elapsed:.1f}s] Status: {status}")
        
        if status in ['COMPLETED', 'FAILED']:
            print(f"Audit Finished in {elapsed:.2f}s!")
            print(f"Findings: {status_resp.get('findings_count', 0)}")
            
            if status == 'FAILED':
                print(f"Error: {status_resp.get('error')}")
                print(f"Summary: {status_resp.get('summary')}")
            
            break
            
        time.sleep(2)

except Exception as e:
    print(f"Error: {e}")
