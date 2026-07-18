import urllib.request
import json
import time

API_URL = "http://localhost:8080"
HEADERS = {
    "X-API-Key": "adv-dev-key-123",
    "Content-Type": "application/json"
}

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
    print("Triggering audit...")
    # Trigger
    resp = post_json("/audit", {
        "target_path": "f:/Adversum/adversum/temp_test_project"
    })
    job_id = resp['id']
    print(f"Audit triggered: Job ID {job_id}")
    
    # Poll
    while True:
        status_resp = get_json(f"/audit/{job_id}")
        status = status_resp['status']
        print(f"Status: {status}")
        
        if status in ['COMPLETED', 'FAILED']:
            print("Audit Finished!")
            print(f"Findings: {status_resp.get('findings_count', 0)}")
            print(f"Robustness Score: {status_resp.get('robustness_score')}")
            
            summary = status_resp.get('summary')
            if summary:
                print("\nSummary:")
                print(summary[:200] + "..." if len(summary) > 200 else summary)
                
            results = status_resp.get('result', [])
            print(f"\nDetailed Findings ({len(results)}):")
            for f in results:
                raw = f.get('raw', {})
                print(f"- [{f.get('validation_status')}] {raw.get('rule_id')}: {raw.get('description')}")
            
            break
            
        time.sleep(2)

except Exception as e:
    print(f"Error: {e}")
