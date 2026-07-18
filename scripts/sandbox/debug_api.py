
import requests
import json
import sys

API_URL = "http://127.0.0.1:8080"
API_KEY = "adv-dev-key-123"

def check_audit(job_id=1):
    url = f"{API_URL}/audit/{job_id}"
    headers = {"api-key": API_KEY}
    
    print(f"Fetching {url}...")
    try:
        resp = requests.get(url, headers=headers)
        print(f"Status: {resp.status_code}")
        
        if resp.status_code == 200:
            data = resp.json()
            findings = data.get("result", [])
            print(f"Robustness Score: {data.get('robustness_score')}")
            print(f"Findings Count (in JSON): {len(findings)}")
            
            if len(findings) > 0:
                print("First finding sample:")
                print(json.dumps(findings[0], indent=2))
            else:
                print("WARNING: 'result' list is empty!")
                
            # Check payload size
            content_len = len(resp.content)
            print(f"Payload Size: {content_len / 1024:.2f} KB")
        else:
            print(f"Error: {resp.text}")
            
    except Exception as e:
        print(f"Connection Failed: {e}")

if __name__ == "__main__":
    check_audit()
