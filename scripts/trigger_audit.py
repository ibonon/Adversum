import requests
import time
import json
import os

API_URL = "http://localhost:8000"
API_KEY = "adv-dev-key-123"
TARGET_PATH = r"f:\Adversum\adversum"

headers = {"X-API-Key": API_KEY}

def run_self_audit():
    print(f"Submitting audit for: {TARGET_PATH}")
    try:
        # Submit
        resp = requests.post(f"{API_URL}/audit", json={"target_path": TARGET_PATH}, headers=headers)
        if resp.status_code != 200:
            print(f"Error submitting audit: {resp.status_code} - {resp.text}")
            return
        
        job_data = resp.json()
        job_id = job_data["id"]
        print(f"Job ID: {job_id}. Waiting for completion...")
        
        # Poll
        while True:
            time.sleep(2)
            resp = requests.get(f"{API_URL}/audit/{job_id}", headers=headers)
            if resp.status_code != 200:
                print(f"Error checking status: {resp.status_code}")
                break
                
            data = resp.json()
            status = data["status"]
            print(f"Status: {status}")
            
            if status in ["COMPLETED", "completed", "FAILED", "failed"]:
                print("Audit Finished.")
                if status.lower() == "completed":
                    findings = data.get("result", [])
                    summary = data.get("summary", "No summary provided.")
                    print(f"\nSummary: {summary}\n")
                    print(f"Total Findings: {len(findings)}")
                    for i, f in enumerate(findings[:5]):
                        print(f"[{i+1}] {f.get('raw', {}).get('rule_id')} - {f.get('validation_status')}: {f.get('raw', {}).get('file_path')}")
                    if len(findings) > 5:
                        print("... and more.")
                else:
                    print(f"Error Message: {data.get('error')}")
                break
                
    except Exception as e:
        print(f"Exception: {e}")

if __name__ == "__main__":
    run_self_audit()
