import requests
import json
import sys
import time

API_URL = "http://localhost:8080"
API_KEY = "adv-dev-key-123"

def trigger_audit(path):
    print(f"Triggering audit for: {path}")
    headers = {
        "X-API-Key": API_KEY,
        "Content-Type": "application/json"
    }
    payload = {
        "target_path": path,
        "project_name": "Adversum Self-Audit"
    }
    
    try:
        response = requests.post(f"{API_URL}/audit", headers=headers, json=payload)
        if response.status_code == 200:
            data = response.json()
            print(f"Audit initiated successfully. Job ID: {data['id']}")
            return data['id']
        else:
            print(f"Failed to initiate audit: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        print(f"Error connecting to API: {e}")
        return None

def monitor_audit(job_id):
    print(f"Monitoring Job {job_id}...")
    headers = {"X-API-Key": API_KEY}
    
    while True:
        try:
            response = requests.get(f"{API_URL}/audit/{job_id}", headers=headers)
            if response.status_code == 200:
                data = response.json()
                status = data['status']
                print(f"Status: {status}")
                
                if status in ["COMPLETED", "FAILED"]:
                    print("Audit finished.")
                    print(f"Summary: {data.get('summary', 'No summary')}")
                    print(f"Findings: {len(data.get('result', []))}")
                    break
            else:
                print(f"Error checking status: {response.status_code}")
                
        except Exception as e:
            print(f"Error checking status: {e}")
            
        time.sleep(2)

if __name__ == "__main__":
    target_path = r"F:\Adversum\adversum"
    job_id = trigger_audit(target_path)
    if job_id:
        monitor_audit(job_id)
