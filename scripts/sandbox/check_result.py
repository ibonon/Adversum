import requests
import json

try:
    # Get List
    resp = requests.get("http://localhost:8080/audits", headers={"X-API-Key": "adv-dev-key-123"})
    audits = resp.json()
    if not audits:
        print("No audits found")
        exit()
        
    latest_id = audits[0]['id']
    print(f"Latest Audit ID: {latest_id}")
    
    # Get Detail
    resp = requests.get(f"http://localhost:8080/audit/{latest_id}", headers={"X-API-Key": "adv-dev-key-123"})
    detail = resp.json()
    
    print(json.dumps(detail, indent=2))
    
except Exception as e:
    print(e)
