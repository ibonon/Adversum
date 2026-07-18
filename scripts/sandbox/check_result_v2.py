import urllib.request
import json
import time

def get_json(url):
    req = urllib.request.Request(url)
    req.add_header('X-API-Key', 'adv-dev-key-123')
    with urllib.request.urlopen(req) as response:
        return json.loads(response.read().decode())

try:
    # List audits
    audits = get_json("http://localhost:8080/audits")
    if not audits:
        print("No audits found")
        exit()
        
    latest = audits[0]
    print(f"Latest ID: {latest['id']}, Status: {latest['status']}")
    
    # Get details
    detail = get_json(f"http://localhost:8080/audit/{latest['id']}")
    print(json.dumps(detail, indent=2))
    
except Exception as e:
    print(f"Error: {e}")
