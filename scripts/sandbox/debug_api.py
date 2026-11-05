
import requests
import json
import sys

# Clé résolue depuis l'environnement ou .env — jamais de valeur en dur.
import pathlib as _pathlib
_sys_path_root = next(p for p in _pathlib.Path(__file__).resolve().parents
                      if (p / "scripts" / "lib" / "api_key.py").exists())
sys.path.insert(0, str(_sys_path_root))
from scripts.lib.api_key import get_api_key  # noqa: E402

API_URL = "http://127.0.0.1:8080"
API_KEY = get_api_key(required=True)

def check_audit(job_id=1):
    url = f"{API_URL}/audit/{job_id}"
    # Le backend attend l'en-tête X-API-Key (le nom "api-key" donnait un 401).
    headers = {"X-API-Key": API_KEY}
    
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
