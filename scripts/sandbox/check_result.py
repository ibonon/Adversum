import requests
import json

# Clé résolue depuis l'environnement ou .env — jamais de valeur en dur.
import pathlib as _pathlib
import sys as _sys
_sys.path.insert(0, str(next(p for p in _pathlib.Path(__file__).resolve().parents
                              if (p / "scripts" / "lib" / "api_key.py").exists())))
from scripts.lib.api_key import get_api_key  # noqa: E402

API_KEY = get_api_key(required=True)

try:
    # Get List
    resp = requests.get("http://localhost:8080/audits", headers={"X-API-Key": API_KEY})
    audits = resp.json()
    if not audits:
        print("No audits found")
        exit()
        
    latest_id = audits[0]['id']
    print(f"Latest Audit ID: {latest_id}")
    
    # Get Detail
    resp = requests.get(f"http://localhost:8080/audit/{latest_id}", headers={"X-API-Key": API_KEY})
    detail = resp.json()
    
    print(json.dumps(detail, indent=2))
    
except Exception as e:
    print(e)
