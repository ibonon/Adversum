import urllib.request
import json
import time

# Clé résolue depuis l'environnement ou .env — jamais de valeur en dur.
import pathlib as _pathlib
import sys as _sys
_sys.path.insert(0, str(next(p for p in _pathlib.Path(__file__).resolve().parents
                              if (p / "scripts" / "lib" / "api_key.py").exists())))
from scripts.lib.api_key import get_api_key  # noqa: E402

API_KEY = get_api_key(required=True)

def get_json(url):
    req = urllib.request.Request(url)
    req.add_header('X-API-Key', API_KEY)
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
