import requests
import json

# Clé résolue depuis l'environnement ou .env — jamais de valeur en dur.
import pathlib as _pathlib
import sys as _sys
_sys.path.insert(0, str(next(p for p in _pathlib.Path(__file__).resolve().parents
                              if (p / "scripts" / "lib" / "api_key.py").exists())))
from scripts.lib.api_key import get_api_key  # noqa: E402

API_URL = "http://localhost:8080"
API_KEY = get_api_key(required=True)

def get_job_error(job_id):
    headers = {"X-API-Key": API_KEY}
    try:
        response = requests.get(f"{API_URL}/audit/{job_id}", headers=headers)
        if response.status_code == 200:
            data = response.json()
            print(f"Status: {data['status']}")
            print(f"Error: {data.get('error')}")
        else:
            print(f"Failed to get job: {response.status_code}")
    except Exception as e:
        print(f"Connection error: {e}")

if __name__ == "__main__":
    get_job_error(3)
