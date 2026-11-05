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

def get_job_error_to_file(job_id):
    headers = {"X-API-Key": API_KEY}
    try:
        response = requests.get(f"{API_URL}/audit/{job_id}", headers=headers)
        with open("job_error.txt", "w", encoding="utf-8") as f:
            if response.status_code == 200:
                data = response.json()
                f.write(f"Status: {data['status']}\n")
                f.write(f"Error: {data.get('error')}\n")
            else:
                f.write(f"Failed to get job: {response.status_code}\n")
    except Exception as e:
        with open("job_error.txt", "w", encoding="utf-8") as f:
            f.write(f"Connection error: {e}\n")

if __name__ == "__main__":
    get_job_error_to_file(3)
