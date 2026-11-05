import argparse
import os
import requests
import json
import sys
import time

# Clé et racine résolues depuis l'environnement ou .env — jamais de valeur en dur.
import pathlib as _pathlib
sys.path.insert(0, str(next(p for p in _pathlib.Path(__file__).resolve().parents
                            if (p / "scripts" / "lib" / "api_key.py").exists())))
from scripts.lib.api_key import find_repo_root, get_api_key  # noqa: E402

API_URL = os.environ.get("API_URL", "http://localhost:8000")
API_KEY = get_api_key(required=True)


def trigger_audit(path: str, project_name: str = "Adversum Self-Audit", api_url: str = None) -> str | None:
    base_url = api_url or API_URL
    print(f"Triggering audit for: {path} (API: {base_url})")
    headers = {
        "X-API-Key": API_KEY,
        "Content-Type": "application/json"
    }
    payload = {
        "target_path": path,
        "project_name": project_name
    }
    
    try:
        response = requests.post(f"{base_url}/audit", headers=headers, json=payload)
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


def monitor_audit(job_id: str, api_url: str = None) -> None:
    base_url = api_url or API_URL
    print(f"Monitoring Job {job_id}...")
    headers = {"X-API-Key": API_KEY}
    
    while True:
        try:
            response = requests.get(f"{base_url}/audit/{job_id}", headers=headers)
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


def parse_args():
    parser = argparse.ArgumentParser(
        description="Trigger an Adversum audit job and monitor its progress to completion."
    )
    parser.add_argument(
        "target_path",
        nargs="?",
        default=os.environ.get("TARGET_PATH", str(find_repo_root())),
        help="Path to scan (defaults to TARGET_PATH env var, or repository root)",
    )
    parser.add_argument(
        "--api-url",
        default=os.environ.get("API_URL", "http://localhost:8000"),
        help="API base URL (defaults to API_URL env var or http://localhost:8000)",
    )
    parser.add_argument(
        "--project-name",
        default=os.environ.get("PROJECT_NAME", "Adversum Self-Audit"),
        help="Project name tag for the audit",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    API_URL = args.api_url
    target_path = args.target_path
    job_id = trigger_audit(target_path, project_name=args.project_name, api_url=args.api_url)
    if job_id:
        monitor_audit(job_id, api_url=args.api_url)
