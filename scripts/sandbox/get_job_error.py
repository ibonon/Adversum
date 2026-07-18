import requests
import json

API_URL = "http://localhost:8080"
API_KEY = "adv-dev-key-123"

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
