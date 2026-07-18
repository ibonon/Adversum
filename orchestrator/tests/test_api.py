from fastapi.testclient import TestClient
from ..config.settings import settings
from ..api.app import app

client = TestClient(app)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_analyze_no_auth():
    response = client.post("/analyze", json={"project_path": "."})
    assert response.status_code == 403

def test_analyze_with_auth():
    headers = {settings.API_KEY_HEADER_NAME: settings.API_KEY_SECRET}
    response = client.post("/analyze", json={"project_path": "."}, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "job_id" in data
    assert data["status"] == "PENDING"
    
    # Store ID for status check
    job_id = data["job_id"]
    
    # Check Status
    status_response = client.get(f"/jobs/{job_id}", headers=headers)
    assert status_response.status_code == 200
    assert status_response.json()["job_id"] == job_id
