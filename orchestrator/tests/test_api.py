"""
Tests pour l'API FastAPI avec mocks complets.
Ces tests fonctionnent sans base de données et sans le binaire Rust.
"""
import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from fastapi.testclient import TestClient

import sys
for mod in ["redis", "arq", "asyncpg"]:
    sys.modules.setdefault(mod, MagicMock())

# Import de l'app après les mocks
from orchestrator.api.app import app  # noqa: E402

client = TestClient(app)


def test_health_check():
    """Le endpoint /health doit retourner status=ok."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data.get("status") == "ok"


def test_analyze_no_auth():
    """Sans clé API, le serveur doit répondre 403."""
    response = client.post("/analyze", json={"project_path": "."})
    assert response.status_code == 403


@patch("orchestrator.pipeline.analysis_pipeline.AnalysisPipeline.run", new_callable=AsyncMock)
def test_analyze_with_auth(mock_run):
    """Avec une clé valide, l'analyse doit créer un job PENDING."""
    from orchestrator.config.settings import settings
    mock_run.return_value = {"findings": [], "stats": {}}

    headers = {settings.API_KEY_HEADER_NAME: settings.API_KEY_SECRET}
    response = client.post("/analyze", json={"project_path": "."}, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "job_id" in data
    assert data["status"] == "PENDING"

    job_id = data["job_id"]
    status_response = client.get(f"/jobs/{job_id}", headers=headers)
    assert status_response.status_code == 200
    assert status_response.json()["job_id"] == job_id
