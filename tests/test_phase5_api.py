"""
Phase 5 Tests — Threat Hunter API & Enterprise Readiness Probes
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("NEBIUS_MOCK", "1")

from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)
HEADERS = {"x-api-key": "adv-dev-key-123"}


class TestPhase5API:
    def test_liveness_probe(self):
        r = client.get("/health/live")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "alive"
        assert "timestamp" in data

    def test_readiness_probe(self):
        r = client.get("/health/ready")
        assert r.status_code == 200
        data = r.json()
        assert data["ready"] is True
        assert data["version"] == "5.0.0"
        assert data["checks"]["api"] == "ok"
        assert data["checks"]["database"] == "ok"

    def test_threat_hunter_status(self):
        r = client.get("/api/v1/hunter/status", headers=HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert "is_running" in data
        assert "chain" in data
        assert "blocks_scanned" in data

    def test_threat_hunter_manual_scan_block(self):
        r = client.post(
            "/api/v1/hunter/scan-block",
            json={"block_number": 500},
            headers=HEADERS,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["block_number"] == 500
        assert "findings" in data
        assert data["threats_count"] >= 1

    def test_threat_hunter_start_and_stop(self):
        # Start
        r_start = client.post(
            "/api/v1/hunter/start",
            json={"chain": "base"},
            headers=HEADERS,
        )
        assert r_start.status_code == 200
        assert r_start.json()["is_running"] is True
        assert r_start.json()["chain"] == "base"

        # Stop
        r_stop = client.post("/api/v1/hunter/stop", headers=HEADERS)
        assert r_stop.status_code == 200
        assert r_stop.json()["is_running"] is False

    def test_threat_hunter_findings_endpoint(self):
        r = client.get("/api/v1/hunter/findings?limit=10", headers=HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert "findings" in data
        assert "count" in data
