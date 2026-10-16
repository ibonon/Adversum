"""
Phase 3 Tests — Attack Simulator API endpoints
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


class TestSimulatorAPI:
    def test_list_scenarios(self):
        r = client.get("/api/v1/simulator/scenarios", headers=HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert data["count"] == 5
        ids = [s["scenario_id"] for s in data["scenarios"]]
        assert "euler_finance" in ids
        assert "ronin_bridge" in ids

    def test_run_euler_finance(self):
        r = client.post(
            "/api/v1/simulator/run-attack",
            json={"scenario_id": "euler_finance"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["scenario_id"] == "euler_finance"
        assert data["attacker_profit_usd"] > 0
        assert data["protocol_loss_usd"] == pytest.approx(197_000_000)

    def test_run_ronin_bridge(self):
        r = client.post(
            "/api/v1/simulator/run-attack",
            json={"scenario_id": "ronin_bridge"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["protocol_loss_usd"] == pytest.approx(625_000_000)

    def test_run_mango_markets(self):
        r = client.post(
            "/api/v1/simulator/run-attack",
            json={"scenario_id": "mango_markets"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["protocol_loss_usd"] == pytest.approx(116_000_000)

    def test_run_wormhole(self):
        r = client.post(
            "/api/v1/simulator/run-attack",
            json={"scenario_id": "wormhole"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["protocol_loss_usd"] == pytest.approx(320_000_000)

    def test_run_generic_with_custom_params(self):
        r = client.post(
            "/api/v1/simulator/run-attack",
            json={
                "scenario_id": "generic_flashloan_cascade",
                "custom_params": {"flash_loan_amount": 20_000_000, "borrow_amount": 15_000_000},
            },
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["success"] is True

    def test_run_unknown_scenario_returns_404(self):
        r = client.post(
            "/api/v1/simulator/run-attack",
            json={"scenario_id": "nonexistent"},
            headers=HEADERS,
        )
        assert r.status_code == 404

    def test_replay_after_run(self):
        # Run first
        run = client.post(
            "/api/v1/simulator/run-attack",
            json={"scenario_id": "euler_finance"},
            headers=HEADERS,
        ).json()
        sim_id = run["simulation_id"]
        # Replay
        r = client.get(f"/api/v1/simulator/replay/{sim_id}", headers=HEADERS)
        assert r.status_code == 200
        assert r.json()["simulation_id"] == sim_id

    def test_replay_unknown_id_returns_404(self):
        r = client.get("/api/v1/simulator/replay/does-not-exist", headers=HEADERS)
        assert r.status_code == 404

    def test_history_endpoint(self):
        r = client.get("/api/v1/simulator/history", headers=HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert "simulations" in data
        assert "count" in data
        assert data["count"] >= 0

    def test_risk_score_known_protocol(self):
        r = client.post(
            "/api/v1/simulator/risk-score",
            json={"protocol": "Euler Finance"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["protocol"] == "Euler Finance"
        assert "composite_risk" in data
        assert data["grade"] in ("A", "B", "C", "D", "F")

    def test_risk_score_unknown_protocol_returns_defaults(self):
        r = client.post(
            "/api/v1/simulator/risk-score",
            json={"protocol": "MyCustomProtocol", "tvl_usd": 1_000_000},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert r.json()["protocol"] == "MyCustomProtocol"

    def test_risk_matrix_endpoint(self):
        r = client.get("/api/v1/simulator/risk-matrix", headers=HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert "matrix" in data
        assert "Euler Finance" in data["matrix"]
        assert len(data["protocols"]) >= 5
