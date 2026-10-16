"""
Phase 4 Tests — Resilience Arena API Endpoints
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


class TestPhase4API:
    def test_simulate_incident_endpoint(self):
        r = client.post(
            "/api/v1/wargame/simulate-incident",
            json={
                "protocol": "Euler Finance",
                "scenario_key": "flashloan_drain",
                "custom_exposure_usd": 60_000_000.0,
            },
            headers=HEADERS,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["protocol"] == "Euler Finance"
        assert data["total_exposure_usd"] == 60_000_000.0
        assert data["capital_saved_usd"] > 50_000_000.0
        assert data["defense_tripped"] is True
        assert len(data["incident_rounds"]) == 4

    def test_synthesize_circuit_breaker_endpoint(self):
        r = client.post(
            "/api/v1/wargame/synthesize-circuit-breaker",
            json={
                "protocol_name": "VaultAlpha",
                "target_token": "WETH",
                "max_tvl_outflow_pct_per_window": 4.0,
                "window_blocks": 15,
                "max_oracle_divergence_pct": 3.0,
                "enable_flash_loan_guard": True,
            },
            headers=HEADERS,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["protocol_name"] == "VaultAlpha"
        assert "VaultAlphaCircuitBreaker" in data["solidity_code"]
        assert data["estimated_gas_overhead"] > 0
        assert len(data["active_protections"]) >= 3

    def test_resilience_benchmark_endpoint(self):
        r = client.get(
            "/api/v1/wargame/resilience-benchmark?protocol=AaveV3",
            headers=HEADERS,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["protocol"] == "AaveV3"
        assert data["scenarios_evaluated"] == 4
        assert data["average_salvage_rate_pct"] >= 90.0

    def test_arena_history_endpoint(self):
        # Trigger at least one clash
        client.post(
            "/api/v1/wargame/simulate-incident",
            json={"protocol": "HistoryTestProtocol"},
            headers=HEADERS,
        )
        r = client.get("/api/v1/wargame/arena-history", headers=HEADERS)
        assert r.status_code == 200
        data = r.json()
        assert "clashes" in data
        assert data["count"] >= 1

    def test_evaluate_invariants_endpoint(self):
        code = """
        contract InvariantTest {
            function swap(uint256 a, uint256 amountOutMin) external nonReentrant {}
        }
        """
        r = client.post(
            "/api/v1/wargame/evaluate-invariants",
            json={"protocol_name": "InvariantTest", "source_code": code},
            headers=HEADERS,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["protocol"] == "InvariantTest"
        assert data["total_invariants"] == 10
        assert len(data["invariant_results"]) == 10
