"""
Phase 4 Tests — Resilience Arena & Clash Simulation
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from modules.incident_response.resilience_arena import (
    ResilienceArena, ClashSimulationResult
)
from modules.incident_response.circuit_breaker import CircuitBreakerConfig


class TestResilienceArena:
    def test_single_clash_simulation(self):
        arena = ResilienceArena()
        res = arena.simulate_clash(
            protocol="Compound",
            scenario_key="flashloan_drain",
            custom_exposure_usd=50_000_000.0,
        )
        assert isinstance(res, ClashSimulationResult)
        assert res.protocol == "Compound"
        assert res.total_exposure_usd == 50_000_000.0
        assert res.capital_saved_usd > 40_000_000.0
        assert res.salvage_rate_pct >= 90.0
        assert res.ttd_ms > 0.0
        assert res.ttm_ms >= res.ttd_ms
        assert res.defense_tripped is True
        assert len(res.incident_rounds) == 4

    def test_all_standard_scenarios(self):
        arena = ResilienceArena()
        for scenario_key in arena.STANDARD_SCENARIOS:
            res = arena.simulate_clash(
                protocol="Aave",
                scenario_key=scenario_key,
            )
            assert res.salvage_rate_pct >= 85.0
            assert res.defense_action == "ON_CHAIN_CIRCUIT_BREAKER_PAUSE"

    def test_benchmark_run(self):
        arena = ResilienceArena()
        bench = arena.run_benchmark(protocol="MakerDAO")
        assert bench["protocol"] == "MakerDAO"
        assert bench["scenarios_evaluated"] == len(arena.STANDARD_SCENARIOS)
        assert bench["average_salvage_rate_pct"] >= 90.0
        assert bench["total_capital_saved_usd"] > 100_000_000.0
        assert len(bench["scenario_details"]) == len(arena.STANDARD_SCENARIOS)

    def test_history_accumulation(self):
        arena = ResilienceArena()
        arena.simulate_clash(protocol="P1")
        arena.simulate_clash(protocol="P2")
        history = arena.get_history()
        assert len(history) >= 2
        assert history[0]["protocol"] == "P1"
        assert history[1]["protocol"] == "P2"
