#!/usr/bin/env python3
"""
Adversum Resilience Arena Simulator
Phase 4 — Simulates adversarial incidents against autonomous circuit breaker defenses,
measuring Time-To-Detect (TTD), Time-To-Mitigate (TTM), and Capital Preservation.
"""
from __future__ import annotations

import time
import uuid
import random
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional

from modules.incident_response.circuit_breaker import (
    CircuitBreakerConfig, CircuitBreakerSynthesizer, SynthesizedCircuitBreaker
)


@dataclass
class ClashSimulationResult:
    clash_id: str
    protocol: str
    scenario_type: str
    total_exposure_usd: float
    capital_saved_usd: float
    capital_loss_usd: float
    salvage_rate_pct: float
    ttd_ms: float                     # Time to detect in ms
    ttm_ms: float                     # Time to mitigate in ms
    defense_action: str
    defense_tripped: bool
    incident_rounds: List[Dict[str, Any]]
    circuit_breaker_status: str
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "clash_id": self.clash_id,
            "protocol": self.protocol,
            "scenario_type": self.scenario_type,
            "total_exposure_usd": round(self.total_exposure_usd, 2),
            "capital_saved_usd": round(self.capital_saved_usd, 2),
            "capital_loss_usd": round(self.capital_loss_usd, 2),
            "salvage_rate_pct": round(self.salvage_rate_pct, 1),
            "ttd_ms": round(self.ttd_ms, 2),
            "ttm_ms": round(self.ttm_ms, 2),
            "defense_action": self.defense_action,
            "defense_tripped": self.defense_tripped,
            "circuit_breaker_status": self.circuit_breaker_status,
            "incident_rounds": self.incident_rounds,
            "timestamp": self.timestamp,
        }


class ResilienceArena:
    """Simulates adversarial incident scenarios against autonomous defense mechanisms."""

    STANDARD_SCENARIOS = {
        "flashloan_drain": {
            "name": "Flash Loan Drain Cascade",
            "exposure_usd": 85_000_000.0,
            "trigger_vector": "RAPID_OUTFLOW",
            "blocks_to_drain_without_defense": 4,
        },
        "oracle_desync": {
            "name": "Oracle Manipulation & Deviation",
            "exposure_usd": 42_000_000.0,
            "trigger_vector": "PRICE_DEVIATION",
            "blocks_to_drain_without_defense": 2,
        },
        "reentrancy_wave": {
            "name": "Recursive Reentrancy Wave",
            "exposure_usd": 28_000_000.0,
            "trigger_vector": "REENTRANCY_FREQUENCY",
            "blocks_to_drain_without_defense": 1,
        },
        "bridge_forgery": {
            "name": "Cross-Chain Signature Forgery",
            "exposure_usd": 150_000_000.0,
            "trigger_vector": "UNBACKED_MINT",
            "blocks_to_drain_without_defense": 3,
        },
    }

    def __init__(self):
        self._history: List[ClashSimulationResult] = []
        self._synthesizer = CircuitBreakerSynthesizer()

    def simulate_clash(
        self,
        protocol: str = "Euler Finance",
        scenario_key: str = "flashloan_drain",
        custom_exposure_usd: Optional[float] = None,
        breaker_config: Optional[CircuitBreakerConfig] = None,
    ) -> ClashSimulationResult:
        """Simulate an adverse scenario against active circuit breaker defenses."""
        clash_id = str(uuid.uuid4())
        scenario = self.STANDARD_SCENARIOS.get(
            scenario_key, self.STANDARD_SCENARIOS["flashloan_drain"]
        )
        total_exposure = custom_exposure_usd or scenario["exposure_usd"]

        cfg = breaker_config or CircuitBreakerConfig(protocol_name=protocol)

        # Simulation mechanics:
        # Time-To-Detect: Off-chain mempool/node detector takes 8 - 45 ms
        # Time-To-Mitigate: On-chain circuit breaker trips within 1 block / 25 - 95 ms
        rng = random.Random(hash(f"{clash_id}{protocol}"))
        ttd = rng.uniform(12.5, 38.0)
        ttm = ttd + rng.uniform(18.0, 52.0)

        # Capital leaked before breaker trips (typically capped by window threshold, e.g. 5%)
        leak_ratio = (cfg.max_tvl_outflow_pct_per_window / 100.0) * rng.uniform(0.7, 1.0)
        capital_loss = total_exposure * leak_ratio
        capital_saved = max(0.0, total_exposure - capital_loss)
        salvage_rate = (capital_saved / total_exposure) * 100.0

        rounds = [
            {
                "round": 1,
                "block_offset": 0,
                "event": "Adversarial transaction packet entered mempool",
                "inflow_outflow_usd": 0.0,
                "state": "MONITORING",
            },
            {
                "round": 2,
                "block_offset": 0,
                "event": f"Mempool anomaly detected via AI pattern matcher in {ttd:.1f}ms",
                "inflow_outflow_usd": -round(capital_loss * 0.4, 2),
                "state": "ALERT_TRIGGERED",
            },
            {
                "round": 3,
                "block_offset": 1,
                "event": f"On-chain CircuitBreaker tripped at {ttm:.1f}ms: Protocol operations frozen",
                "inflow_outflow_usd": -round(capital_loss * 0.6, 2),
                "state": "CIRCUIT_BREAKER_TRIPPED",
            },
            {
                "round": 4,
                "block_offset": 1,
                "event": f"Emergency guardian notified: ${capital_saved:,.0f} preserved ({salvage_rate:.1f}%)",
                "inflow_outflow_usd": 0.0,
                "state": "SECURED",
            },
        ]

        result = ClashSimulationResult(
            clash_id=clash_id,
            protocol=protocol,
            scenario_type=scenario["name"],
            total_exposure_usd=total_exposure,
            capital_saved_usd=capital_saved,
            capital_loss_usd=capital_loss,
            salvage_rate_pct=salvage_rate,
            ttd_ms=ttd,
            ttm_ms=ttm,
            defense_action="ON_CHAIN_CIRCUIT_BREAKER_PAUSE",
            defense_tripped=True,
            incident_rounds=rounds,
            circuit_breaker_status="TRIPPED_AND_SECURED",
        )

        self._history.append(result)
        return result

    def run_benchmark(self, protocol: str = "Standard Protocol") -> Dict[str, Any]:
        """Runs resilience benchmark across all standard threat scenarios."""
        results = []
        for key in self.STANDARD_SCENARIOS:
            res = self.simulate_clash(protocol=protocol, scenario_key=key)
            results.append(res.to_dict())

        avg_salvage = sum(r["salvage_rate_pct"] for r in results) / len(results)
        avg_ttd = sum(r["ttd_ms"] for r in results) / len(results)
        avg_ttm = sum(r["ttm_ms"] for r in results) / len(results)
        total_saved = sum(r["capital_saved_usd"] for r in results)

        return {
            "protocol": protocol,
            "scenarios_evaluated": len(results),
            "average_salvage_rate_pct": round(avg_salvage, 1),
            "average_ttd_ms": round(avg_ttd, 2),
            "average_ttm_ms": round(avg_ttm, 2),
            "total_capital_saved_usd": round(total_saved, 2),
            "scenario_details": results,
        }

    def get_history(self) -> List[Dict[str, Any]]:
        return [r.to_dict() for r in self._history]
