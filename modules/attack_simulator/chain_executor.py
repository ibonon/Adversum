#!/usr/bin/env python3
"""
Adversum Cross-Protocol Economic Attack Chain Executor
Phase 3 — Simulates multi-step DeFi attack chains with cascade propagation.

Supported attack primitives:
  FLASH_LOAN       — Borrow large capital without collateral (Aave, dYdX, Balancer)
  ORACLE_MANIP     — Manipulate on-chain spot price oracle (Uniswap v2 TWAP bypass)
  LIQUIDATION      — Self-liquidation or forced liquidation of under-collateralized position
  BRIDGE_DRAIN     — Cross-chain bridge message forgery / validator key compromise
  GOVERNANCE_VOTE  — Flash-loan-powered governance takeover
  PRICE_PUMP       — Market price manipulation via large swap
  UNBACKED_MINT    — Mint tokens without proper collateral verification
  DONATE_ATTACK    — Donate to reserve to skew accounting (Euler-style)
  REPAY_FLASH      — Repay flash loan after extracting profit
"""
from __future__ import annotations

import uuid
import time
import logging
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional
from enum import Enum

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Attack Step Primitives
# ---------------------------------------------------------------------------

class AttackPrimitive(str, Enum):
    FLASH_LOAN       = "FLASH_LOAN"
    ORACLE_MANIP     = "ORACLE_MANIP"
    LIQUIDATION      = "LIQUIDATION"
    BRIDGE_DRAIN     = "BRIDGE_DRAIN"
    GOVERNANCE_VOTE  = "GOVERNANCE_VOTE"
    PRICE_PUMP       = "PRICE_PUMP"
    UNBACKED_MINT    = "UNBACKED_MINT"
    DONATE_ATTACK    = "DONATE_ATTACK"
    REPAY_FLASH      = "REPAY_FLASH"
    CUSTOM           = "CUSTOM"


@dataclass
class AttackStep:
    """A single step in a multi-step attack chain."""
    primitive:       AttackPrimitive
    protocol:        str                    # e.g. "Aave", "Uniswap", "Euler"
    description:     str
    capital_in:      float  = 0.0          # USD value of assets entering this step
    capital_out:     float  = 0.0          # USD value of assets exiting this step
    gas_usd:         float  = 0.0          # Estimated gas cost in USD
    block_delta:     int    = 0            # Blocks elapsed during this step
    token:           str    = "ETH"
    metadata:        Dict[str, Any] = field(default_factory=dict)

    @property
    def net_impact(self) -> float:
        """Positive = profit extracted, negative = cost."""
        return self.capital_out - self.capital_in - self.gas_usd

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["primitive"] = self.primitive.value if hasattr(self.primitive, "value") else str(self.primitive)
        d["net_impact"] = self.net_impact
        return d


@dataclass
class AttackChain:
    """A named, ordered sequence of attack steps."""
    name:          str
    scenario_id:   str
    description:   str
    chain_id:      int    = 1              # EVM chain (1=Ethereum, 56=BSC, etc.)
    steps:         List[AttackStep] = field(default_factory=list)
    tags:          List[str]        = field(default_factory=list)
    real_hack_ref: str = ""                # Reference to real-world hack (e.g. tx hash)
    loss_usd:      float = 0.0            # Historical protocol loss in USD

    def add_step(self, step: AttackStep) -> "AttackChain":
        self.steps.append(step)
        return self

    def total_gas(self) -> float:
        return sum(s.gas_usd for s in self.steps)

    def attacker_profit(self) -> float:
        """Net profit to attacker across the full chain."""
        return sum(s.net_impact for s in self.steps)

    def protocol_loss(self) -> float:
        """Total capital drained from victim protocols.
        Uses loss_usd (historical record) when set; falls back to step summation.
        """
        if self.loss_usd > 0:
            return self.loss_usd
        return sum(
            s.capital_out for s in self.steps
            if s.primitive not in (AttackPrimitive.FLASH_LOAN, AttackPrimitive.REPAY_FLASH)
        )

    def block_span(self) -> int:
        return sum(s.block_delta for s in self.steps)


# ---------------------------------------------------------------------------
# Simulation Result
# ---------------------------------------------------------------------------

@dataclass
class SimulationResult:
    simulation_id:   str
    scenario_id:     str
    scenario_name:   str
    chain:           AttackChain
    attacker_profit: float
    protocol_loss:   float
    total_gas:       float
    block_span:      int
    success:         bool
    cascade_triggered: bool
    cascade_protocols: List[str]
    steps_detail:    List[Dict[str, Any]]
    risk_index:      float          # 0–100
    mitre_techniques: List[str]
    timestamp:       float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "simulation_id":    self.simulation_id,
            "scenario_id":      self.scenario_id,
            "scenario_name":    self.scenario_name,
            "attacker_profit_usd": round(self.attacker_profit, 2),
            "protocol_loss_usd":   round(self.protocol_loss, 2),
            "total_gas_usd":       round(self.total_gas, 2),
            "block_span":          self.block_span,
            "success":             self.success,
            "cascade_triggered":   self.cascade_triggered,
            "cascade_protocols":   self.cascade_protocols,
            "risk_index":          round(self.risk_index, 1),
            "mitre_techniques":    self.mitre_techniques,
            "steps":               self.steps_detail,
            "timestamp":           self.timestamp,
        }


# ---------------------------------------------------------------------------
# Cascade Engine
# ---------------------------------------------------------------------------

# Protocols that can be cascaded from a given protocol under attack
CASCADE_MAP: Dict[str, List[str]] = {
    "Euler Finance":    ["Compound", "Aave", "Balancer"],
    "Compound":         ["Aave", "dYdX"],
    "Aave":             ["Compound", "Curve"],
    "Mango Markets":    ["Solend", "Port Finance"],
    "Ronin Bridge":     ["Axie Infinity", "Sky Mavis"],
    "Wormhole":         ["Solana DeFi", "Portal Bridge"],
    "Nomad Bridge":     ["Moonbeam", "Evmos"],
    "Cream Finance":    ["Yearn Finance", "Yearn v2"],
}

# MITRE ATT&CK for DeFi mapping
PRIMITIVE_TO_MITRE: Dict[AttackPrimitive, str] = {
    AttackPrimitive.FLASH_LOAN:      "T1078 - Valid Accounts (Flash Loan Capital)",
    AttackPrimitive.ORACLE_MANIP:    "T1565.001 - Data Manipulation: Stored Data",
    AttackPrimitive.LIQUIDATION:     "T1499 - Endpoint Denial of Service (Liquidation Cascade)",
    AttackPrimitive.BRIDGE_DRAIN:    "T1190 - Exploit Public-Facing Application (Bridge)",
    AttackPrimitive.GOVERNANCE_VOTE: "T1078.004 - Valid Accounts: Cloud Accounts (Governance)",
    AttackPrimitive.PRICE_PUMP:      "T1565 - Data Manipulation (Price Feed)",
    AttackPrimitive.UNBACKED_MINT:   "T1036 - Masquerading (Unbacked Token Mint)",
    AttackPrimitive.DONATE_ATTACK:   "T1499.004 - Application Exhaustion Flood",
    AttackPrimitive.REPAY_FLASH:     "T1070 - Indicator Removal (Flash Loan Repay)",
    AttackPrimitive.CUSTOM:          "T1059 - Command and Scripting Interpreter",
}


class AttackChainExecutor:
    """
    Executes and simulates DeFi attack chains.
    Tracks step-by-step outcomes, cascade propagation, profit/loss, and risk scoring.
    """

    def __init__(self):
        self._history: List[SimulationResult] = []

    # ------------------------------------------------------------------
    def execute(self, chain: AttackChain) -> SimulationResult:
        """
        Simulate the full attack chain.
        Returns a SimulationResult with all metrics.
        """
        sim_id = str(uuid.uuid4())
        steps_detail: List[Dict[str, Any]] = []
        cumulative_profit = 0.0

        for idx, step in enumerate(chain.steps):
            step_dict = step.to_dict()
            step_dict["step_index"] = idx
            step_dict["cumulative_profit_usd"] = round(
                cumulative_profit + step.net_impact, 2
            )
            cumulative_profit += step.net_impact
            steps_detail.append(step_dict)

        # Cascade detection
        cascade_protocols: List[str] = []
        cascade_triggered = False
        for step in chain.steps:
            if step.protocol in CASCADE_MAP and step.capital_out > 1_000_000:
                cascade_protocols.extend(CASCADE_MAP[step.protocol])
                cascade_triggered = True
        cascade_protocols = list(dict.fromkeys(cascade_protocols))  # deduplicate

        # MITRE techniques
        mitre = list(dict.fromkeys(
            PRIMITIVE_TO_MITRE.get(step.primitive, "") for step in chain.steps
        ))
        mitre = [m for m in mitre if m]

        # Risk index: based on profit/loss ratio and cascade factor
        base_risk = min(100.0, (chain.attacker_profit() / max(chain.protocol_loss(), 1)) * 50)
        cascade_bonus = 20.0 if cascade_triggered else 0.0
        risk_index = min(100.0, base_risk + cascade_bonus + len(chain.steps) * 2)

        result = SimulationResult(
            simulation_id=sim_id,
            scenario_id=chain.scenario_id,
            scenario_name=chain.name,
            chain=chain,
            attacker_profit=chain.attacker_profit(),
            protocol_loss=chain.protocol_loss(),
            total_gas=chain.total_gas(),
            block_span=chain.block_span(),
            success=chain.attacker_profit() > 0,
            cascade_triggered=cascade_triggered,
            cascade_protocols=cascade_protocols,
            steps_detail=steps_detail,
            risk_index=risk_index,
            mitre_techniques=mitre,
        )

        self._history.append(result)
        logger.info(
            "Simulation %s | scenario=%s | profit=$%.0f | loss=$%.0f | risk=%.1f",
            sim_id[:8], chain.scenario_id, result.attacker_profit,
            result.protocol_loss, result.risk_index
        )
        return result

    def get_history(self) -> List[Dict[str, Any]]:
        return [r.to_dict() for r in self._history]

    def get_by_id(self, sim_id: str) -> Optional[SimulationResult]:
        for r in self._history:
            if r.simulation_id == sim_id:
                return r
        return None

    def clear_history(self) -> None:
        self._history.clear()
