#!/usr/bin/env python3
"""
Adversum DeFi Risk Scorer
Phase 3 — Economic risk scoring engine for DeFi protocols.

Scores protocols across 6 attack vectors:
  1. Oracle Risk      — susceptibility to price manipulation
  2. Flash Loan Risk  — capital availability and guard mechanisms
  3. Bridge Risk      — cross-chain trust assumptions
  4. Governance Risk  — token concentration and time-lock adequacy
  5. Liquidity Risk   — TVL concentration and pool depth
  6. Smart Contract Risk — code quality, audit status, upgrade patterns
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Risk Vectors
# ---------------------------------------------------------------------------

RISK_VECTORS = [
    "oracle_risk",
    "flash_loan_risk",
    "bridge_risk",
    "governance_risk",
    "liquidity_risk",
    "smart_contract_risk",
]

VECTOR_LABELS = {
    "oracle_risk":          "Oracle Manipulation",
    "flash_loan_risk":      "Flash Loan Attack",
    "bridge_risk":          "Cross-Chain Bridge",
    "governance_risk":      "Governance Takeover",
    "liquidity_risk":       "Liquidity Concentration",
    "smart_contract_risk":  "Smart Contract Exploit",
}

# Mitigations per vector
MITIGATIONS: Dict[str, str] = {
    "oracle_risk":          "Use Chainlink TWAP oracles with 30-min minimum delay; add circuit breakers on >5% price delta per block",
    "flash_loan_risk":      "Implement re-entrancy guards, use block.timestamp checks, and require multi-tx for large position changes",
    "bridge_risk":          "Increase validator quorum to >2/3 of independently operated nodes; use optimistic fraud proofs with 7-day challenge window",
    "governance_risk":      "Enforce minimum 48h time-lock on all governance execution; use quadratic voting to reduce whale dominance",
    "liquidity_risk":       "Cap maximum single-LP position at 20% of TVL; add withdrawal delay during volatility spikes",
    "smart_contract_risk":  "Require 3+ independent audits; implement formal verification for core invariants; use pause guardian mechanism",
}


# ---------------------------------------------------------------------------
# Protocol Risk Profiles (based on public post-mortems)
# ---------------------------------------------------------------------------

# Scores are 0–100. Higher = more risky.
PROTOCOL_PROFILES: Dict[str, Dict[str, float]] = {
    "Euler Finance": {
        "oracle_risk": 45.0,
        "flash_loan_risk": 92.0,   # Euler had flash loan capability exploited
        "bridge_risk": 10.0,
        "governance_risk": 30.0,
        "liquidity_risk": 65.0,
        "smart_contract_risk": 78.0,  # donateToReserves bug
        "tvl_usd": 197_000_000,
        "audit_count": 3,
        "chain": "Ethereum",
    },
    "Ronin Bridge": {
        "oracle_risk": 20.0,
        "flash_loan_risk": 10.0,
        "bridge_risk": 98.0,       # 5/9 validators controlled by Sky Mavis
        "governance_risk": 75.0,
        "liquidity_risk": 40.0,
        "smart_contract_risk": 55.0,
        "tvl_usd": 625_000_000,
        "audit_count": 1,
        "chain": "Ronin",
    },
    "Mango Markets": {
        "oracle_risk": 95.0,       # Single self-reported oracle
        "flash_loan_risk": 60.0,
        "bridge_risk": 5.0,
        "governance_risk": 85.0,   # Governance vote to approve hack repayment
        "liquidity_risk": 70.0,
        "smart_contract_risk": 40.0,
        "tvl_usd": 116_000_000,
        "audit_count": 2,
        "chain": "Solana",
    },
    "Wormhole": {
        "oracle_risk": 10.0,
        "flash_loan_risk": 5.0,
        "bridge_risk": 97.0,       # Signature verification bypass
        "governance_risk": 50.0,
        "liquidity_risk": 35.0,
        "smart_contract_risk": 88.0,  # Critical signature bug
        "tvl_usd": 320_000_000,
        "audit_count": 2,
        "chain": "Multi-chain",
    },
    "Compound": {
        "oracle_risk": 35.0,
        "flash_loan_risk": 55.0,
        "bridge_risk": 5.0,
        "governance_risk": 65.0,   # COMP distribution governance bug
        "liquidity_risk": 45.0,
        "smart_contract_risk": 30.0,
        "tvl_usd": 3_000_000_000,
        "audit_count": 5,
        "chain": "Ethereum",
    },
    "Aave": {
        "oracle_risk": 20.0,
        "flash_loan_risk": 40.0,
        "bridge_risk": 25.0,
        "governance_risk": 35.0,
        "liquidity_risk": 30.0,
        "smart_contract_risk": 20.0,
        "tvl_usd": 8_000_000_000,
        "audit_count": 8,
        "chain": "Multi-chain",
    },
    "Curve Finance": {
        "oracle_risk": 30.0,
        "flash_loan_risk": 45.0,
        "bridge_risk": 10.0,
        "governance_risk": 40.0,
        "liquidity_risk": 55.0,
        "smart_contract_risk": 42.0,   # Vyper reentrancy 2023
        "tvl_usd": 4_000_000_000,
        "audit_count": 6,
        "chain": "Multi-chain",
    },
    "Uniswap v3": {
        "oracle_risk": 25.0,
        "flash_loan_risk": 30.0,
        "bridge_risk": 5.0,
        "governance_risk": 30.0,
        "liquidity_risk": 20.0,
        "smart_contract_risk": 15.0,
        "tvl_usd": 5_000_000_000,
        "audit_count": 10,
        "chain": "Multi-chain",
    },
}


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------

@dataclass
class RiskScore:
    protocol:    str
    scores:      Dict[str, float]          # vector → score (0–100)
    composite:   float                     # weighted average
    grade:       str                       # A/B/C/D/F
    tvl_usd:     float
    chain:       str
    audit_count: int
    mitigations: Dict[str, str]
    top_risk:    str                       # highest-risk vector name

    def to_dict(self) -> Dict:
        return {
            "protocol":    self.protocol,
            "scores":      {VECTOR_LABELS.get(k, k): round(v, 1) for k, v in self.scores.items()},
            "composite_risk": round(self.composite, 1),
            "grade":       self.grade,
            "tvl_usd":     self.tvl_usd,
            "chain":       self.chain,
            "audit_count": self.audit_count,
            "top_risk_vector": VECTOR_LABELS.get(self.top_risk, self.top_risk),
            "mitigations": {VECTOR_LABELS.get(k, k): v for k, v in self.mitigations.items()},
        }


# ---------------------------------------------------------------------------
# Scorer
# ---------------------------------------------------------------------------

# Weights for composite score
VECTOR_WEIGHTS: Dict[str, float] = {
    "oracle_risk":          0.20,
    "flash_loan_risk":      0.15,
    "bridge_risk":          0.15,
    "governance_risk":      0.15,
    "liquidity_risk":       0.15,
    "smart_contract_risk":  0.20,
}


def _grade(score: float) -> str:
    if score < 20:   return "A"
    if score < 40:   return "B"
    if score < 60:   return "C"
    if score < 75:   return "D"
    return "F"


class DeFiRiskScorer:
    """Scores DeFi protocols across 6 economic attack vectors."""

    def score_protocol(
        self,
        protocol: str,
        custom_overrides: Optional[Dict[str, float]] = None,
        tvl_usd: Optional[float] = None,
    ) -> RiskScore:
        """
        Score a known protocol, optionally overriding individual vector scores.
        """
        profile = PROTOCOL_PROFILES.get(protocol)
        if profile is None:
            # Unknown protocol — use conservative mid-range defaults
            profile = {v: 50.0 for v in RISK_VECTORS}
            profile.update({
                "tvl_usd": tvl_usd or 10_000_000,
                "audit_count": 0,
                "chain": "Unknown",
            })

        scores: Dict[str, float] = {v: profile.get(v, 50.0) for v in RISK_VECTORS}

        # Apply TVL amplifier: higher TVL = higher target attractiveness
        effective_tvl = tvl_usd or profile.get("tvl_usd", 0)
        if effective_tvl > 1_000_000_000:
            scores["liquidity_risk"] = min(100.0, scores["liquidity_risk"] * 1.15)

        # Apply custom overrides
        if custom_overrides:
            for k, v in custom_overrides.items():
                if k in scores:
                    scores[k] = max(0.0, min(100.0, float(v)))

        composite = sum(scores[v] * VECTOR_WEIGHTS[v] for v in RISK_VECTORS)
        top_risk = max(scores, key=lambda k: scores[k])

        # Only include mitigations for high-risk vectors (>60)
        relevant_mitigations = {
            k: MITIGATIONS[k] for k in scores if scores[k] > 60
        }

        return RiskScore(
            protocol=protocol,
            scores=scores,
            composite=composite,
            grade=_grade(composite),
            tvl_usd=effective_tvl,
            chain=profile.get("chain", "Unknown"),
            audit_count=int(profile.get("audit_count", 0)),
            mitigations=relevant_mitigations,
            top_risk=top_risk,
        )

    def score_all_known(self) -> List[RiskScore]:
        """Return risk scores for all known protocols."""
        return [self.score_protocol(p) for p in PROTOCOL_PROFILES]

    def risk_matrix(self) -> Dict[str, Dict[str, float]]:
        """
        Returns a protocol × vector matrix of risk scores.
        Format: { protocol_name: { vector_label: score } }
        """
        matrix: Dict[str, Dict[str, float]] = {}
        for protocol in PROTOCOL_PROFILES:
            rs = self.score_protocol(protocol)
            matrix[protocol] = {
                VECTOR_LABELS.get(k, k): round(v, 1)
                for k, v in rs.scores.items()
            }
        return matrix

    @staticmethod
    def known_protocols() -> List[str]:
        return list(PROTOCOL_PROFILES.keys())
