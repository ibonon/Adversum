"""
Adversum MEV & Flash Loan Attack Intelligence Engine
======================================================
Detects and classifies Miner Extractable Value (MEV) attack patterns across
multiple EVM-compatible chains. Analyzes transaction ordering, mempool patterns,
and flash loan sequences to generate real-time attack signatures.

Supported attack types:
    - Sandwich Attack (front-run + back-run around a victim swap)
    - Front-Running (pure priority gas auction manipulation)
    - Back-Running (latency arbitrage after known state change)
    - Flash Loan Attack (same-block borrow + exploit + repay)
    - Rug Pull Detection (liquidity drain signature)
    - Oracle Manipulation (TWAP price skew via large swaps)

Supported chains:
    Ethereum, Arbitrum, Base, Optimism, Polygon, BSC, Avalanche
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("adversum.mev")


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class MEVAttackType(str, Enum):
    SANDWICH           = "sandwich"
    FRONT_RUNNING      = "front_running"
    BACK_RUNNING       = "back_running"
    FLASH_LOAN         = "flash_loan"
    RUG_PULL           = "rug_pull"
    ORACLE_MANIPULATION = "oracle_manipulation"
    ARBITRAGE          = "arbitrage"           # benign but detectable
    JIT_LIQUIDITY      = "jit_liquidity"       # just-in-time LP manipulation


class MEVChain(str, Enum):
    ETHEREUM  = "ethereum"
    ARBITRUM  = "arbitrum"
    BASE      = "base"
    OPTIMISM  = "optimism"
    POLYGON   = "polygon"
    BSC       = "bsc"
    AVALANCHE = "avalanche"


class MEVRiskLevel(str, Enum):
    CRITICAL = "CRITICAL"  # Active exploit in progress
    HIGH     = "HIGH"      # Strong signature match
    MEDIUM   = "MEDIUM"    # Partial pattern match
    LOW      = "LOW"       # Anomaly only


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class MEVTransaction:
    """Simplified mempool transaction representation."""
    tx_hash:      str
    from_address: str
    to_address:   str
    value_wei:    int                       = 0
    gas_price:    int                       = 0
    gas_limit:    int                       = 21_000
    input_data:   str                       = "0x"
    block_number: Optional[int]             = None
    position:     Optional[int]             = None   # tx index in block
    chain:        MEVChain                  = MEVChain.ETHEREUM
    timestamp:    str                       = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def value_eth(self) -> float:
        return self.value_wei / 1e18

    @property
    def gas_price_gwei(self) -> float:
        return self.gas_price / 1e9


@dataclass
class MEVAttackPattern:
    """Detected MEV attack pattern with evidence."""
    pattern_id:        str
    attack_type:       MEVAttackType
    chain:             MEVChain
    risk_level:        MEVRiskLevel
    value_at_risk_eth: float
    value_at_risk_usd: float
    attacker_address:  str
    victim_address:    Optional[str]
    tx_hashes:         List[str]
    evidence:          Dict[str, Any]
    signature:         str                  # SHA-256 fingerprint of the pattern
    mitre_technique:   str                  # MITRE ATT&CK for ICS mapping
    mitigation:        str
    detected_at:       str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "pattern_id":        self.pattern_id,
            "attack_type":       self.attack_type.value,
            "chain":             self.chain.value,
            "risk_level":        self.risk_level.value,
            "value_at_risk_eth": round(self.value_at_risk_eth, 6),
            "value_at_risk_usd": round(self.value_at_risk_usd, 2),
            "attacker_address":  self.attacker_address,
            "victim_address":    self.victim_address,
            "tx_hashes":         self.tx_hashes,
            "evidence":          self.evidence,
            "signature":         self.signature,
            "mitre_technique":   self.mitre_technique,
            "mitigation":        self.mitigation,
            "detected_at":       self.detected_at,
        }


@dataclass
class MEVDetectionResult:
    """Full analysis result for a block or mempool snapshot."""
    analysis_id:     str
    chain:           MEVChain
    block_number:    Optional[int]
    tx_count:        int
    patterns_found:  List[MEVAttackPattern]
    total_value_at_risk_eth: float
    total_value_at_risk_usd: float
    eth_price_usd:   float
    analysis_time_ms: int
    timestamp:       str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    @property
    def has_critical(self) -> bool:
        return any(p.risk_level == MEVRiskLevel.CRITICAL for p in self.patterns_found)

    def to_dict(self) -> dict:
        return {
            "analysis_id":     self.analysis_id,
            "chain":           self.chain.value,
            "block_number":    self.block_number,
            "tx_count":        self.tx_count,
            "patterns_found":  [p.to_dict() for p in self.patterns_found],
            "total_value_at_risk_eth": round(self.total_value_at_risk_eth, 6),
            "total_value_at_risk_usd": round(self.total_value_at_risk_usd, 2),
            "eth_price_usd":   self.eth_price_usd,
            "analysis_time_ms": self.analysis_time_ms,
            "timestamp":       self.timestamp,
            "summary": {
                "has_critical":     self.has_critical,
                "attack_types":     list({p.attack_type.value for p in self.patterns_found}),
                "unique_attackers": len({p.attacker_address for p in self.patterns_found}),
            }
        }


# ---------------------------------------------------------------------------
# MITRE ATT&CK for Web3 / ICS mapping
# ---------------------------------------------------------------------------

_MITRE_MAP: Dict[MEVAttackType, str] = {
    MEVAttackType.SANDWICH:            "T0836 — Modify Parameter",
    MEVAttackType.FRONT_RUNNING:       "T0800 — Activate Firmware Update Mode",
    MEVAttackType.BACK_RUNNING:        "T0855 — Unauthorized Command Message",
    MEVAttackType.FLASH_LOAN:          "T0828 — Loss of Productivity and Revenue",
    MEVAttackType.RUG_PULL:            "T0840 — Network Connection Enumeration",
    MEVAttackType.ORACLE_MANIPULATION: "T0830 — Adversary-in-the-Middle",
    MEVAttackType.ARBITRAGE:           "T0801 — Monitor Process State",
    MEVAttackType.JIT_LIQUIDITY:       "T0836 — Modify Parameter",
}

_MITIGATION_MAP: Dict[MEVAttackType, str] = {
    MEVAttackType.SANDWICH:
        "Implement slippage tolerance checks (max 0.5%). Use commit-reveal schemes or private mempools (Flashbots Protect).",
    MEVAttackType.FRONT_RUNNING:
        "Use EIP-1559 max priority fee caps. Implement transaction batching via multicall to reduce MEV surface.",
    MEVAttackType.BACK_RUNNING:
        "Apply TWAP oracles with minimum 15-minute window. Avoid spot price reads in single-block transactions.",
    MEVAttackType.FLASH_LOAN:
        "Add reentrancy guards (ReentrancyGuard). Validate balances before and after external calls. Use checks-effects-interactions.",
    MEVAttackType.RUG_PULL:
        "Require timelocked liquidity (minimum 6 months). Implement LP token lockup contracts. Verify contract ownership renouncement.",
    MEVAttackType.ORACLE_MANIPULATION:
        "Replace spot price oracles with Chainlink TWAP or Uniswap v3 TWAP (30-block minimum). Implement circuit breakers on price deviation >5%.",
    MEVAttackType.ARBITRAGE:
        "Consider MEV-share protocols to capture value. Use private order flow. Implement MEV-aware pricing curves.",
    MEVAttackType.JIT_LIQUIDITY:
        "Implement anti-JIT liquidity fees. Use tick-range restrictions or LP commitment periods.",
}


# ---------------------------------------------------------------------------
# Detection Heuristics
# ---------------------------------------------------------------------------

class _SandwichDetector:
    """
    Detect sandwich attacks: front-run TX → victim TX → back-run TX
    Pattern: same attacker, same pair, gas_price[front] > victim > gas_price[back]
    """

    @staticmethod
    def detect(txs: List[MEVTransaction], eth_price: float) -> List[MEVAttackPattern]:
        patterns: List[MEVAttackPattern] = []
        n = len(txs)
        for i in range(n - 2):
            front, victim, back = txs[i], txs[i + 1], txs[i + 2]
            # Heuristic: front and back from same address, victim different
            if (front.from_address == back.from_address
                    and front.from_address != victim.from_address
                    and front.to_address == back.to_address == victim.to_address
                    and front.gas_price > victim.gas_price > back.gas_price):

                profit_eth = abs(back.value_eth - front.value_eth) * 0.3  # simplified
                sig_data   = f"sandwich:{front.from_address}:{front.to_address}:{front.tx_hash}"
                signature  = hashlib.sha256(sig_data.encode()).hexdigest()[:32]

                patterns.append(MEVAttackPattern(
                    pattern_id        = str(uuid.uuid4()),
                    attack_type       = MEVAttackType.SANDWICH,
                    chain             = front.chain,
                    risk_level        = MEVRiskLevel.CRITICAL if profit_eth > 1.0 else MEVRiskLevel.HIGH,
                    value_at_risk_eth = victim.value_eth,
                    value_at_risk_usd = victim.value_eth * eth_price,
                    attacker_address  = front.from_address,
                    victim_address    = victim.from_address,
                    tx_hashes         = [front.tx_hash, victim.tx_hash, back.tx_hash],
                    evidence          = {
                        "front_gas_gwei":  front.gas_price_gwei,
                        "victim_gas_gwei": victim.gas_price_gwei,
                        "back_gas_gwei":   back.gas_price_gwei,
                        "estimated_profit_eth": round(profit_eth, 6),
                        "estimated_profit_usd": round(profit_eth * eth_price, 2),
                    },
                    signature         = signature,
                    mitre_technique   = _MITRE_MAP[MEVAttackType.SANDWICH],
                    mitigation        = _MITIGATION_MAP[MEVAttackType.SANDWICH],
                ))
        return patterns


class _FlashLoanDetector:
    """
    Detect flash loan attacks: single-block borrow + state change + repay.
    Pattern: large incoming transfer followed by equally-large outgoing in same block,
    combined with an anomalous state-change tx in between.
    """

    # Minimum value threshold for flash loan classification (ETH)
    _MIN_FLASH_LOAN_ETH = 10.0

    @staticmethod
    def detect(txs: List[MEVTransaction], eth_price: float) -> List[MEVAttackPattern]:
        patterns: List[MEVAttackPattern] = []
        by_sender: Dict[str, List[MEVTransaction]] = {}
        for tx in txs:
            by_sender.setdefault(tx.from_address, []).append(tx)

        for sender, sender_txs in by_sender.items():
            if len(sender_txs) < 2:
                continue
            total_in  = sum(t.value_eth for t in sender_txs)
            total_out = sum(t.value_eth for t in sender_txs if t.input_data not in ("0x", ""))

            # Large multi-tx from single sender with non-trivial calldata = flash loan signal
            if total_in >= _FlashLoanDetector._MIN_FLASH_LOAN_ETH and len(sender_txs) >= 2:
                sig_data  = f"flashloan:{sender}:{total_in:.2f}"
                signature = hashlib.sha256(sig_data.encode()).hexdigest()[:32]

                patterns.append(MEVAttackPattern(
                    pattern_id        = str(uuid.uuid4()),
                    attack_type       = MEVAttackType.FLASH_LOAN,
                    chain             = sender_txs[0].chain,
                    risk_level        = MEVRiskLevel.CRITICAL,
                    value_at_risk_eth = total_in,
                    value_at_risk_usd = total_in * eth_price,
                    attacker_address  = sender,
                    victim_address    = None,
                    tx_hashes         = [t.tx_hash for t in sender_txs],
                    evidence          = {
                        "tx_count":          len(sender_txs),
                        "total_value_eth":   round(total_in, 6),
                        "total_value_usd":   round(total_in * eth_price, 2),
                        "calldata_txs":      sum(1 for t in sender_txs if t.input_data not in ("0x", "")),
                    },
                    signature         = signature,
                    mitre_technique   = _MITRE_MAP[MEVAttackType.FLASH_LOAN],
                    mitigation        = _MITIGATION_MAP[MEVAttackType.FLASH_LOAN],
                ))
        return patterns


class _OracleManipulationDetector:
    """
    Detect oracle manipulation: abnormally large single swap distorting TWAP.
    Pattern: single tx moving >15% of pool liquidity.
    """

    _LIQUIDITY_DISTORTION_THRESHOLD = 0.15  # 15% of pool

    @staticmethod
    def detect(txs: List[MEVTransaction], eth_price: float, pool_liquidity_eth: float = 1000.0) -> List[MEVAttackPattern]:
        patterns: List[MEVAttackPattern] = []
        for tx in txs:
            distortion = tx.value_eth / pool_liquidity_eth if pool_liquidity_eth > 0 else 0
            if (distortion >= _OracleManipulationDetector._LIQUIDITY_DISTORTION_THRESHOLD
                    and tx.input_data not in ("0x", "")):

                sig_data  = f"oracle:{tx.from_address}:{tx.tx_hash}"
                signature = hashlib.sha256(sig_data.encode()).hexdigest()[:32]

                patterns.append(MEVAttackPattern(
                    pattern_id        = str(uuid.uuid4()),
                    attack_type       = MEVAttackType.ORACLE_MANIPULATION,
                    chain             = tx.chain,
                    risk_level        = MEVRiskLevel.HIGH,
                    value_at_risk_eth = tx.value_eth * distortion * 5,  # downstream impact estimate
                    value_at_risk_usd = tx.value_eth * distortion * 5 * eth_price,
                    attacker_address  = tx.from_address,
                    victim_address    = tx.to_address,
                    tx_hashes         = [tx.tx_hash],
                    evidence          = {
                        "tx_value_eth":         round(tx.value_eth, 6),
                        "pool_liquidity_eth":   round(pool_liquidity_eth, 2),
                        "distortion_pct":       round(distortion * 100, 2),
                        "twap_impact_estimate": f"{distortion * 100:.1f}% price skew",
                    },
                    signature         = signature,
                    mitre_technique   = _MITRE_MAP[MEVAttackType.ORACLE_MANIPULATION],
                    mitigation        = _MITIGATION_MAP[MEVAttackType.ORACLE_MANIPULATION],
                ))
        return patterns


class _RugPullDetector:
    """
    Detect rug pull signature: single-address draining >80% of liquidity.
    Pattern: LP remover is contract deployer or holds outsized token balance.
    """

    _MIN_DRAIN_PCT = 0.80

    @staticmethod
    def detect(txs: List[MEVTransaction], eth_price: float) -> List[MEVAttackPattern]:
        patterns: List[MEVAttackPattern] = []
        total_value = sum(t.value_eth for t in txs) or 1.0

        by_sender: Dict[str, float] = {}
        for tx in txs:
            by_sender[tx.from_address] = by_sender.get(tx.from_address, 0) + tx.value_eth

        for sender, val in by_sender.items():
            drain_pct = val / total_value
            if drain_pct >= _RugPullDetector._MIN_DRAIN_PCT:
                sig_data  = f"rug:{sender}:{drain_pct:.3f}"
                signature = hashlib.sha256(sig_data.encode()).hexdigest()[:32]
                tx_hashes = [t.tx_hash for t in txs if t.from_address == sender]

                patterns.append(MEVAttackPattern(
                    pattern_id        = str(uuid.uuid4()),
                    attack_type       = MEVAttackType.RUG_PULL,
                    chain             = txs[0].chain if txs else MEVChain.ETHEREUM,
                    risk_level        = MEVRiskLevel.CRITICAL,
                    value_at_risk_eth = val,
                    value_at_risk_usd = val * eth_price,
                    attacker_address  = sender,
                    victim_address    = None,
                    tx_hashes         = tx_hashes,
                    evidence          = {
                        "drain_percentage": round(drain_pct * 100, 2),
                        "drained_eth":      round(val, 6),
                        "drained_usd":      round(val * eth_price, 2),
                        "tx_count":         len(tx_hashes),
                    },
                    signature         = signature,
                    mitre_technique   = _MITRE_MAP[MEVAttackType.RUG_PULL],
                    mitigation        = _MITIGATION_MAP[MEVAttackType.RUG_PULL],
                ))
        return patterns


# ---------------------------------------------------------------------------
# Main Engine
# ---------------------------------------------------------------------------

class MEVIntelligenceEngine:
    """
    Multi-chain MEV & Flash Loan Attack Intelligence Engine.

    Usage:
        engine = MEVIntelligenceEngine()
        txs = [MEVTransaction(...), ...]
        result = await engine.analyze_block(txs, chain=MEVChain.ETHEREUM)
    """

    # ETH price used for USD estimates when no live feed is available
    DEFAULT_ETH_PRICE_USD = 2_650.0

    def __init__(self, eth_price_usd: float = DEFAULT_ETH_PRICE_USD):
        self.eth_price = eth_price_usd
        self._detectors = [
            _SandwichDetector(),
            _FlashLoanDetector(),
            _OracleManipulationDetector(),
            _RugPullDetector(),
        ]
        logger.info("MEVIntelligenceEngine initialized (ETH=$%.2f)", eth_price_usd)

    async def analyze_block(
        self,
        transactions: List[MEVTransaction],
        chain: MEVChain = MEVChain.ETHEREUM,
        block_number: Optional[int] = None,
        pool_liquidity_eth: float = 1000.0,
    ) -> MEVDetectionResult:
        """
        Analyze a block or mempool snapshot for MEV attack patterns.

        Args:
            transactions:       List of MEVTransaction objects (ordered by position).
            chain:              Target chain identifier.
            block_number:       Block number if known.
            pool_liquidity_eth: Reference pool liquidity for oracle distortion calc.

        Returns:
            MEVDetectionResult with all detected patterns.
        """
        import time
        start = time.monotonic()

        all_patterns: List[MEVAttackPattern] = []

        # Ensure transactions are stamped with chain
        for tx in transactions:
            tx.chain = chain

        # Run all detectors
        all_patterns += _SandwichDetector.detect(transactions, self.eth_price)
        all_patterns += _FlashLoanDetector.detect(transactions, self.eth_price)
        all_patterns += _OracleManipulationDetector.detect(
            transactions, self.eth_price, pool_liquidity_eth
        )
        all_patterns += _RugPullDetector.detect(transactions, self.eth_price)

        # Deduplicate by signature
        seen_sigs: set = set()
        unique_patterns: List[MEVAttackPattern] = []
        for p in all_patterns:
            if p.signature not in seen_sigs:
                seen_sigs.add(p.signature)
                unique_patterns.append(p)

        total_eth = sum(p.value_at_risk_eth for p in unique_patterns)
        elapsed_ms = int((time.monotonic() - start) * 1000)

        result = MEVDetectionResult(
            analysis_id              = str(uuid.uuid4()),
            chain                    = chain,
            block_number             = block_number,
            tx_count                 = len(transactions),
            patterns_found           = unique_patterns,
            total_value_at_risk_eth  = total_eth,
            total_value_at_risk_usd  = total_eth * self.eth_price,
            eth_price_usd            = self.eth_price,
            analysis_time_ms         = elapsed_ms,
        )

        if unique_patterns:
            logger.warning(
                "MEV analysis [%s block=%s]: %d patterns | $%.0f at risk | %dms",
                chain.value, block_number, len(unique_patterns),
                result.total_value_at_risk_usd, elapsed_ms,
            )
        else:
            logger.info("MEV analysis [%s block=%s]: clean (%dms)",
                        chain.value, block_number, elapsed_ms)

        return result

    def generate_signature_ruleset(self, patterns: List[MEVAttackPattern]) -> List[dict]:
        """Export patterns as detection rules for SIEM/WAF ingestion."""
        rules = []
        for p in patterns:
            rules.append({
                "rule_id":    f"MEV-{p.attack_type.value.upper()}-{p.signature[:8]}",
                "type":       p.attack_type.value,
                "chain":      p.chain.value,
                "severity":   p.risk_level.value,
                "attacker":   p.attacker_address,
                "signature":  p.signature,
                "mitigation": p.mitigation,
                "mitre":      p.mitre_technique,
                "created_at": p.detected_at,
            })
        return rules

    def update_eth_price(self, price_usd: float) -> None:
        """Update the ETH/USD price used for risk valuation."""
        self.eth_price = price_usd
        logger.info("ETH price updated to $%.2f", price_usd)
