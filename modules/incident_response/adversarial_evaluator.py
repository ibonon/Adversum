#!/usr/bin/env python3
"""
Adversum DeFi Invariant & Adversarial Evaluator
Phase 4 — Evaluates smart contracts against 10 critical DeFi economic invariants
and security properties.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Optional


@dataclass
class InvariantResult:
    invariant_id: str
    name: str
    category: str
    passed: bool
    confidence: float
    description: str
    violation_scenario: Optional[str] = None
    mitigation_advice: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ProtocolEvaluationReport:
    protocol: str
    total_invariants: int
    passed_count: int
    failed_count: int
    resilience_score: float         # 0 - 100
    invariant_results: List[InvariantResult]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protocol": self.protocol,
            "total_invariants": self.total_invariants,
            "passed_count": self.passed_count,
            "failed_count": self.failed_count,
            "resilience_score": round(self.resilience_score, 1),
            "invariant_results": [r.to_dict() for r in self.invariant_results],
        }


class AdversarialInvariantEvaluator:
    """Evaluates Solidity / DeFi contract source or model against 10 core security invariants."""

    INVARIANTS = [
        ("INV-01", "Conservation of Value", "Accounting", "Total supply of wrapped tokens must always equal or be less than locked reserves."),
        ("INV-02", "Collateralization Floor", "Lending", "Borrows must never exceed collateral value scaled by liquidation threshold."),
        ("INV-03", "Reentrancy Impossibility", "Execution", "State modifications must strictly precede external calls (Checks-Effects-Interactions)."),
        ("INV-04", "Oracle Freshness & Bounds", "Oracles", "Oracle updates must be constrained by heartbeat timeout and circuit-breaker delta limits."),
        ("INV-05", "Privilege & Timelock Segregation", "Governance", "Critical parameter updates must be subject to multi-hour timelocks and non-single-owner keys."),
        ("INV-06", "Slippage & Minimum Return", "DEX/AMM", "Trades must require explicit minimum return amounts (`amountOutMin`) provided by caller."),
        ("INV-07", "Flash Loan Isolation", "Lending", "Flash loan callbacks must verify initiator and balance restoration invariant."),
        ("INV-08", "Balance Invariance Under Failure", "ERC20", "Failed token transfers must revert and not silently return false without detection."),
        ("INV-09", "Reserve Ratio Stability", "Liquidity", "Protocol utilization rate must not exceed cap that causes liquidity lockup."),
        ("INV-10", "Cross-Chain Message Finality", "Bridges", "Cross-chain minting requires valid multi-signature verification and replay nonce."),
    ]

    def evaluate_code(self, source_code: str, protocol_name: str = "TargetProtocol") -> ProtocolEvaluationReport:
        results: List[InvariantResult] = []

        code_lower = source_code.lower()

        for inv_id, name, cat, desc in self.INVARIANTS:
            passed = True
            violation = None
            mitigation = None

            if inv_id == "INV-01":
                # Check donate / unbacked mint risks
                if "donateto" in code_lower or "mint(" in code_lower and "require(" not in code_lower:
                    passed = False
                    violation = "Potential unbacked minting or arbitrary donation skewing reserves."
                    mitigation = "Enforce invariant `totalSupply <= totalAssets()` in post-condition modifier."

            elif inv_id == "INV-02":
                # Check collateral check
                if "borrow" in code_lower and ("collateral" not in code_lower and "health" not in code_lower):
                    passed = False
                    violation = "Borrow function detected without evident health factor verification."
                    mitigation = "Incorporate `require(getHealthFactor(user) >= 1e18, 'Undercollateralized')`."

            elif inv_id == "INV-03":
                # Checks-Effects-Interactions
                if ".call{value:" in source_code or ".call(" in source_code:
                    if "nonreentrant" not in code_lower and "reentrancyguard" not in code_lower:
                        passed = False
                        violation = "External low-level call without explicit ReentrancyGuard modifier."
                        mitigation = "Add OpenZeppelin `ReentrancyGuard` and apply `nonReentrant`."

            elif inv_id == "INV-04":
                # Oracle verification
                if "latestrounddata" in code_lower or "getreserves" in code_lower:
                    if "answeredinround" not in code_lower and "twap" not in code_lower:
                        passed = False
                        violation = "Oracle read lacks round completeness or stale heartbeat checks."
                        mitigation = "Verify `updatedAt > block.timestamp - 3600` and `answeredInRound >= roundId`."

            elif inv_id == "INV-05":
                # Timelock
                if "onlyowner" in code_lower and "timelock" not in code_lower:
                    passed = False
                    violation = "Immediate owner execution on sensitive functions without timelock."
                    mitigation = "Route admin parameter setters through a 48h TimelockController."

            elif inv_id == "INV-06":
                # Slippage
                if "swap" in code_lower and "amountoutmin" not in code_lower and "minamount" not in code_lower:
                    passed = False
                    violation = "Token swap execution without minimum output slippage protection."
                    mitigation = "Require caller to specify `amountOutMin` and revert if received < minimum."

            elif inv_id == "INV-07":
                # Flash loan callback
                if "executeoperation" in code_lower or "onflashloan" in code_lower:
                    if "msg.sender == pool" not in code_lower and "initiator" not in code_lower:
                        passed = False
                        violation = "Flash loan callback lacks strict verification of lending pool caller."
                        mitigation = "Assert `require(msg.sender == address(lendingPool))` inside callback."

            elif inv_id == "INV-08":
                # ERC20 return check
                if ".transfer(" in source_code and "safeerc20" not in code_lower and "require(" not in code_lower:
                    passed = False
                    violation = "Direct token transfer without SafeERC20 wrapper or boolean check."
                    mitigation = "Import and use OpenZeppelin `SafeERC20` with `safeTransfer`."

            elif inv_id == "INV-09":
                # Utilization / reserve cap
                if "borrow" in code_lower and "utilization" not in code_lower and "maxborrow" not in code_lower:
                    passed = False
                    violation = "Uncapped pool utilization could cause complete withdrawal freeze."
                    mitigation = "Implement dynamic interest rate curve with emergency utilization circuit breaker."

            elif inv_id == "INV-10":
                # Cross-chain signature & replay
                if "processmessage" in code_lower or "executewithdrawal" in code_lower:
                    if "nonce" not in code_lower or "recovered" not in code_lower:
                        passed = False
                        violation = "Cross-chain message processor lacks explicit replay nonce protection."
                        mitigation = "Track `mapping(bytes32 => bool) executedHashes` to prevent replay."

            results.append(InvariantResult(
                invariant_id=inv_id,
                name=name,
                category=cat,
                passed=passed,
                confidence=0.92,
                description=desc,
                violation_scenario=violation,
                mitigation_advice=mitigation,
            ))

        passed_count = sum(1 for r in results if r.passed)
        failed_count = len(results) - passed_count
        score = (passed_count / len(results)) * 100.0

        return ProtocolEvaluationReport(
            protocol=protocol_name,
            total_invariants=len(results),
            passed_count=passed_count,
            failed_count=failed_count,
            resilience_score=score,
            invariant_results=results,
        )
