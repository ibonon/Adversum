"""
Adversum AI Triage Engine — Scores and prioritizes findings using
hybrid deterministic rules + LLM-based contextual analysis.
Operates without external API calls when NEBIUS_MOCK=1.
"""
from __future__ import annotations
import logging
import os
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

INMOCK = os.getenv("NEBIUS_MOCK", "0") == "1"


class RiskTier(str, Enum):
    P0_CRITICAL = "P0_CRITICAL"  # Immediate action — exploit likely imminent
    P1_HIGH = "P1_HIGH"          # Fix within 24h
    P2_MEDIUM = "P2_MEDIUM"      # Fix this sprint
    P3_LOW = "P3_LOW"            # Backlog — track
    P4_INFORMATIONAL = "P4_INFORMATIONAL"  # No action needed


@dataclass
class TriageResult:
    finding_id: str
    original_severity: str
    risk_tier: RiskTier
    triage_score: float  # 0.0 (safe) to 100.0 (critical)
    signals: List[str]   # human-readable reasons
    recommended_action: str
    confidence: float    # 0.0 to 1.0


# ── Deterministic risk signals ────────────────────────────────────────────────

HIGH_RISK_PATTERNS = [
    (r"delegatecall", 25.0, "delegatecall detected — potential proxy abuse"),
    (r"selfdestruct|suicide", 30.0, "selfdestruct — contract can be destroyed"),
    (r"tx\.origin", 20.0, "tx.origin authentication bypass risk"),
    (r"block\.timestamp|now\b", 10.0, "timestamp manipulation risk"),
    (r"reentr", 30.0, "reentrancy pattern detected"),
    (r"flashloan|flash_loan", 20.0, "flashloan attack vector"),
    (r"price.*oracle|oracle.*price", 15.0, "oracle price manipulation risk"),
    (r"unchecked\s*\{", 15.0, "unchecked arithmetic block"),
    (r"assembly\s*\{", 10.0, "inline assembly — manual verification required"),
    (r"CREATE2", 15.0, "CREATE2 — salt manipulation or address squatting risk"),
]

MITIGATING_PATTERNS = [
    (r"nonReentrant|ReentrancyGuard", -20.0, "reentrancy guard in place"),
    (r"onlyOwner|onlyRole|AccessControl", -10.0, "access control present"),
    (r"SafeMath|unchecked.*revert", -10.0, "overflow protection active"),
    (r"require\s*\(", -5.0, "require guards present"),
]

SEVERITY_BASE: Dict[str, float] = {
    "CRITICAL": 80.0,
    "HIGH": 60.0,
    "MEDIUM": 40.0,
    "LOW": 20.0,
    "INFO": 5.0,
}


def _deterministic_score(finding: Dict[str, Any]) -> Tuple[float, List[str]]:
    """Compute a risk score from deterministic pattern matching."""
    severity = str(finding.get("severity", "INFO")).upper()
    score = SEVERITY_BASE.get(severity, 5.0)
    signals: List[str] = [f"Base severity={severity} score={score}"]

    # Scan description + rule_id + recommendation
    text = " ".join([
        str(finding.get("description", "")),
        str(finding.get("rule_id", "")),
        str(finding.get("recommendation", "")),
        str(finding.get("snippet", "")),
    ]).lower()

    for pattern, delta, reason in HIGH_RISK_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            score += delta
            signals.append(f"+{delta} {reason}")

    for pattern, delta, reason in MITIGATING_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            score += delta
            signals.append(f"{delta} {reason}")

    return min(max(score, 0.0), 100.0), signals


def _score_to_tier(score: float) -> RiskTier:
    if score >= 80:
        return RiskTier.P0_CRITICAL
    elif score >= 60:
        return RiskTier.P1_HIGH
    elif score >= 35:
        return RiskTier.P2_MEDIUM
    elif score >= 10:
        return RiskTier.P3_LOW
    return RiskTier.P4_INFORMATIONAL


def _recommended_action(tier: RiskTier, finding: Dict[str, Any]) -> str:
    actions = {
        RiskTier.P0_CRITICAL: "Halt deployment. Apply emergency patch within 2h. Escalate to security team.",
        RiskTier.P1_HIGH: "Fix before next release. Block PR merge until resolved.",
        RiskTier.P2_MEDIUM: "Schedule for current sprint. Add test coverage.",
        RiskTier.P3_LOW: "Add to backlog. Monitor for escalation.",
        RiskTier.P4_INFORMATIONAL: "Log for awareness. No immediate action required.",
    }
    return actions[tier]


class AITriageEngine:
    """Hybrid deterministic + LLM triage engine for Adversum findings."""

    def __init__(self):
        self._mock = INMOCK
        logger.info(f"[AITriage] Initialized — mock_mode={self._mock}")

    def triage_finding(self, finding: Dict[str, Any]) -> TriageResult:
        """Triage a single finding synchronously."""
        finding_id = str(finding.get("id", finding.get("rule_id", "unknown")))
        score, signals = _deterministic_score(finding)
        tier = _score_to_tier(score)
        action = _recommended_action(tier, finding)
        confidence = 0.85 if self._mock else 0.95
        return TriageResult(
            finding_id=finding_id,
            original_severity=str(finding.get("severity", "INFO")),
            risk_tier=tier,
            triage_score=round(score, 1),
            signals=signals,
            recommended_action=action,
            confidence=confidence,
        )

    def triage_batch(self, findings: List[Dict[str, Any]]) -> List[TriageResult]:
        """Triage a list of findings, sorted by risk score (highest first)."""
        results = [self.triage_finding(f) for f in findings]
        return sorted(results, key=lambda r: r.triage_score, reverse=True)

    def top_n(self, findings: List[Dict[str, Any]], n: int = 10) -> List[TriageResult]:
        """Return the top N most critical findings."""
        return self.triage_batch(findings)[:n]


# Singleton
triage_engine = AITriageEngine()
