"""
Tests for the Adversum AI Triage Engine.
Run with: python -m pytest tests/test_ai_triage.py -v
"""
import os
import sys
from pathlib import Path

# Ensure project root in path
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

# Enable mock mode so no external calls are made
os.environ["NEBIUS_MOCK"] = "1"

import pytest
from orchestrator.services.ai_triage import (
    AITriageEngine,
    RiskTier,
    TriageResult,
    _deterministic_score,
    _score_to_tier,
    triage_engine,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def engine():
    return AITriageEngine()


@pytest.fixture
def critical_finding():
    return {
        "id": "F001",
        "severity": "CRITICAL",
        "description": "Reentrancy vulnerability found in withdraw function",
        "rule_id": "SWC-107",
        "recommendation": "Add nonReentrant modifier",
        "snippet": "function withdraw() public { (bool ok,) = msg.sender.call{value: bal}(''); }",
    }


@pytest.fixture
def info_finding():
    return {
        "id": "F099",
        "severity": "INFO",
        "description": "Minor code style issue",
        "rule_id": "STYLE-001",
        "recommendation": "Consider renaming variable",
        "snippet": "uint x = 1;",
    }


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_critical_severity_scores_high(engine, critical_finding):
    """CRITICAL severity should yield a high triage score (>= 60)."""
    result = engine.triage_finding(critical_finding)
    assert result.triage_score >= 60.0, f"Expected score >= 60, got {result.triage_score}"


def test_reentrancy_pattern_increases_score(engine):
    """Presence of reentrancy-related text should add to the score vs baseline."""
    base_finding = {"id": "B1", "severity": "MEDIUM", "description": "some issue", "rule_id": "X", "snippet": ""}
    reentr_finding = {"id": "B2", "severity": "MEDIUM", "description": "reentrancy detected in withdraw", "rule_id": "X", "snippet": ""}

    base_score, _ = _deterministic_score(base_finding)
    reentr_score, _ = _deterministic_score(reentr_finding)

    assert reentr_score > base_score, "Reentrancy pattern should increase score"


def test_mitigation_pattern_decreases_score(engine):
    """nonReentrant guard should reduce the score vs no mitigation."""
    vuln = {"id": "V1", "severity": "HIGH", "description": "reentrancy detected", "rule_id": "SWC-107", "snippet": ""}
    mitigated = {"id": "V2", "severity": "HIGH", "description": "reentrancy detected", "rule_id": "SWC-107", "snippet": "nonReentrant modifier applied"}

    score_vuln, _ = _deterministic_score(vuln)
    score_mit, _ = _deterministic_score(mitigated)

    assert score_mit < score_vuln, "Mitigation pattern should decrease score"


def test_triage_result_fields_present(engine, critical_finding):
    """TriageResult must contain all required fields with correct types."""
    result = engine.triage_finding(critical_finding)

    assert isinstance(result, TriageResult)
    assert isinstance(result.finding_id, str)
    assert isinstance(result.original_severity, str)
    assert isinstance(result.risk_tier, RiskTier)
    assert isinstance(result.triage_score, float)
    assert isinstance(result.signals, list)
    assert len(result.signals) >= 1
    assert isinstance(result.recommended_action, str)
    assert 0.0 <= result.confidence <= 1.0


def test_batch_sorted_by_score(engine):
    """triage_batch must return findings sorted descending by triage_score."""
    findings = [
        {"id": "low", "severity": "LOW", "description": "minor", "rule_id": "L1", "snippet": ""},
        {"id": "crit", "severity": "CRITICAL", "description": "reentrancy selfdestruct", "rule_id": "C1", "snippet": ""},
        {"id": "med", "severity": "MEDIUM", "description": "medium issue", "rule_id": "M1", "snippet": ""},
    ]
    results = engine.triage_batch(findings)

    scores = [r.triage_score for r in results]
    assert scores == sorted(scores, reverse=True), f"Batch not sorted descending: {scores}"


def test_top_n_returns_n_results(engine):
    """top_n must return exactly n results (or fewer if fewer findings exist)."""
    findings = [
        {"id": f"F{i}", "severity": "MEDIUM", "description": f"issue {i}", "rule_id": f"R{i}", "snippet": ""}
        for i in range(20)
    ]
    top5 = engine.top_n(findings, n=5)
    assert len(top5) == 5


def test_tier_p0_for_score_80_plus():
    """Score >= 80 must map to P0_CRITICAL tier."""
    assert _score_to_tier(80.0) == RiskTier.P0_CRITICAL
    assert _score_to_tier(95.0) == RiskTier.P0_CRITICAL
    assert _score_to_tier(100.0) == RiskTier.P0_CRITICAL


def test_tier_p4_for_info_severity(engine, info_finding):
    """INFO-only finding with no risk patterns must land in P3_LOW or P4_INFORMATIONAL."""
    result = engine.triage_finding(info_finding)
    assert result.risk_tier in (RiskTier.P3_LOW, RiskTier.P4_INFORMATIONAL), (
        f"INFO finding should be P3/P4, got {result.risk_tier}"
    )
