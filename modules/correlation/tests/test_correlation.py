"""Tests for the Universal Correlation Engine."""
import os
import sys
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from correlation.engine import CorrelationEngine


def _make_finding(rule_id, severity, file="test.py", line=10, engine="native"):
    return {
        "rule_id": rule_id,
        "severity": severity,
        "file": file,
        "line": line,
        "message": f"Vuln: {rule_id}",
        "snippet": f"# {rule_id} code",
        "engine": engine,
    }


class TestCorrelationEngine:
    def setup_method(self):
        self.engine = CorrelationEngine()

    def test_empty_input(self):
        result = self.engine.correlate_findings([])
        assert result == []

    def test_single_finding_passthrough(self):
        findings = [_make_finding("SOL-001", "HIGH")]
        result = self.engine.correlate_findings(findings)
        assert len(result) == 1
        assert result[0]["cwe"]["cwe_id"].startswith("CWE-")
        assert result[0]["consensus_score"] == 0.78  # single engine

    def test_multi_engine_quorum_boosts_confidence(self):
        findings = [
            _make_finding("SOL-001", "CRITICAL", engine="slither"),
            _make_finding("SOL-001", "CRITICAL", engine="aderyn"),
            _make_finding("SOL-001", "HIGH", engine="semgrep"),
        ]
        result = self.engine.correlate_findings(findings)
        assert len(result) == 1
        assert result[0]["consensus_score"] == 0.99
        assert "VERY HIGH" in result[0]["confidence_level"]
        assert result[0]["cluster_size"] == 3

    def test_duplicate_deduplication(self):
        """Two findings on the same file/line should be clustered."""
        findings = [
            _make_finding("EVAL-001", "HIGH", file="app.py", line=42, engine="native"),
            _make_finding("eval_used", "HIGH", file="app.py", line=43, engine="semgrep"),
        ]
        result = self.engine.correlate_findings(findings)
        # Should be clustered into one finding
        assert len(result) == 1
        assert result[0]["cluster_size"] == 2

    def test_different_files_not_clustered(self):
        findings = [
            _make_finding("SOL-001", "HIGH", file="a.sol", line=10),
            _make_finding("SOL-001", "HIGH", file="b.sol", line=10),
        ]
        result = self.engine.correlate_findings(findings)
        assert len(result) == 2

    def test_owasp_compliance_mapping(self):
        findings = [_make_finding("eval_used", "CRITICAL", file="app.py")]
        result = self.engine.correlate_findings(findings)
        assert "A03" in result[0]["owasp"]  # Injection

    def test_cwe_mapping_reentrancy(self):
        findings = [_make_finding("SOL-001-reentrancy", "CRITICAL", file="c.sol")]
        result = self.engine.correlate_findings(findings)
        assert result[0]["cwe"]["cwe_id"] == "CWE-841"

    def test_executive_scorecard_clean(self):
        scorecard = self.engine.compute_executive_scorecard([])
        assert scorecard["security_score"] == 100
        assert scorecard["security_grade"] == "AAA"

    def test_executive_scorecard_critical(self):
        # Use different files so findings are NOT clustered (testing raw count impact)
        findings = [_make_finding("SOL-001", "CRITICAL", file=f"file{i}.sol", line=i*10) for i in range(5)]
        correlated = self.engine.correlate_findings(findings)
        scorecard = self.engine.compute_executive_scorecard(correlated)
        assert scorecard["security_score"] < 50
        assert scorecard["security_grade"] in ("BB", "B", "F")
        assert not scorecard["ccss_ready"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
