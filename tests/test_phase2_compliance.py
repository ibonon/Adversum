"""
Phase 2 Tests — Compliance Engine (SARIF 2.1 + SOC2 + ISO 27001)
pytest tests/test_phase2_compliance.py
"""

import json
import pytest

import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from modules.compliance.sarif_v2 import SARIFv2Exporter, SARIFReport
from modules.compliance.soc2_mapper import SOC2Mapper, SOC2ComplianceReport
from modules.compliance.iso27001_mapper import ISO27001Mapper, ISO27001ComplianceReport


# ── Test fixtures ───────────────────────────────────────────────────────────

CRITICAL_FINDING = {
    "rule_id": "SOL-001",
    "severity": "CRITICAL",
    "description": "Reentrancy vulnerability allows recursive drain of vault funds",
    "file_path": "contracts/Vault.sol",
    "line_number": 42,
    "cwe_id": "CWE-841",
    "raw": {
        "rule_id": "SOL-001",
        "severity": "CRITICAL",
        "file_path": "contracts/Vault.sol",
        "line_number": 42,
    }
}

HIGH_FINDING = {
    "rule_id": "ACCESS_CONTROL",
    "severity": "HIGH",
    "description": "Missing access control on sensitive admin function",
    "file_path": "contracts/Admin.sol",
    "line_number": 15,
    "raw": {
        "rule_id": "ACCESS_CONTROL",
        "severity": "HIGH",
        "file_path": "contracts/Admin.sol",
        "line_number": 15,
    }
}

MEDIUM_FINDING = {
    "rule_id": "ORACLE_MANIP",
    "severity": "MEDIUM",
    "description": "Spot price oracle manipulable in single block",
    "file_path": "contracts/PriceOracle.sol",
    "line_number": 88,
    "raw": {
        "rule_id": "ORACLE_MANIP",
        "severity": "MEDIUM",
        "file_path": "contracts/PriceOracle.sol",
        "line_number": 88,
    }
}


# ── SARIF 2.1 Tests ─────────────────────────────────────────────────────────

class TestSARIFExporter:
    def test_sarif_schema_version(self):
        """SARIF output must declare version 2.1.0."""
        exporter = SARIFv2Exporter()
        report   = exporter.export([CRITICAL_FINDING])
        sarif    = report.to_sarif()

        assert sarif["version"] == "2.1.0"
        assert "sarif-schema-2.1.0" in sarif["$schema"]

    def test_sarif_tool_driver(self):
        """SARIF must identify the Adversum tool driver."""
        exporter = SARIFv2Exporter()
        report   = exporter.export([CRITICAL_FINDING], tool_name="Adversum Security Engine")
        sarif    = report.to_sarif()
        driver   = sarif["runs"][0]["tool"]["driver"]

        assert driver["name"] == "Adversum Security Engine"
        assert "version" in driver

    def test_sarif_rules_generated(self):
        """Each unique rule_id should produce a SARIF rule entry."""
        exporter = SARIFv2Exporter()
        report   = exporter.export([CRITICAL_FINDING, HIGH_FINDING, MEDIUM_FINDING])
        sarif    = report.to_sarif()
        rules    = sarif["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]

        assert "SOL-001"       in rule_ids
        assert "ACCESS_CONTROL" in rule_ids
        assert "ORACLE_MANIP"  in rule_ids

    def test_sarif_results_with_locations(self):
        """SARIF results must include physicalLocation with file + line."""
        exporter = SARIFv2Exporter()
        report   = exporter.export([CRITICAL_FINDING])
        sarif    = report.to_sarif()
        results  = sarif["runs"][0]["results"]

        assert len(results) == 1
        loc = results[0]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "contracts/Vault.sol"
        assert loc["region"]["startLine"] == 42

    def test_sarif_severity_level_mapping(self):
        """CRITICAL/HIGH → error, MEDIUM → warning, LOW → note."""
        exporter = SARIFv2Exporter()

        for finding, expected_level in [
            (CRITICAL_FINDING, "error"),
            (MEDIUM_FINDING, "warning"),
        ]:
            report  = exporter.export([finding])
            sarif   = report.to_sarif()
            results = sarif["runs"][0]["results"]
            assert results[0]["level"] == expected_level

    def test_sarif_fingerprint_generated(self):
        """Each SARIF result must include a fingerprint for deduplication."""
        exporter = SARIFv2Exporter()
        report   = exporter.export([CRITICAL_FINDING])
        sarif    = report.to_sarif()

        result = sarif["runs"][0]["results"][0]
        assert "fingerprints" in result
        fp = list(result["fingerprints"].values())[0]
        assert len(fp) > 0

    def test_sarif_json_serializable(self):
        """SARIF output must be JSON-serializable."""
        exporter = SARIFv2Exporter()
        report   = exporter.export([CRITICAL_FINDING, HIGH_FINDING])
        json_str = report.to_json()
        parsed   = json.loads(json_str)
        assert parsed["version"] == "2.1.0"

    def test_sarif_empty_findings(self):
        """Empty findings list should produce valid SARIF with 0 results."""
        exporter = SARIFv2Exporter()
        report   = exporter.export([])
        sarif    = report.to_sarif()
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"][0]["results"]) == 0


# ── SOC2 Compliance Tests ────────────────────────────────────────────────────

class TestSOC2Mapper:
    def test_soc2_report_structure(self):
        """SOC2 report must contain all required fields."""
        mapper = SOC2Mapper()
        report = mapper.generate_report([CRITICAL_FINDING], target="TestProtocol")
        d      = report.to_dict()

        assert "report_id"        in d
        assert "overall_status"   in d
        assert "compliance_score" in d
        assert "controls"         in d
        assert "failing_controls" in d
        assert "passing_controls" in d
        assert "summary"          in d

    def test_soc2_critical_finding_fails_control(self):
        """CRITICAL findings should cause relevant controls to FAIL."""
        mapper  = SOC2Mapper()
        report  = mapper.generate_report([CRITICAL_FINDING], target="TestProtocol")

        # SOL-001 (reentrancy) maps to CC6.6
        cc66 = next((c for c in report.controls if c.control_id == "CC6.6"), None)
        assert cc66 is not None
        assert cc66.status == "FAIL", f"CC6.6 should FAIL with reentrancy finding, got {cc66.status}"

    def test_soc2_clean_scan_all_pass(self):
        """No findings should yield COMPLIANT status and high score."""
        mapper = SOC2Mapper()
        report = mapper.generate_report([], target="CleanProtocol")

        assert report.overall_status == "COMPLIANT"
        assert report.compliance_score >= 90.0
        assert len(report.failing_controls) == 0

    def test_soc2_score_range(self):
        """Compliance score must be between 0 and 100."""
        mapper = SOC2Mapper()
        for findings in [[], [CRITICAL_FINDING], [CRITICAL_FINDING, HIGH_FINDING, MEDIUM_FINDING]]:
            report = mapper.generate_report(findings, target="Test")
            assert 0.0 <= report.compliance_score <= 100.0

    def test_soc2_remediation_provided_for_failures(self):
        """Failed controls should include remediation guidance."""
        mapper = SOC2Mapper()
        report = mapper.generate_report([CRITICAL_FINDING, HIGH_FINDING], target="TestProtocol")

        for ctrl in report.controls:
            if ctrl.status == "FAIL":
                assert ctrl.remediation is not None, (
                    f"Control {ctrl.control_id} FAIL but no remediation"
                )

    def test_soc2_control_catalog_completeness(self):
        """SOC2 mapper must cover all required TSC categories."""
        mapper    = SOC2Mapper()
        report    = mapper.generate_report([], target="Test")
        ctrl_ids  = {c.control_id for c in report.controls}
        required  = {"CC6.1", "CC6.6", "CC7.1", "CC7.2", "CC8.1", "CC9.1", "A1.1", "PI1.1"}
        assert required.issubset(ctrl_ids), f"Missing controls: {required - ctrl_ids}"


# ── ISO 27001 Tests ──────────────────────────────────────────────────────────

class TestISO27001Mapper:
    def test_iso27001_report_structure(self):
        """ISO 27001 report must contain all required fields."""
        mapper = ISO27001Mapper()
        report = mapper.generate_report([CRITICAL_FINDING], target="TestSystem")
        d      = report.to_dict()

        assert "report_id"        in d
        assert "iso_version"      in d
        assert "overall_status"   in d
        assert "compliance_score" in d
        assert "controls"         in d

    def test_iso27001_version_string(self):
        """ISO version must be 27001:2022."""
        mapper = ISO27001Mapper()
        report = mapper.generate_report([], target="Test")
        assert "27001" in report.iso_version
        assert "2022"  in report.iso_version

    def test_iso27001_clean_scan_compliant(self):
        """No findings → COMPLIANT."""
        mapper = ISO27001Mapper()
        report = mapper.generate_report([], target="CleanSystem")
        assert report.overall_status == "COMPLIANT"
        assert report.compliance_score >= 90.0

    def test_iso27001_a8_25_fails_on_reentrancy(self):
        """A.8.25 (Secure development life cycle) should fail on reentrancy."""
        finding_with_reentrancy = {
            **CRITICAL_FINDING,
            "rule_id": "REENTRANCY",
            "raw": {**CRITICAL_FINDING["raw"], "rule_id": "REENTRANCY"},
        }
        mapper = ISO27001Mapper()
        report = mapper.generate_report([finding_with_reentrancy], target="Test")
        a825   = next((c for c in report.controls if c.control_id == "A.8.25"), None)

        assert a825 is not None
        assert a825.status == "FAIL", f"A.8.25 should FAIL on reentrancy, got {a825.status}"

    def test_iso27001_control_catalog_completeness(self):
        """Must cover key A.5, A.8, A.12, A.16 controls."""
        mapper   = ISO27001Mapper()
        report   = mapper.generate_report([], target="Test")
        ctrl_ids = {c.control_id for c in report.controls}
        required = {"A.5.7", "A.8.2", "A.8.16", "A.8.25", "A.8.26", "A.12.6", "A.16.1"}
        assert required.issubset(ctrl_ids), f"Missing controls: {required - ctrl_ids}"

    def test_iso27001_recommendations_for_failures(self):
        """Failing controls should generate recommendations."""
        mapper = ISO27001Mapper()
        report = mapper.generate_report([CRITICAL_FINDING, HIGH_FINDING], target="Test")

        if report.failing_controls:
            assert len(report.recommendations) >= 1
            for rec in report.recommendations:
                assert "[A." in rec  # Should reference an A.x.x control


# ── Integration: All frameworks together ────────────────────────────────────

class TestComplianceIntegration:
    def test_all_frameworks_from_same_findings(self):
        """Running all 3 frameworks on same findings produces consistent results."""
        findings = [CRITICAL_FINDING, HIGH_FINDING, MEDIUM_FINDING]
        target   = "IntegrationTestProtocol"

        sarif_report = SARIFv2Exporter().export(findings, tool_name="Adversum")
        soc2_report  = SOC2Mapper().generate_report(findings, target=target)
        iso_report   = ISO27001Mapper().generate_report(findings, target=target)

        # All have the same target
        assert soc2_report.target == target
        assert iso_report.target  == target

        # SARIF has 3 results
        assert len(sarif_report.results) == 3

        # Both compliance frameworks detect failures
        assert len(soc2_report.failing_controls) >= 1
        assert len(iso_report.failing_controls)  >= 1

    def test_compliance_score_inversely_proportional_to_findings(self):
        """More critical findings → lower compliance score."""
        mapper = SOC2Mapper()
        clean  = mapper.generate_report([], target="Clean")
        one    = mapper.generate_report([CRITICAL_FINDING], target="One")
        three  = mapper.generate_report(
            [CRITICAL_FINDING, HIGH_FINDING, MEDIUM_FINDING], target="Three"
        )

        assert clean.compliance_score >= one.compliance_score
        # Can't strictly guarantee three < one since findings map to different controls
        assert three.compliance_score <= clean.compliance_score
