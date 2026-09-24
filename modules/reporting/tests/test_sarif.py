import os
import sys
import unittest
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from reporting.sarif_exporter import SarifExporter

class TestSarifExporter(unittest.TestCase):
    def setUp(self):
        self.exporter = SarifExporter()

    def test_sarif_schema_and_version(self):
        findings = [
            {
                "rule_id": "SOL-001",
                "title": "Reentrancy Vulnerability",
                "description": "External call before state update",
                "severity": "CRITICAL",
                "file": "contracts/Vault.sol",
                "line": 42,
                "snippet": "msg.sender.call{value: amount}('');",
                "module": "solidity",
                "consensus_score": 0.99,
                "confidence_level": "VERY HIGH (Quorum 3+ Engines)",
                "engines_confirmed": ["native", "semgrep", "slither"],
                "cwe": {"cwe_id": "CWE-841", "name": "Improper Enforcement of Behavioral Workflow", "url": "https://cwe.mitre.org/data/definitions/841.html"},
                "owasp": "SC01:2026-Reentrancy & State Machine Flaws",
                "fix_code": "balances[msg.sender] -= amount;\nmsg.sender.call{value: amount}('');"
            }
        ]
        scorecard = {
            "security_score": 75,
            "security_grade": "A",
            "posture_status": "SECURE",
            "total_findings": 1,
            "multi_engine_quorums": 1,
            "ccss_ready": False
        }
        sarif = self.exporter.export(findings, base_path="/", executive_scorecard=scorecard)

        self.assertEqual(sarif["version"], "2.1.0")
        self.assertIn("https://raw.githubusercontent.com", sarif["$schema"])
        runs = sarif["runs"]
        self.assertEqual(len(runs), 1)

        run = runs[0]
        self.assertEqual(run["tool"]["driver"]["name"], "Adversum Security Intelligence")
        self.assertEqual(len(run["results"]), 1)

        result = run["results"][0]
        self.assertEqual(result["ruleId"], "SOL-001")
        self.assertEqual(result["level"], "error")
        self.assertIn("fixes", result)
        self.assertEqual(len(result["fixes"]), 1)

        props = result["properties"]
        self.assertEqual(props["consensusScore"], 0.99)
        self.assertEqual(props["cwe"], "CWE-841")

        run_props = run["properties"]
        self.assertEqual(run_props["adversumScore"], 75)
        self.assertEqual(run_props["adversumGrade"], "A")

if __name__ == "__main__":
    unittest.main()
