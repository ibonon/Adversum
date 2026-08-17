#!/usr/bin/env python3
"""
Unit and Integration Tests for Semgrep Runner & Institutional Rules
"""
import unittest
import json
import os
import sys
import yaml

# Ensure modules directory is on sys.path
MODULES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if MODULES_DIR not in sys.path:
    sys.path.insert(0, MODULES_DIR)

from semgrep_runner.scanner import SemgrepScanner, SemgrepFinding

SAMPLE_SEMGREP_JSON = json.dumps({
    "version": "1.60.0",
    "results": [
        {
            "check_id": "institutional.cex-unatomic-balance-deduction",
            "path": "trading/order_book.py",
            "start": {"line": 42, "col": 5},
            "end": {"line": 42, "col": 45},
            "extra": {
                "message": "User balance is deducted without atomic CAS operation or database row locking.",
                "severity": "ERROR",
                "lines": "user.balance = user.balance - amount",
                "metadata": {
                    "cwe": "CWE-362",
                    "cvss": 9.8,
                    "rule_id": "SEMGREP-CEX-001",
                    "title": "Unatomic Balance Deduction / Race Condition",
                    "recommendation": "Use database row-level locking (SELECT FOR UPDATE)."
                }
            }
        },
        {
            "check_id": "institutional.crypto-jwt-none-algorithm",
            "path": "auth/token.js",
            "start": {"line": 88, "col": 12},
            "end": {"line": 88, "col": 60},
            "extra": {
                "message": "JWT configured with algorithm none allows token forgery.",
                "severity": "ERROR",
                "lines": "jwt.verify(token, {algorithms: ['none']})",
                "metadata": {
                    "cwe": ["CWE-347"],
                    "cvss": 9.8,
                    "rule_id": "SEMGREP-CRYPTO-002",
                    "title": "JWT Algorithm None Token Forgery",
                    "recommendation": "Reject the none algorithm explicitly."
                }
            }
        },
        {
            "check_id": "institutional.web-ssrf-unvalidated-url",
            "path": "services/webhook.py",
            "start": {"line": 115, "col": 1},
            "end": {"line": 115, "col": 40},
            "extra": {
                "message": "HTTP request to user-supplied URL can lead to SSRF.",
                "severity": "WARNING",
                "lines": "requests.get(request.args.get('url'))",
                "metadata": {
                    "cwe": "CWE-918",
                    "cvss": 8.6,
                    "rule_id": "SEMGREP-WEB-003",
                    "title": "Server-Side Request Forgery (SSRF)",
                    "recommendation": "Validate requested URLs against an allowlist."
                }
            }
        }
    ],
    "errors": []
})


class TestSemgrepRunner(unittest.TestCase):
    def setUp(self):
        self.scanner = SemgrepScanner()
        self.rules_dir = os.path.join(MODULES_DIR, "semgrep_runner", "rules", "institutional")

    def test_institutional_yaml_rules_syntax(self):
        """Validates syntax and schema for all institutional Semgrep YAML rules."""
        yaml_files = [
            "cex_trading.yaml",
            "crypto_security.yaml",
            "web_api_security.yaml",
            "smart_contracts.yaml"
        ]

        for fname in yaml_files:
            fpath = os.path.join(self.rules_dir, fname)
            self.assertTrue(os.path.exists(fpath), f"Missing rules file: {fpath}")
            
            with open(fpath, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            self.assertIn("rules", data, f"No 'rules' key in {fname}")
            rules = data["rules"]
            self.assertGreater(len(rules), 0, f"Empty rules list in {fname}")

            for r in rules:
                self.assertIn("id", r)
                self.assertIn("languages", r)
                self.assertIn("severity", r)
                self.assertIn("message", r)
                self.assertIn("metadata", r)
                self.assertIn("cwe", r["metadata"])
                self.assertIn("cvss", r["metadata"])
                self.assertIn("rule_id", r["metadata"])
                self.assertIn("recommendation", r["metadata"])

    def test_json_parsing(self):
        """Tests parsing of Semgrep JSON output into normalized SemgrepFinding objects."""
        findings = self.scanner.parse_json_output(SAMPLE_SEMGREP_JSON, "test_target")
        self.assertEqual(len(findings), 3)

        # 1. CEX Race condition
        f1 = next(f for f in findings if f.rule_id == "SEMGREP-CEX-001")
        self.assertEqual(f1.severity, "CRITICAL")
        self.assertEqual(f1.cwe, "CWE-362")
        self.assertEqual(f1.file, "trading/order_book.py")
        self.assertEqual(f1.line, 42)
        self.assertEqual(f1.cvss_score, 9.8)
        self.assertEqual(f1.module, "semgrep")
        self.assertIn("balance", f1.snippet)

        # 2. JWT none alg
        f2 = next(f for f in findings if f.rule_id == "SEMGREP-CRYPTO-002")
        self.assertEqual(f2.severity, "CRITICAL")
        self.assertEqual(f2.cwe, "CWE-347")
        self.assertEqual(f2.file, "auth/token.js")
        self.assertEqual(f2.line, 88)

        # 3. SSRF
        f3 = next(f for f in findings if f.rule_id == "SEMGREP-WEB-003")
        self.assertEqual(f3.severity, "MEDIUM")
        self.assertEqual(f3.cwe, "CWE-918")
        self.assertEqual(f3.file, "services/webhook.py")
        self.assertEqual(f3.line, 115)


if __name__ == "__main__":
    unittest.main()
