#!/usr/bin/env python3
"""
Unit and Integration Tests for Trivy Runner (SCA, Dependency CVEs, IaC & Secrets)
"""
import unittest
import json
import os
import sys

# Ensure modules directory is on sys.path
MODULES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if MODULES_DIR not in sys.path:
    sys.path.insert(0, MODULES_DIR)

from trivy_runner.scanner import TrivyScanner, TrivyFinding

SAMPLE_TRIVY_JSON = json.dumps({
    "SchemaVersion": 2,
    "ArtifactName": "test-repo",
    "ArtifactType": "filesystem",
    "Results": [
        {
            "Target": "package-lock.json",
            "Class": "lang-pkgs",
            "Type": "npm",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-45853",
                    "PkgName": "zlib",
                    "InstalledVersion": "1.2.11",
                    "FixedVersion": "1.3.0",
                    "Status": "fixed",
                    "Severity": "CRITICAL",
                    "Title": "zlib: integer overflow and resultant buffer overflow in zipOpenNewFileInZip4_64",
                    "Description": "MiniZip in zlib through 1.3 has an integer overflow and resultant buffer overflow in zipOpenNewFileInZip4_64.",
                    "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-45853",
                    "CweIDs": ["CWE-190", "CWE-122"],
                    "CVSS": {
                        "nvd": {
                            "V3Score": 9.8,
                            "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                        }
                    }
                },
                {
                    "VulnerabilityID": "CVE-2024-21501",
                    "PkgName": "axios",
                    "InstalledVersion": "0.21.1",
                    "FixedVersion": "1.6.0",
                    "Status": "fixed",
                    "Severity": "HIGH",
                    "Title": "axios: Cross-Site Request Forgery (CSRF) via unauthorized header forwarding",
                    "Description": "Axios before 1.6.0 improperly forwards headers on redirect.",
                    "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-21501",
                    "CweIDs": ["CWE-352"],
                    "CVSS": {
                        "nvd": {
                            "V3Score": 7.5
                        }
                    }
                }
            ]
        },
        {
            "Target": "Dockerfile",
            "Class": "config",
            "Type": "dockerfile",
            "Misconfigurations": [
                {
                    "Type": "Dockerfile Security Check",
                    "ID": "DS002",
                    "Title": "Image user should not be 'root'",
                    "Description": "Running containers with 'root' privileges increases attack surface.",
                    "Message": "Specify at least one non-root USER instruction.",
                    "Resolution": "Add 'USER appuser' or specify a non-root UID in Dockerfile.",
                    "Severity": "HIGH",
                    "PrimaryURL": "https://avd.aquasec.com/misconfig/ds002",
                    "Status": "FAIL",
                    "Lines": [{"Number": 1}]
                }
            ]
        },
        {
            "Target": "config/aws.env",
            "Class": "secret",
            "Secrets": [
                {
                    "RuleID": "aws-secret-access-key",
                    "Category": "AWS",
                    "Severity": "CRITICAL",
                    "Title": "AWS Secret Access Key",
                    "StartLine": 5,
                    "EndLine": 5,
                    "Match": "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                }
            ]
        }
    ]
})


class TestTrivyRunner(unittest.TestCase):
    def setUp(self):
        self.scanner = TrivyScanner()

    def test_json_parsing_vulnerabilities(self):
        """Tests parsing of SCA / CVE package vulnerabilities from Trivy JSON."""
        findings = self.scanner.parse_json_output(SAMPLE_TRIVY_JSON, "test_repo")
        
        # Filter for package vulnerabilities
        cve_findings = [f for f in findings if f.rule_id.startswith("TRIVY-CVE-")]
        self.assertEqual(len(cve_findings), 2)

        # 1. zlib CRITICAL CVE
        zlib_cve = next(f for f in cve_findings if "CVE-2023-45853" in f.rule_id)
        self.assertEqual(zlib_cve.severity, "CRITICAL")
        self.assertEqual(zlib_cve.cwe, "CWE-190")
        self.assertEqual(zlib_cve.pkg_name, "zlib")
        self.assertEqual(zlib_cve.installed_version, "1.2.11")
        self.assertEqual(zlib_cve.fixed_version, "1.3.0")
        self.assertEqual(zlib_cve.cvss_score, 9.8)
        self.assertEqual(zlib_cve.file, "package-lock.json")
        self.assertIn("Upgrade zlib to version 1.3.0", zlib_cve.recommendation)
        self.assertEqual(zlib_cve.module, "trivy")

        # 2. axios HIGH CVE
        axios_cve = next(f for f in cve_findings if "CVE-2024-21501" in f.rule_id)
        self.assertEqual(axios_cve.severity, "HIGH")
        self.assertEqual(axios_cve.cwe, "CWE-352")
        self.assertEqual(axios_cve.pkg_name, "axios")
        self.assertEqual(axios_cve.installed_version, "0.21.1")
        self.assertEqual(axios_cve.fixed_version, "1.6.0")
        self.assertEqual(axios_cve.cvss_score, 7.5)

    def test_json_parsing_misconfigurations(self):
        """Tests parsing of IaC misconfigurations (Dockerfile root check)."""
        findings = self.scanner.parse_json_output(SAMPLE_TRIVY_JSON, "test_repo")
        
        iac_findings = [f for f in findings if f.rule_id.startswith("TRIVY-IAC-")]
        self.assertEqual(len(iac_findings), 1)

        root_misc = iac_findings[0]
        self.assertEqual(root_misc.rule_id, "TRIVY-IAC-DS002")
        self.assertEqual(root_misc.severity, "HIGH")
        self.assertEqual(root_misc.file, "Dockerfile")
        self.assertEqual(root_misc.line, 1)
        self.assertIn("USER appuser", root_misc.recommendation)

    def test_json_parsing_secrets(self):
        """Tests parsing of leaked secrets detected by Trivy."""
        findings = self.scanner.parse_json_output(SAMPLE_TRIVY_JSON, "test_repo")
        
        secret_findings = [f for f in findings if f.rule_id.startswith("TRIVY-SECRET-")]
        self.assertEqual(len(secret_findings), 1)

        aws_sec = secret_findings[0]
        self.assertEqual(aws_sec.severity, "CRITICAL")
        self.assertEqual(aws_sec.cwe, "CWE-798")
        self.assertEqual(aws_sec.file, "config/aws.env")
        self.assertEqual(aws_sec.line, 5)
        self.assertIn("revoke and rotate", aws_sec.recommendation.lower())


if __name__ == "__main__":
    unittest.main()
