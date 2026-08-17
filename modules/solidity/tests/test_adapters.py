#!/usr/bin/env python3
"""
Unit and Integration Tests for Slither and Aderyn Adapters
"""
import unittest
import json
import os
import sys

# Ensure modules directory is on sys.path
MODULES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if MODULES_DIR not in sys.path:
    sys.path.insert(0, MODULES_DIR)

from solidity.adapters.slither_adapter import SlitherAdapter, SLITHER_DETECTOR_MAP
from solidity.adapters.aderyn_adapter import AderynAdapter, ADERYN_DETECTOR_MAP
from solidity.adapters.orchestrator import MultiEngineOrchestrator
from solidity.scanner import SolFinding
from poc_generator.generator import FoundryPoCGenerator

SAMPLE_SLITHER_JSON = json.dumps({
    "success": True,
    "error": None,
    "results": {
        "detectors": [
            {
                "check": "reentrancy-eth",
                "impact": "High",
                "confidence": "High",
                "description": "VulnerableVault.withdraw(uint256) sends eth to msg.sender before balances are updated.",
                "elements": [
                    {
                        "type": "function",
                        "name": "withdraw",
                        "source_mapping": {
                            "filename_relative": "contracts/VulnerableVault.sol",
                            "filename_absolute": "/path/contracts/VulnerableVault.sol",
                            "lines": [42, 43, 44]
                        }
                    }
                ]
            },
            {
                "check": "tx-origin",
                "impact": "Medium",
                "confidence": "High",
                "description": "VulnerableVault.transferOwnership(address) uses tx.origin for authorization.",
                "elements": [
                    {
                        "type": "function",
                        "name": "transferOwnership",
                        "source_mapping": {
                            "filename_relative": "contracts/VulnerableVault.sol",
                            "lines": [88]
                        }
                    }
                ]
            },
            {
                "check": "suicidal",
                "impact": "High",
                "confidence": "High",
                "description": "VulnerableVault.kill() allows arbitrary caller to destroy contract.",
                "elements": [
                    {
                        "type": "function",
                        "name": "kill",
                        "source_mapping": {
                            "filename_relative": "contracts/VulnerableVault.sol",
                            "lines": [120]
                        }
                    }
                ]
            }
        ]
    }
})

SAMPLE_ADERYN_JSON = json.dumps({
    "files_summary": {"total_source_units": 1},
    "critical_issues": {
        "issues": [
            {
                "detector_name": "reentrancy-vulnerabilities",
                "title": "State change after external call without reentrancy guard",
                "description": "Functions calling external contracts before state updates allow recursive draining.",
                "instances": [
                    {
                        "contract_path": "contracts/VulnerableVault.sol",
                        "line_no": 42,
                        "src": "msg.sender.call{value: amount}(\"\")"
                    }
                ]
            }
        ]
    },
    "high_issues": {
        "issues": [
            {
                "detector_name": "unsafe-erc20-operations",
                "title": "Unsafe ERC20 transfer return value ignored",
                "description": "Calling transfer without checking return value.",
                "instances": [
                    {
                        "contract_path": "contracts/TokenBridge.sol",
                        "line_no": 75,
                        "src": "IERC20(token).transfer(recipient, amount);"
                    }
                ]
            }
        ]
    }
})


class TestSolidityAdapters(unittest.TestCase):
    def setUp(self):
        self.slither_adapter = SlitherAdapter()
        self.aderyn_adapter = AderynAdapter()
        self.orchestrator = MultiEngineOrchestrator(enable_native=True, enable_slither=True, enable_aderyn=True)

    def test_slither_json_parsing(self):
        findings = self.slither_adapter.parse_json_output(SAMPLE_SLITHER_JSON, "contracts/VulnerableVault.sol")
        self.assertEqual(len(findings), 3)

        # 1. Reentrancy
        reentrancy = next(f for f in findings if "REENTRANCY" in f.rule_id)
        self.assertEqual(reentrancy.severity, "CRITICAL")
        self.assertEqual(reentrancy.cwe, "CWE-841")
        self.assertEqual(reentrancy.swc, "SWC-107")
        self.assertEqual(reentrancy.line, 42)
        self.assertEqual(reentrancy.cvss_score, 9.8)

        # 2. tx.origin
        tx_origin = next(f for f in findings if "TX_ORIGIN" in f.rule_id)
        self.assertEqual(tx_origin.severity, "HIGH")
        self.assertEqual(tx_origin.cwe, "CWE-284")
        self.assertEqual(tx_origin.line, 88)

        # 3. suicidal
        suicidal = next(f for f in findings if "SUICIDAL" in f.rule_id)
        self.assertEqual(suicidal.severity, "CRITICAL")
        self.assertEqual(suicidal.cwe, "CWE-284")
        self.assertEqual(suicidal.line, 120)

    def test_aderyn_json_parsing(self):
        findings = self.aderyn_adapter.parse_json_output(SAMPLE_ADERYN_JSON, "contracts/VulnerableVault.sol")
        self.assertEqual(len(findings), 2)

        reentrancy = next(f for f in findings if "REENTRANCY" in f.rule_id)
        self.assertEqual(reentrancy.severity, "CRITICAL")
        self.assertEqual(reentrancy.cwe, "CWE-841")
        self.assertEqual(reentrancy.line, 42)

        erc20 = next(f for f in findings if "UNSAFE_ERC20" in f.rule_id)
        self.assertEqual(erc20.severity, "HIGH")
        self.assertEqual(erc20.file, "contracts/TokenBridge.sol")
        self.assertEqual(erc20.line, 75)

    def test_orchestrator_deduplication(self):
        # Native finding on Line 42
        native_finding = SolFinding(
            rule_id="SOL-001",
            severity="CRITICAL",
            cwe="CWE-841",
            swc="SWC-107",
            title="Reentrancy Vulnerability",
            description="External call before state change.",
            file="contracts/VulnerableVault.sol",
            line=42,
            snippet="msg.sender.call{value: amount}('');",
            recommendation="Apply CEI pattern.",
            cvss_score=9.8
        )

        # Slither finding on Line 42
        slither_findings = self.slither_adapter.parse_json_output(SAMPLE_SLITHER_JSON, "contracts/VulnerableVault.sol")

        # Aderyn finding on Line 42
        aderyn_findings = self.aderyn_adapter.parse_json_output(SAMPLE_ADERYN_JSON, "contracts/VulnerableVault.sol")

        all_findings = [native_finding] + slither_findings + aderyn_findings
        
        # Deduplicate
        deduped = self.orchestrator.deduplicate(all_findings)

        # Reentrancy on Line 42 should be merged into 1 finding with corroborated description
        line_42_findings = [f for f in deduped if f.file == "contracts/VulnerableVault.sol" and f.line == 42]
        self.assertEqual(len(line_42_findings), 1)
        self.assertIn("Corroborated by", line_42_findings[0].description)

    def test_foundry_poc_generation_from_slither_findings(self):
        poc_gen = FoundryPoCGenerator()
        findings = self.slither_adapter.parse_json_output(SAMPLE_SLITHER_JSON, "contracts/VulnerableVault.sol")
        reentrancy = next(f for f in findings if "REENTRANCY" in f.rule_id)

        # Convert SolFinding to dict format expected by poc generator
        finding_dict = {
            "rule_id": reentrancy.rule_id,
            "title": reentrancy.title,
            "severity": reentrancy.severity,
            "cwe": reentrancy.cwe,
            "file": reentrancy.file,
            "line": reentrancy.line,
            "module": "solidity"
        }

        poc_code = poc_gen.generate_poc(finding_dict)
        self.assertIsNotNone(poc_code)
        self.assertIn("contract ReentrancyAttacker", poc_code)
        self.assertIn("forge-std/Test.sol", poc_code)


if __name__ == "__main__":
    unittest.main()
