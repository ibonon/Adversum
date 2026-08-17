#!/usr/bin/env python3
"""
Unit and Integration Tests for Adversum Intelligence Engine
"""
import unittest
import os
import sys

# Ensure modules directory is on sys.path
MODULES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if MODULES_DIR not in sys.path:
    sys.path.insert(0, MODULES_DIR)

from intelligence.exploit_chaining import ExploitChainer, AttackChain
from intelligence.invariant_miner import InvariantMiner, InvariantHarness
from intelligence.role_economic_flow import RoleEconomicFlowAnalyzer
from intelligence.smart_patch_validator import SmartPatchValidator

SAMPLE_VAULT_SOLIDITY = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract LiquidityVault {
    address public owner;
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    uint256 public feeRate;

    constructor() {
        owner = msg.sender;
        feeRate = 50; // 0.5%
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        totalSupply += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount;
    }

    function transferOwnership(address newOwner) external {
        require(tx.origin == owner, "Not owner");
        owner = newOwner;
    }
}
"""


class TestIntelligenceEngine(unittest.TestCase):
    def setUp(self):
        self.chainer = ExploitChainer()
        self.miner = InvariantMiner()
        self.flow_analyzer = RoleEconomicFlowAnalyzer()
        self.patch_validator = SmartPatchValidator()

    def test_exploit_chainer(self):
        """Tests synthesis of multi-step attack chains and Mermaid diagrams."""
        sample_findings = [
            {
                "rule_id": "SOL-001",
                "severity": "CRITICAL",
                "cwe": "CWE-841",
                "title": "Reentrancy Attack",
                "file": "contracts/Vault.sol",
                "line": 24,
                "snippet": "msg.sender.call{value: amount}('')"
            },
            {
                "rule_id": "SOL-009",
                "severity": "HIGH",
                "cwe": "CWE-682",
                "title": "Spot Price Oracle Manipulation",
                "file": "contracts/Oracle.sol",
                "line": 15,
                "snippet": "getReserves()"
            },
            {
                "rule_id": "SOL-002",
                "severity": "CRITICAL",
                "cwe": "CWE-284",
                "title": "tx.origin Used for Authorization",
                "file": "contracts/Vault.sol",
                "line": 30,
                "snippet": "require(tx.origin == owner)"
            }
        ]

        chains = self.chainer.synthesize_chains(sample_findings)
        self.assertGreater(len(chains), 0)

        # Verify Flash loan + Reentrancy chain
        reentrancy_chain = next((c for c in chains if "Reentrancy" in c.title), None)
        self.assertIsNotNone(reentrancy_chain)
        self.assertEqual(reentrancy_chain.composite_severity, "CRITICAL")
        self.assertIn("graph", reentrancy_chain.mermaid_diagram)
        self.assertGreater(len(reentrancy_chain.steps), 0)

        # Verify Phishing to Ownership chain
        phishing_chain = next((c for c in chains if "Phishing" in c.title), None)
        self.assertIsNotNone(phishing_chain)
        self.assertEqual(phishing_chain.chain_id, "CHAIN-002")

    def test_invariant_miner_and_foundry_suite(self):
        """Tests automatic discovery of invariants and generation of Foundry Invariant Fuzzing suite."""
        harness = self.miner.generate_foundry_suite(SAMPLE_VAULT_SOLIDITY, "LiquidityVault")
        
        self.assertEqual(harness.contract_name, "LiquidityVault")
        self.assertGreater(len(harness.invariants), 0)

        # Verify invariant types mined
        inv_ids = [inv.invariant_id for inv in harness.invariants]
        self.assertIn("INV-001", inv_ids) # Conservation
        self.assertIn("INV-003", inv_ids) # Owner integrity

        # Verify Foundry test code structure
        self.assertIn("contract LiquidityVaultInvariantTest is Test", harness.test_sol_code)
        self.assertIn("targetContract(address(handler));", harness.test_sol_code)
        self.assertIn("contract LiquidityVaultHandler", harness.handler_sol_code)
        self.assertIn("ghost_totalDeposits", harness.handler_sol_code)

    def test_role_economic_flow_analysis(self):
        """Tests role privilege mapping and economic flow asymmetry detection."""
        report = self.flow_analyzer.analyze(SAMPLE_VAULT_SOLIDITY, "LiquidityVault")

        self.assertEqual(report.target_name, "LiquidityVault")
        self.assertGreater(len(report.roles), 0)
        self.assertGreater(len(report.flows), 0)

        # Reentrancy on line 24 makes withdraw() an asymmetric leak
        self.assertTrue(report.has_economic_asymmetry)
        self.assertIn("CRITICAL ECONOMIC ASYMMETRY DETECTED", report.asymmetry_summary)
        self.assertIn("graph TD", report.mermaid_flowchart)

    def test_smart_patch_validator(self):
        """Tests AST patch synthesis and SMT verification of vulnerability elimination."""
        finding = {
            "rule_id": "SOL-002",
            "file": "contracts/LiquidityVault.sol",
            "line": 30,
            "snippet": "require(tx.origin == owner, 'Not owner');",
            "module": "solidity"
        }

        patch = self.patch_validator.generate_and_verify_patch(finding, SAMPLE_VAULT_SOLIDITY)
        self.assertIsNotNone(patch)
        self.assertTrue(patch.syntax_valid)
        self.assertTrue(patch.vulnerability_eliminated)
        self.assertTrue(patch.is_smt_verified)
        self.assertIn("SMT FORMAL PROOF", patch.verification_proof)
        self.assertIn("msg.sender", patch.diff)


if __name__ == "__main__":
    unittest.main()
