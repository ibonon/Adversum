"""
Phase 3 Tests — PoC Generator integration with Attack Simulator
"""
import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("NEBIUS_MOCK", "1")

from modules.poc_generator.generator import FoundryPoCGenerator
from modules.attack_simulator.scenarios import SCENARIO_REGISTRY
from modules.attack_simulator.chain_executor import AttackPrimitive


def step_to_finding(step, idx=0):
    """Convert an AttackStep to a finding dict compatible with PoC generator."""
    primitive_to_rule = {
        AttackPrimitive.FLASH_LOAN:      "FLASH_LOAN_CALLBACK",
        AttackPrimitive.ORACLE_MANIP:    "ORACLE_MANIPULATION",
        AttackPrimitive.LIQUIDATION:     "REENTRANCY",
        AttackPrimitive.BRIDGE_DRAIN:    "CROSS_CHAIN_VULN",
        AttackPrimitive.DONATE_ATTACK:   "SOL-001",
        AttackPrimitive.UNBACKED_MINT:   "SOL-001",
        AttackPrimitive.GOVERNANCE_VOTE: "ACCESS_CONTROL",
        AttackPrimitive.PRICE_PUMP:      "ORACLE_MANIPULATION",
        AttackPrimitive.REPAY_FLASH:     "FLASH_LOAN_CALLBACK",
    }
    return {
        "rule_id":    primitive_to_rule.get(step.primitive, "CUSTOM"),
        "severity":   "CRITICAL",
        "cwe":        "CWE-682",
        "title":      step.description[:60],
        "file":       f"{step.protocol.replace(' ', '_')}.sol",
        "line":       idx * 10 + 1,
        "snippet":    f"// {step.protocol} step",
        "recommendation": "Apply security controls",
    }


class TestPoCIntegration:
    def test_poc_generator_imports(self):
        gen = FoundryPoCGenerator()
        assert gen is not None

    def test_euler_steps_generate_pocs(self):
        gen = FoundryPoCGenerator()
        chain = SCENARIO_REGISTRY["euler_finance"]()
        pocs = []
        for idx, step in enumerate(chain.steps):
            finding = step_to_finding(step, idx)
            poc = gen.generate_poc(finding)
            if poc:
                pocs.append(poc)
        assert len(pocs) > 0

    def test_ronin_bridge_drain_generates_poc(self):
        gen = FoundryPoCGenerator()
        chain = SCENARIO_REGISTRY["ronin_bridge"]()
        drain_steps = [s for s in chain.steps if s.primitive == AttackPrimitive.BRIDGE_DRAIN]
        assert len(drain_steps) > 0
        for step in drain_steps:
            poc = gen.generate_poc(step_to_finding(step))
            assert poc is not None
            assert "pragma solidity" in poc

    def test_reentrancy_poc_contains_attacker_contract(self):
        gen = FoundryPoCGenerator()
        finding = {"rule_id": "REENTRANCY", "severity": "CRITICAL", "cwe": "CWE-841",
                   "title": "Reentrancy", "file": "Vault.sol", "line": 1, "snippet": "", "recommendation": ""}
        poc = gen.generate_poc(finding)
        assert "ReentrancyAttacker" in poc

    def test_oracle_manip_poc_contains_mock_pair(self):
        gen = FoundryPoCGenerator()
        finding = {"rule_id": "ORACLE_MANIPULATION", "severity": "CRITICAL", "cwe": "CWE-682",
                   "title": "Oracle manip", "file": "Oracle.sol", "line": 1, "snippet": "", "recommendation": ""}
        poc = gen.generate_poc(finding)
        assert "MockUniswapV2Pair" in poc

    def test_flash_loan_callback_poc(self):
        gen = FoundryPoCGenerator()
        finding = {"rule_id": "FLASH_LOAN_CALLBACK", "severity": "CRITICAL", "cwe": "",
                   "title": "Flash loan", "file": "Pool.sol", "line": 1, "snippet": "", "recommendation": ""}
        poc = gen.generate_poc(finding)
        assert "executeOperation" in poc

    def test_export_pocs_for_euler_chain(self, tmp_path):
        gen = FoundryPoCGenerator()
        chain = SCENARIO_REGISTRY["euler_finance"]()
        findings = [step_to_finding(s, i) for i, s in enumerate(chain.steps)]
        files = gen.export_pocs_for_findings(findings, output_dir=str(tmp_path))
        assert len(files) > 0
        for f in files:
            assert os.path.exists(f)
            with open(f) as fh:
                content = fh.read()
            assert "pragma solidity" in content

    def test_all_scenarios_produce_at_least_one_poc(self):
        gen = FoundryPoCGenerator()
        for sid, fn in SCENARIO_REGISTRY.items():
            chain = fn()
            findings = [step_to_finding(s, i) for i, s in enumerate(chain.steps)]
            pocs = [gen.generate_poc(f) for f in findings]
            pocs = [p for p in pocs if p]
            assert len(pocs) > 0, f"No PoC generated for scenario {sid}"
