"""
Test Suite: Phase 1 — Tri-Partite Self-Healing & GitHub Auto-PR
"""

import pytest
from orchestrator.services.self_healing import TriPartiteSelfHealingEngine, PullRequestPackage


def test_self_healing_pr_reentrancy():
    engine = TriPartiteSelfHealingEngine()
    finding = {
        "id": "FINDING-SOL-001",
        "rule_id": "SOL-001",
        "file": "contracts/Vault.sol",
        "line": 42,
        "severity": "CRITICAL",
        "cwe": "CWE-841",
        "description": "External call before state update allows recursive reentrancy drain.",
        "snippet": "balances[msg.sender] -= amount;\nmsg.sender.call{value: amount}('');"
    }

    pr_pkg: PullRequestPackage = engine.generate_verified_pr(
        finding=finding,
        repo_url="https://github.com/organization/digital-assets-vault",
        apply_to_disk=False
    )

    assert pr_pkg.rule_id == "SOL-001"
    assert "eradicate SOL-001" in pr_pkg.pr_title
    assert pr_pkg.branch_name.startswith("adversum/fix-sol001")
    assert pr_pkg.verification_status == "CONFIRMED_FIXED"
    assert "MATHEMATICALLY_PROVEN" in pr_pkg.formal_proof_badge
    assert len(pr_pkg.unified_diff) > 20
    assert "Checks-Effects-Interactions" in pr_pkg.pr_markdown_body
    assert len(pr_pkg.git_cli_commands) >= 4


def test_self_healing_pr_tx_origin():
    engine = TriPartiteSelfHealingEngine()
    finding = {
        "id": "FINDING-SOL-002",
        "rule_id": "SOL-002",
        "file": "contracts/Treasury.sol",
        "line": 10,
        "severity": "CRITICAL",
        "cwe": "CWE-284",
        "description": "tx.origin used for authentication instead of msg.sender.",
        "snippet": "require(tx.origin == owner, 'Not authorized');"
    }

    pr_pkg: PullRequestPackage = engine.generate_verified_pr(
        finding=finding
    )

    assert pr_pkg.rule_id == "SOL-002"
    assert "msg.sender" in pr_pkg.patched_code_snippet
    assert "tx.origin" not in pr_pkg.patched_code_snippet
    assert pr_pkg.verification_status == "CONFIRMED_FIXED"
