"""
Test Suite: Phase 1 — Live Fork Exploit & Proof of Exploit (PoE)
"""

import pytest
from modules.live_fork.engine import LiveForkEngine, ProofOfExploit


def test_live_fork_reentrancy_exploit():
    engine = LiveForkEngine()
    finding = {
        "id": "FINDING-SOL-001",
        "rule_id": "SOL-001",
        "title": "Reentrancy Vulnerability in Vault.sol",
        "file": "contracts/Vault.sol",
        "line": 42,
        "severity": "CRITICAL",
        "snippet": "msg.sender.call{value: amount}(''); balances[msg.sender] -= amount;"
    }

    proof: ProofOfExploit = engine.execute_live_exploit(
        finding=finding,
        initial_vault_eth=50.0,
        network="ethereum-mainnet-fork"
    )

    assert proof.rule_id == "SOL-001"
    assert proof.status == "CONFIRMED_DRAINED"
    assert proof.initial_vault_balance_eth == 50.0
    assert proof.final_vault_balance_eth == 0.0
    assert proof.attacker_profit_eth == 50.0
    assert proof.attacker_profit_usd == 50.0 * 2650.0
    assert proof.tx_hash.startswith("0x")
    assert proof.state_root_after.startswith("0x")
    assert proof.empirical_badge == "PROVEN_ON_CHAIN_FORK_0_PERCENT_FP"
    assert len(proof.traces) >= 4

    # Verify call trace contains reentrancy frames
    trace_types = [t["call_type"] for t in proof.traces]
    assert any("REENTER" in t for t in trace_types)
    assert any(t["status"] == "DRAINED_TO_ATTACKER" for t in proof.traces)


def test_live_fork_phishing_tx_origin():
    engine = LiveForkEngine()
    finding = {
        "id": "FINDING-SOL-002",
        "rule_id": "SOL-002",
        "title": "tx.origin Phishing Authorization Bypass",
        "file": "contracts/Wallet.sol",
        "line": 15,
        "severity": "CRITICAL",
        "snippet": "require(tx.origin == owner);"
    }

    proof: ProofOfExploit = engine.execute_live_exploit(
        finding=finding,
        initial_vault_eth=120.0
    )

    assert proof.rule_id == "SOL-002"
    assert proof.status == "CONFIRMED_DRAINED"
    assert proof.attacker_profit_eth == 120.0
    assert len(proof.traces) >= 3
    assert any(t["status"] == "AUTH_BYPASSED_TX_ORIGIN" for t in proof.traces)
