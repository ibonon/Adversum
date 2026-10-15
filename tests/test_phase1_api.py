"""
Test Suite: Phase 1 — FastAPI Endpoints (Live Fork, Self-Healing PR, Clean Remediation)
"""

import pytest
from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)
API_HEADERS = {"X-API-Key": "adv-dev-key-123"}


def test_api_live_fork_endpoint():
    payload = {
        "finding": {
            "id": "FINDING-001",
            "rule_id": "SOL-001",
            "file": "contracts/Vault.sol",
            "title": "Reentrancy in Vault.sol",
            "severity": "CRITICAL",
            "snippet": "msg.sender.call{value: amount}(''); balances[msg.sender] -= amount;"
        },
        "initial_vault_eth": 80.0,
        "network": "ethereum-mainnet-fork"
    }

    response = client.post("/api/v1/exploit/live-fork", json=payload, headers=API_HEADERS)
    assert response.status_code == 200
    data = response.json()

    assert data["rule_id"] == "SOL-001"
    assert data["status"] == "CONFIRMED_DRAINED"
    assert data["initial_vault_balance_eth"] == 80.0
    assert data["final_vault_balance_eth"] == 0.0
    assert data["attacker_profit_eth"] == 80.0
    assert data["tx_hash"].startswith("0x")
    assert data["empirical_badge"] == "PROVEN_ON_CHAIN_FORK_0_PERCENT_FP"
    assert len(data["traces"]) >= 3


def test_api_self_healing_pr_endpoint():
    payload = {
        "finding": {
            "id": "FINDING-002",
            "rule_id": "SOL-002",
            "file": "contracts/Treasury.sol",
            "severity": "CRITICAL",
            "cwe": "CWE-284",
            "description": "tx.origin used for authentication instead of msg.sender.",
            "snippet": "require(tx.origin == owner, 'Not authorized');"
        },
        "repo_url": "https://github.com/defi/treasury",
        "apply_to_disk": False
    }

    response = client.post("/api/v1/remediation/self-healing-pr", json=payload, headers=API_HEADERS)
    assert response.status_code == 200
    data = response.json()

    assert data["rule_id"] == "SOL-002"
    assert "eradicate SOL-002" in data["pr_title"]
    assert "msg.sender" in data["patched_code_snippet"]
    assert data["verification_status"] == "CONFIRMED_FIXED"
    assert "MATHEMATICALLY_PROVEN" in data["formal_proof_badge"]
    assert len(data["git_cli_commands"]) >= 3


def test_api_remediate_endpoint():
    payload = {
        "findings": [{
            "id": "FINDING-003",
            "file": "contracts/Vault.sol",
            "line": 42,
            "rule_id": "SOL-001",
            "snippet": "balances[msg.sender] -= amount;\nmsg.sender.call{value: amount}('');"
        }]
    }

    response = client.post("/api/v1/scan/remediate", json=payload, headers=API_HEADERS)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "diffs" in data
