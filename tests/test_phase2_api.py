"""
Phase 2 Tests — API Endpoints (MEV, Threat Model, Compliance, Threat Stream)
pytest tests/test_phase2_api.py
"""

import json
import pytest
from fastapi.testclient import TestClient

import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

os.environ.setdefault("API_KEY", "adv-dev-key-123")
os.environ.setdefault("NEBIUS_MOCK", "1")

from api.main import app

client = TestClient(app, headers={"X-API-Key": "adv-dev-key-123"})

SAMPLE_FINDING = {
    "rule_id": "SOL-001",
    "severity": "CRITICAL",
    "description": "Reentrancy vulnerability in withdraw()",
    "file_path": "contracts/Vault.sol",
    "line_number": 42,
    "raw": {
        "rule_id": "SOL-001",
        "severity": "CRITICAL",
        "file_path": "contracts/Vault.sol",
        "line_number": 42,
    }
}

SANDWICH_TXS = [
    {"tx_hash": "0x" + "a" * 64, "from_address": "0x" + "dead" * 10, "to_address": "0x" + "1234" * 10,
     "value_wei": 50_000_000_000_000_000_000, "gas_price": 200_000_000_000, "input_data": "0xd0e30db0"},
    {"tx_hash": "0x" + "b" * 64, "from_address": "0x" + "cafe" * 10, "to_address": "0x" + "1234" * 10,
     "value_wei": 10_000_000_000_000_000_000, "gas_price": 50_000_000_000,  "input_data": "0xd0e30db0"},
    {"tx_hash": "0x" + "c" * 64, "from_address": "0x" + "dead" * 10, "to_address": "0x" + "1234" * 10,
     "value_wei": 49_000_000_000_000_000_000, "gas_price": 30_000_000_000,  "input_data": "0xd0e30db0"},
]


# ── Threat Stream History ────────────────────────────────────────────────────

def test_threat_stream_history_endpoint():
    """GET /api/v1/threat-stream/history returns event list and stats."""
    resp = client.get("/api/v1/threat-stream/history?limit=10")
    assert resp.status_code == 200
    data = resp.json()
    assert "events" in data
    assert "stats"  in data
    assert isinstance(data["events"], list)


def test_threat_stream_stats_endpoint():
    """GET /api/v1/threat-stream/stats returns stats dict."""
    resp = client.get("/api/v1/threat-stream/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "published"          in data
    assert "active_subscribers" in data
    assert "dropped"            in data


# ── MEV Intelligence ────────────────────────────────────────────────────────

def test_mev_analyze_endpoint_sandwich():
    """POST /api/v1/intelligence/mev-analyze detects sandwich attack."""
    payload = {
        "transactions":      SANDWICH_TXS,
        "chain":             "ethereum",
        "pool_liquidity_eth": 1000.0,
        "eth_price_usd":     2650.0,
    }
    resp = client.post("/api/v1/intelligence/mev-analyze", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    assert "analysis_id"              in data
    assert "patterns_found"           in data
    assert "total_value_at_risk_usd"  in data
    assert "tx_count"                 in data
    assert data["tx_count"] == 3

    # Should detect sandwich pattern
    sandwiches = [p for p in data["patterns_found"] if p["attack_type"] == "sandwich"]
    assert len(sandwiches) >= 1


def test_mev_analyze_endpoint_empty_block():
    """POST /api/v1/intelligence/mev-analyze with no txs returns clean result."""
    resp = client.post("/api/v1/intelligence/mev-analyze", json={
        "transactions": [], "chain": "arbitrum"
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["tx_count"] == 0
    assert data["patterns_found"] == []


def test_mev_analyze_invalid_chain_defaults_to_ethereum():
    """Unknown chain should default to ethereum without 422 error."""
    resp = client.post("/api/v1/intelligence/mev-analyze", json={
        "transactions": SANDWICH_TXS,
        "chain": "nonexistent-chain-xyz",
    })
    assert resp.status_code == 200
    assert resp.json()["chain"] == "ethereum"


# ── Autonomous Threat Modeling ──────────────────────────────────────────────

def test_threat_model_endpoint_vulnerable_code():
    """POST /api/v1/intelligence/threat-model returns STRIDE+PASTA report."""
    payload = {
        "source_code": "function withdraw() public { require(tx.origin == owner); selfdestruct(payable(msg.sender)); }",
        "target": "TestVault",
    }
    resp = client.post("/api/v1/intelligence/threat-model", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    assert "report_id"      in data
    assert "overall_risk"   in data
    assert "stride"         in data
    assert "pasta"          in data
    assert "attack_paths"   in data
    assert data["stride"]["total_threats"] >= 1
    assert data["pasta"]["completed"]      == 7


def test_threat_model_endpoint_empty_code():
    """POST /api/v1/intelligence/threat-model with empty code returns valid report."""
    resp = client.post("/api/v1/intelligence/threat-model", json={
        "source_code": "",
        "target": "EmptyTarget",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "report_id" in data


# ── Compliance Engine ────────────────────────────────────────────────────────

def test_compliance_report_soc2_only():
    """POST /api/v1/compliance/report generates SOC2 report."""
    resp = client.post("/api/v1/compliance/report", json={
        "findings":    [SAMPLE_FINDING],
        "target":      "MyProtocol",
        "frameworks":  ["soc2"],
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "soc2" in data["frameworks"]
    soc2 = data["frameworks"]["soc2"]
    assert "compliance_score"  in soc2
    assert "overall_status"    in soc2
    assert "controls"          in soc2


def test_compliance_report_iso27001_only():
    """POST /api/v1/compliance/report generates ISO 27001 report."""
    resp = client.post("/api/v1/compliance/report", json={
        "findings":   [SAMPLE_FINDING],
        "target":     "MySystem",
        "frameworks": ["iso27001"],
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "iso27001" in data["frameworks"]
    iso = data["frameworks"]["iso27001"]
    assert "compliance_score" in iso
    assert "iso_version"      in iso


def test_compliance_report_sarif_only():
    """POST /api/v1/compliance/report generates SARIF 2.1 report."""
    resp = client.post("/api/v1/compliance/report", json={
        "findings":   [SAMPLE_FINDING],
        "target":     "MyProtocol",
        "frameworks": ["sarif"],
    })
    assert resp.status_code == 200
    data  = resp.json()
    sarif = data["frameworks"]["sarif"]
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 1


def test_compliance_report_all_frameworks():
    """POST /api/v1/compliance/report generates all 3 frameworks at once."""
    resp = client.post("/api/v1/compliance/report", json={
        "findings":   [SAMPLE_FINDING],
        "target":     "AllFrameworks",
        "frameworks": ["soc2", "iso27001", "sarif"],
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "soc2"     in data["frameworks"]
    assert "iso27001" in data["frameworks"]
    assert "sarif"    in data["frameworks"]


def test_compliance_report_no_findings_compliant():
    """Empty findings → SOC2 COMPLIANT + high score."""
    resp = client.post("/api/v1/compliance/report", json={
        "findings":   [],
        "target":     "CleanProtocol",
        "frameworks": ["soc2"],
    })
    assert resp.status_code == 200
    soc2 = resp.json()["frameworks"]["soc2"]
    assert soc2["overall_status"] == "COMPLIANT"
    assert soc2["compliance_score"] >= 90.0
