"""
Tests for: ThreatGraph (NetworkX), HeuristicsEngineV2, and new API endpoints.
"""
import os
import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("NEBIUS_MOCK", "1")

from fastapi.testclient import TestClient
from api.main import app
from orchestrator.services.threat_graph import ThreatGraph, ThreatNode, ThreatEdge, NodeType, reset_threat_graph
from modules.threat_hunter.heuristics_v2 import HeuristicsEngineV2, heuristics_v2

client = TestClient(app)
VALID_HEADERS = {"X-API-Key": "adv-dev-key-123"}

# ── Sample data ───────────────────────────────────────────────────────────────

SAMPLE_FINDINGS = [
    {"id": "f1", "rule_id": "REENTRANCY-001", "file": "Vault.sol", "severity": "CRITICAL",
     "description": "reentrancy in withdraw", "snippet": "call{value: amount}(\"\")"},
    {"id": "f2", "rule_id": "DELEGATE-002", "file": "Proxy.sol", "severity": "HIGH",
     "description": "delegatecall to user-supplied address", "snippet": "delegatecall(data)"},
    {"id": "f3", "rule_id": "TIMESTAMP-003", "file": "Auction.sol", "severity": "MEDIUM",
     "description": "block.timestamp used for expiry", "snippet": "block.timestamp"},
]


class TestThreatGraph:
    def test_empty_graph_returns_zero_counts(self):
        g = ThreatGraph()
        d = g.to_dict()
        assert d["node_count"] == 0
        assert d["edge_count"] == 0

    def test_build_from_findings_creates_nodes(self):
        g = ThreatGraph()
        g.build_from_findings(SAMPLE_FINDINGS)
        d = g.to_dict()
        assert d["node_count"] > 0
        assert d["edge_count"] > 0

    def test_finding_nodes_and_contract_nodes_created(self):
        g = ThreatGraph()
        g.build_from_findings(SAMPLE_FINDINGS)
        d = g.to_dict()
        node_ids = [n["id"] for n in d["nodes"]]
        assert "Vault.sol" in node_ids
        assert "f1" in node_ids

    def test_blast_radius_from_finding(self):
        g = ThreatGraph()
        g.build_from_findings(SAMPLE_FINDINGS)
        result = g.blast_radius("f1")
        assert result.root_node == "f1"
        assert "Vault.sol" in result.affected_nodes

    def test_blast_radius_unknown_node(self):
        g = ThreatGraph()
        result = g.blast_radius("nonexistent_node")
        assert result.affected_nodes == []

    def test_centrality_returns_scores(self):
        g = ThreatGraph()
        g.build_from_findings(SAMPLE_FINDINGS)
        c = g.centrality()
        assert isinstance(c, dict)
        # All scores should be in [0, 1]
        for score in c.values():
            assert 0.0 <= score <= 1.0

    def test_to_dict_has_top_critical_nodes(self):
        g = ThreatGraph()
        g.build_from_findings(SAMPLE_FINDINGS)
        d = g.to_dict()
        assert "top_critical_nodes" in d

    def test_manual_node_and_edge_addition(self):
        g = ThreatGraph()
        g.add_node(ThreatNode("exploit_1", NodeType.EXPLOIT, "Flash Loan Attack", "CRITICAL"))
        g.add_node(ThreatNode("contract_1", NodeType.CONTRACT, "LendingPool.sol"))
        g.add_edge(ThreatEdge("exploit_1", "contract_1", "exploits", weight=4.0))
        d = g.to_dict()
        assert d["node_count"] == 2
        assert d["edge_count"] == 1


class TestHeuristicsV2:
    def test_rule_count_at_least_15(self):
        assert heuristics_v2.rule_count >= 15

    def test_selfdestruct_detected(self):
        code = "function kill() external { selfdestruct(payable(owner)); }"
        results = heuristics_v2.scan(code)
        rule_ids = [r.rule_id for r in results]
        assert "HEU-001" in rule_ids

    def test_delegatecall_detected(self):
        code = "target.delegatecall(data);"
        results = heuristics_v2.scan(code)
        rule_ids = [r.rule_id for r in results]
        assert "HEU-002" in rule_ids

    def test_tx_origin_detected(self):
        code = "require(tx.origin == owner, 'not authorized');"
        results = heuristics_v2.scan(code)
        rule_ids = [r.rule_id for r in results]
        assert "HEU-003" in rule_ids

    def test_critical_sorted_first(self):
        code = """
        selfdestruct(payable(msg.sender));
        block.timestamp > expiry;
        """
        results = heuristics_v2.scan(code)
        assert len(results) >= 2
        assert results[0].severity.value == "CRITICAL"

    def test_clean_code_no_findings(self):
        code = "function safeAdd(uint a, uint b) pure returns (uint) { return a + b; }"
        results = heuristics_v2.scan(code)
        assert len(results) == 0

    def test_scan_files_returns_flat_list(self):
        files = [
            {"path": "A.sol", "content": "selfdestruct(payable(owner));"},
            {"path": "B.sol", "content": "tx.origin == msg.sender;"},
        ]
        results = heuristics_v2.scan_files(files)
        assert isinstance(results, list)
        assert len(results) >= 2
        for r in results:
            assert "rule_id" in r
            assert "file" in r
            assert "severity" in r

    def test_line_number_populated(self):
        code = "pragma solidity ^0.8.0;\n\nselfdestruct(payable(owner));"
        results = heuristics_v2.scan(code)
        assert results[0].line == 3

    def test_confidence_in_range(self):
        code = "delegatecall(data);"
        results = heuristics_v2.scan(code)
        for r in results:
            assert 0.0 <= r.confidence <= 1.0


class TestNewAPIEndpoints:
    def test_threat_graph_endpoint(self):
        response = client.post(
            "/api/v1/intelligence/threat-graph",
            headers=VALID_HEADERS,
            json={"findings": SAMPLE_FINDINGS},
        )
        assert response.status_code == 200
        data = response.json()
        assert "node_count" in data
        assert "edge_count" in data
        assert "nodes" in data

    def test_blast_radius_endpoint(self):
        response = client.post(
            "/api/v1/intelligence/blast-radius",
            headers=VALID_HEADERS,
            params={"root_node_id": "f1"},
            json={"findings": SAMPLE_FINDINGS},
        )
        assert response.status_code == 200
        data = response.json()
        assert "root_node" in data
        assert "affected_nodes" in data

    def test_heuristics_scan_endpoint(self):
        response = client.post(
            "/api/v1/intelligence/heuristics-scan",
            headers=VALID_HEADERS,
            json={"findings": [
                {"file": "Vault.sol", "snippet": "selfdestruct(payable(owner));", "description": ""},
            ]},
        )
        assert response.status_code == 200
        data = response.json()
        assert "rule_count" in data
        assert data["rule_count"] >= 15

    def test_triage_endpoint_exists(self):
        response = client.post(
            "/api/v1/intelligence/triage",
            headers=VALID_HEADERS,
            json={"findings": SAMPLE_FINDINGS},
        )
        assert response.status_code == 200
        data = response.json()
        assert "total" in data
        assert data["total"] == len(SAMPLE_FINDINGS)
