"""
Adversum Threat Graph — NetworkX-powered dependency graph of threats.
Maps: exploit → vulnerable contract → impacted DeFi protocol.
Used for blast-radius analysis and cross-protocol cascade simulation.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

try:
    import networkx as nx
    _NX_AVAILABLE = True
except ImportError:
    _NX_AVAILABLE = False
    logger.warning("[ThreatGraph] networkx not available — graph features disabled")


# ── Node types ────────────────────────────────────────────────────────────────

class NodeType:
    EXPLOIT = "exploit"
    CONTRACT = "contract"
    PROTOCOL = "protocol"
    FINDING = "finding"
    ATTACKER = "attacker"


@dataclass
class ThreatNode:
    node_id: str
    node_type: str
    label: str
    severity: str = "INFO"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ThreatEdge:
    source: str
    target: str
    relation: str           # e.g. "exploits", "impacts", "calls", "emits"
    weight: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BlastRadius:
    root_node: str
    affected_nodes: List[str]
    affected_protocols: List[str]
    depth: int
    total_value_at_risk_usd: float
    critical_paths: List[List[str]]


# ── Core graph engine ─────────────────────────────────────────────────────────

class ThreatGraph:
    """
    Directed weighted graph of threat relationships.

    Nodes: exploits, contracts, protocols, findings, attackers
    Edges: exploits→contract, contract→protocol, finding→contract, etc.

    Methods:
    - add_node / add_edge
    - blast_radius(node_id): find all impacted nodes from a root
    - critical_paths(source, target): highest-risk attack paths
    - centrality(): which nodes are most critical (betweenness centrality)
    - to_dict(): serializable summary for API responses
    """

    def __init__(self):
        if _NX_AVAILABLE:
            self._g = nx.DiGraph()
        else:
            self._g = None
        self._nodes: Dict[str, ThreatNode] = {}
        self._edges: List[ThreatEdge] = []

    def add_node(self, node: ThreatNode) -> None:
        self._nodes[node.node_id] = node
        if self._g is not None:
            self._g.add_node(
                node.node_id,
                node_type=node.node_type,
                label=node.label,
                severity=node.severity,
            )

    def add_edge(self, edge: ThreatEdge) -> None:
        self._edges.append(edge)
        if self._g is not None:
            self._g.add_edge(
                edge.source,
                edge.target,
                relation=edge.relation,
                weight=edge.weight,
            )

    def blast_radius(self, root_node_id: str, max_depth: int = 5) -> BlastRadius:
        """Compute all nodes reachable from root (DFS/BFS traversal)."""
        if not _NX_AVAILABLE or self._g is None:
            return BlastRadius(
                root_node=root_node_id,
                affected_nodes=[],
                affected_protocols=[],
                depth=0,
                total_value_at_risk_usd=0.0,
                critical_paths=[],
            )
        try:
            reachable: Set[str] = set(
                nx.single_source_shortest_path_length(
                    self._g, root_node_id, cutoff=max_depth
                ).keys()
            ) - {root_node_id}
        except nx.NodeNotFound:
            reachable = set()

        affected_protocols = [
            nid for nid in reachable
            if self._nodes.get(nid, ThreatNode("", "", "")).node_type == NodeType.PROTOCOL
        ]
        total_var = sum(
            self._nodes[n].metadata.get("value_at_risk_usd", 0.0)
            for n in reachable
            if n in self._nodes
        )

        # Find top-3 critical paths by weight
        critical_paths: List[List[str]] = []
        for target in list(reachable)[:10]:
            try:
                path = nx.shortest_path(self._g, root_node_id, target, weight="weight")
                critical_paths.append(path)
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                pass
        critical_paths.sort(key=len, reverse=True)

        return BlastRadius(
            root_node=root_node_id,
            affected_nodes=sorted(reachable),
            affected_protocols=affected_protocols,
            depth=max(
                (nx.shortest_path_length(self._g, root_node_id, n)
                 for n in reachable
                 if nx.has_path(self._g, root_node_id, n)),
                default=0,
            ),
            total_value_at_risk_usd=total_var,
            critical_paths=critical_paths[:3],
        )

    def centrality(self) -> Dict[str, float]:
        """Return betweenness centrality for all nodes (most critical = highest score)."""
        if not _NX_AVAILABLE or self._g is None or len(self._g) == 0:
            return {}
        return {
            nid: round(score, 4)
            for nid, score in nx.betweenness_centrality(self._g, normalized=True).items()
        }

    def to_dict(self) -> Dict[str, Any]:
        """Serialize for API JSON response."""
        cent = self.centrality()
        return {
            "node_count": len(self._nodes),
            "edge_count": len(self._edges),
            "nodes": [
                {
                    "id": n.node_id,
                    "type": n.node_type,
                    "label": n.label,
                    "severity": n.severity,
                    "centrality": cent.get(n.node_id, 0.0),
                    **n.metadata,
                }
                for n in self._nodes.values()
            ],
            "edges": [
                {
                    "source": e.source,
                    "target": e.target,
                    "relation": e.relation,
                    "weight": e.weight,
                }
                for e in self._edges
            ],
            "top_critical_nodes": sorted(
                cent.items(), key=lambda x: x[1], reverse=True
            )[:5],
        }

    def build_from_findings(self, findings: List[Dict[str, Any]]) -> "ThreatGraph":
        """
        Convenience factory: auto-populate the graph from a list of findings dicts.
        Creates contract nodes, finding nodes, and edges between them.
        """
        for f in findings:
            finding_id = str(f.get("id", f.get("rule_id", "unknown")))
            contract_id = f.get("file", "unknown_contract")
            severity = str(f.get("severity", "INFO"))

            # Ensure contract node
            if contract_id not in self._nodes:
                self.add_node(ThreatNode(
                    node_id=contract_id,
                    node_type=NodeType.CONTRACT,
                    label=contract_id,
                    severity=severity,
                ))

            # Finding node
            self.add_node(ThreatNode(
                node_id=finding_id,
                node_type=NodeType.FINDING,
                label=f.get("rule_id", finding_id),
                severity=severity,
                metadata={"description": f.get("description", "")},
            ))

            # Edge: finding → contract
            self.add_edge(ThreatEdge(
                source=finding_id,
                target=contract_id,
                relation="affects",
                weight={"CRITICAL": 4.0, "HIGH": 3.0, "MEDIUM": 2.0, "LOW": 1.0}.get(severity, 0.5),
            ))

        return self


# ── Singleton ─────────────────────────────────────────────────────────────────
_global_threat_graph = ThreatGraph()


def get_threat_graph() -> ThreatGraph:
    return _global_threat_graph


def reset_threat_graph() -> ThreatGraph:
    global _global_threat_graph
    _global_threat_graph = ThreatGraph()
    return _global_threat_graph
