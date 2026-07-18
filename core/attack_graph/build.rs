use crate::attack_graph::types::{AttackGraph, AttackNode, AttackEdge};
use crate::rules::types::Report;

pub struct GraphBuilder;

impl GraphBuilder {
    pub fn build(reports: Vec<Report>) -> AttackGraph {
        let mut graph = AttackGraph::new();
        
        // 1. Create Nodes from Reports
        for (i, report) in reports.into_iter().enumerate() {
            graph.nodes.push(AttackNode {
                id: i,
                report,
            });
        }
        
        // 2. heuristic Edge Creation (Future: Use Rule Postconditions)
        // For now, if two reports share the same BlockID, maybe they are related?
        // Or if one is TaintSource and other is TaintSink...
        // For industrial safety, we don't guess blindly.
        // We only add edges if explicitly certain.
        // Current logic: Disconnected nodes (flat list), ready for future expansion.
        
        graph
    }
}
