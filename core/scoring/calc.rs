use crate::scoring::types::{Score, severity_to_score};
use crate::attack_graph::types::AttackNode;

pub struct Scorer;

impl Scorer {
    /// Calculate score for a specific node in the context of the graph
    pub fn calculate(node: &AttackNode) -> Score {
        // Deterministic Calculation
        let base = severity_to_score(node.report.severity);
        
        // Future: Adjust based on Graph depth (e.g. if root node, higher exploitability)
        // For now: Base mapping.
        
        Score {
            base_score: base,
            impact: base * 0.6, // Dummy weight
            exploitability: base * 0.4,
        }
    }
}
