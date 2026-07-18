use serde::{Deserialize, Serialize};
use crate::rules::types::Report;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackNode {
    pub id: usize,
    pub report: Report, // The vulnerability
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackEdge {
    pub from: usize,
    pub to: usize,
    pub description: String, // "Enables", "Reveals Key", etc.
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttackGraph {
    pub nodes: Vec<AttackNode>,
    pub edges: Vec<AttackEdge>,
}

impl AttackGraph {
    pub fn new() -> Self {
        Self::default()
    }
}
