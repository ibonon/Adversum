use serde::{Deserialize, Serialize};
use crate::ir::types::Program;
use crate::cfg::types::ControlFlowGraph;
use crate::dataflow::analysis::TaintAnalysis;
use crate::interner::Interner;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub rule_id: String,
    pub name: String,
    pub description: String,
    pub severity: Severity,
    // Location info (BlockId, Instruction Index)
    pub block_id: usize,
    pub instr_idx: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Context passed to every rule during evaluation.
pub struct MatchContext<'a> {
    pub program: &'a Program,
    pub cfg: &'a ControlFlowGraph,
    pub dataflow: &'a TaintAnalysis<'a>,
    pub interner: &'a Interner,
}

/// The Interface for valid security rules.
pub trait Rule {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn severity(&self) -> Severity;
    
    /// Evaluates the rule against the code context.
    /// Returns a list of findings (Reports).
    fn evaluate(&self, ctx: &MatchContext) -> Vec<Report>;
}
