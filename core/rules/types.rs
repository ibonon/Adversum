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
    /// Optional source line (1-indexed), used for deterministic attack-chain
    /// ordering across reports. Populated when the analysis carries line info.
    #[serde(default)]
    pub line: Option<usize>,
    /// File the report belongs to, used to scope attack chains to a single
    /// translation unit (we never guess cross-file flows without proof).
    #[serde(default)]
    pub file_path: Option<String>,
    /// The input variable or expression that was consumed by the sink.
    #[serde(default)]
    pub source_var: Option<String>,
    /// The output variable populated by this vulnerability, enabling later steps.
    #[serde(default)]
    pub output_var: Option<String>,
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
