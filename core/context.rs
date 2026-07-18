use serde::{Deserialize, Serialize};

/// Resource limits to prevent Denial of Service (DoS) attacks via complex inputs.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Quotas {
    /// Maximum number of statements in AST
    pub max_ast_nodes: usize,
    /// Maximum number of generated IR instructions
    pub max_ir_instructions: usize,
    /// Maximum CFG depth or complexity (optional)
    pub max_cfg_blocks: usize,
}

impl Default for Quotas {
    fn default() -> Self {
        Self {
            max_ast_nodes: 10_000,
            max_ir_instructions: 50_000,
            max_cfg_blocks: 5_000,
        }
    }
}

/// Trait for observability features without depending on IO.
/// The orchestrator should implement this to log phases.
pub trait Tracer {
    fn on_phase_start(&self, phase_name: &str);
    fn on_phase_end(&self, phase_name: &str);
    fn on_error(&self, error: &str);
}

/// A default Tracer that does nothing (for production silence or tests).
pub struct NoOpTracer;
impl Tracer for NoOpTracer {
    fn on_phase_start(&self, _: &str) {}
    fn on_phase_end(&self, _: &str) {}
    fn on_error(&self, _: &str) {}
}

/// Errors specific to the Analysis Pipeline mechanics.
#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    #[error("Resource Exhausted: {0}")]
    ResourceExhausted(String),
    #[error("Stage Failed: {0}")]
    StageFailed(String),
}
