use std::collections::{HashSet, HashMap};
use crate::interner::SymbolId;

#[derive(Debug, Clone, Default)]
pub struct FunctionSummary {
    /// Indices of parameters that, if tainted, will cause the return value to be tainted.
    pub tainted_returns: HashSet<usize>,
    /// Indices of parameters that are passed to a sensitive sink inside this function.
    /// Maps parameter index to the sink function's SymbolId.
    pub sink_params: HashMap<usize, Vec<SymbolId>>,
}

impl FunctionSummary {
    pub fn new() -> Self {
        Self {
            tainted_returns: HashSet::new(),
            sink_params: HashMap::new(),
        }
    }
}

use crate::ir::types::Module;
use crate::callgraph::CallGraph;
use crate::cfg::build::CfgBuilder;
use crate::dataflow::analysis::{TaintAnalysis, TaintConfig, FlowFinding};
use crate::dataflow::taint::TaintState;

pub fn compute_summaries(module: &Module, cg: &CallGraph, config: &TaintConfig) -> HashMap<SymbolId, FunctionSummary> {
    let mut summaries = HashMap::new();
    
    // Process functions (can be optimized with topological sort later)
    for (func_id, func_ir) in &module.program.functions {
        let mut summary = FunctionSummary::new();
        
        let cfg = CfgBuilder::new(&crate::ir::types::Program { instructions: func_ir.instructions.clone(), functions: HashMap::new() }).build();
        
        for (i, param_sym) in func_ir.params.iter().enumerate() {
            let mut initial_state = TaintState::new();
            initial_state.taint(&crate::ir::types::Operand::Var(*param_sym));
            
            let mut analysis = TaintAnalysis::new(
                &crate::ir::types::Program { instructions: func_ir.instructions.clone(), functions: HashMap::new() },
                &cfg,
                config.clone(),
                &summaries
            );
            
            analysis.run(initial_state);
            
            // Check if return value is tainted
            let mut returns_tainted = false;
            for exit_block in &cfg.exits {
                if let Some(state) = analysis.get_exit_state(*exit_block) {
                    let blk = cfg.get_block(*exit_block).unwrap();
                    if blk.instr_range.end > 0 {
                        let last_idx = blk.instr_range.end - 1;
                        if let crate::ir::types::Instr::Return(Some(ret_op)) = &func_ir.instructions[last_idx] {
                            if state.is_tainted(ret_op) {
                                returns_tainted = true;
                                break;
                            }
                        }
                    }
                }
            }
            if returns_tainted {
                summary.tainted_returns.insert(i);
            }
            
            // Check if parameter reached a sink
            let mut sinks_reached = Vec::new();
            for finding in analysis.findings {
                sinks_reached.push(finding.sink_func);
            }
            if !sinks_reached.is_empty() {
                summary.sink_params.insert(i, sinks_reached);
            }
        }
        
        summaries.insert(*func_id, summary);
    }
    
    summaries
}

