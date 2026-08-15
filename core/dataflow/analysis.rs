use crate::ir::types::{Instr, Program, Operand};
use crate::cfg::types::{ControlFlowGraph, BlockId};
use crate::dataflow::taint::TaintState;
use std::collections::{VecDeque, BTreeMap, HashMap};
use crate::dataflow::summary::FunctionSummary;

pub struct TaintAnalysis<'a> {
    program: &'a Program,
    pub cfg: &'a ControlFlowGraph,
    // Map BlockId -> Entry State
    pub in_states: BTreeMap<BlockId, TaintState>,
    // Map BlockId -> Exit State
    pub out_states: BTreeMap<BlockId, TaintState>,
    // Configuration for sources and sinks
    pub config: TaintConfig,
    // Tracked findings during analysis
    pub findings: Vec<FlowFinding>,
    /// Map from instruction index to source line (1-indexed).
    /// Built by the IR lowering pass and passed in here.
    pub instr_lines: Vec<usize>,
    pub summaries: &'a HashMap<crate::interner::SymbolId, FunctionSummary>,
}

#[derive(Debug, Clone, Default)]
pub struct TaintConfig {
    pub sources: Vec<crate::interner::SymbolId>,
    pub sinks: Vec<crate::interner::SymbolId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowFinding {
    pub sink_instr_idx: usize,
    pub sink_func: crate::interner::SymbolId,
    pub evidence: String,
    /// Source line number (1-indexed). 0 means unknown.
    pub line: usize,
}

impl<'a> TaintAnalysis<'a> {
    pub fn new(program: &'a Program, cfg: &'a ControlFlowGraph, config: TaintConfig, summaries: &'a HashMap<crate::interner::SymbolId, FunctionSummary>) -> Self {
        Self {
            program,
            cfg,
            in_states: BTreeMap::new(),
            out_states: BTreeMap::new(),
            config,
            findings: Vec::new(),
            instr_lines: Vec::new(),
            summaries,
        }
    }

    /// Provide the instruction→source-line mapping from the lowering pass.
    pub fn with_line_map(mut self, lines: Vec<usize>) -> Self {
        self.instr_lines = lines;
        self
    }

    pub fn run(&mut self, initial_taint: TaintState) {
        // Initialize worklist
        let mut worklist: VecDeque<BlockId> = VecDeque::new();
        
        // Init entry block
        if let Some(entry_blk) = self.cfg.get_block(self.cfg.entry) {
             self.in_states.insert(entry_blk.id, initial_taint.clone());
             worklist.push_back(entry_blk.id);
        }

        // Iteration
        let mut visited_count = 0; // Guard against infinite loops? Only needed if non-monotonic transfer (not the case here)
        
        while let Some(block_id) = worklist.pop_front() {
            visited_count += 1;
            
            // 1. Compute IN[B] = Union(OUT[P]) for preds P
            // For entry block, IN is initialized. For others:
            let mut input_state = if block_id == self.cfg.entry {
                 self.in_states.get(&block_id).cloned().unwrap_or_default()
            } else {
                 let mut s = TaintState::new();
                 if let Some(blk) = self.cfg.get_block(block_id) {
                     for &pred in &blk.preds {
                         if let Some(pred_out) = self.out_states.get(&pred) {
                             s.merge(pred_out);
                         }
                     }
                 }
                 s
            };

            // 2. Compute OUT[B] = Transfer(IN[B])
            // Transfer logic: Iterate instructions, apply taint rules
            let mut current_state = input_state.clone();
            if let Some(blk) = self.cfg.get_block(block_id) {
                if blk.instr_range.end <= self.program.instructions.len() {
                     for (offset, instr) in self.program.instructions[blk.instr_range.clone()].iter().enumerate() {
                         let global_idx = blk.instr_range.start + offset;
                         self.transfer_instr(&mut current_state, instr, global_idx);
                     }
                }
            }

            // 3. Check for change
            let changed = if let Some(old_out) = self.out_states.get(&block_id) {
                 old_out != &current_state
            } else {
                 true
            };

            if changed {
                self.out_states.insert(block_id, current_state);
                // Add successors to worklist
                if let Some(blk) = self.cfg.get_block(block_id) {
                    for &succ in &blk.succs {
                        if !worklist.contains(&succ) {
                             worklist.push_back(succ);
                        }
                    }
                }
            }
        }
    }
    
    fn transfer_instr(&mut self, state: &mut TaintState, instr: &Instr, instr_idx: usize) {
        match instr {
            Instr::FieldStore { obj, field, src } => {
                if state.is_tainted(src) {
                    state.taint_field(*obj, *field);
                }
            }
            Instr::FieldLoad { dest, obj, field } => {
                if state.is_field_tainted(*obj, *field) {
                    state.taint(dest);
                } else {
                    state.untaint(dest);
                }
            }
            Instr::Assign { dest, src } => {
                if state.is_tainted(src) {
                    state.taint(dest);
                } else {
                    state.untaint(dest);
                }
            }
            Instr::Binary { dest, left, right, .. } => {
                if state.is_tainted(left) || state.is_tainted(right) {
                    state.taint(dest);
                } else {
                    state.untaint(dest);
                }
            }
            Instr::Unary { dest, operand, .. } => {
                if state.is_tainted(operand) {
                    state.taint(dest);
                } else {
                    state.untaint(dest);
                }
            }
            Instr::Call { dest, func, args } => {
                let src_line = self.instr_lines.get(instr_idx).copied().unwrap_or(0);
                
                // Check if callee is a known summary
                let mut is_known_callee = false;
                let mut return_tainted = false;

                if let Some(summary) = self.summaries.get(func) {
                    is_known_callee = true;
                    // Check if any argument passed to a sink-parameter is tainted
                    for (param_idx, sinks) in &summary.sink_params {
                        if let Some(arg) = args.get(*param_idx) {
                            if state.is_tainted(arg) {
                                for sink_func in sinks {
                                    self.findings.push(FlowFinding {
                                        sink_instr_idx: instr_idx,
                                        sink_func: *sink_func,
                                        evidence: format!("Tainted argument {} passed to sensitive sink via inter-procedural flow", param_idx),
                                        line: src_line,
                                    });
                                }
                            }
                        }
                    }
                    
                    // Check if return value becomes tainted
                    for param_idx in &summary.tainted_returns {
                        if let Some(arg) = args.get(*param_idx) {
                            if state.is_tainted(arg) {
                                return_tainted = true;
                                break;
                            }
                        }
                    }
                    
                    // Apply tainted fields to caller's self object
                    if !summary.tainted_self_fields.is_empty() {
                        if let Some(crate::ir::types::Operand::Var(self_sym)) = args.first() {
                            for field in &summary.tainted_self_fields {
                                state.taint_field(*self_sym, *field);
                            }
                        }
                    }
                }

                // Rule 1: Identification of Sources
                if self.config.sources.contains(func) {
                    if let Some(d) = dest {
                        state.taint(d);
                    }
                }

                // Rule 2: Identification of Sinks (Direct)
                if self.config.sinks.contains(func) {
                    for (i, arg) in args.iter().enumerate() {
                        if state.is_tainted(arg) {
                            self.findings.push(FlowFinding {
                                sink_instr_idx: instr_idx,
                                sink_func: *func,
                                evidence: format!("Tainted argument {} passed to sensitive sink", i),
                                line: src_line,
                            });
                        }
                    }
                }

                // Rule 3: Propagation via calls
                if let Some(d) = dest {
                    if self.config.sources.contains(func) {
                        // Already tainted
                    } else if is_known_callee {
                        if return_tainted {
                            state.taint(d);
                        } else {
                            state.untaint(d);
                        }
                    } else {
                        // Unknown callee -> Conservative Propagation
                        let any_tainted = args.iter().any(|a| state.is_tainted(a));
                        if any_tainted {
                            state.taint(d);
                        } else {
                            state.untaint(d);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    
    pub fn get_exit_state(&self, block_id: BlockId) -> Option<&TaintState> {
        self.out_states.get(&block_id)
    }
}
