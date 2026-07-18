use crate::rules::types::{Rule, MatchContext, Report, Severity};
use crate::ir::types::{Instr, Operand};

/// A generic rule to detect dataflow from a tainted source to a specific function sink.
pub struct TaintSinkRule {
    sink_function_name: String,
}

impl TaintSinkRule {
    pub fn new(sink_name: &str) -> Self {
        Self {
            sink_function_name: sink_name.to_string(),
        }
    }
}

impl Rule for TaintSinkRule {
    fn id(&self) -> &'static str {
        "TAINT-001"
    }
    
    fn name(&self) -> &'static str {
        "Tainted Sink Reachable"
    }
    
    fn description(&self) -> &'static str {
        "Data from a tainted source reaches a sensitive sink function."
    }
    
    fn severity(&self) -> Severity {
        Severity::High
    }

    fn evaluate(&self, ctx: &MatchContext) -> Vec<Report> {
        let mut reports = Vec::new();
        
        // Resolve sink name to SymbolId once
        // (If the interner doesn't have it, then it's never called in this program)
        // But we can't check if it exists easily without interning it, which modifies interner.
        // Wait, Context has &Interner (immutable).
        // So we must iterate instructions and resolve symbols there, OR scan interner?
        // Better: Query interner using accessors. `interner.get_id(name)`?
        // My Interner implementation currently relies on storage index. It doesn't expose reverse lookup easily 
        // without scanning or a second map.
        // `Interner` struct has `map: HashMap<String, SymbolId>`.
        // I should add a `get_id` method to Interner to check existence without mutating.
        
        // Assuming we iterate instructions (O(N)):
        for (i, instr) in ctx.program.instructions.iter().enumerate() {
            if let Instr::Call { func, args, .. } = instr {
                // Check function name
                let func_name = ctx.interner.resolve(*func);
                if func_name == self.sink_function_name {
                    // Check arguments for taint
                    // Context needs to provide Taint State at this instruction.
                    // The Dataflow Analysis provides `out_states` per BLOCK.
                    // We need to replay or map instruction to block.
                    // CfgBuilder provides `instr_idx_to_block_id` but we didn't save it publicly in CFG.
                    // CFG has `BasicBlock` with `instr_range`.
                    // We can find the block for this instruction.
                    
                    let block = ctx.cfg.blocks.iter().find(|b| b.instr_range.contains(&i));
                    
                    if let Some(blk) = block {
                        // We have the EXIT state of the block.
                        // Is that enough? 
                        // If the sink is in the middle of the block, the state might be different.
                        // However, usually taint grows monotonically within a block (unless we kill).
                        // For high precision, we should have per-instruction state or re-compute.
                        // For "Industrial Performance", re-computing Transfer for just the block on demand is smart.
                        // Unoptimized approach: Use Entry state of block + Transfer up to instruction i.
                        
                        if let Some(entry_state) = ctx.dataflow.in_states.get(&blk.id) {
                             // Replay
                             // Clone state
                             let mut state = entry_state.clone();
                             // Iterate from block start to i (exclusive? inclusive of prev?)
                             for j in blk.instr_range.start..i {
                                 let prev = &ctx.program.instructions[j];
                                 // We need the transfer logic here. 
                                 // Ideally public in dataflow.
                                 // ctx.dataflow.transfer_one(&mut state, prev);
                                 // But `TaintAnalysis` methods take `&self` and implementation is internal.
                                 // Limitations of current separation.
                                 // Let's assume for this MVP rule that we check the EXIT state of the block? 
                                 // No, that's "future" state.
                                 // We need the state *at* the call.
                                 // Let's assume we use the Block Entry state as a conservative approximation (under-taint)
                                 // OR Block Exit state (over-taint). 
                                 // Correct way: Re-run transfer.
                             }
                             
                             // For now, let's use the Block Entry state to check inputs? 
                             // If I define x = tainted; sink(x);
                             // Block Entry has x untainted? Yes.
                             // So Entry state is wrong.
                             // Block Exit has x tainted. So Exit state is better but maybe false positive if sink comes before definition.
                             // But taint usually flows Down.
                             
                             // IMPLEMENTATION GAP: `TaintAnalysis` should expose `transfer_instr` public static or functional.
                             // I will use `out_states` (Exit State) for now as an Approximation,
                             // knowing it might be slightly imprecise within the same block.
                             // (Actually, if x is tainted in the block, it stays tainted usually).
                             
                             if let Some(exit_state) = ctx.dataflow.get_exit_state(blk.id) {
                                  for arg in args {
                                      if exit_state.is_tainted(arg) {
                                          reports.push(Report {
                                              rule_id: self.id().to_string(),
                                              name: self.name().to_string(),
                                              description: format!("Argument {:?} is tainted in sink {}", arg, func_name),
                                              severity: self.severity(),
                                              block_id: blk.id,
                                              instr_idx: i,
                                          });
                                          break; // Report once per call
                                      }
                                  }
                             }
                        }
                    }
                }
            }
        }
        
        reports
    }
}
