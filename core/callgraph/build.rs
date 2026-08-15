use crate::ir::types::{Instr, Program};
use crate::callgraph::types::{CallGraph, CallNode};
use crate::interner::SymbolId;
use std::collections::HashSet;

pub struct CallGraphBuilder<'a> {
    program: &'a Program,
}

impl<'a> CallGraphBuilder<'a> {
    pub fn new(program: &'a Program) -> Self {
        Self { program }
    }

    pub fn build(self) -> CallGraph {
        let mut cg = CallGraph::new();

        // Register all functions as nodes
        for (func_id, _func_ir) in &self.program.functions {
            cg.nodes.insert(*func_id, CallNode { func_name: *func_id });
            cg.callees.insert(*func_id, HashSet::new());
        }

        // Iterate through all functions to find calls
        for (caller_id, func_ir) in &self.program.functions {
            for instr in &func_ir.instructions {
                if let Instr::Call { func: callee_id, .. } = instr {
                    // Only add edge if callee is known in the program (user-defined function)
                    if self.program.functions.contains_key(callee_id) {
                        cg.edges.push((*caller_id, *callee_id));
                        cg.callees.entry(*caller_id).or_default().insert(*callee_id);
                    }
                }
            }
        }

        // Also check top-level instructions (which aren't in any function)
        // Let's use a special SymbolId for the "main" module scope if needed, or just ignore for CG.
        // For taint analysis, top-level is analyzed first or as "main".

        cg
    }
}
