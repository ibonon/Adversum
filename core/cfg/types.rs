use serde::{Deserialize, Serialize};
use std::ops::Range;

/// Unique identifier for a Basic Block.
pub type BlockId = usize;

/// A Basic Block in the Control Flow Graph.
/// Represents a sequence of Linear IR instructions that execute sequentially.
/// Uses a Range into the main Program instruction vector to avoid copying.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicBlock {
    pub id: BlockId,
    // Range of instructions in the IR program's instruction vector
    pub instr_range: Range<usize>,
    pub preds: Vec<BlockId>,
    pub succs: Vec<BlockId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlFlowGraph {
    pub blocks: Vec<BasicBlock>,
    pub entry: BlockId,
    // There can be multiple exit blocks (returns)
    pub exits: Vec<BlockId>,
}

impl ControlFlowGraph {
    pub fn new() -> Self {
        Self {
            blocks: Vec::with_capacity(32), // Pre-allocate small capacity
            entry: 0,
            exits: Vec::new(),
        }
    }
    
    pub fn get_block(&self, id: BlockId) -> Option<&BasicBlock> {
        self.blocks.get(id)
    }
}
