use crate::ir::types::{Instr, Program};
use crate::cfg::types::{BasicBlock, BlockId, ControlFlowGraph};
use std::collections::{HashMap, BTreeMap};

/// Builds a Control Flow Graph from a Linear IR Program.
pub struct CfgBuilder<'a> {
    program: &'a Program,
    leaders: Vec<usize>, // Indicies of instructions that start a block
    // Map IR Label ID -> Instruction Index
    label_map: HashMap<usize, usize>,
}

impl<'a> CfgBuilder<'a> {
    pub fn new(program: &'a Program) -> Self {
        Self {
            program,
            leaders: Vec::new(),
            label_map: HashMap::new(),
        }
    }

    /// Primary build function
    pub fn build(mut self) -> ControlFlowGraph {
        if self.program.instructions.is_empty() {
             return ControlFlowGraph::new();
        }

        // 1. Identify Labels
        for (idx, instr) in self.program.instructions.iter().enumerate() {
            if let Instr::Label(lbl_id) = instr {
                self.label_map.insert(*lbl_id, idx);
            }
        }

        // 2. Identify Leaders
        // The first instruction is always a leader
        self.leaders.push(0);

        for (idx, instr) in self.program.instructions.iter().enumerate() {
             match instr {
                Instr::Jump(target) | Instr::JumpIf { label: target, .. } => {
                    // Target of a jump is a leader
                     if let Some(&target_idx) = self.label_map.get(target) {
                         self.leaders.push(target_idx);
                     }
                     // Instruction after a jump is a leader
                     if idx + 1 < self.program.instructions.len() {
                         self.leaders.push(idx + 1);
                     }
                }
                Instr::Return(_) => {
                    // Instruction after return is a leader (unreachable, or next block)
                    if idx + 1 < self.program.instructions.len() {
                         self.leaders.push(idx + 1);
                     }
                }
                // Call does not break basic block in this model (unless it throws/diverges)
                _ => {}
             }
        }
        
        self.leaders.sort_unstable();
        self.leaders.dedup();

        // 3. Create Blocks
        let mut cfg = ControlFlowGraph::new();
        let mut instr_idx_to_block_id: BTreeMap<usize, BlockId> = BTreeMap::new();

        for (i, &start_idx) in self.leaders.iter().enumerate() {
            let end_idx = if i + 1 < self.leaders.len() {
                self.leaders[i + 1] 
            } else {
                self.program.instructions.len()
            };

            let block = BasicBlock {
                id: i,
                instr_range: start_idx..end_idx,
                preds: Vec::new(),
                succs: Vec::new(),
            };
            
            instr_idx_to_block_id.insert(start_idx, i);
            cfg.blocks.push(block);
        }

        // 4. Connect Edges
        // We iterate blocks and look at the LAST instruction to determine successors
        for i in 0..cfg.blocks.len() {
            let range_end = cfg.blocks[i].instr_range.end;
             if range_end == 0 { continue; } // Empty block?
            let last_instr_idx = range_end - 1;
            let last_instr = &self.program.instructions[last_instr_idx];

            let mut successors = Vec::new();

            match last_instr {
                Instr::Jump(target) => {
                     if let Some(&target_instr_idx) = self.label_map.get(target) {
                         if let Some(&target_block_id) = self.get_block_starting_at(&instr_idx_to_block_id, target_instr_idx) {
                             successors.push(target_block_id);
                         }
                     }
                }
                Instr::JumpIf { label: target, .. } => {
                     // Conditional Branch
                     // Branch taken:
                     if let Some(&target_instr_idx) = self.label_map.get(target) {
                         if let Some(&target_block_id) = self.get_block_starting_at(&instr_idx_to_block_id, target_instr_idx) {
                             successors.push(target_block_id);
                         }
                     }
                     // Fallthrough: next block physically
                     // Only if not the very last block physically (conceptually usually yes)
                     if i + 1 < cfg.blocks.len() {
                         successors.push(i + 1);
                     }
                }
                Instr::Return(_) => {
                    cfg.exits.push(i);
                }
                _ => {
                    // Fallthrough for normal instructions that are at end of block 
                    // (e.g., block ended because next instr is a jump target)
                    if i + 1 < cfg.blocks.len() {
                        successors.push(i + 1);
                    }
                }
            }
            
            // Update CFG
            for &succ in &successors {
                 // borrowing check: cannot mutate cfg.blocks[succ] while holding blocks[i]
                 // Do this in a separate pass or uses distinct indices.
            }
            // Store successors temporarily or scoped.
            // Actually, we can just collect edges (src, dst) then apply.
        }

        // Re-do step 4 cleanly to avoid borrow checker issues
        let mut edges: Vec<(usize, usize)> = Vec::new();
        
        for i in 0..cfg.blocks.len() {
            let range_end = cfg.blocks[i].instr_range.end;
            if range_end == 0 { continue; }
            let last_instr_idx = range_end - 1;
            let last_instr = &self.program.instructions[last_instr_idx];

            match last_instr {
                 Instr::Jump(target) => {
                     if let Some(&target_instr_idx) = self.label_map.get(target) {
                         if let Some(&target_block_id) = self.get_block_starting_at(&instr_idx_to_block_id, target_instr_idx) {
                             edges.push((i, target_block_id));
                         }
                     }
                 }
                Instr::JumpIf { label: target, .. } => {
                     if let Some(&target_instr_idx) = self.label_map.get(target) {
                         if let Some(&target_block_id) = self.get_block_starting_at(&instr_idx_to_block_id, target_instr_idx) {
                             edges.push((i, target_block_id));
                         }
                     }
                     if i + 1 < cfg.blocks.len() {
                         edges.push((i, i + 1));
                     }
                }
                Instr::Return(_) => {
                    // No successors
                }
                _ => {
                     if i + 1 < cfg.blocks.len() {
                         edges.push((i, i + 1));
                     }
                }
            }
        }
        
        // Apply edges
        for (src, dst) in edges {
            cfg.blocks[src].succs.push(dst);
            cfg.blocks[dst].preds.push(src);
        }
        
        cfg
    }
    
    // Helper to find block ID from instruction index (must be exact match for leader)
    // Actually, because we define blocks exactly by leaders, searching for leader index is correct.
    fn get_block_starting_at<'m>(&self, map: &'m BTreeMap<usize, BlockId>, idx: usize) -> Option<&'m BlockId> {
        map.get(&idx)
    }
}
