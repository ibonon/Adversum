
use crate::ir::types::*;
use crate::cfg::build::CfgBuilder;

#[test]
fn test_cfg_branching() {
    // IR:
    // 0: Start
    // 1: JumpIf cond L1 (Label @ 3)
    // 2: Jump L2 (Label @ 5)
    // 3: L1:
    // 4: ...
    // 5: L2:
    // 6: End
    
    let instructions = vec![
        Instr::Nop,                           // 0
        Instr::JumpIf { cond: Operand::Constant("true".into()), label: 1 }, // 1, jumps to Label(1)
        Instr::Jump(2),                       // 2, jumps to Label(2)
        Instr::Label(1),                      // 3
        Instr::Nop,                           // 4
        Instr::Label(2),                      // 5
        Instr::Nop                            // 6
    ];
    let prog = Program { instructions };
    
    let cfg = CfgBuilder::new(&prog).build();
    
    // Leaders: 
    // 0 (Start)
    // 3 (Target of JumpIf, and idx 1 is jump) Wait: 
    //   Instr 1 is JumpIf. Target is Label 1 (idx 3). So 3 is leader.
    //   Instr 2 is Jump. Target is Label 2 (idx 5). So 5 is leader.
    //   Instr after JumpIf (idx 2) is leader.
    //   Instr after Jump (idx 3) is leader.
    // Leaders: 0, 2, 3, 5.
    
    // Blocks:
    // B0: [0..2] -> Instrs 0, 1. Ends with JumpIf. Succs: B2(Label1->3), B1(Fallthrough->2)
    // B1: [2..3] -> Instr 2. Ends with Jump. Succs: B3(Label2->5)
    // B2: [3..5] -> Instrs 3, 4. No jump, fallthrough. Succs: B3(Fallthrough->5)
    // B3: [5..7] -> Instrs 5, 6. End. Succs: None? Or implicit return?
    
    assert_eq!(cfg.blocks.len(), 4);
    
    let b0 = &cfg.blocks[0];
    assert!(b0.succs.contains(&1));
    assert!(b0.succs.contains(&2));
    assert_eq!(b0.succs.len(), 2);
    
    let b1 = &cfg.blocks[1];
    assert!(b1.succs.contains(&3));
    assert_eq!(b1.succs.len(), 1);
    
    let b2 = &cfg.blocks[2];
    assert!(b2.succs.contains(&3));
}
