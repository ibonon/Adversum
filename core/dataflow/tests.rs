
use crate::ir::types::*;
use crate::cfg::build::CfgBuilder;
use crate::dataflow::analysis::TaintAnalysis;
use crate::dataflow::taint::TaintState;
use crate::interner::Interner;

#[test]
fn test_taint_propagation() {
    let mut interner = Interner::new();
    let x = interner.intern("x");
    let y = interner.intern("y");
    let z = interner.intern("z");
    let source = interner.intern("source");

    // x = source (tainted)
    // y = x + 1
    // z = y
    
    let instructions = vec![
        Instr::Assign { 
            dest: Operand::Var(x), 
            src: Operand::Var(source) 
        },
        Instr::Binary { 
            dest: Operand::Var(y), 
            op: Op::Add, 
            left: Operand::Var(x), 
            right: Operand::Constant("1".into()) 
        },
        Instr::Assign {
            dest: Operand::Var(z),
            src: Operand::Var(y)
        }
    ];
    let prog = Program { instructions };
    let cfg = CfgBuilder::new(&prog).build();
    let mut analysis = TaintAnalysis::new(&prog, &cfg);
    
    let mut initial_state = TaintState::new();
    initial_state.taint(&Operand::Var(source));
    
    analysis.run(initial_state);
    
    let end_state = analysis.get_exit_state(0).expect("Block 0 state missing");
    
    assert!(end_state.is_tainted(&Operand::Var(x)));
    assert!(end_state.is_tainted(&Operand::Var(y)));
    assert!(end_state.is_tainted(&Operand::Var(z)));
}
