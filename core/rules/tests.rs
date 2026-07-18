
use crate::ir::types::*;
use crate::cfg::build::CfgBuilder;
use crate::dataflow::analysis::TaintAnalysis;
use crate::dataflow::taint::TaintState;
use crate::interner::Interner;
use crate::rules::engine::RuleEngine;
use crate::rules::defs::TaintSinkRule;
use crate::rules::types::MatchContext;

#[test]
fn test_taint_sink_rule() {
    let mut interner = Interner::new();
    let x = interner.intern("x");
    let source = interner.intern("source");
    let exec = interner.intern("exec"); // The Sink

    // x = source (tainted)
    // exec(x)
    
    let instructions = vec![
        Instr::Assign { 
            dest: Operand::Var(x), 
            src: Operand::Var(source) 
        },
        Instr::Call {
            dest: None,
            func: exec,
            args: vec![Operand::Var(x)],
        }
    ];
    let prog = Program { instructions };
    let cfg = CfgBuilder::new(&prog).build();
    let mut analysis = TaintAnalysis::new(&prog, &cfg);
    
    let mut initial_state = TaintState::new();
    initial_state.taint(&Operand::Var(source));
    analysis.run(initial_state);
    
    let ctx = MatchContext {
        program: &prog,
        cfg: &cfg,
        dataflow: &analysis,
        interner: &interner,
    };
    
    let mut engine = RuleEngine::new();
    engine.add_rule(TaintSinkRule::new("exec"));
    
    let findings = engine.execute(&ctx);
    assert!(!findings.is_empty());
    assert_eq!(findings[0].rule_id, "TAINT-001");
}
