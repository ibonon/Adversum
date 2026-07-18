
use crate::ast::types::*;
use crate::ir::lower::LoweringContext;
use crate::ir::types::{Instr, Op, Operand};
use crate::interner::SymbolId;

#[test]
fn test_ir_lowering_arithmetic() {
    let span = Span { start: 0, end: 0, file_id: 0 };
    // let x = 1 + 2;
    let prog = Program {
        statements: vec![
            Stmt::Let {
                name: "x".to_string(),
                value: Expr::Binary {
                    op: BinOp::Add,
                    left: Box::new(Expr::Literal { value: Literal::Int(1), span: span.clone() }),
                    right: Box::new(Expr::Literal { value: Literal::Int(2), span: span.clone() }),
                    span: span.clone()
                },
                span: span.clone()
            }
        ]
    };

    let (ir, interner) = LoweringContext::new().build(&prog);
    
    // Check if "x" is interned
    // We don't know the exact ID without checking interner, but Lowering probably assigned one.
    // The test logic needs to verify the structure.
    
    assert!(!ir.instructions.is_empty());
    match &ir.instructions[0] {
        Instr::Binary { dest, op, .. } => {
            assert_eq!(*op, Op::Add);
        }
        _ => panic!("Expected Binary instruction"),
    }
    match &ir.instructions[1] {
        Instr::Assign { dest, src } => {
            match dest {
                Operand::Var(id) => {
                     // Verify ID resolves to "x"
                     assert_eq!(interner.resolve(*id), "x");
                },
                _ => panic!("Expected Var(x)"),
            }
        }
        _ => panic!("Expected Assign instruction"),
    }
}
