use crate::interner::SymbolId;
use crate::ir::types::{Instr, Op, Operand, Program};

use super::ast::{SmtBinaryOp, SmtExpr, SmtSort};
use super::invariants::InvariantType;
use super::solver::{SmtSolveStatus, SmtSolver};
use super::symbolic::SymbolicExecutor;
use super::verify_program;

#[test]
fn symbolic_executor_tracks_arithmetic_expressions() {
    let program = Program {
        instructions: vec![
            Instr::Assign {
                dest: Operand::Temp(0),
                src: Operand::Constant("4".into()),
            },
            Instr::Binary {
                dest: Operand::Temp(1),
                op: Op::Add,
                left: Operand::Temp(0),
                right: Operand::Constant("2".into()),
            },
            Instr::Return(Some(Operand::Temp(1))),
        ],
        functions: Default::default(),
    };

    let states = SymbolicExecutor::execute(&program);
    let state = states.first().expect("final symbolic state");
    let expr = state
        .registers
        .get(&Operand::Temp(1))
        .expect("symbolic register t1");

    assert_eq!(
        expr,
        &SmtExpr::binary(
            SmtBinaryOp::Add,
            SmtExpr::int_const(4),
            SmtExpr::int_const(2)
        )
    );
}

#[test]
fn solver_proves_valid_arithmetic_invariant_by_unsat() {
    let x = SmtExpr::var("x", SmtSort::Int);
    let constraints = vec![
        SmtExpr::binary(SmtBinaryOp::Gt, x.clone(), SmtExpr::int_const(0)),
        SmtExpr::not(SmtExpr::binary(
            SmtBinaryOp::Gt,
            SmtExpr::binary(SmtBinaryOp::Add, x, SmtExpr::int_const(1)),
            SmtExpr::int_const(1),
        )),
    ];

    let result = SmtSolver::solve(&constraints);
    assert_eq!(result.status, SmtSolveStatus::Unsat);
}

#[test]
fn division_by_zero_invariant_returns_counterexample() {
    let program = Program {
        instructions: vec![
            Instr::Binary {
                dest: Operand::Temp(0),
                op: Op::Div,
                left: Operand::Constant("10".into()),
                right: Operand::Var(SymbolId(7)),
            },
            Instr::Return(Some(Operand::Temp(0))),
        ],
        functions: Default::default(),
    };

    let result = verify_program(&program, InvariantType::DivisionByZeroSafe);

    assert_eq!(result.status, "violated");
    assert_eq!(
        result
            .counterexample
            .as_ref()
            .and_then(|model| model.get("v7"))
            .map(String::as_str),
        Some("0")
    );
}
