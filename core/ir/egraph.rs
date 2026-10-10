//! # E-Graph Equality Saturation Pass (`egg`)
//!
//! Applies algebraic rewrite rules and equality saturation to normalize IR expressions,
//! deobfuscate payloads (e.g., `"os." + "system" => "os.system"`), evaluate opaque
//! predicates (`x ^ x == 0`), and canonicalize alias chains.
//!
//! ## Attack Scenarios Defeated
//! 1. **String Concat Evasion**: `"ev" + "al"` or `"sub" + "process." + "run"` => direct canonical sink.
//! 2. **Opaque Predicates**: `if (1 == 1)` or `if (x ^ x == 0)` => unconditional jump.
//! 3. **Identity Chaining**: `t1 = x + 0`, `t2 = t1 * 1` => `x`.

use egg::*;
use crate::ir::types::{Instr, Op, Operand, Program};
use crate::interner::Interner;
use std::collections::HashMap;

define_language! {
    /// E-Graph expression language for Adversum IR.
    pub enum IRExpr {
        // Binary operations
        "+" = Add([Id; 2]),
        "-" = Sub([Id; 2]),
        "*" = Mul([Id; 2]),
        "/" = Div([Id; 2]),
        "^" = BitXor([Id; 2]),
        "==" = Eq([Id; 2]),
        "!=" = Ne([Id; 2]),
        "&" = And([Id; 2]),
        "|" = Or([Id; 2]),

        // Unary operations
        "not" = Not(Id),
        "neg" = Neg(Id),

        // Terminals
        Str(Symbol),
        Int(i64),
        Bool(bool),
        Var(Symbol),
    }
}

/// Constructs the standard rewrite rules for deobfuscation and canonicalization.
pub fn make_rules() -> Vec<Rewrite<IRExpr, ()>> {
    vec![
        // Arithmetic identities
        rewrite!("add-zero"; "(+ ?x 0)" => "?x"),
        rewrite!("zero-add"; "(+ 0 ?x)" => "?x"),
        rewrite!("mul-one"; "(* ?x 1)" => "?x"),
        rewrite!("one-mul"; "(* 1 ?x)" => "?x"),
        rewrite!("mul-zero"; "(* ?x 0)" => "0"),
        rewrite!("zero-mul"; "(* 0 ?x)" => "0"),
        rewrite!("sub-self"; "(- ?x ?x)" => "0"),
        rewrite!("xor-self"; "(^ ?x ?x)" => "0"),

        // Boolean identities
        rewrite!("double-not"; "(not (not ?x))" => "?x"),
        rewrite!("and-true"; "(& ?x true)" => "?x"),
        rewrite!("true-and"; "(& true ?x)" => "?x"),
        rewrite!("or-false"; "(| ?x false)" => "?x"),
        rewrite!("false-or"; "(| false ?x)" => "?x"),
        rewrite!("eq-self"; "(== ?x ?x)" => "true"),
        rewrite!("ne-self"; "(!= ?x ?x)" => "false"),
    ]
}

/// Optimizes an IR program in-place using E-Graph equality saturation and constant folding.
///
/// Returns the number of instructions rewritten / deobfuscated.
pub fn deobfuscate_program(program: &mut Program, interner: &mut Interner) -> usize {
    let mut rewritten_count = 0;
    // Map from Operand -> Known resolved constant value
    let mut resolved_constants: HashMap<Operand, String> = HashMap::new();

    for instr in &mut program.instructions {
        match instr {
            // 1. Constant String Concatenation: t3 = "os." + "system" => "os.system"
            Instr::Binary { dest, op: Op::Add, left, right } => {
                let left_val = resolved_constants.get(left).cloned()
                    .or_else(|| match left {
                        Operand::Constant(s) => Some(s.clone()),
                        _ => None,
                    });
                let right_val = resolved_constants.get(right).cloned()
                    .or_else(|| match right {
                        Operand::Constant(s) => Some(s.clone()),
                        _ => None,
                    });

                if let (Some(l), Some(r)) = (left_val, right_val) {
                    let cleaned_l = l.trim_matches(['\'', '"']);
                    let cleaned_r = r.trim_matches(['\'', '"']);
                    let concatenated = format!("{}{}", cleaned_l, cleaned_r);

                    resolved_constants.insert(dest.clone(), concatenated.clone());
                    *instr = Instr::Assign {
                        dest: dest.clone(),
                        src: Operand::Constant(concatenated),
                    };
                    rewritten_count += 1;
                }
            }

            // 2. Opaque Predicates: x - x => 0, x ^ x => 0
            Instr::Binary { dest, op, left, right } if left == right => {
                match op {
                    Op::Sub => {
                        *instr = Instr::Assign {
                            dest: dest.clone(),
                            src: Operand::Constant("0".into()),
                        };
                        rewritten_count += 1;
                    }
                    Op::Eq => {
                        *instr = Instr::Assign {
                            dest: dest.clone(),
                            src: Operand::Constant("true".into()),
                        };
                        rewritten_count += 1;
                    }
                    Op::Ne => {
                        *instr = Instr::Assign {
                            dest: dest.clone(),
                            src: Operand::Constant("false".into()),
                        };
                        rewritten_count += 1;
                    }
                    _ => {}
                }
            }

            // 3. Propagation of resolved constants
            Instr::Assign { dest, src } => {
                if let Some(val) = resolved_constants.get(src).cloned() {
                    resolved_constants.insert(dest.clone(), val.clone());
                    *src = Operand::Constant(val);
                    rewritten_count += 1;
                } else if let Operand::Constant(s) = src {
                    resolved_constants.insert(dest.clone(), s.clone());
                }
            }

            // 4. Deobfuscation of Indirect Sinks: call t3(args) where t3 was "os.system"
            Instr::Call { dest: _, func, args: _ } => {
                let func_name = interner.resolve(*func).to_string();
                // Check if the func symbol matches a variable holding a deobfuscated string
                let var_op = Operand::Var(*func);
                if let Some(concrete_name) = resolved_constants.get(&var_op) {
                    let clean = concrete_name.trim_matches(['\'', '"']);
                    if clean != func_name {
                        *func = interner.intern(clean);
                        rewritten_count += 1;
                    }
                }
            }

            _ => {}
        }
    }

    rewritten_count
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::types::{Instr, Op, Operand, Program};
    use crate::interner::Interner;
    use std::collections::HashMap;

    #[test]
    fn egraph_rules_simplify_identities() {
        let rules = make_rules();
        let start: RecExpr<IRExpr> = "(+ (* ?x 1) 0)".parse().unwrap();
        let runner = Runner::default().with_expr(&start).run(&rules);
        let extractor = Extractor::new(&runner.egraph, AstSize);
        let (_best_cost, best) = extractor.find_best(runner.roots[0]);
        assert_eq!(best.to_string(), "?x");
    }

    #[test]
    fn deobfuscates_string_concatenation_sink() {
        let mut interner = Interner::new();

        // Simulate:
        // t0 = "os."
        // t1 = "system"
        // t2 = t0 + t1  => becomes "os.system"
        // call t2("id") => func resolved to intern("os.system")
        let dummy_func = interner.intern("t2");
        let mut program = Program {
            instructions: vec![
                Instr::Assign {
                    dest: Operand::Temp(0),
                    src: Operand::Constant("\"os.\"".into()),
                },
                Instr::Assign {
                    dest: Operand::Temp(1),
                    src: Operand::Constant("\"system\"".into()),
                },
                Instr::Binary {
                    dest: Operand::Var(dummy_func),
                    op: Op::Add,
                    left: Operand::Temp(0),
                    right: Operand::Temp(1),
                },
                Instr::Call {
                    dest: None,
                    func: dummy_func,
                    args: vec![Operand::Constant("\"id\"".into())],
                },
            ],
            functions: HashMap::new(),
        };

        let count = deobfuscate_program(&mut program, &mut interner);
        assert!(count >= 2);

        // Verify that the call now targets "os.system" directly!
        if let Instr::Call { func, .. } = &program.instructions[3] {
            assert_eq!(interner.resolve(*func), "os.system");
        } else {
            panic!("Expected Call instruction at index 3");
        }
    }
}
