use super::ast::{SmtExpr, Sort};
use super::symbolic::SymbolicState;
use serde::{Serialize, Deserialize};

/// Invariants de sécurité formels vérifiables par SMT
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityInvariant {
    /// Overflow: a + b <= MAX_UINT256 (pour Solidity/Vyper)
    NoArithmeticOverflow,
    /// Division sûre: le dénominateur est toujours != 0
    DivisionByZeroSafe,
    /// Chemin sûr: resolved_path.starts_with(base_dir) — modélisé symboliquement
    PathTraversalSafe,
    /// Le return value est toujours positif ou nul
    NonNegativeReturn,
    /// Aucune exécution ne peut atteindre un état unsafe (personnalisé)
    Custom(String),
}

/// Formule SMT représentant la négation de l'invariant (pour prouver par réfutation)
/// Si la formule est UNSAT => l'invariant est prouvé.
/// Si la formule est SAT   => le modèle est un contre-exemple (violation).
pub struct InvariantQuery {
    /// Formule représentant la condition d'ERREUR (negation de l'invariant)
    pub violation_formula: SmtExpr,
    /// Variables symboliques déclarées (pour le header SMT-LIB2)
    pub declared_vars: Vec<super::ast::SmtVar>,
    /// Description textuelle
    pub description: String,
}

impl SecurityInvariant {
    /// Génère la formule SMT de vérification pour cet invariant,
    /// en tenant compte de l'état symbolique après exécution.
    pub fn to_query(&self, state: &SymbolicState, context: &InvariantContext) -> InvariantQuery {
        match self {
            SecurityInvariant::NoArithmeticOverflow => {
                // Pour chaque opération arithmétique dans l'état symbolique,
                // vérifier que le résultat est dans [0, 2^256 - 1]
                // On cherche si une addition peut déborder : a + b > MAX
                let max_uint256 = SmtExpr::IntLit(i64::MAX); // Approximation pour demo (vrai: 2^256-1)
                let a = SmtExpr::int_var("sym_a");
                let b = SmtExpr::int_var("sym_b");
                // Violation: a >= 0 AND b >= 0 AND a + b > MAX
                let violation = SmtExpr::And(vec![
                    state.path_formula(),
                    SmtExpr::Ge(Box::new(a.clone()), Box::new(SmtExpr::IntLit(0))),
                    SmtExpr::Ge(Box::new(b.clone()), Box::new(SmtExpr::IntLit(0))),
                    SmtExpr::Gt(
                        Box::new(SmtExpr::Add(Box::new(a.clone()), Box::new(b.clone()))),
                        Box::new(max_uint256),
                    ),
                ]);
                InvariantQuery {
                    violation_formula: violation,
                    declared_vars: vec![
                        super::ast::SmtVar { name: "sym_a".to_string(), sort: Sort::Int },
                        super::ast::SmtVar { name: "sym_b".to_string(), sort: Sort::Int },
                    ],
                    description: "Arithmetic overflow: a + b may exceed MAX_UINT256".to_string(),
                }
            }
            SecurityInvariant::DivisionByZeroSafe => {
                // Violation: le dénominateur est == 0
                let denom = state.registers.get("__denominator__")
                    .cloned()
                    .unwrap_or_else(|| SmtExpr::int_var("sym_denom"));
                let violation = SmtExpr::And(vec![
                    state.path_formula(),
                    SmtExpr::Eq(Box::new(denom), Box::new(SmtExpr::IntLit(0))),
                ]);
                InvariantQuery {
                    violation_formula: violation,
                    declared_vars: state.declared_vars.clone(),
                    description: "Division by zero: denominator may be 0".to_string(),
                }
            }
            SecurityInvariant::PathTraversalSafe => {
                // Modèle simplifié: si resolved_path contient ".." alors violation
                // On représente le path comme une variable String symbolique
                // et on cherche si la contrainte "path contains .." est satisfiable
                let path_var = SmtExpr::bool_var("path_contains_dotdot");
                let violation = SmtExpr::And(vec![
                    state.path_formula(),
                    path_var, // True si le path contient ..
                ]);
                InvariantQuery {
                    violation_formula: violation,
                    declared_vars: vec![
                        super::ast::SmtVar { name: "path_contains_dotdot".to_string(), sort: Sort::Bool },
                    ],
                    description: "Path traversal: resolved path may escape base directory".to_string(),
                }
            }
            SecurityInvariant::NonNegativeReturn => {
                let ret = state.registers.get("__return__")
                    .cloned()
                    .unwrap_or_else(|| SmtExpr::int_var("sym_ret"));
                let violation = SmtExpr::And(vec![
                    state.path_formula(),
                    SmtExpr::Lt(Box::new(ret), Box::new(SmtExpr::IntLit(0))),
                ]);
                InvariantQuery {
                    violation_formula: violation,
                    declared_vars: state.declared_vars.clone(),
                    description: "Return value may be negative".to_string(),
                }
            }
            SecurityInvariant::Custom(desc) => {
                InvariantQuery {
                    violation_formula: SmtExpr::BoolLit(false), // UNSAT trivial
                    declared_vars: vec![],
                    description: format!("Custom invariant: {}", desc),
                }
            }
        }
    }
}

/// Contexte supplémentaire pour la génération de formules
#[derive(Debug, Default)]
pub struct InvariantContext {
    pub function_name: String,
    pub file_path: String,
}
