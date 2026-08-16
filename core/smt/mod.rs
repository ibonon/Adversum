pub mod ast;
pub mod symbolic;
pub mod invariants;
pub mod solver;

pub use ast::{SmtExpr, SmtVar, Sort};
pub use symbolic::{SymbolicState, execute_symbolically, symbolize_function};
pub use invariants::{SecurityInvariant, InvariantQuery, InvariantContext};
pub use solver::{SmtSolver, SmtResult, Interval};

use serde::{Serialize, Deserialize};
use pyo3::prelude::*;
use crate::ir::types::{FunctionIR, Program};

/// Résultat complet d'une vérification formelle SMT exposé à Python via PyO3
#[pyclass(get_all)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtProofResult {
    /// "PROVED" si UNSAT (invariant garanti), "VIOLATED" si SAT (contre-exemple), "UNKNOWN" sinon
    pub verdict: String,
    /// Description de l'invariant vérifié
    pub invariant: String,
    /// Contre-exemple concret (si SAT)
    pub counterexample: Option<String>,
    /// Formule SMT-LIB2 générée
    pub smtlib2_formula: String,
    /// Nom de la fonction ou fichier analysé
    pub target: String,
}

#[pymethods]
impl SmtProofResult {
    #[new]
    #[pyo3(signature = (verdict, invariant, counterexample, smtlib2_formula, target))]
    fn new(verdict: String, invariant: String, counterexample: Option<String>,
           smtlib2_formula: String, target: String) -> Self {
        Self { verdict, invariant, counterexample, smtlib2_formula, target }
    }

    fn __repr__(&self) -> String {
        format!("SmtProofResult(verdict={}, invariant={})", self.verdict, self.invariant)
    }
}

/// Vérifie un invariant de sécurité sur une FunctionIR sérialisée en JSON
/// Appelable depuis Python: adversum_core.verify_invariant_smt(ir_json, invariant_type, target)
#[pyfunction]
pub fn verify_invariant_smt(ir_json: &str, invariant_type: &str, target: &str) -> PyResult<SmtProofResult> {
    // Désérialiser la FunctionIR depuis JSON
    let func: FunctionIR = serde_json::from_str(ir_json)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Invalid IR JSON: {}", e)))?;

    // Choisir l'invariant
    let invariant = match invariant_type {
        "overflow" | "NoArithmeticOverflow" => SecurityInvariant::NoArithmeticOverflow,
        "divzero" | "DivisionByZeroSafe"   => SecurityInvariant::DivisionByZeroSafe,
        "path" | "PathTraversalSafe"        => SecurityInvariant::PathTraversalSafe,
        "nonneg" | "NonNegativeReturn"      => SecurityInvariant::NonNegativeReturn,
        other => SecurityInvariant::Custom(other.to_string()),
    };

    // Exécution symbolique
    let mut state = SymbolicState::new();
    for &param in &func.params {
        let name = format!("param_{}", param.0);
        let expr = state.fresh_input(&name, Sort::Int);
        state.registers.insert(format!("v{}", param.0), expr);
    }
    execute_symbolically(&func.instructions, &mut state);

    // Générer la formule de vérification
    let ctx = InvariantContext {
        function_name: format!("{}", func.name.0),
        file_path: target.to_string(),
    };
    let query = invariant.to_query(&state, &ctx);
    
    // Lancer le solveur
    let solver = SmtSolver::new();
    let smtlib2 = solver.to_smtlib2_script(&query.violation_formula, &query.declared_vars);
    let result = solver.check(&query.violation_formula, &query.declared_vars);

    let (verdict, counterexample) = match result {
        SmtResult::Unsat => ("PROVED".to_string(), None),
        SmtResult::Sat { model } => {
            let ce = model.iter()
                .map(|(k, v)| format!("{} = {}", k, v))
                .collect::<Vec<_>>()
                .join(", ");
            ("VIOLATED".to_string(), Some(ce))
        }
        SmtResult::Unknown(msg) => ("UNKNOWN".to_string(), Some(msg)),
    };

    Ok(SmtProofResult {
        verdict,
        invariant: query.description,
        counterexample,
        smtlib2_formula: smtlib2,
        target: target.to_string(),
    })
}
