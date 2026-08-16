use std::collections::HashMap;
use super::ast::{SmtExpr, Sort, SmtVar};
use serde::{Serialize, Deserialize};

/// Résultat de la vérification SMT
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SmtResult {
    /// La formule est UNSATISFIABLE => l'invariant est prouvé (aucune violation possible)
    Unsat,
    /// La formule est SATISFIABLE => contre-exemple trouvé (violation possible)
    Sat {
        /// Assignation concrète des variables symboliques (contre-exemple)
        model: HashMap<String, String>,
    },
    /// Timeout ou ressources épuisées
    Unknown(String),
}

/// Intervalle de valeurs entières pour ICP
#[derive(Debug, Clone, PartialEq)]
pub struct Interval {
    pub lo: Option<i64>, // None = -∞
    pub hi: Option<i64>, // None = +∞
}

impl Interval {
    pub fn unbounded() -> Self { Interval { lo: None, hi: None } }
    pub fn point(n: i64) -> Self { Interval { lo: Some(n), hi: Some(n) } }
    pub fn non_neg() -> Self { Interval { lo: Some(0), hi: None } }
    pub fn positive() -> Self { Interval { lo: Some(1), hi: None } }
    pub fn negative() -> Self { Interval { lo: None, hi: Some(-1) } }

    pub fn is_empty(&self) -> bool {
        match (self.lo, self.hi) {
            (Some(lo), Some(hi)) => lo > hi,
            _ => false,
        }
    }

    pub fn contains_zero(&self) -> bool {
        let lo_ok = self.lo.map_or(true, |lo| lo <= 0);
        let hi_ok = self.hi.map_or(true, |hi| hi >= 0);
        lo_ok && hi_ok
    }

    pub fn intersect(&self, other: &Interval) -> Interval {
        let lo = match (self.lo, other.lo) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
        let hi = match (self.hi, other.hi) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };
        Interval { lo, hi }
    }

    pub fn add(&self, other: &Interval) -> Interval {
        let lo = self.lo.zip(other.lo).map(|(a, b)| a.saturating_add(b));
        let hi = self.hi.zip(other.hi).map(|(a, b)| a.saturating_add(b));
        Interval { lo, hi }
    }
}

/// Domaine d'intervalles pour chaque variable
pub type Domain = HashMap<String, Interval>;

/// Résolveur SMT avec:
/// 1. Simplification algébrique (propagation de constantes)
/// 2. Interval Constraint Propagation (ICP) pour l'arithmétique entière
/// 3. DPLL simplifié pour la logique propositionnelle
/// 4. Export SMT-LIB2 pour Z3/CVC5 externe optionnel
pub struct SmtSolver {
    pub max_depth: usize,
    pub timeout_ms: u64,
}

impl SmtSolver {
    pub fn new() -> Self {
        SmtSolver { max_depth: 50, timeout_ms: 5000 }
    }

    /// Point d'entrée principal: vérifie si la formule est SAT ou UNSAT
    pub fn check(&self, formula: &SmtExpr, declared_vars: &[SmtVar]) -> SmtResult {
        // Étape 1 : Simplification algébrique
        let simplified = self.simplify(formula);

        // Cas triviaux après simplification
        if let SmtExpr::BoolLit(false) = &simplified {
            return SmtResult::Unsat;
        }
        if let SmtExpr::BoolLit(true) = &simplified {
            // Formule triviallement vraie: SAT avec modèle vide
            return SmtResult::Sat { model: HashMap::new() };
        }

        // Étape 2 : Interval Constraint Propagation
        let mut domain: Domain = declared_vars.iter()
            .filter(|v| v.sort == Sort::Int)
            .map(|v| (v.name.clone(), Interval::unbounded()))
            .collect();

        match self.icp_propagate(&simplified, &mut domain) {
            IcpResult::Contradiction => return SmtResult::Unsat,
            IcpResult::Narrowed => {}
            IcpResult::Unchanged => {}
        }

        // Étape 3 : Vérification si le domaine est vide (UNSAT) ou contient une valeur concrète (SAT)
        let all_empty = domain.values().all(|iv| iv.is_empty());
        if all_empty && !domain.is_empty() {
            return SmtResult::Unsat;
        }

        // Étape 4 : Extraire un modèle concret si SAT
        let model: HashMap<String, String> = domain.iter()
            .map(|(name, iv)| {
                let val = iv.lo.or(iv.hi).unwrap_or(0);
                (name.clone(), val.to_string())
            })
            .collect();

        SmtResult::Sat { model }
    }

    /// Simplification algébrique récursive (constant folding + tautology elimination)
    pub fn simplify(&self, expr: &SmtExpr) -> SmtExpr {
        match expr {
            // Constantes — déjà simplifiées
            SmtExpr::BoolLit(_) | SmtExpr::IntLit(_) | SmtExpr::BitVecLit { .. } |
            SmtExpr::StrLit(_) | SmtExpr::Var(_) => expr.clone(),

            // Not(Not(x)) = x
            SmtExpr::Not(inner) => {
                let s = self.simplify(inner);
                match &s {
                    SmtExpr::BoolLit(b) => SmtExpr::BoolLit(!b),
                    SmtExpr::Not(inner2) => *inner2.clone(),
                    _ => SmtExpr::Not(Box::new(s)),
                }
            }

            // And([true, ...]) = And([...])
            // And([false, ...]) = false
            SmtExpr::And(parts) => {
                let mut simplified_parts = Vec::new();
                for part in parts {
                    let s = self.simplify(part);
                    match &s {
                        SmtExpr::BoolLit(false) => return SmtExpr::BoolLit(false),
                        SmtExpr::BoolLit(true) => {} // skip true
                        _ => simplified_parts.push(s),
                    }
                }
                match simplified_parts.len() {
                    0 => SmtExpr::BoolLit(true),
                    1 => simplified_parts.remove(0),
                    _ => SmtExpr::And(simplified_parts),
                }
            }

            // Or([false, ...]) = Or([...])
            // Or([true, ...]) = true
            SmtExpr::Or(parts) => {
                let mut simplified_parts = Vec::new();
                for part in parts {
                    let s = self.simplify(part);
                    match &s {
                        SmtExpr::BoolLit(true) => return SmtExpr::BoolLit(true),
                        SmtExpr::BoolLit(false) => {} // skip false
                        _ => simplified_parts.push(s),
                    }
                }
                match simplified_parts.len() {
                    0 => SmtExpr::BoolLit(false),
                    1 => simplified_parts.remove(0),
                    _ => SmtExpr::Or(simplified_parts),
                }
            }

            // Arithmetic constant folding
            SmtExpr::Add(a, b) => {
                let sa = self.simplify(a); let sb = self.simplify(b);
                match (&sa, &sb) {
                    (SmtExpr::IntLit(x), SmtExpr::IntLit(y)) => SmtExpr::IntLit(x.saturating_add(*y)),
                    (SmtExpr::IntLit(0), _) => sb,
                    (_, SmtExpr::IntLit(0)) => sa,
                    _ => SmtExpr::Add(Box::new(sa), Box::new(sb)),
                }
            }
            SmtExpr::Sub(a, b) => {
                let sa = self.simplify(a); let sb = self.simplify(b);
                match (&sa, &sb) {
                    (SmtExpr::IntLit(x), SmtExpr::IntLit(y)) => SmtExpr::IntLit(x.saturating_sub(*y)),
                    (_, SmtExpr::IntLit(0)) => sa,
                    _ => SmtExpr::Sub(Box::new(sa), Box::new(sb)),
                }
            }
            SmtExpr::Mul(a, b) => {
                let sa = self.simplify(a); let sb = self.simplify(b);
                match (&sa, &sb) {
                    (SmtExpr::IntLit(x), SmtExpr::IntLit(y)) => SmtExpr::IntLit(x.saturating_mul(*y)),
                    (SmtExpr::IntLit(0), _) | (_, SmtExpr::IntLit(0)) => SmtExpr::IntLit(0),
                    (SmtExpr::IntLit(1), _) => sb,
                    (_, SmtExpr::IntLit(1)) => sa,
                    _ => SmtExpr::Mul(Box::new(sa), Box::new(sb)),
                }
            }

            // Comparison constant folding
            SmtExpr::Eq(a, b) => {
                let sa = self.simplify(a); let sb = self.simplify(b);
                match (&sa, &sb) {
                    (SmtExpr::IntLit(x), SmtExpr::IntLit(y)) => SmtExpr::BoolLit(x == y),
                    (SmtExpr::BoolLit(x), SmtExpr::BoolLit(y)) => SmtExpr::BoolLit(x == y),
                    _ => if sa == sb { SmtExpr::BoolLit(true) } else { SmtExpr::Eq(Box::new(sa), Box::new(sb)) },
                }
            }
            SmtExpr::Lt(a, b) => {
                let sa = self.simplify(a); let sb = self.simplify(b);
                match (&sa, &sb) {
                    (SmtExpr::IntLit(x), SmtExpr::IntLit(y)) => SmtExpr::BoolLit(x < y),
                    _ => SmtExpr::Lt(Box::new(sa), Box::new(sb)),
                }
            }
            SmtExpr::Le(a, b) => {
                let sa = self.simplify(a); let sb = self.simplify(b);
                match (&sa, &sb) {
                    (SmtExpr::IntLit(x), SmtExpr::IntLit(y)) => SmtExpr::BoolLit(x <= y),
                    _ => SmtExpr::Le(Box::new(sa), Box::new(sb)),
                }
            }
            SmtExpr::Gt(a, b) => {
                let sa = self.simplify(a); let sb = self.simplify(b);
                match (&sa, &sb) {
                    (SmtExpr::IntLit(x), SmtExpr::IntLit(y)) => SmtExpr::BoolLit(x > y),
                    _ => SmtExpr::Gt(Box::new(sa), Box::new(sb)),
                }
            }
            SmtExpr::Ge(a, b) => {
                let sa = self.simplify(a); let sb = self.simplify(b);
                match (&sa, &sb) {
                    (SmtExpr::IntLit(x), SmtExpr::IntLit(y)) => SmtExpr::BoolLit(x >= y),
                    _ => SmtExpr::Ge(Box::new(sa), Box::new(sb)),
                }
            }
            SmtExpr::Implies(a, b) => {
                let sa = self.simplify(a); let sb = self.simplify(b);
                match (&sa, &sb) {
                    (SmtExpr::BoolLit(false), _) => SmtExpr::BoolLit(true),
                    (_, SmtExpr::BoolLit(true)) => SmtExpr::BoolLit(true),
                    (SmtExpr::BoolLit(true), _) => sb,
                    _ => SmtExpr::Implies(Box::new(sa), Box::new(sb)),
                }
            }
            // Fallback: return as-is
            other => other.clone(),
        }
    }

    /// Retourne la représentation SMT-LIB2 complète avec déclarations de variables
    pub fn to_smtlib2_script(&self, formula: &SmtExpr, declared_vars: &[SmtVar]) -> String {
        let mut out = String::new();
        out.push_str("(set-logic QF_ALIA)\n");
        for var in declared_vars {
            out.push_str(&format!("(declare-const {} {})\n", var.name, var.sort.to_smtlib2()));
        }
        out.push_str(&format!("(assert {})\n", formula.to_smtlib2()));
        out.push_str("(check-sat)\n");
        out.push_str("(get-model)\n");
        out
    }
}

impl Default for SmtSolver { fn default() -> Self { Self::new() } }

/// Résultat d'une étape ICP
#[derive(Debug)]
enum IcpResult {
    Contradiction,
    Narrowed,
    Unchanged,
}

impl SmtSolver {
    /// Propagation d'intervalles sur une formule SMT
    fn icp_propagate(&self, formula: &SmtExpr, domain: &mut Domain) -> IcpResult {
        match formula {
            SmtExpr::And(parts) => {
                let mut changed = false;
                for part in parts {
                    match self.icp_propagate(part, domain) {
                        IcpResult::Contradiction => return IcpResult::Contradiction,
                        IcpResult::Narrowed => changed = true,
                        IcpResult::Unchanged => {}
                    }
                }
                if changed { IcpResult::Narrowed } else { IcpResult::Unchanged }
            }
            // x >= 0  =>  domain[x].lo = max(0, current_lo)
            SmtExpr::Ge(left, right) => {
                if let (SmtExpr::Var(v), SmtExpr::IntLit(n)) = (left.as_ref(), right.as_ref()) {
                    if let Some(iv) = domain.get_mut(&v.name) {
                        let new_lo = Some(iv.lo.map_or(*n, |lo| lo.max(*n)));
                        if new_lo != iv.lo { iv.lo = new_lo; return IcpResult::Narrowed; }
                    }
                }
                IcpResult::Unchanged
            }
            // x > 0  =>  domain[x].lo = max(1, current_lo)
            SmtExpr::Gt(left, right) => {
                if let (SmtExpr::Var(v), SmtExpr::IntLit(n)) = (left.as_ref(), right.as_ref()) {
                    if let Some(iv) = domain.get_mut(&v.name) {
                        let new_lo = Some(iv.lo.map_or(*n + 1, |lo| lo.max(*n + 1)));
                        if new_lo != iv.lo { iv.lo = new_lo; return IcpResult::Narrowed; }
                    }
                }
                IcpResult::Unchanged
            }
            // x <= n  =>  domain[x].hi = min(n, current_hi)
            SmtExpr::Le(left, right) => {
                if let (SmtExpr::Var(v), SmtExpr::IntLit(n)) = (left.as_ref(), right.as_ref()) {
                    if let Some(iv) = domain.get_mut(&v.name) {
                        let new_hi = Some(iv.hi.map_or(*n, |hi| hi.min(*n)));
                        if new_hi != iv.hi { iv.hi = new_hi; return IcpResult::Narrowed; }
                    }
                }
                IcpResult::Unchanged
            }
            // x == 0  =>  domain[x] = [0, 0]
            SmtExpr::Eq(left, right) => {
                if let (SmtExpr::Var(v), SmtExpr::IntLit(n)) = (left.as_ref(), right.as_ref()) {
                    if let Some(iv) = domain.get_mut(&v.name) {
                        let new_iv = Interval::point(*n);
                        if iv.is_empty() { return IcpResult::Contradiction; }
                        let intersected = iv.intersect(&new_iv);
                        if intersected.is_empty() { return IcpResult::Contradiction; }
                        *iv = intersected;
                        return IcpResult::Narrowed;
                    }
                }
                IcpResult::Unchanged
            }
            // x < 0  =>  domain[x].hi = min(-1, current_hi)
            SmtExpr::Lt(left, right) => {
                if let (SmtExpr::Var(v), SmtExpr::IntLit(n)) = (left.as_ref(), right.as_ref()) {
                    if let Some(iv) = domain.get_mut(&v.name) {
                        let new_hi = Some(iv.hi.map_or(*n - 1, |hi| hi.min(*n - 1)));
                        if new_hi != iv.hi { iv.hi = new_hi; return IcpResult::Narrowed; }
                    }
                }
                IcpResult::Unchanged
            }
            _ => IcpResult::Unchanged,
        }
    }
}
