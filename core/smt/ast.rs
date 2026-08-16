use serde::{Serialize, Deserialize};

/// Sorts SMT (types logiques)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Sort {
    Bool,
    Int,
    Real,
    BitVec(u32),            // BitVec(256) pour uint256 Solidity
    Array(Box<Sort>, Box<Sort>), // Array(key, value)
    Str,
}

/// Variable SMT nommée avec un sort
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmtVar {
    pub name: String,
    pub sort: Sort,
}

/// Expression SMT complète (termes + formules)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SmtExpr {
    // Constantes
    BoolLit(bool),
    IntLit(i64),
    BitVecLit { value: u64, width: u32 },
    StrLit(String),
    
    // Variables symboliques
    Var(SmtVar),
    
    // Opérateurs arithmétiques (Int)
    Add(Box<SmtExpr>, Box<SmtExpr>),
    Sub(Box<SmtExpr>, Box<SmtExpr>),
    Mul(Box<SmtExpr>, Box<SmtExpr>),
    Div(Box<SmtExpr>, Box<SmtExpr>),
    Mod(Box<SmtExpr>, Box<SmtExpr>),
    Neg(Box<SmtExpr>),
    
    // Opérateurs BitVec (pour uint256)
    BvAdd(Box<SmtExpr>, Box<SmtExpr>),
    BvSub(Box<SmtExpr>, Box<SmtExpr>),
    BvMul(Box<SmtExpr>, Box<SmtExpr>),
    BvUdiv(Box<SmtExpr>, Box<SmtExpr>),
    BvUrem(Box<SmtExpr>, Box<SmtExpr>),
    BvAnd(Box<SmtExpr>, Box<SmtExpr>),
    BvOr(Box<SmtExpr>, Box<SmtExpr>),
    BvXor(Box<SmtExpr>, Box<SmtExpr>),
    BvShl(Box<SmtExpr>, Box<SmtExpr>),
    BvLshr(Box<SmtExpr>, Box<SmtExpr>),
    
    // Comparaisons
    Eq(Box<SmtExpr>, Box<SmtExpr>),
    Ne(Box<SmtExpr>, Box<SmtExpr>),
    Lt(Box<SmtExpr>, Box<SmtExpr>),
    Le(Box<SmtExpr>, Box<SmtExpr>),
    Gt(Box<SmtExpr>, Box<SmtExpr>),
    Ge(Box<SmtExpr>, Box<SmtExpr>),
    BvUlt(Box<SmtExpr>, Box<SmtExpr>),
    BvUle(Box<SmtExpr>, Box<SmtExpr>),
    BvUgt(Box<SmtExpr>, Box<SmtExpr>),
    BvUge(Box<SmtExpr>, Box<SmtExpr>),
    
    // Logique propositionnelle
    And(Vec<SmtExpr>),
    Or(Vec<SmtExpr>),
    Not(Box<SmtExpr>),
    Implies(Box<SmtExpr>, Box<SmtExpr>),
    Ite(Box<SmtExpr>, Box<SmtExpr>, Box<SmtExpr>), // if-then-else
    
    // Arrays
    Select(Box<SmtExpr>, Box<SmtExpr>),            // array[index]
    Store(Box<SmtExpr>, Box<SmtExpr>, Box<SmtExpr>), // array[index] = value
}

impl SmtExpr {
    /// Serialize to SMT-LIB2 format string
    pub fn to_smtlib2(&self) -> String {
        match self {
            SmtExpr::BoolLit(b) => if *b { "true".to_string() } else { "false".to_string() },
            SmtExpr::IntLit(n) => if *n < 0 { format!("(- {})", -n) } else { n.to_string() },
            SmtExpr::BitVecLit { value, width } => format!("(_ bv{} {})", value, width),
            SmtExpr::StrLit(s) => format!("\"{}\"", s.replace('"', "\\\"")),
            SmtExpr::Var(v) => v.name.clone(),
            SmtExpr::Add(a, b) => format!("(+ {} {})", a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::Sub(a, b) => format!("(- {} {})", a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::Mul(a, b) => format!("(* {} {})", a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::Div(a, b) => format!("(div {} {})", a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::Mod(a, b) => format!("(mod {} {})", a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::Neg(a)     => format!("(- {})", a.to_smtlib2()),
            SmtExpr::BvAdd(a, b) => format!("(bvadd {} {})", a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::BvSub(a, b) => format!("(bvsub {} {})", a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::BvMul(a, b) => format!("(bvmul {} {})", a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::BvUdiv(a, b) => format!("(bvudiv {} {})", a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::BvUrem(a, b) => format!("(bvurem {} {})", a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::BvAnd(a, b) => format!("(bvand {} {})", a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::BvOr(a, b)  => format!("(bvor {} {})", a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::BvXor(a, b) => format!("(bvxor {} {})", a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::BvShl(a, b) => format!("(bvshl {} {})", a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::BvLshr(a, b) => format!("(bvlshr {} {})", a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::Eq(a, b)   => format!("(= {} {})", a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::Ne(a, b)   => format!("(not (= {} {}))", a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::Lt(a, b)   => format!("(< {} {})", a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::Le(a, b)   => format!("(<= {} {})", a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::Gt(a, b)   => format!("(> {} {})", a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::Ge(a, b)   => format!("(>= {} {})", a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::BvUlt(a, b) => format!("(bvult {} {})", a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::BvUle(a, b) => format!("(bvule {} {})", a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::BvUgt(a, b) => format!("(bvugt {} {})", a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::BvUge(a, b) => format!("(bvuge {} {})", a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::And(exprs) => {
                if exprs.is_empty() { return "true".to_string(); }
                if exprs.len() == 1 { return exprs[0].to_smtlib2(); }
                format!("(and {})", exprs.iter().map(|e| e.to_smtlib2()).collect::<Vec<_>>().join(" "))
            }
            SmtExpr::Or(exprs) => {
                if exprs.is_empty() { return "false".to_string(); }
                if exprs.len() == 1 { return exprs[0].to_smtlib2(); }
                format!("(or {})", exprs.iter().map(|e| e.to_smtlib2()).collect::<Vec<_>>().join(" "))
            }
            SmtExpr::Not(e) => format!("(not {})", e.to_smtlib2()),
            SmtExpr::Implies(a, b) => format!("(=> {} {})", a.to_smtlib2(), b.to_smtlib2()),
            SmtExpr::Ite(c, t, f) => format!("(ite {} {} {})", c.to_smtlib2(), t.to_smtlib2(), f.to_smtlib2()),
            SmtExpr::Select(arr, idx) => format!("(select {} {})", arr.to_smtlib2(), idx.to_smtlib2()),
            SmtExpr::Store(arr, idx, val) => format!("(store {} {} {})", arr.to_smtlib2(), idx.to_smtlib2(), val.to_smtlib2()),
        }
    }

    /// Returns the sort/type of this expression (best-effort)
    pub fn infer_sort(&self) -> Sort {
        match self {
            SmtExpr::BoolLit(_) | SmtExpr::Eq(..) | SmtExpr::Ne(..) | SmtExpr::Lt(..) |
            SmtExpr::Le(..) | SmtExpr::Gt(..) | SmtExpr::Ge(..) | SmtExpr::And(..) |
            SmtExpr::Or(..) | SmtExpr::Not(..) | SmtExpr::Implies(..) |
            SmtExpr::BvUlt(..) | SmtExpr::BvUle(..) | SmtExpr::BvUgt(..) | SmtExpr::BvUge(..) => Sort::Bool,
            SmtExpr::IntLit(_) | SmtExpr::Add(..) | SmtExpr::Sub(..) | SmtExpr::Mul(..) |
            SmtExpr::Div(..) | SmtExpr::Mod(..) | SmtExpr::Neg(..) => Sort::Int,
            SmtExpr::BitVecLit { width, .. } => Sort::BitVec(*width),
            SmtExpr::BvAdd(a, _) => a.infer_sort(),
            SmtExpr::StrLit(_) => Sort::Str,
            SmtExpr::Var(v) => v.sort.clone(),
            _ => Sort::Int, // fallback
        }
    }

    // Convenience constructors
    pub fn int_var(name: impl Into<String>) -> Self {
        SmtExpr::Var(SmtVar { name: name.into(), sort: Sort::Int })
    }
    pub fn bool_var(name: impl Into<String>) -> Self {
        SmtExpr::Var(SmtVar { name: name.into(), sort: Sort::Bool })
    }
    pub fn bv256_var(name: impl Into<String>) -> Self {
        SmtExpr::Var(SmtVar { name: name.into(), sort: Sort::BitVec(256) })
    }
}

impl Sort {
    pub fn to_smtlib2(&self) -> String {
        match self {
            Sort::Bool => "Bool".to_string(),
            Sort::Int  => "Int".to_string(),
            Sort::Real => "Real".to_string(),
            Sort::BitVec(w) => format!("(_ BitVec {})", w),
            Sort::Array(k, v) => format!("(Array {} {})", k.to_smtlib2(), v.to_smtlib2()),
            Sort::Str => "String".to_string(),
        }
    }
}
