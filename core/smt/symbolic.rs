use std::collections::HashMap;
use crate::ir::types::{Instr, Operand, Op, FunctionIR};
use crate::interner::SymbolId;
use super::ast::{SmtExpr, SmtVar, Sort};
use serde::{Serialize, Deserialize};

/// Compteur global pour générer des noms de variables symboliques frais
static FRESH_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn fresh_var(prefix: &str, sort: Sort) -> SmtExpr {
    let id = FRESH_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    SmtExpr::Var(SmtVar { name: format!("{}_{}", prefix, id), sort })
}

/// État symbolique d'un chemin d'exécution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolicState {
    /// Mapping: Operand IR -> expression symbolique SMT
    pub registers: HashMap<String, SmtExpr>,
    /// Condition de chemin: conjonction des prédicats de branchement
    pub path_condition: Vec<SmtExpr>,
    /// Mémoire heap: (obj_sym, field_sym) -> expression SMT
    pub memory: HashMap<(u32, u32), SmtExpr>,
    /// Toutes les variables symboliques déclarées dans cet état
    pub declared_vars: Vec<SmtVar>,
}

impl SymbolicState {
    pub fn new() -> Self {
        Self {
            registers: HashMap::new(),
            path_condition: vec![SmtExpr::BoolLit(true)],
            memory: HashMap::new(),
            declared_vars: Vec::new(),
        }
    }

    /// Crée une variable symbolique fraîche pour un paramètre d'entrée
    pub fn fresh_input(&mut self, name: &str, sort: Sort) -> SmtExpr {
        let var = SmtVar { name: name.to_string(), sort: sort.clone() };
        self.declared_vars.push(var.clone());
        SmtExpr::Var(var)
    }

    /// Lit la valeur symbolique d'un Operand IR
    pub fn read_operand(&self, op: &Operand) -> SmtExpr {
        match op {
            Operand::Temp(t) => {
                let key = format!("t{}", t);
                self.registers.get(&key).cloned()
                    .unwrap_or_else(|| SmtExpr::int_var(format!("undef_t{}", t)))
            }
            Operand::Var(v) => {
                let key = format!("v{}", v.0);
                self.registers.get(&key).cloned()
                    .unwrap_or_else(|| SmtExpr::int_var(format!("undef_v{}", v.0)))
            }
            Operand::Constant(s) => {
                // Essaie de parser comme entier
                if let Ok(n) = s.parse::<i64>() {
                    SmtExpr::IntLit(n)
                } else if s == "true" {
                    SmtExpr::BoolLit(true)
                } else if s == "false" {
                    SmtExpr::BoolLit(false)
                } else {
                    SmtExpr::StrLit(s.clone())
                }
            }
        }
    }

    /// Ecrit une expression symbolique dans un Operand de destination
    pub fn write_operand(&mut self, dest: &Operand, expr: SmtExpr) {
        let key = match dest {
            Operand::Temp(t) => format!("t{}", t),
            Operand::Var(v)  => format!("v{}", v.0),
            Operand::Constant(_) => return, // On n'écrit pas dans une constante
        };
        self.registers.insert(key, expr);
    }

    /// Ajoute une contrainte de chemin
    pub fn add_constraint(&mut self, cond: SmtExpr) {
        self.path_condition.push(cond);
    }

    /// Retourne la condition de chemin complète comme conjonction
    pub fn path_formula(&self) -> SmtExpr {
        SmtExpr::And(self.path_condition.clone())
    }
}

impl Default for SymbolicState {
    fn default() -> Self { Self::new() }
}

/// Évalue symboliquement un Op IR en une SmtExpr
fn symbolic_binop(op: &Op, left: SmtExpr, right: SmtExpr) -> SmtExpr {
    match op {
        Op::Add => SmtExpr::Add(Box::new(left), Box::new(right)),
        Op::Sub => SmtExpr::Sub(Box::new(left), Box::new(right)),
        Op::Mul => SmtExpr::Mul(Box::new(left), Box::new(right)),
        Op::Div => SmtExpr::Div(Box::new(left), Box::new(right)),
        Op::Mod => SmtExpr::Mod(Box::new(left), Box::new(right)),
        Op::Eq  => SmtExpr::Eq(Box::new(left), Box::new(right)),
        Op::Ne  => SmtExpr::Ne(Box::new(left), Box::new(right)),
        Op::Lt  => SmtExpr::Lt(Box::new(left), Box::new(right)),
        Op::Le  => SmtExpr::Le(Box::new(left), Box::new(right)),
        Op::Gt  => SmtExpr::Gt(Box::new(left), Box::new(right)),
        Op::Ge  => SmtExpr::Ge(Box::new(left), Box::new(right)),
        Op::And => SmtExpr::And(vec![left, right]),
        Op::Or  => SmtExpr::Or(vec![left, right]),
        Op::Not | Op::Neg => SmtExpr::Not(Box::new(left)), // unary misuse — handled below
    }
}

/// Exécute symboliquement une liste d'instructions IR sur un SymbolicState
pub fn execute_symbolically(instrs: &[Instr], state: &mut SymbolicState) {
    for instr in instrs {
        match instr {
            Instr::Assign { dest, src } => {
                let val = state.read_operand(src);
                state.write_operand(dest, val);
            }
            Instr::Binary { dest, op, left, right } => {
                let l = state.read_operand(left);
                let r = state.read_operand(right);
                let result = symbolic_binop(op, l, r);
                state.write_operand(dest, result);
            }
            Instr::Unary { dest, op, operand } => {
                let val = state.read_operand(operand);
                let result = match op {
                    Op::Neg => SmtExpr::Neg(Box::new(val)),
                    Op::Not => SmtExpr::Not(Box::new(val)),
                    _ => val,
                };
                state.write_operand(dest, result);
            }
            Instr::JumpIf { cond, .. } => {
                // On ajoute la condition de branchement au chemin
                let cond_expr = state.read_operand(cond);
                state.add_constraint(cond_expr);
            }
            Instr::FieldLoad { dest, obj, field } => {
                let sym = state.memory.get(&(obj.0, field.0)).cloned()
                    .unwrap_or_else(|| {
                        let var = SmtVar {
                            name: format!("field_{}_{}", obj.0, field.0),
                            sort: Sort::Int,
                        };
                        SmtExpr::Var(var)
                    });
                state.write_operand(dest, sym);
            }
            Instr::FieldStore { obj, field, src } => {
                let val = state.read_operand(src);
                state.memory.insert((obj.0, field.0), val);
            }
            Instr::Return(Some(op)) => {
                let val = state.read_operand(op);
                state.registers.insert("__return__".to_string(), val);
            }
            _ => {} // Label, Jump, Call, Nop, Return(None)
        }
    }
}

/// Exécute symboliquement une FunctionIR, en créant des inputs symboliques pour les paramètres
pub fn symbolize_function(func: &FunctionIR, sort_hint: Sort) -> SymbolicState {
    let mut state = SymbolicState::new();
    // Créer une variable symbolique fraîche pour chaque paramètre
    for &param in &func.params {
        let name = format!("param_{}", param.0);
        let expr = state.fresh_input(&name, sort_hint.clone());
        state.registers.insert(format!("v{}", param.0), expr);
    }
    execute_symbolically(&func.instructions, &mut state);
    state
}
