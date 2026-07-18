use std::collections::BTreeSet;
use crate::ir::types::Operand;
use crate::interner::SymbolId;

// Represents the set of tainted values (Temps or Vars).
// Using BTreeSet for deterministic iteration and sparse storage optimization.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TaintState {
    pub tainted_temps: BTreeSet<usize>,
    pub tainted_vars: BTreeSet<SymbolId>,
}

impl TaintState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_tainted(&self, op: &Operand) -> bool {
        match op {
            Operand::Temp(t) => self.tainted_temps.contains(t),
            Operand::Var(v) => self.tainted_vars.contains(v),
            Operand::Constant(_) => false,
        }
    }

    pub fn taint(&mut self, op: &Operand) {
        match op {
            Operand::Temp(t) => { self.tainted_temps.insert(*t); }
            Operand::Var(v) => { self.tainted_vars.insert(*v); }
            Operand::Constant(_) => {} 
        }
    }
    
    pub fn untaint(&mut self, op: &Operand) {
        match op {
            Operand::Temp(t) => { self.tainted_temps.remove(t); }
            Operand::Var(v) => { self.tainted_vars.remove(v); }
            Operand::Constant(_) => {}
        }
    }

    pub fn merge(&mut self, other: &TaintState) -> bool {
        let len_temps = self.tainted_temps.len();
        let len_vars = self.tainted_vars.len();
        
        self.tainted_temps.extend(other.tainted_temps.iter().cloned());
        self.tainted_vars.extend(other.tainted_vars.iter().cloned());
        
        len_temps != self.tainted_temps.len() || len_vars != self.tainted_vars.len()
    }
}
