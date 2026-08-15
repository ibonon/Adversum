use serde::{Deserialize, Serialize};
use crate::interner::SymbolId;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operand {
    Var(SymbolId),    // Source variable (Interned)
    Temp(usize),      // Intermediate temporary
    Constant(String), // Values kept as string for now
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Op {
    Add, Sub, Mul, Div, Mod,
    Eq, Ne, Lt, Le, Gt, Ge,
    And, Or, Not, Neg,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Instr {
    /// L1:
    Label(usize),
    
    /// t1 = t2
    Assign { dest: Operand, src: Operand },
    
    /// t1 = t2 + t3
    Binary { dest: Operand, op: Op, left: Operand, right: Operand },
    
    /// t1 = -t2
    Unary { dest: Operand, op: Op, operand: Operand },
    
    /// goto L1
    Jump(usize),
    
    /// if t1 goto L1
    JumpIf { cond: Operand, label: usize },
    
    /// call function
    Call { dest: Option<Operand>, func: SymbolId, args: Vec<Operand> },
    
    /// return t1
    Return(Option<Operand>),
    
    /// No-op
    Nop,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FunctionIR {
    pub name: SymbolId,
    pub params: Vec<SymbolId>,
    pub instructions: Vec<Instr>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Program {
    pub instructions: Vec<Instr>,
    pub functions: std::collections::HashMap<SymbolId, FunctionIR>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Module {
    pub program: Program,
}
