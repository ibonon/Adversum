use serde::{Deserialize, Serialize};

/// Represents a source code location.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    pub file_id: usize,
}

/// The root of an Abstract Syntax Tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Program {
    pub statements: Vec<Stmt>,
}

/// Represents a statement in the code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Stmt {
    /// Variable binding: `let x = 1;`
    Let {
        name: String,
        value: Expr,
        span: Span,
    },
    /// Assignment: `x = 2;`
    Assign {
        target: Expr,
        value: Expr,
        span: Span,
    },
    /// Conditional execution: `if x { ... } else { ... }`
    If {
        condition: Expr,
        then_block: Vec<Stmt>,
        else_block: Option<Vec<Stmt>>,
        span: Span,
    },
    /// Loop execution: `while x { ... }`
    While {
        condition: Expr,
        body: Vec<Stmt>,
        span: Span,
    },
    /// Return statement: `return x;`
    Return {
        value: Option<Expr>,
        span: Span,
    },
    /// Class definition: `class Foo: ...`
    Class {
        name: String,
        body: Vec<Stmt>,
        span: Span,
    },
    /// Expression as a statement: `x + 1;`
    Expr {
        expr: Expr,
        span: Span,
    },
    /// Function definition: `def foo(a, b): ...`
    FunctionDef {
        name: String,
        params: Vec<String>,
        body: Vec<Stmt>,
        span: Span,
    },
}

/// Represents an expression that evaluates to a value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Expr {
    /// Literal value: `1`, `"hello"`, `true`
    Literal {
        value: Literal,
        span: Span,
    },
    /// Identifier lookup: `x`
    Identifier {
        name: String,
        span: Span,
    },
    /// Binary operation: `x + y`
    Binary {
        op: BinOp,
        left: Box<Expr>,
        right: Box<Expr>,
        span: Span,
    },
    /// Unary operation: `!x`
    Unary {
        op: UnOp,
        operand: Box<Expr>,
        span: Span,
    },
    /// Function call: `foo(x, y)`
    Call {
        function: Box<Expr>,
        args: Vec<Expr>,
        span: Span,
    },
}

/// primitive literal values.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Literal {
    Int(i64),
    Float(f64),
    Bool(bool),
    String(String),
    Null,
}

/// Binary operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinOp {
    Add, Sub, Mul, Div, Mod,
    Eq, Ne, Lt, Le, Gt, Ge,
    And, Or,
    BitAnd, BitOr, BitXor,
}

/// Unary operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnOp {
    Neg, // -x
    Not, // !x
}
