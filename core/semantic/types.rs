use serde::{Deserialize, Serialize};
use crate::ast::types::Span;
use crate::interner::SymbolId;

/// Represents the type of a value or symbol.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Type {
    Int,
    Float,
    Bool,
    String,
    Void,
    /// For types we can't resolve yet or don't care about at this layer
    Unknown,
}

/// A symbol definition (variable, function, etc.).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Symbol {
    pub name: SymbolId,
    pub ty: Type,
    pub def_span: Span,
    // Unique ID for this specific declaration
    pub id: usize,
}
