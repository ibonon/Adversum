use std::collections::BTreeMap;
use crate::semantic::types::Symbol;
use crate::interner::SymbolId;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SemanticError {
    #[error("Symbol ID '{0:?}' already defined in this scope")]
    AlreadyDefined(SymbolId),
}

/// A single scope containing symbols.
/// Uses BTreeMap for deterministic order.
#[derive(Debug, Default)]
pub struct Scope {
    symbols: BTreeMap<SymbolId, Symbol>,
}

/// Symbol Table managing nested scopes.
#[derive(Debug, Default)]
pub struct SymbolTable {
    // Stack of scopes. Last is current.
    scopes: Vec<Scope>,
    // Counter for unique symbol IDs
    next_id: usize,
}

impl SymbolTable {
    pub fn new() -> Self {
        Self {
            scopes: vec![Scope::default()], 
            next_id: 0,
        }
    }

    pub fn enter_scope(&mut self) {
        self.scopes.push(Scope::default());
    }

    pub fn exit_scope(&mut self) {
        if self.scopes.len() > 1 {
            self.scopes.pop();
        }
    }

    /// Define a symbol in the current scope.
    pub fn define(&mut self, mut symbol: Symbol) -> Result<usize, SemanticError> {
        let current_scope = self.scopes.last_mut().ok_or_else(|| SemanticError::AlreadyDefined(SymbolId::NULL))?; 
        
        if current_scope.symbols.contains_key(&symbol.name) {
            return Err(SemanticError::AlreadyDefined(symbol.name));
        }
        
        // Assign ID
        let id = self.next_id;
        self.next_id += 1;
        symbol.id = id;
        
        current_scope.symbols.insert(symbol.name, symbol);
        Ok(id)
    }

    /// Lookup a symbol recursively from inner to outer scope.
    pub fn lookup(&self, name: SymbolId) -> Option<&Symbol> {
        for scope in self.scopes.iter().rev() {
            if let Some(sym) = scope.symbols.get(&name) {
                return Some(sym);
            }
        }
        None
    }
    
    /// Check if defined in current scope (for shadowing checks).
    pub fn lookup_current(&self, name: SymbolId) -> Option<&Symbol> {
        self.scopes.last().and_then(|s| s.symbols.get(&name))
    }
}
