use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// Lightweight handle to an interned string.
/// Using u32 for compactness (supports 4 billion strings, sufficient).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default, Serialize, Deserialize)]
pub struct SymbolId(pub u32);

impl SymbolId {
    /// Reserved ID for empty or invalid.
    pub const NULL: SymbolId = SymbolId(0);
}

/// Bidirectional String Interner.
/// Maps String -> SymbolId and SymbolId -> String.
#[derive(Debug, Clone, Default)]
pub struct Interner {
    map: HashMap<String, SymbolId>,
    vec: Vec<String>,
}

impl Interner {
    pub fn new() -> Self {
        let mut interner = Self {
            map: HashMap::new(),
            vec: Vec::new(),
        };
        // Ensure ID 0 is NULL/Empty if we want
        interner.intern("");
        interner
    }

    /// Interns a string. If it exists, returns existing ID.
    pub fn intern(&mut self, name: &str) -> SymbolId {
        if let Some(&id) = self.map.get(name) {
            return id;
        }

        let name_string = name.to_string();
        let id = SymbolId(self.vec.len() as u32);
        self.vec.push(name_string.clone());
        self.map.insert(name_string, id);
        id
    }

    /// Resolves ID to String. Panics if invalid ID (should not happen if usage is correct).
    // Using simple lookup.
    pub fn resolve(&self, id: SymbolId) -> &str {
        &self.vec[id.0 as usize]
    }
    
    // Resolves ID to String (Option safe version)
    pub fn get(&self, id: SymbolId) -> Option<&str> {
        self.vec.get(id.0 as usize).map(|s| s.as_str())
    }
}
