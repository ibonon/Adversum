use serde::{Deserialize, Serialize};
use crate::interner::SymbolId;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallNode {
    pub func_name: SymbolId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallGraph {
    pub nodes: HashMap<SymbolId, CallNode>,
    pub edges: Vec<(SymbolId, SymbolId)>,
    // Mapping from caller to set of callees
    pub callees: HashMap<SymbolId, HashSet<SymbolId>>,
}

impl CallGraph {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: Vec::new(),
            callees: HashMap::new(),
        }
    }
}
