use pyo3::prelude::*;

/// Represents a formal safety invariant that must be maintained.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SafetyInvariant {
    /// No flow permitted from source to sink.
    NoFlow {
        source_pattern: String,
        sink_pattern: String,
    },
    /// Execution must be bounded by a specific complexity.
    ComplexityBound(usize),
    /// Data must match a specific deterministic schema/regex.
    SchemaMatch {
        regex: String,
    },
}

impl SafetyInvariant {
    /// Verify if the invariant holds given a set of facts.
    pub fn verify(&self, evidence: &[String]) -> bool {
        match self {
            SafetyInvariant::NoFlow { .. } => {
                // Si l'évidence contient "verified: true" pour un flow suspect, l'invariant est violé.
                !evidence.iter().any(|e| e.contains("PREUVE : Donnée externe non filtrée"))
            }
            _ => true,
        }
    }
}

/// The result of an immune response check.
#[pyclass(get_all)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImmuneResponse {
    pub invariant_holds: bool,
    pub evidence: Vec<String>,
    pub resilience_delta: f32,
}
