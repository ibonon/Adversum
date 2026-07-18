use serde::{Deserialize, Serialize};
use crate::rules::types::Severity;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Score {
    pub base_score: f64, // 0.0 - 10.0
    pub impact: f64,
    pub exploitability: f64,
}

impl Default for Score {
    fn default() -> Self {
        Self { base_score: 0.0, impact: 0.0, exploitability: 0.0 }
    }
}

pub fn severity_to_score(severity: Severity) -> f64 {
    match severity {
        Severity::Critical => 9.0,
        Severity::High => 7.0,
        Severity::Medium => 5.0,
        Severity::Low => 2.0,
    }
}
