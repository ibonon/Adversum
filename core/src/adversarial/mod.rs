pub mod attacks;
pub mod error;

use pyo3::prelude::*;

use serde::{Serialize, Deserialize};
use error::AdversarialError;

/// Validate an adversarial request before processing
pub fn validate_request(req: &AdversarialRequest) -> Result<(), AdversarialError> {
    // Check epsilon bounds
    if req.epsilon < 0.0 || req.epsilon > 1.0 {
        return Err(AdversarialError::InvalidEpsilon(req.epsilon));
    }
    
    // Check shape consistency
    let expected_len: usize = req.shape.iter().product();
    if expected_len != req.input_data.len() {
        return Err(AdversarialError::InvalidShape {
            expected: expected_len,
            actual: req.input_data.len(),
        });
    }
    
    Ok(())
}



#[pyclass(get_all, set_all)]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OracleConfig {
    pub boundary_type: String,
    pub threshold: f32,
    pub sensitive_patterns: Option<Vec<String>>,
    pub defense_level: f32,
    pub defense_type: Option<String>,
    pub waf_enabled: bool,
    pub threat_threshold: f32,
    pub block_threshold: f32,
}

#[pymethods]
impl OracleConfig {
    #[new]
    #[pyo3(signature = (boundary_type, threshold, sensitive_patterns=None, defense_level=0.0, defense_type=None, waf_enabled=false, threat_threshold=50.0, block_threshold=100.0))]
    fn new(
        boundary_type: String,
        threshold: f32,
        sensitive_patterns: Option<Vec<String>>,
        defense_level: f32,
        defense_type: Option<String>,
        waf_enabled: bool,
        threat_threshold: f32,
        block_threshold: f32,
    ) -> Self {
        Self {
            boundary_type,
            threshold,
            sensitive_patterns,
            defense_level,
            defense_type,
            waf_enabled,
            threat_threshold,
            block_threshold,
        }
    }
}

#[pyclass(get_all, set_all)]
#[derive(Debug, Serialize, Deserialize)]
pub struct AdversarialRequest {
    pub algorithm: String,
    pub input_data: Vec<f32>,
    pub shape: Vec<usize>,
    pub target_class: Option<usize>,
    pub epsilon: f32,
    pub oracle_config: Option<OracleConfig>,
    pub shadow_model_id: Option<String>,
    pub query_budget: Option<usize>,
    // LLM Specific Fields
    pub prompt: Option<String>,
    pub latent_vectors: Option<Vec<f32>>,
}

#[pymethods]
impl AdversarialRequest {
    #[new]
    #[pyo3(signature = (algorithm, input_data, shape, target_class=None, epsilon=0.1, oracle_config=None, shadow_model_id=None, query_budget=None, prompt=None, latent_vectors=None))]
    fn new(
        algorithm: String,
        input_data: Vec<f32>,
        shape: Vec<usize>,
        target_class: Option<usize>,
        epsilon: f32,
        oracle_config: Option<OracleConfig>,
        shadow_model_id: Option<String>,
        query_budget: Option<usize>,
        prompt: Option<String>,
        latent_vectors: Option<Vec<f32>>,
    ) -> Self {
        Self {
            algorithm,
            input_data,
            shape,
            target_class,
            epsilon,
            oracle_config,
            shadow_model_id,
            query_budget,
            prompt,
            latent_vectors,
        }
    }
}

#[pyclass(get_all)]
#[derive(Debug, Serialize, Deserialize)]
pub struct AdversarialResult {
    pub algorithm: String,
    pub perturbed_data: Vec<f32>,
    pub success: bool,
    pub perturbation_norm: f32,
    pub query_count: usize,
    pub cost: f32,
    pub detected: bool,
    pub blocked_by_waf: bool,
    pub threat_score: f32,
    // LLM Specific Results
    pub adversarial_prompt: Option<String>,
    pub robustness_score: f32, // 0.0 - 1.0 (Higher is better)
}

#[cfg(test)]
mod tests;
