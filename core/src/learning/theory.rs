use super::Parameters;
use serde::{Serialize, Deserialize};
use pyo3::prelude::*;

/// Configuration for the Bastounis Instability Check
/// Based on "The mathematics of adversarial attacks in AI" (2025)
/// Checks if the model falls into the regime where instability is mathematically guaranteed.
#[pyclass(get_all, set_all)]
#[derive(Debug, Serialize, Deserialize)]
pub struct ModelConfig {
    pub hidden_layers: Vec<usize>, // Dimensions N1, N2... L-1
    pub input_dim: usize,          // N0
    pub training_samples: usize,   // r
    pub validation_samples: usize, // s
}

#[pymethods]
impl ModelConfig {
    #[new]
    fn new(hidden_layers: Vec<usize>, input_dim: usize, training_samples: usize, validation_samples: usize) -> Self {
        Self { hidden_layers, input_dim, training_samples, validation_samples }
    }
}

#[pyclass(get_all)]
#[derive(Debug, Serialize, Deserialize)]
pub struct StabilityAnalysis {
    pub is_theoretically_unstable: bool,
    pub instability_probability: f32, // Lower bound on probability of instability (1-p)
    pub critical_sample_ratio: f32,
    pub theoretical_message: String,
}

pub struct BastounisVerifier;

impl BastounisVerifier {
    /// Checks Theorem 2.2 condition (2.3):
    /// r + s >= C * max(p^-3, q^3/2 * (Product(Ni + 1))^3/2)
    ///
    /// If this holds, the network is likely unstable despite high accuracy.
    pub fn analyze(config: &ModelConfig) -> StabilityAnalysis {
        // C is a large constant in the paper, we estimate a practical lower bound for detection sensitivity
        // The paper mentions C >= 43 * c1^-6 etc. For practical auditing, we use a normalized scaling factor.
        let c_factor = 1000.0; 
        
        let total_samples = (config.training_samples + config.validation_samples) as f64;
        
        // Calculate Product term: (N1+1)...(NL-1+1)
        let architecture_complexity: f64 = config.hidden_layers.iter()
            .map(|&n| (n + 1) as f64)
            .product();
            
        // Limit for q (subset size for instability). We assume q=1 for existence of ANY instability.
        let _q = 1.0;
        
        // We invert the formula to find the critical probability p
        // r + s approx C * architecture_complexity^1.5 * p^-3
        // p^3 approx C * arch^1.5 / (r+s)
        // p approx (C * arch^1.5 / (r+s))^(1/3)
        
        let complexity_term = architecture_complexity.powf(1.5);
        let p_cubed = (c_factor * complexity_term) / total_samples;
        let p_critical = p_cubed.powf(1.0/3.0);
        
        // If p_critical is small, it means the probability of stability (p) is low.
        // Probability of instability > 1 - p.
        
        let normalized_p = p_critical.min(1.0).max(0.001);
        let prob_instability = 1.0 - normalized_p;
        
        let unstable = prob_instability > 0.95;

        let message = if unstable {
            format!(
                "CRITICAL: Theorem 2.2 Violation. Fixed architecture (complexity {:.0}) with dataset size {} guarantees instability (p > {:.2}). Variable dimensions required.",
                architecture_complexity, total_samples, prob_instability
            )
        } else {
            format!(
                "Stable Regime: Dataset size {} is insufficient to trigger Theorem 2.2 guarantees for this architecture complexity ({:.0}).",
                total_samples, architecture_complexity
            )
        };

        StabilityAnalysis {
            is_theoretically_unstable: unstable,
            instability_probability: prob_instability as f32,
            critical_sample_ratio: (total_samples / complexity_term) as f32,
            theoretical_message: message,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bastounis_instability_detection() {
        // Case 1: Complex network, small dataset -> Should be unstable
        let config_unstable = ModelConfig {
            hidden_layers: vec![100, 100, 100], // High complexity
            input_dim: 784,
            training_samples: 1000,
            validation_samples: 100,
        };
        
        let result = BastounisVerifier::analyze(&config_unstable);
        // We expect high instability probability because Complexity is huge vs samples
        assert!(result.instability_probability > 0.5, "Should detect high instability probability");

        // Case 2: Simple network, large dataset -> Should be stable(r)
        let config_stable = ModelConfig {
            hidden_layers: vec![10], // Low complexity
            input_dim: 10,
            training_samples: 1_000_000,
            validation_samples: 10_000,
        };
        
        let result_stable = BastounisVerifier::analyze(&config_stable);
        assert!(result_stable.instability_probability < 0.5, "Should be relatively stable");
    }
}

