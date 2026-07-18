use ndarray::ArrayD;

/// Fisher Information Matrix (Diagonal Approximation) for EWC
/// Represents `sigma^2` in the formula: lambda * sum(theta_i^2 / 2*sigma_i^2)
pub struct FisherInformation {
    pub diagonal: ArrayD<f32>,
}

impl FisherInformation {
    pub fn new(diagonal: ArrayD<f32>) -> Self {
        Self { diagonal }
    }

    /// Computes the regularization gradient: lambda * (theta / sigma^2)
    /// This corresponds to the derivative of sum(theta^2 / 2*sigma^2)
    pub fn compute_regularization_gradient(&self, theta: &ArrayD<f32>, lambda: f32) -> ArrayD<f32> {
        // gradient = lambda * theta / sigma^2
        let regularization = theta / &self.diagonal;
        regularization * lambda
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndarray::{arr1, IxDyn};

    #[test]
    fn test_ewc_gradient() {
        // Setup: theta = [2.0, 4.0], sigma^2 = [0.5, 2.0], lambda = 1.0
        // Expected gradient = 1.0 * [2.0/0.5, 4.0/2.0] = [4.0, 2.0]
        
        let theta = arr1(&[2.0, 4.0]).into_dyn();
        let sigma_sq = arr1(&[0.5, 2.0]).into_dyn();
        
        let fisher = FisherInformation::new(sigma_sq);
        let grad = fisher.compute_regularization_gradient(&theta, 1.0);
        
        assert_eq!(grad[0], 4.0);
        assert_eq!(grad[1], 2.0);
    }
}
