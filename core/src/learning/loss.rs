use ndarray::ArrayD;
use super::ewc::FisherInformation;

/// Combined Loss Computation Component
/// Implements: L_combined = L_task + alpha * L_adv
pub struct CombinedLoss {
    pub alpha: f32, // Adversarial weight
    pub lambda: f32, // EWC Regularization weight
}

impl CombinedLoss {
    pub fn new(alpha: f32, lambda: f32) -> Self {
        Self { alpha, lambda }
    }

    /// Computes the total gradient vector:
    /// Grad_total = Grad_current + lambda * (theta/sigma^2) + alpha * Grad_adv(x+delta*)
    pub fn compute_total_gradient(
        &self,
        task_gradient: &ArrayD<f32>,
        adversarial_gradient: &ArrayD<f32>,
        current_theta: &ArrayD<f32>,
        fisher: Option<&FisherInformation>,
    ) -> ArrayD<f32> {
        let mut total_grad = task_gradient.clone();

        // 1. Add EWC Regularization Term (if Fisher info is present)
        // Term: lambda * (theta / sigma^2)
        if let Some(fisher_info) = fisher {
            let ewc_grad = fisher_info.compute_regularization_gradient(current_theta, self.lambda);
            total_grad = total_grad + ewc_grad;
        }

        // 2. Add Adversarial Loss Term
        // Term: alpha * Grad_adv
        let weighted_adv_grad = adversarial_gradient * self.alpha;
        total_grad = total_grad + weighted_adv_grad;

        total_grad
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndarray::{arr1, IxDyn};
    use crate::learning::ewc::FisherInformation;

    #[test]
    fn test_combined_gradient() {
        // Setup scenarios corresponding to the user's derivation
        // 1. Task Gradient (Current Loss)
        let task_grad = arr1(&[1.0, 1.0]).into_dyn();
        
        // 2. Adversarial Gradient (Worst-case perturbation)
        let adv_grad = arr1(&[0.5, -0.5]).into_dyn();
        
        // 3. EWC Components
        let theta = arr1(&[2.0, 4.0]).into_dyn();
        let sigma_sq = arr1(&[0.5, 2.0]).into_dyn(); // sigma_sq
        let fisher = FisherInformation::new(sigma_sq);
        
        // Weights
        let alpha = 0.1; // Adversarial weight
        let lambda = 1.0; // EWC weight

        let loss_computer = CombinedLoss::new(alpha, lambda);
        
        let total_grad = loss_computer.compute_total_gradient(
            &task_grad,
            &adv_grad,
            &theta,
            Some(&fisher)
        );
        
        // Calculation Verification:
        // Index 0:
        // Task = 1.0
        // EWC = lambda * (theta/sigma^2) = 1.0 * (2.0 / 0.5) = 4.0
        // Adv = alpha * 0.5 = 0.05
        // Sum = 1.0 + 4.0 + 0.05 = 5.05
        
        // Index 1:
        // Task = 1.0
        // EWC = 1.0 * (4.0 / 2.0) = 2.0
        // Adv = alpha * (-0.5) = -0.05
        // Sum = 1.0 + 2.0 - 0.05 = 2.95
        
        assert!((total_grad[0] - 5.05).abs() < 1e-6);
        assert!((total_grad[1] - 2.95).abs() < 1e-6);
    }
}
