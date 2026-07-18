use ndarray::ArrayD;
use super::Gradients;

/// A simple wrapper for gradients using ndarray
pub struct StandardGradient {
    pub grads: ArrayD<f32>,
}

impl StandardGradient {
    pub fn new(grads: ArrayD<f32>) -> Self {
        Self { grads }
    }
}

impl Gradients for StandardGradient {
    fn as_array(&self) -> &ArrayD<f32> {
        &self.grads
    }
    
    fn add(&mut self, other: &ArrayD<f32>) {
        self.grads = &self.grads + other;
    }
}
