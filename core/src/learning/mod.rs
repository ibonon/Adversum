pub mod ewc;
pub mod loss;
pub mod gradients;
pub mod theory;
pub mod bounds;




use ndarray::ArrayD;

/// Trait representing trainable parameters (Theta)
pub trait Parameters {
    fn as_array(&self) -> &ArrayD<f32>;
    fn as_array_mut(&mut self) -> &mut ArrayD<f32>;
}

/// Trait representing gradients (Nabla)
pub trait Gradients {
    fn as_array(&self) -> &ArrayD<f32>;
    fn add(&mut self, other: &ArrayD<f32>);
}
