use thiserror::Error;

/// Errors that can occur during adversarial attack execution
#[derive(Error, Debug)]
pub enum AdversarialError {
    #[error("Invalid shape: expected {expected} elements based on shape dimensions, got {actual} elements in input data")]
    InvalidShape { expected: usize, actual: usize },
    
    #[error("Shape dimensions mismatch: shape {shape:?} incompatible with data length {data_len}")]
    ShapeMismatch { 
        shape: Vec<usize>, 
        data_len: usize 
    },
    
    #[error("Invalid epsilon value: {0} (must be between 0.0 and 1.0)")]
    InvalidEpsilon(f32),
    
    #[error("Invalid algorithm: '{0}' is not supported")]
    UnknownAlgorithm(String),
    
    #[error("Query budget exceeded: used {used} queries, budget was {budget}")]
    BudgetExceeded { used: usize, budget: usize },
    
    #[error("Invalid target class: {0}")]
    InvalidTargetClass(i32),
    
    #[error("Array creation failed: {0}")]
    ArrayCreationError(String),
}

/// Conversion to PyO3 errors for FFI boundary
impl From<AdversarialError> for pyo3::PyErr {
    fn from(err: AdversarialError) -> pyo3::PyErr {
        pyo3::exceptions::PyValueError::new_err(err.to_string())
    }
}
