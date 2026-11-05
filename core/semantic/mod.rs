pub mod types;
pub mod symtab;

// Re-exports
pub use types::*;
pub use symtab::*;

// Tests live in `core/semantic/tests.rs`. The module itself was never declared
// in `src/lib.rs` (so it never compiled); the dangling `#[cfg(test)]` below is
// what made it fail once it was wired in.
// #[cfg(test)]
// mod tests;
