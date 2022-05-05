//! A base library for iterfacing with streams of vectors and matrices.
//!
//! This library extends the abstraction layer provided by [`ark_std::iterable::Iterable`]
//! with streams that repeat the same element over and over, and that iterate in reversed order.

pub mod dummy;
pub(crate) mod slice;

pub use ark_std::iterable::Iterable;
pub use slice::Reverse;
