//! A base library for iterfacing with streams of vectors and matrices.
//!
//! This library presents the abstraction layer for the _streaming model_.
//! Essentially, it provides a set of handy utilities as a wrapper around iterators.

// DummyStream
pub mod dummy;
pub(crate) mod slice;

pub use slice::Reversed;
pub use ark_std::iterable::Iterable;