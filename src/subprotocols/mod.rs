//! A collection of elastic arguments.
//!
//! This module provides:
//! - [`tensorcheck::TensorcheckProof`],
//!     an argument for claims of the form \\(\langle f, \otimes_j (1, \rho_j) \rangle = t\\).
//!     This can be used for proving batches of multivariate evaluations claims using
//!     univariate polynomial commitments.
//! - [`sumcheck::proof::Sumcheck`],
//!    the multivariate sumcheck implementation, implemented in 3 flavours: linear-time, log-space, and elastic.
//! - [`entryproduct::EntryProduct`],
//!    an argument for proving knowledge of the product of all the components in a vector \\(\vec f\\).
//! - [`plookup`], an argument for proving lookup relations.
//!
//!

pub mod entryproduct;
pub mod plookup;
pub mod tensorcheck;

pub mod sumcheck;
