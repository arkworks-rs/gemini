//! Elastic arguments for R1CS.
//!
//! This library provides essentually two arugments:
//! - [`snark::Proof`], for non-preprocessing SNARKs.
//!     It provides a non-interactive succinct argument of knowledge for R1CS
//!     without indexer, and where the verifier complexity is linear in the circuit size.
//! - [`psnark::Proof`] for preprocessing SNARKs.
//!     It provides a non-interactive succinct argument of knowledge for R1CS
//!     where the verifier complexity is logarithmic in the circuit size.
//!
//! Choice of the [`PairingEngine`](ark_ec::PairingEngine), the pairing-friendly elliptic curve,
//! is entirely up to the implementor.
//! All arguments are internally using the [`kzg`](crate::kzg) commitment scheme,
//! however one nothing would present in the future from supporting a univariate
//! or multivariate commitment scheme.
//!
//! Additionally, some sub-protocols are exported so that
//! their space- and time- efficient impelementation might be used also elsewhere.
//! - [`tensorcheck::TensorCheckProof`],
//!     an argument for claims of the form \\(\langle f, \otimes_j (1, \rho_j) \rangle = t\\).
//!     This can be used for proving batches of multivariate evaluations claims using
//!     univariate polynomial commitments.
//! - [`sumcheck::proof::Sumcheck`],
//!    the multivariate sumcheck implementation, implemented in 3 flavours: linear-time, log-space, and elastic.
//!

#![feature(iter_advance_by)]
// #![deny(unused_import_braces, unused_qualifications,
//         trivial_casts)]
// #![deny(trivial_numeric_casts, private_in_public)]
// #![deny(stable_features, unreachable_pub, non_shorthand_field_patterns)]
// #![deny(unused_attributes, unused_imports, unused_mut, missing_docs)]
// #![deny(renamed_and_removed_lints, stable_features, unused_allocation)]
#![deny(unused_comparisons, bare_trait_objects, unused_must_use, const_err)]
#[forbid(unsafe_code)]
#[macro_use]
extern crate ark_std;

pub(crate) const PROTOCOL_NAME: &[u8] = b"GEMINI-v0";

#[doc(hidden)]
pub mod circuit;
mod misc;

pub mod kzg;
/// Preprocessing SNARK for R1CS.
#[allow(dead_code)]
pub mod psnark;
pub mod snark;
/// Data structures for the streaming model.
pub mod iterable;
pub mod sumcheck;

pub mod entryproduct;

pub mod tensorcheck;
mod transcript;

const SPACE_TIME_THRESHOLD: usize = 22;
// const SUMCHECK_BUF_SIZE: usize = 1 << 20;

/// Error identifying a failure in the proof verification.
#[derive(Debug, Clone)]
pub struct VerificationError;

use ark_std::fmt;

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Error in stream.")
    }
}

/// Verification result.
pub type VerificationResult = ark_std::result::Result<(), VerificationError>;
