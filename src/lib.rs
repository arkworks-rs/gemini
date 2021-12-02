//! Elastic arguments for R1CS.
#![feature(iter_advance_by)]
#![feature(associated_type_bounds)]
// #![deny(unused_import_braces, //unused_qualifications,
//         trivial_casts)]
// #![deny(trivial_numeric_casts, private_in_public)]
// #![deny(stable_features, unreachable_pub, non_shorthand_field_patterns)]
// #![deny(unused_attributes, unused_imports, unused_mut, missing_docs)]
// #![deny(renamed_and_removed_lints, stable_features, unused_allocation)]
// #![deny(unused_comparisons, bare_trait_objects, unused_must_use, const_err)]
#[forbid(unsafe_code)]
#[macro_use]
extern crate ark_std;

pub(crate) const PROTOCOL_NAME: &[u8] = b"GEMINI-v0";

#[doc(hidden)]
pub mod circuit;
mod misc;

/// KZG polynomial commitment, space- and time-efficient.
pub mod kzg;
/// Preprocessing SNARK for R1CS.
#[allow(dead_code)]
pub mod psnark;
/// SNARK for R1CS.
pub mod snark;
/// Data structures for the streaming model.
pub mod stream;
pub mod sumcheck;

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
