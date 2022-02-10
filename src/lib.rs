//! Elastic arguments for R1CS.
//!
//! This library provides essentually two arguments:
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
//! These are grouped in [`subprotocols`].

#![feature(iter_advance_by)]
#![no_std]
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

/// The domain separator, used when proving statements on gemini.
pub(crate) const PROTOCOL_NAME: &[u8] = b"GEMINI-v0";
/// The threshold for switching from space to time prover within the sumcheck.
const SPACE_TIME_THRESHOLD: usize = 22;
// const SUMCHECK_BUF_SIZE: usize = 1 << 20;


// public modules

pub mod errors;
pub mod iterable;
pub mod kzg;
pub mod psnark;
pub mod snark;
pub mod subprotocols;

// private modules

#[doc(hidden)]
pub mod circuit;
mod misc;
mod transcript;


