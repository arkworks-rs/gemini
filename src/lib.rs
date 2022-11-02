#![doc = include_str!("docs/lib_docs.md")]

#![feature(iter_advance_by)]
#![no_std]
#![deny(unused_comparisons, bare_trait_objects, unused_must_use, const_err)]
#![forbid(unsafe_code)]
#![deny(trivial_numeric_casts)]
#![deny(private_in_public)]
#![deny(unused_allocation)]

// Lints disable from other arkworks packages:
// - trivial_casts: this causes errors for "trivial casts" when converting an Iterable `It` to
// `dyn Iterable`.

// #![deny(stable_features, , non_shorthand_field_patterns)]
// #![deny(unused_attributes, unused_imports, unused_mut, unused_import_braces, unused_qualifications, missing_docs)]
// #![deny(renamed_and_removed_lints, stable_features, unused_allocation)]
#[macro_use]
extern crate ark_std;

/// The domain separator, used when proving statements on gemini.
pub(crate) const PROTOCOL_NAME: &[u8] = b"GEMINI-v0";
/// The threshold for switching from space to time prover within the sumcheck.
const SPACE_TIME_THRESHOLD: usize = 22;
// const SUMCHECK_BUF_SIZE: usize = 1 << 20;

pub mod errors;
pub mod iterable;


/// \
///
/// # Multi KZG Protocol Math Overview
///
/// ### Univariate Polynomial Commitments
///
#[doc = include_str!("docs/univariate_protocol.md")]
pub mod kzg;

/// \
///
/// # Multi KZG Protocol Math Overview
///
/// ### Multivariate Polynomial Commitments
///
#[doc = include_str!("docs/multivariate_protocol.md")]
pub mod multikzg;


pub mod psnark;
pub mod snark;
pub mod subprotocols;

// private modules

#[doc(hidden)]
pub mod circuit;
mod misc;

mod transcript;
