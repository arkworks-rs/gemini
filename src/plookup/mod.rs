//! The plookup protocol of Gabizon and Williamson [[GW20](https://eprint.iacr.org//315.pdf)].
//!
//! As of today, this module implements only the suport functions that can be used to generate
//! the entry product subclaims as a result of the plookup protocol.

pub mod streams;
pub mod time_prover;

#[cfg(test)]
mod tests;
