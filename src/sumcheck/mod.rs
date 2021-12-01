pub mod proof;
pub mod prover;
pub mod streams;

/// The elastic prover implementation
pub mod elastic_prover;
/// The logarithmic-space (quasilinear-time) prover implementation.
pub mod space_prover;
/// The linear-time (linear-space) prover implementation.
pub mod time_prover;

mod subclaim;

pub use elastic_prover::ElasticProver;
pub use prover::Prover;
pub use space_prover::SpaceProver;
pub use subclaim::Subclaim;
pub use time_prover::TimeProver;

#[cfg(test)]
mod tests;
