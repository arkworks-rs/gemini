//! Elastic *non-preprocessing* SNARK for R1CS.
//!
mod elastic_prover;
mod time_prover;
mod verifier;

/// Utilities for producing streams in SNARK protocol.
mod streams;
#[cfg(test)]
mod tests;

use ark_ec::PairingEngine;

use crate::kzg::Commitment;
use crate::subprotocols::sumcheck::prover::ProverMsgs;
use crate::subprotocols::tensorcheck::TensorcheckProof;

/// The SNARK proof, composed of all prover's messages sent throughout the protocol.
#[derive(PartialEq, Eq)]
pub struct Proof<E: PairingEngine> {
    witness_commitment: Commitment<E>,
    zc_alpha: E::Fr,
    first_sumcheck_msgs: ProverMsgs<E::Fr>,
    second_sumcheck_msgs: ProverMsgs<E::Fr>,
    tensorcheck_proof: TensorcheckProof<E>,
}

impl<E: PairingEngine> ark_std::fmt::Debug for Proof<E> {
    fn fmt(&self, f: &mut ark_std::fmt::Formatter<'_>) -> ark_std::fmt::Result {
        f.debug_struct("Proof").finish()
    }
}
