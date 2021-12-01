mod elastic_prover;
mod time_prover;
mod verifier;

/// Utilities for producing streams in SNARK protocol.
mod streams;
#[cfg(test)]
mod tests;

use ark_ec::PairingEngine;

use crate::sumcheck::prover::ProverMsg;

use crate::kzg::Commitment;
use crate::tensorcheck::TensorCheckProof;

/// The SNARK proof, composed of all prover's messages sent throughout the protocol.
pub struct Proof<E: PairingEngine> {
    witness_commitment: Commitment<E>,
    zc_alpha: E::Fr,
    first_sumcheck_msgs: Vec<ProverMsg<E::Fr>>,
    ra_a_z: E::Fr,
    second_sumcheck_msgs: Vec<ProverMsg<E::Fr>>,
    tensor_evaluation: E::Fr,
    tensor_check_proof: TensorCheckProof<E>,
}
