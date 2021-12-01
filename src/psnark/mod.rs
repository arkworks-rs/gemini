//!
//
//!
//!
mod elastic_prover;
mod time_prover;

mod streams;

use ark_ec::PairingEngine;

use crate::kzg::{Commitment, EvaluationProof};
use crate::sumcheck::prover::ProverMsg;

/// The preprocessing SNARK proof, containing all prover's messages.
pub struct Proof<E: PairingEngine> {
    first_sumcheck_messages: Vec<ProverMsg<E::Fr>>,
    second_sumcheck_messages: Vec<ProverMsg<E::Fr>>,
    third_sumcheck_messages: Vec<ProverMsg<E::Fr>>,
    ep_sumcheck_messages: Vec<ProverMsg<E::Fr>>,
    commitments: Vec<Commitment<E>>,
    proofs: EvaluationProof<E>,
    evaluations: Vec<[E::Fr; 2]>,
}
