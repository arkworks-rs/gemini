//!
//
//!
//!
mod elastic_prover;
mod time_prover;

mod streams;

use ark_ec::PairingEngine;

use crate::kzg::{Commitment, EvaluationProof};
use crate::sumcheck::prover::RoundMsg;

/// The preprocessing SNARK proof, containing all prover's messages.
pub struct Proof<E: PairingEngine> {
    first_sumcheck_messages: Vec<RoundMsg<E::Fr>>,
    second_sumcheck_messages: Vec<RoundMsg<E::Fr>>,
    third_sumcheck_messages: Vec<RoundMsg<E::Fr>>,
    ep_sumcheck_messages: Vec<RoundMsg<E::Fr>>,
    commitments: Vec<Commitment<E>>,
    proofs: EvaluationProof<E>,
    evaluations: Vec<[E::Fr; 2]>,
}
