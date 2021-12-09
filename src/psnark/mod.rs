//! Elastic preprocessing SNARK for R1CS.
//!
//!
//!
//!
//!
mod elastic_prover;
mod time_prover;

mod streams;

use ark_ec::PairingEngine;

use crate::kzg::{Commitment, EvaluationProof};
use crate::sumcheck::prover::ProverMsgs;

/// The preprocessing SNARK proof, containing all prover's messages.
pub struct Proof<E: PairingEngine> {
    first_sumcheck_messages: ProverMsgs<E::Fr>,
    second_sumcheck_messages: ProverMsgs<E::Fr>,
    third_sumcheck_messages: ProverMsgs<E::Fr>,
    ep_sumcheck_messages: ProverMsgs<E::Fr>,
    commitments: Vec<Commitment<E>>,
    proofs: EvaluationProof<E>,
    evaluations: Vec<[E::Fr; 2]>,
}
