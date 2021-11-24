use ark_ec::PairingEngine;

use crate::kzg::{Commitment, EvaluationProof};
use crate::sumcheck::prover::ProverMsg;

pub struct Proof<E: PairingEngine> {
    pub first_sumcheck_messages: Vec<ProverMsg<E::Fr>>,
    pub second_sumcheck_messages: Vec<ProverMsg<E::Fr>>,
    pub third_sumcheck_messages: Vec<ProverMsg<E::Fr>>,
    pub ep_sumcheck_messages: Vec<ProverMsg<E::Fr>>,
    pub commitments: Vec<Commitment<E>>,
    pub proofs: EvaluationProof<E>,
    pub evaluations: Vec<[E::Fr; 2]>,
}
