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

use crate::entryproduct;
use crate::kzg::{Commitment, EvaluationProof};
use crate::sumcheck::prover::ProverMsgs;
use crate::tensorcheck::TensorcheckProof;

/// The preprocessing SNARK proof, containing all prover's messages.
pub struct Proof<E: PairingEngine> {
    witness_commitment: Commitment<E>,
    zc_alpha: E::Fr,
    first_sumcheck_msgs: ProverMsgs<E::Fr>,
    r_star_commitments: [Commitment<E>; 3],
    z_star_commitment: Commitment<E>,
    second_sumcheck_msgs: ProverMsgs<E::Fr>,
    set_r_ep: E::Fr,
    subset_r_ep: E::Fr,
    sorted_r_ep: E::Fr,
    sorted_r_commitment: Commitment<E>,
    set_alpha_ep: E::Fr,
    subset_alpha_ep: E::Fr,
    sorted_alpha_ep: E::Fr,
    sorted_alpha_commitment: Commitment<E>,
    set_z_ep: E::Fr,
    subset_z_ep: E::Fr,
    sorted_z_ep: E::Fr,
    sorted_z_commitment: Commitment<E>,
    ep_msgs: entryproduct::ProverMsgs<E>,
    ralpha_star_mu: (E::Fr, EvaluationProof<E>),
    rstars_vals: [E::Fr; 2],
    third_sumcheck_msgs: ProverMsgs<E::Fr>,
    tensor_check_proof: TensorcheckProof<E>,
}
