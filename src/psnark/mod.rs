//! Elastic preprocessing SNARK for R1CS.
//!
//!
//!
//!
//!
#[allow(unused_assignments)]
mod elastic_prover;
mod time_prover;

mod streams;

use ark_ec::PairingEngine;

use crate::kzg::Commitment;
use crate::sumcheck::prover::ProverMsgs;
use crate::tensorcheck::TensorCheckProof;

/// The preprocessing SNARK proof, containing all prover's messages.
pub struct Proof<E: PairingEngine> {
    witness_commitment: Commitment<E>,
    zc_alpha: E::Fr,
    first_sumcheck_msgs: ProverMsgs<E::Fr>,
    com_rb_star: Commitment<E>,
    com_rc_star: Commitment<E>,
    com_z_star: Commitment<E>,
    second_sumcheck_msgs: ProverMsgs<E::Fr>,
    pl_r_set_ep: E::Fr,
    pl_r_subset_ep: E::Fr,
    pl_r_sorted_ep: E::Fr,
    pl_z_set_ep: E::Fr,
    pl_z_subset_ep: E::Fr,
    pl_z_sorted_ep: E::Fr,
    third_sumcheck_msgs: ProverMsgs<E::Fr>,
    tensor_check_proof: TensorCheckProof<E>,
}
