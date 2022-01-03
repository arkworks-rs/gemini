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

use crate::entryproduct;
use crate::kzg::Commitment;
use crate::sumcheck::prover::ProverMsgs;
use crate::tensorcheck::TensorCheckProof;

/// The preprocessing SNARK proof, containing all prover's messages.
pub struct Proof<E: PairingEngine> {
    witness_commitment: Commitment<E>,
    zc_alpha: E::Fr,
    first_sumcheck_msgs: ProverMsgs<E::Fr>,
    rb_star_commitment: Commitment<E>,
    rc_star_commitment: Commitment<E>,
    z_star_commitment: Commitment<E>,
    z_star_rs: [E::Fr; 3],
    second_sumcheck_msgs: ProverMsgs<E::Fr>,
    set_r_ep: E::Fr,
    subset_r_ep: E::Fr,
    sorted_r_ep: E::Fr,
    sorted_r_commitment: Commitment<E>,
    set_z_ep: E::Fr,
    subset_z_ep: E::Fr,
    sorted_z_ep: E::Fr,
    sorted_z_commitment: Commitment<E>,
    ep_msgs: entryproduct::ProverMsgs<E>,
    third_sumcheck_msgs: ProverMsgs<E::Fr>,
    tensor_check_proof: TensorCheckProof<E>,
}
