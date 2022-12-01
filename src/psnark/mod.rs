//! Elastic preprocessing SNARK for R1CS.
//!
//!
//!
//!
//!
mod elastic_prover;
mod time_prover;
mod verifier;

mod streams;

#[cfg(test)]
mod tests;

use ark_ec::pairing::Pairing;
use ark_serialize::*;
use ark_std::vec::Vec;

use crate::kzg::{Commitment, EvaluationProof};
use crate::subprotocols::entryproduct;
use crate::subprotocols::sumcheck::prover::ProverMsgs;
use crate::subprotocols::tensorcheck::TensorcheckProof;



pub type Index<E> = Vec<Commitment<E>>;


/// The preprocessing SNARK proof, containing all prover messages.
#[derive(CanonicalSerialize, PartialEq, Eq)]
pub struct Proof<E: Pairing> {
    witness_commitment: Commitment<E>,
    zc_alpha: E::ScalarField,
    first_sumcheck_msgs: ProverMsgs<E::ScalarField>,
    r_star_commitments: [Commitment<E>; 3],
    z_star_commitment: Commitment<E>,
    second_sumcheck_msgs: ProverMsgs<E::ScalarField>,
    set_r_ep: E::ScalarField,
    subset_r_ep: E::ScalarField,
    sorted_r_commitment: Commitment<E>,
    set_alpha_ep: E::ScalarField,
    subset_alpha_ep: E::ScalarField,
    sorted_alpha_commitment: Commitment<E>,
    set_z_ep: E::ScalarField,
    subset_z_ep: E::ScalarField,
    sorted_z_commitment: Commitment<E>,
    ep_msgs: entryproduct::ProverMsgs<E>,
    ralpha_star_acc_mu_evals: Vec<E::ScalarField>,
    ralpha_star_acc_mu_proof: EvaluationProof<E>,
    rstars_vals: [E::ScalarField; 2],
    third_sumcheck_msgs: ProverMsgs<E::ScalarField>,
    tensorcheck_proof: TensorcheckProof<E>,
}
