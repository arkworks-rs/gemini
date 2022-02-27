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

use ark_ec::PairingEngine;
use ark_ff::PrimeField;
use ark_std::vec::Vec;
use ark_std::Zero;

use crate::kzg::{Commitment, EvaluationProof};
use crate::subprotocols::entryproduct;
use crate::subprotocols::sumcheck::prover::ProverMsgs;
use crate::subprotocols::tensorcheck::TensorcheckProof;

/// The preprocessing SNARK proof, containing all prover messages.
#[allow(unused)]
#[derive(PartialEq, Eq)]
pub struct Proof<E: PairingEngine> {
    witness_commitment: Commitment<E>,
    zc_alpha: E::Fr,
    first_sumcheck_msgs: ProverMsgs<E::Fr>,
    r_star_commitments: [Commitment<E>; 3],
    z_star_commitment: Commitment<E>,
    second_sumcheck_msgs: ProverMsgs<E::Fr>,
    set_r_ep: E::Fr,
    subset_r_ep: E::Fr,
    sorted_r_commitment: Commitment<E>,
    set_alpha_ep: E::Fr,
    subset_alpha_ep: E::Fr,
    sorted_alpha_commitment: Commitment<E>,
    set_z_ep: E::Fr,
    subset_z_ep: E::Fr,
    sorted_z_commitment: Commitment<E>,
    ep_msgs: entryproduct::ProverMsgs<E>,
    ralpha_star_acc_mu_evals: Vec<E::Fr>,
    ralpha_star_acc_mu_proof: EvaluationProof<E>,
    rstars_vals: [E::Fr; 2],
    third_sumcheck_msgs: ProverMsgs<E::Fr>,
    tensorcheck_proof: TensorcheckProof<E>,
}

impl<E: PairingEngine> Proof<E> {
    pub fn size_in_bytes(&self) -> usize {
        let mut res = 0;
        let size_of_fe_in_bytes = E::Fr::zero().into_repr().as_ref().len() * 8;
        let size_of_gp_in_bytes = self.witness_commitment.size_in_bytes();

        // witness_commitment: Commitment<E>,
        res += size_of_gp_in_bytes;
        // zc_alpha: E::Fr,
        res += size_of_fe_in_bytes;
        // first_sumcheck_msgs: ProverMsgs<E::Fr>,
        res += self.first_sumcheck_msgs.size_in_bytes();
        // r_star_commitments: [Commitment<E>; 3],
        res += 3 * size_of_gp_in_bytes;
        // z_star_commitment: Commitment<E>,
        res += size_of_gp_in_bytes;
        // second_sumcheck_msgs: ProverMsgs<E::Fr>,
        res += self.second_sumcheck_msgs.size_in_bytes();
        // set_r_ep: E::Fr,
        // subset_r_ep: E::Fr,
        // sorted_r_commitment: Commitment<E>,
        // set_alpha_ep: E::Fr,
        // subset_alpha_ep: E::Fr,
        // sorted_alpha_commitment: Commitment<E>,
        // set_z_ep: E::Fr,
        // subset_z_ep: E::Fr,
        // sorted_z_commitment: Commitment<E>,
        res += (2 * size_of_fe_in_bytes + size_of_gp_in_bytes) * 3;
        // ep_msgs: entryproduct::ProverMsgs<E>,
        res += self.ep_msgs.size_in_bytes();
        // ralpha_star_acc_mu_evals: Vec<E::Fr>,
        res += self.ralpha_star_acc_mu_evals.len() * size_of_fe_in_bytes;
        // ralpha_star_acc_mu_proof: EvaluationProof<E>,
        res += size_of_gp_in_bytes;
        // rstars_vals: [E::Fr; 2],
        res += self.rstars_vals.len() * 2 * size_of_fe_in_bytes;
        // third_sumcheck_msgs: ProverMsgs<E::Fr>,
        res += self.third_sumcheck_msgs.size_in_bytes();
        // tensorcheck_proof: TensorcheckProof<E>,
        res += self.tensorcheck_proof.size_in_bytes();
        res
    }
}
