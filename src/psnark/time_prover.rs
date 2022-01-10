/// Time-efficient preprocessing SNARK for R1CS.
use ark_ec::PairingEngine;
use ark_ff::Field;
use ark_std::One;

use crate::circuit::R1CS;
use crate::kzg::CommitterKey;
use crate::misc::{
    evaluate_le, hadamard, joint_matrices, linear_combination, powers, product_matrix_vector,
    sum_matrices, tensor,
};
use crate::sumcheck::proof::Sumcheck;
use crate::transcript::GeminiTranscript;

use crate::PROTOCOL_NAME;

use super::Proof;

#[inline]
fn lookup<T: Copy>(v: &[T], index: &Vec<usize>) -> Vec<T> {
    index.iter().map(|&i| v[i]).collect()
}

#[inline]
fn plookup<F: Field>(
    subset: &Vec<F>,
    set: &Vec<F>,
    index: &Vec<usize>,
    gamma: F,
    chi: F,
) -> (Vec<Vec<F>>, F, F, Vec<F>, Vec<Vec<F>>) {
    todo!()
}

impl<E: PairingEngine> Proof<E> {
    /// Given as input the R1CS instance `r1cs`
    /// and the committer key `ck`,
    /// return a new _preprocessing_ SNARK using the elastic prover.
    pub fn new_time(r1cs: &R1CS<E::Fr>, ck: &CommitterKey<E>) -> Proof<E> {
        let z_a = product_matrix_vector(&r1cs.a, &r1cs.z);
        let z_b = product_matrix_vector(&r1cs.b, &r1cs.z);
        let z_c = product_matrix_vector(&r1cs.c, &r1cs.z);

        let mut transcript = merlin::Transcript::new(PROTOCOL_NAME);
        let witness_commitment_time = start_timer!(|| "Commitment to w");
        let witness_commitment = ck.commit(&r1cs.w);
        end_timer!(witness_commitment_time);

        transcript.append_commitment(b"witness", &witness_commitment);
        let alpha = transcript.get_challenge(b"alpha");

        let zc_alpha = evaluate_le(&z_c, &alpha);
        transcript.append_scalar(b"zc(alpha)", &zc_alpha);

        let first_sumcheck_time = start_timer!(|| "First sumcheck");
        let first_proof = Sumcheck::new_time(&mut transcript, &z_a, &z_b, &alpha);
        end_timer!(first_sumcheck_time);

        let b_challenges = tensor(&first_proof.challenges);
        let c_challenges = powers(alpha, b_challenges.len());
        let a_challenges = hadamard(&b_challenges, &c_challenges);

        let joint_matrix = sum_matrices(&r1cs.a, &r1cs.b, &r1cs.c);
        let (row, col, row_index, col_index, val_a, val_b, val_c) =
            joint_matrices(&joint_matrix, &r1cs.a, &r1cs.b, &r1cs.c);

        let r_a_star = lookup(&a_challenges, &row_index);
        let r_b_star = lookup(&b_challenges, &row_index);
        let r_c_star = lookup(&c_challenges, &row_index);
        let z_star = lookup(&r1cs.z, &col_index);

        let z_r_commitments_time = start_timer!(|| "Commitments to z* and r*");
        let z_r_commitments = ck.batch_commit(vec![&r_a_star, &r_b_star, &r_c_star, &z_star]);
        end_timer!(z_r_commitments_time);

        z_r_commitments
            .iter()
            .for_each(|c| transcript.append_commitment(b"commitment", c));

        let eta = transcript.get_challenge::<E::Fr>(b"eta");
        let eta2 = eta.square();

        let r_star_val = linear_combination(
            &[
                hadamard(&r_a_star, &val_a),
                hadamard(&r_b_star, &val_b),
                hadamard(&r_c_star, &val_c),
            ],
            &[E::Fr::one(), eta, eta2],
        )
        .unwrap();

        let second_sumcheck_time = start_timer!(|| "Second sumcheck");
        let second_proof = Sumcheck::new_time(&mut transcript, &z_star, &r_star_val, &E::Fr::one());
        let second_sumcheck_msgs = second_proof.prover_messages();
        end_timer!(second_sumcheck_time);

        let gamma = transcript.get_challenge(b"gamma");
        let chi = transcript.get_challenge(b"chi");

        let (r_lookup_vec, r_subset_prod, r_set_prod, r_sorted, r_partial_prods) =
            plookup(&r_a_star, &a_challenges, &row_index, gamma, chi);
        let (z_lookup_vec, z_subset_prod, z_set_prod, z_sorted, z_partial_prods) =
            plookup(&z_star, &r1cs.z, &col_index, gamma, chi);

        vec![r_subset_prod, r_set_prod, z_subset_prod, z_set_prod]
            .iter()
            .for_each(|c| transcript.append_scalar(b"entryprod", c));

        let sorted_commitments_time = start_timer!(|| "Commitments to sorted vectors");
        let sorted_commitments = ck.batch_commit(vec![&r_sorted, &z_sorted]);
        end_timer!(sorted_commitments_time);

        let partial_prod_commitments_time = start_timer!(|| "Commitments to partial prods");
        let r_partial_prod_commitments = ck.batch_commit(&r_partial_prods);
        let z_partial_prod_commitments = ck.batch_commit(&z_partial_prods);
        end_timer!(partial_prod_commitments_time);

        sorted_commitments
            .iter()
            .chain(r_partial_prod_commitments.iter())
            .chain(z_partial_prod_commitments.iter())
            .for_each(|c| transcript.append_commitment(b"commitment", c));

        todo!()
    }
}
