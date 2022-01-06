/// Time-efficient preprocessing SNARK for R1CS.
use ark_ec::PairingEngine;

use crate::circuit::R1CS;
use crate::kzg::CommitterKey;
use crate::misc::{
    evaluate_le, hadamard, joint_matrices, powers, product_matrix_vector, sum_matrices, tensor,
};
use crate::sumcheck::proof::Sumcheck;
use crate::transcript::GeminiTranscript;

use crate::PROTOCOL_NAME;

use super::Proof;

#[inline]
fn lookup<T: Copy>(v: &[T], index: &[usize]) -> Vec<T> {
    index.iter().map(|&i| v[i]).collect()
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
        let (row, col, val_a, val_b, val_c) =
            joint_matrices(&joint_matrix, &r1cs.a, &r1cs.b, &r1cs.c);

        // let z_a_star = lookup(&r1cs.z, &col_a);
        // let r_a_star = lookup(&r_a, &row_a);
        // let rz_a_star = hadamard(&z_a_star, &r_a_star);
        // let _second_sumcheck1 =
        //     Sumcheck::new_time(&mut transcript, &val_a, &rz_a_star, &E::Fr::one());

        todo!()
    }
}
