//! The verifier for the algebraic proofs.
use ark_ec::pairing::Pairing;

use crate::circuit::R1cs;
use crate::errors::{VerificationError, VerificationResult};
use crate::kzg::VerifierKey;
use crate::misc::{
    evaluate_le, hadamard_unsafe, ip, ip_unsafe, powers, product_matrix_vector, tensor,
};
use crate::snark::Proof;
use crate::subprotocols::sumcheck::Subclaim;
use crate::transcript::GeminiTranscript;
use crate::PROTOCOL_NAME;

impl<E: Pairing> Proof<E> {
    /// Verification function for SNARK proof.
    /// The input contains the R1CS instance and the verification key
    /// of polynomial commitment.
    pub fn verify(&self, r1cs: &R1cs<E::ScalarField>, vk: &VerifierKey<E>) -> VerificationResult {
        let mut transcript = merlin::Transcript::new(PROTOCOL_NAME);
        let witness_commitment = self.witness_commitment;

        transcript.append_serializable(b"witness", &witness_commitment);
        let alpha = transcript.get_challenge(b"alpha");
        let first_sumcheck_msgs = &self.first_sumcheck_msgs;

        // First sumcheck
        transcript.append_serializable(b"zc(alpha)", &self.zc_alpha);

        let subclaim_1 = Subclaim::new(&mut transcript, first_sumcheck_msgs, self.zc_alpha)?;

        let eta = transcript.get_challenge::<E::ScalarField>(b"eta");
        let etas = powers(eta, 3);

        let num_constraints = r1cs.a.len();
        let tensor_challenges = tensor(&subclaim_1.challenges);
        let alpha_powers = powers(alpha, num_constraints);
        let hadamard_randomness = hadamard_unsafe(&tensor_challenges, &alpha_powers);

        // Second sumcheck
        let asserted_sum_2 = ip(
            &[
                subclaim_1.final_foldings[0][0],
                subclaim_1.final_foldings[0][1],
                self.zc_alpha,
            ],
            &etas,
        );

        let subclaim_2 =
            Subclaim::new(&mut transcript, &self.second_sumcheck_msgs, asserted_sum_2)?;

        // Tensorcheck
        let gamma = transcript.get_challenge::<E::ScalarField>(b"batch_challenge");
        self.tensorcheck_proof
            .folded_polynomials_commitments
            .iter()
            .for_each(|c| transcript.append_serializable(b"commitment", c));
        let beta = transcript.get_challenge::<E::ScalarField>(b"evaluation-chal");
        let beta_powers = powers(beta, num_constraints);
        let minus_beta_powers = powers(-beta, num_constraints);

        let a_beta_powers = product_matrix_vector(&r1cs.a, &beta_powers);
        let b_beta_powers = product_matrix_vector(&r1cs.b, &beta_powers);
        let c_beta_powers = product_matrix_vector(&r1cs.c, &beta_powers);
        let a_minus_beta_powers = product_matrix_vector(&r1cs.a, &minus_beta_powers);
        let b_minus_beta_powers = product_matrix_vector(&r1cs.b, &minus_beta_powers);
        let c_minus_beta_powers = product_matrix_vector(&r1cs.c, &minus_beta_powers);

        let m_pos = ip(
            &[
                ip(&a_beta_powers, &hadamard_randomness),
                ip_unsafe(&b_beta_powers, &tensor_challenges),
                ip(&c_beta_powers, &alpha_powers),
            ],
            &etas,
        );
        let m_neg = ip(
            &[
                ip(&a_minus_beta_powers, &hadamard_randomness),
                ip_unsafe(&b_minus_beta_powers, &tensor_challenges),
                ip(&c_minus_beta_powers, &alpha_powers),
            ],
            &etas,
        );

        let beta_power = beta_powers[r1cs.x.len()];
        let x_beta = evaluate_le(&r1cs.x, &beta);
        let x_minus_beta = evaluate_le(&r1cs.x, &-beta);
        let z_pos = x_beta + beta_power * self.tensorcheck_proof.base_polynomials_evaluations[0][1];

        let beta_power = if (r1cs.x.len() & 1) == 0 {
            beta_power
        } else {
            -beta_power
        };
        let z_neg =
            x_minus_beta + beta_power * self.tensorcheck_proof.base_polynomials_evaluations[0][2];

        let direct_base_polynomials_evaluations =
            vec![[m_pos + gamma * z_pos, m_neg + gamma * z_neg]];

        self.tensorcheck_proof
            .verify(
                &mut transcript,
                vk,
                &[subclaim_2.final_foldings[0].to_vec()],
                &[self.witness_commitment],
                &direct_base_polynomials_evaluations,
                &[subclaim_2.challenges],
                beta,
                gamma,
            )
            .map_err(|_| VerificationError)
    }
}
