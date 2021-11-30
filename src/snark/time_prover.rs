//! The Time prover for the algebraic proofs.
use ark_ec::PairingEngine;
use ark_ff::{Field, One, Zero};
use log::debug;

use crate::circuit::R1CS;
use crate::kzg::time::CommitterKey;
use crate::misc::{evaluate_le, hadamard};
use crate::misc::{powers, product_matrix_vector, tensor};
use crate::snark::Proof;
use crate::sumcheck::proof::Sumcheck;
use crate::tensorcheck::TensorCheckProof;
use crate::transcript::GeminiTranscript;
use crate::PROTOCOL_NAME;

impl<E: PairingEngine> Proof<E> {
    /// Function for creating SNARK proof using the time-efficient prover.
    /// The input contains the R1CS instance and committer key of polynomial commitments.
    pub fn new_time(r1cs: &R1CS<E::Fr>, ck: &CommitterKey<E>) -> Proof<E>
    where
        E: PairingEngine,
    {
        let snark_time = start_timer!(|| module_path!());


        debug!(
            "features:{};space-time-threshold:{};tensor-expansion:{};msm-buffer:{}",
            crate::misc::_features_enabled(),
            crate::SPACE_TIME_THRESHOLD,
            crate::misc::TENSOR_EXPANSION_LOG,
            crate::kzg::msm::MAX_MSM_BUFFER_LOG,
        );

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

        // XXXX change me
        let num_constraints = r1cs.z.len();
        let b_challenges = tensor(&first_proof.challenges);
        let c_challenges = powers(alpha, num_constraints);
        let a_challenges = hadamard(&b_challenges, &c_challenges);

        let ra_a_z = first_proof.final_foldings[0][0];
        let eta = transcript.get_challenge::<E::Fr>(b"eta");
        let eta2 = eta.square();

        let mut abc_tensored = vec![E::Fr::zero(); num_constraints];

        for (i, row_a) in r1cs.a.iter().enumerate() {
            for &(val, col) in row_a {
                abc_tensored[col] += a_challenges[i] * val;
            }
        }

        for (i, row_b) in r1cs.b.iter().enumerate() {
            for &(val, col) in row_b {
                abc_tensored[col] += eta * b_challenges[i] * val;
            }
        }

        for (i, row_c) in r1cs.c.iter().enumerate() {
            for &(val, col) in row_c {
                abc_tensored[col] += eta2 * c_challenges[i] * val;
            }
        }

        let second_sumcheck_time = start_timer!(|| "Second sumcheck");
        let second_proof = Sumcheck::new_time(
            &mut transcript,
            &abc_tensored,
            &r1cs.z, // XXX. this can be borrowed?
            &E::Fr::one(),
        );
        end_timer!(second_sumcheck_time);


        let tensor_evaluation = second_proof.final_foldings[0][0];
        transcript.append_scalar(b"tensor-eval", &tensor_evaluation);

        // derive the points needed from the challenges
        let tc_base_polynomials = [&r1cs.w];
        let second_sumcheck_polynomials = [&abc_tensored, &r1cs.z];
        let tc_body_polynomials = [(
            &second_sumcheck_polynomials[..],
            &second_proof.challenges[..],
        )];
        let tensorcheck_time = start_timer!(|| "Tensorcheck");
        let tensor_check_proof = TensorCheckProof::new_time(
            &mut transcript,
            ck,
            tc_base_polynomials,
            tc_body_polynomials,
        );
        end_timer!(tensorcheck_time);

        end_timer!(snark_time);
        Proof {
            witness_commitment,
            zc_alpha,
            first_sumcheck_msgs: first_proof.messages,
            ra_a_z,
            second_sumcheck_msgs: second_proof.messages,
            tensor_evaluation,
            tensor_check_proof,
        }
    }
}
