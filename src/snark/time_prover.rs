//! The Time prover for the algebraic proofs.
use ark_ec::pairing::Pairing;
use ark_ff::{Field, One, Zero};
use log::debug;

use crate::circuit::R1cs;
use crate::kzg::CommitterKey;
use crate::misc::{evaluate_le, hadamard};
use crate::misc::{powers, product_matrix_vector, tensor};
use crate::snark::Proof;
use crate::subprotocols::sumcheck::proof::Sumcheck;
use crate::subprotocols::tensorcheck::TensorcheckProof;
use crate::transcript::GeminiTranscript;
use crate::PROTOCOL_NAME;

impl<E: Pairing> Proof<E> {
    /// Given as input the R1CS instance `r1cs` and the committer key `ck` for the polynomial commitment scheme,
    /// produce a new SNARK proof using the time-efficient prover.
    pub fn new_time(r1cs: &R1cs<E::ScalarField>, ck: &CommitterKey<E>) -> Proof<E>
    where
        E: Pairing,
    {
        let snark_time = start_timer!(|| module_path!());

        debug!(
            "features:{};space-time-threshold:{};tensor-expansion:{}",
            crate::misc::_features_enabled(),
            crate::SPACE_TIME_THRESHOLD,
            crate::misc::TENSOR_EXPANSION_LOG,
        );

        let z_a = product_matrix_vector(&r1cs.a, &r1cs.z);
        let z_b = product_matrix_vector(&r1cs.b, &r1cs.z);
        let z_c = product_matrix_vector(&r1cs.c, &r1cs.z);

        let mut transcript = merlin::Transcript::new(PROTOCOL_NAME);
        let witness_commitment_time = start_timer!(|| "Commitment to w");
        let witness_commitment = ck.commit(&r1cs.w);
        end_timer!(witness_commitment_time);

        transcript.append_serializable(b"witness", &witness_commitment);
        let alpha = transcript.get_challenge(b"alpha");

        let zc_alpha = evaluate_le(&z_c, &alpha);
        transcript.append_serializable(b"zc(alpha)", &zc_alpha);

        let first_sumcheck_time = start_timer!(|| "First sumcheck");
        let first_proof = Sumcheck::new_time(&mut transcript, &z_a, &z_b, &alpha);
        let first_sumcheck_msgs = first_proof.prover_messages();
        end_timer!(first_sumcheck_time);

        let b_challenges = tensor(&first_proof.challenges);
        let c_challenges = powers(alpha, b_challenges.len());
        let a_challenges = hadamard(&b_challenges, &c_challenges);

        let eta = transcript.get_challenge::<E::ScalarField>(b"eta");
        let eta2 = eta.square();

        let mut abc_tensored = vec![E::ScalarField::zero(); r1cs.z.len()];

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
            &r1cs.z,
            &E::ScalarField::one(),
        );
        let second_sumcheck_msgs = second_proof.prover_messages();
        end_timer!(second_sumcheck_time);

        // derive the points needed from the challenges
        let tc_base_polynomials = [&r1cs.w];
        let second_sumcheck_polynomials = [&abc_tensored, &r1cs.z];
        let tc_body_polynomials = [(
            &second_sumcheck_polynomials[..],
            &second_proof.challenges[..],
        )];
        let tensorcheck_time = start_timer!(|| "Tensorcheck");
        let tensorcheck_proof = TensorcheckProof::new_time(
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
            first_sumcheck_msgs,
            second_sumcheck_msgs,
            tensorcheck_proof,
        }
    }
}
