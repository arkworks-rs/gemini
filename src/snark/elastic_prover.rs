//! Space-efficient algebraic prover implementation for R1CS.
use ark_ec::PairingEngine;
use ark_ff::Field;
use ark_std::borrow::Borrow;
use ark_std::One;
use log::debug;
use merlin::Transcript;

use crate::circuit::R1CStream;
use crate::kzg::space::CommitterKeyStream;
use crate::misc::{evaluate_be, evaluate_le, expand_tensor, powers, strip_last, MatrixElement};
use crate::snark::streams::MatrixTensor;
use crate::snark::Proof;
use crate::stream::Streamer;
use crate::sumcheck::proof::Sumcheck;
use crate::sumcheck::streams::FoldedPolynomialTree;
use crate::tensorcheck::{evaluate_folding, partially_foldtree, TensorCheckProof};
use crate::transcript::GeminiTranscript;
use crate::{lincomb, PROTOCOL_NAME, SPACE_TIME_THRESHOLD};

#[allow(dead_code)]
pub fn elastic_tensorcheck<F, E, SG, SB, SF1>(
    transcript: &mut Transcript,
    ck: CommitterKeyStream<E, SG>,
    base_polynomial: SB,
    body_polynomials: (SF1, &[F]),
) -> TensorCheckProof<E>
where
    F: Field,
    E: PairingEngine<Fr = F>,
    SG: Streamer,
    SG::Item: Borrow<E::G1Affine>,
    SB: Streamer,
    SB::Item: Borrow<E::Fr>,
    SF1: Streamer<Item = F>,
{
    let tensorcheck_challenges = strip_last(body_polynomials.1);
    let time_ck = ck.as_committer_key(usize::min(1 << SPACE_TIME_THRESHOLD, ck.powers_of_g.len()));
    let (tensorcheck_sfoldings, tensorcheck_tfoldings) =
        partially_foldtree(body_polynomials.0, tensorcheck_challenges);
    let mut folded_polynomials_commitments = ck.commit_folding(tensorcheck_sfoldings);
    folded_polynomials_commitments.extend(time_ck.batch_commit(&tensorcheck_tfoldings));

    // add commitments to transcript
    folded_polynomials_commitments
        .iter()
        .for_each(|c| transcript.append_commitment(b"commitment", c));
    let eval_chal = transcript.get_challenge::<E::Fr>(b"evaluation-chal");
    let eval_points = [eval_chal.square(), eval_chal, -eval_chal];

    let mut folded_polynomials_evaluations =
        evaluate_folding(tensorcheck_sfoldings, eval_points[1])
            .into_iter()
            .zip(evaluate_folding(tensorcheck_sfoldings, eval_points[2]))
            .map(|(x, y)| [x, y])
            .collect::<Vec<_>>();
    folded_polynomials_evaluations.extend(tensorcheck_tfoldings.into_iter().map(|p| {
        [
            evaluate_le(&p, &eval_points[1]),
            evaluate_le(&p, &eval_points[2]),
        ]
    }));
    let evaluations_w = [
        evaluate_be(base_polynomial.stream(), &eval_points[0]),
        evaluate_be(base_polynomial.stream(), &eval_points[1]),
        evaluate_be(base_polynomial.stream(), &eval_points[2]),
    ];
    evaluations_w
        .iter()
        .for_each(|e| transcript.append_scalar(b"eval", e));
    folded_polynomials_evaluations
        .iter()
        .flatten()
        .for_each(|e| transcript.append_scalar(b"eval", e));
    let open_chal = transcript.get_challenge::<E::Fr>(b"open-chal");
    let open_chal_len = body_polynomials.1.len() + 1;
    let open_chals = powers(open_chal, open_chal_len);

    let tensorcheck_open_time = start_timer!(|| "Commitment open");
    let open_space_chals = &open_chals[1..];
    let tensorcheck_foldings =
        FoldedPolynomialTree::new(body_polynomials.0, tensorcheck_challenges);
    let (_, proof_w) = ck.open_multi_points(base_polynomial, &eval_points);
    let (_, proof) = ck.open_folding(tensorcheck_foldings, &eval_points, open_space_chals);
    // let time_proof = time_ck.batch_open_multi_points(tensorcheck_tfoldings, &eval_points, open_time_chals);
    let evaluation_proof = proof_w + proof;
    end_timer!(tensorcheck_open_time);
    TensorCheckProof {
        folded_polynomials_commitments,
        folded_polynomials_evaluations,
        evaluation_proof,
        base_polynomials_evaluations: vec![evaluations_w],
    }
}

/// Streaming function for producing the tensor check proof.
pub fn tensorcheck<F, E, SG, SB, SF1>(
    transcript: &mut Transcript,
    ck: CommitterKeyStream<E, SG>,
    base_polynomial: SB,
    body_polynomials: (SF1, &[F]),
) -> TensorCheckProof<E>
where
    F: Field,
    E: PairingEngine<Fr = F>,
    SG: Streamer,
    SG::Item: Borrow<E::G1Affine>,
    SB: Streamer,
    SB::Item: Borrow<E::Fr>,
    SF1: Streamer<Item = F>,
{
    let tensorcheck_challenges = strip_last(body_polynomials.1);
    let tensorcheck_foldings =
        FoldedPolynomialTree::new(body_polynomials.0, tensorcheck_challenges);
    let folded_polynomials_commitments = ck.commit_folding(tensorcheck_foldings);

    // add commitments to transcript
    folded_polynomials_commitments
        .iter()
        .for_each(|c| transcript.append_commitment(b"commitment", c));
    let eval_chal = transcript.get_challenge::<E::Fr>(b"evaluation-chal");
    let eval_points = [eval_chal.square(), eval_chal, -eval_chal];

    let folded_polynomials_evaluations = evaluate_folding(tensorcheck_foldings, eval_points[1])
        .into_iter()
        .zip(evaluate_folding(tensorcheck_foldings, eval_points[2]))
        .map(|(x, y)| [x, y])
        .collect::<Vec<_>>();
    let evaluations_w = [
        evaluate_be(base_polynomial.stream(), &eval_points[0]),
        evaluate_be(base_polynomial.stream(), &eval_points[1]),
        evaluate_be(base_polynomial.stream(), &eval_points[2]),
    ];
    evaluations_w
        .iter()
        .for_each(|e| transcript.append_scalar(b"eval", e));
    folded_polynomials_evaluations
        .iter()
        .flatten()
        .for_each(|e| transcript.append_scalar(b"eval", e));
    let open_chal = transcript.get_challenge::<E::Fr>(b"open-chal");
    let open_chal_len = body_polynomials.1.len() + 1;
    let open_chals = powers(open_chal, open_chal_len);

    let (_, proof_w) = ck.open_multi_points(base_polynomial, &eval_points);
    let (_, proof) = ck.open_folding(tensorcheck_foldings, &eval_points, &open_chals[1..]);
    let evaluation_proof = proof_w + proof;
    TensorCheckProof {
        folded_polynomials_commitments,
        folded_polynomials_evaluations,
        evaluation_proof,
        base_polynomials_evaluations: vec![evaluations_w],
    }
}

impl<E: PairingEngine> Proof<E> {
    /// Function for creating SNARK proof using the space-efficient prover.
    /// The input contains streams of R1CS instance and committer key.
    pub fn new_space<SM, SG, SZ, SW>(
        r1cs: R1CStream<SM, SZ, SW>,
        ck: CommitterKeyStream<E, SG>,
    ) -> Proof<E>
    where
        E: PairingEngine,
        SM: Streamer,
        SZ: Streamer,
        SW: Streamer,
        SG: Streamer,
        SM::Item: Borrow<MatrixElement<E::Fr>>,
        SZ::Item: Borrow<E::Fr>,
        SW::Item: Borrow<E::Fr>,
        SZ::Item: Borrow<E::Fr>,
        SZ::Item: Borrow<E::Fr>,
        SG::Item: Borrow<E::G1Affine>,
    {
        let algebraic_proof_time = start_timer!(|| "ARK::Prove");

        debug!(
            "features:{};space-time-threshold:{};tensor-expansion:{};msm-buffer:{}",
            crate::misc::_features_enabled(),
            crate::SPACE_TIME_THRESHOLD,
            crate::misc::TENSOR_EXPANSION_LOG,
            crate::kzg::msm::MAX_MSM_BUFFER_LOG,
        );

        let mut transcript = merlin::Transcript::new(PROTOCOL_NAME);
        // send the vector w
        let witness_commitment_time = start_timer!(|| "Commitment to w");
        let witness_commitment = ck.commit(r1cs.witness);
        end_timer!(witness_commitment_time);

        // send witness, receive challenge.
        transcript.append_commitment(b"witness", &witness_commitment);
        let alpha = transcript.get_challenge(b"alpha");

        // send evaluation of zc(alpha)
        let zc_alpha = evaluate_be(r1cs.z_c.stream(), &alpha);
        transcript.append_scalar(b"zc(alpha)", &zc_alpha);

        // run the sumcheck for z_a and z_b with twist alpha
        let first_sumcheck_time = start_timer!(|| "First sumcheck");
        let first_proof = Sumcheck::new_elastic(&mut transcript, r1cs.z_a, r1cs.z_b, alpha);
        end_timer!(first_sumcheck_time);

        // after sumcheck, generate a new challenge
        let ra_a_z = first_proof.final_foldings[0][0];
        let eta = transcript.get_challenge::<E::Fr>(b"eta");
        // run the second sumcheck
        let mut a_tensors: Vec<E::Fr> = Vec::new();
        let mut b_tensors = Vec::new();
        let mut c_tensors = Vec::new();
        let mut first_prover_randomness = first_proof.challenges.iter();
        let r = first_prover_randomness.next().unwrap();
        let mut acc = alpha;

        a_tensors.push(acc * r);
        b_tensors.push(*r);
        c_tensors.push(acc);

        for r in first_prover_randomness {
            acc = acc.square();

            a_tensors.push(acc * r);
            b_tensors.push(*r);
            c_tensors.push(acc);
        }

        let a_tensors_expanded = expand_tensor(&a_tensors);
        let b_tensors_expanded = expand_tensor(&b_tensors);
        let c_tensors_expanded = expand_tensor(&c_tensors);
        let len = r1cs.z.len();
        let a_alpha = MatrixTensor::new(r1cs.a_rowm, &a_tensors_expanded, len);
        let b_alpha = MatrixTensor::new(r1cs.b_rowm, &b_tensors_expanded, len);
        let c_alpha = MatrixTensor::new(r1cs.c_rowm, &c_tensors_expanded, len);
        let sumcheck_batch_challenges = powers(eta, 3);
        let lhs = lincomb!((a_alpha, b_alpha, c_alpha), &sumcheck_batch_challenges);

        let second_sumcheck_time = start_timer!(|| "Second sumcheck");
        let second_proof = Sumcheck::new_elastic(&mut transcript, lhs, r1cs.z, E::Fr::one());
        end_timer!(second_sumcheck_time);

        let tensor_evaluation = second_proof.final_foldings[0][0];
        transcript.append_scalar(b"tensor-eval", &tensor_evaluation);
        let batch_challenge = transcript.get_challenge::<E::Fr>(b"batch_challenge");

        let tensorcheck_time = start_timer!(|| "Tensorcheck");
        let tensorcheck_batch_challenges = powers(batch_challenge, 2);
        let tensorcheck_polynomials = lincomb!((lhs, r1cs.z), &tensorcheck_batch_challenges);
        let tensor_check_proof = tensorcheck(
            &mut transcript,
            ck,
            r1cs.witness,
            (tensorcheck_polynomials, &second_proof.challenges),
        );
        end_timer!(tensorcheck_time);

        end_timer!(algebraic_proof_time);
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
