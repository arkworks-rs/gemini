//! Space-efficient algebraic prover implementation for R1CS.
use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_std::borrow::Borrow;
use ark_std::vec::Vec;
use ark_std::One;
use log::debug;
use merlin::Transcript;

use crate::circuit::R1csStream;
use crate::iterable::Iterable;
use crate::kzg::CommitterKeyStream;
use crate::misc::{evaluate_be, evaluate_le, hadamard, powers, powers2, strip_last, MatrixElement};
use crate::snark::streams::MatrixTensor;
use crate::snark::Proof;
use crate::subprotocols::sumcheck::proof::Sumcheck;
use crate::subprotocols::sumcheck::streams::FoldedPolynomialTree;
use crate::subprotocols::tensorcheck::{evaluate_folding, partially_foldtree, TensorcheckProof};
use crate::transcript::GeminiTranscript;
use crate::{lincomb, PROTOCOL_NAME, SPACE_TIME_THRESHOLD};

#[allow(dead_code)]
pub fn elastic_tensorcheck<F, E, SG, SB, SF1>(
    transcript: &mut Transcript,
    ck: CommitterKeyStream<E, SG>,
    base_polynomial: &SB,
    body_polynomials: (&SF1, &[F]),
    max_msm_buffer: usize,
) -> TensorcheckProof<E>
where
    F: Field,
    E: Pairing<ScalarField = F>,
    SG: Iterable,
    SG::Item: Borrow<E::G1Affine>,
    SB: Iterable,
    SB::Item: Borrow<E::ScalarField>,
    SF1: Iterable<Item = F>,
{
    let tensorcheck_challenges = strip_last(body_polynomials.1);
    let time_ck = ck.as_committer_key(usize::min(1 << SPACE_TIME_THRESHOLD, ck.powers_of_g.len()));
    let (tensorcheck_sfoldings, tensorcheck_tfoldings) =
        partially_foldtree(body_polynomials.0, tensorcheck_challenges);
    let mut folded_polynomials_commitments =
        ck.commit_folding(&tensorcheck_sfoldings, max_msm_buffer);
    folded_polynomials_commitments.extend(time_ck.batch_commit(&tensorcheck_tfoldings));

    // add commitments to transcript
    folded_polynomials_commitments
        .iter()
        .for_each(|c| transcript.append_serializable(b"commitment", c));
    let eval_chal = transcript.get_challenge::<E::ScalarField>(b"evaluation-chal");
    let eval_points = [eval_chal.square(), eval_chal, -eval_chal];

    let mut folded_polynomials_evaluations =
        evaluate_folding(&tensorcheck_sfoldings, eval_points[1])
            .into_iter()
            .zip(evaluate_folding(&tensorcheck_sfoldings, eval_points[2]))
            .map(|(x, y)| [x, y])
            .collect::<Vec<_>>();
    folded_polynomials_evaluations.extend(tensorcheck_tfoldings.into_iter().map(|p| {
        [
            evaluate_le(&p, &eval_points[1]),
            evaluate_le(&p, &eval_points[2]),
        ]
    }));
    let evaluations_w = [
        evaluate_be(base_polynomial.iter(), &eval_points[0]),
        evaluate_be(base_polynomial.iter(), &eval_points[1]),
        evaluate_be(base_polynomial.iter(), &eval_points[2]),
    ];
    evaluations_w
        .iter()
        .for_each(|e| transcript.append_serializable(b"eval", &e));
    folded_polynomials_evaluations
        .iter()
        .flatten()
        .for_each(|e| transcript.append_serializable(b"eval", e));
    let open_chal = transcript.get_challenge::<E::ScalarField>(b"open-chal");
    let open_chal_len = body_polynomials.1.len() + 1;
    let open_chals = powers(open_chal, open_chal_len);

    let tensorcheck_open_time = start_timer!(|| "Commitment open");
    let open_space_chals = &open_chals[1..];
    let tensorcheck_foldings =
        FoldedPolynomialTree::new(body_polynomials.0, tensorcheck_challenges);
    let (_, proof_w) = ck.open_multi_points(base_polynomial, &eval_points, max_msm_buffer);
    let (_, proof) = ck.open_folding(
        tensorcheck_foldings,
        &eval_points,
        open_space_chals,
        max_msm_buffer,
    );
    // let time_proof = time_ck.batch_open_multi_points(tensorcheck_tfoldings, &eval_points, open_time_chals);
    let evaluation_proof = proof_w + proof;
    end_timer!(tensorcheck_open_time);
    TensorcheckProof {
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
    base_polynomial: &SB,
    body_polynomials: (&SF1, &[F]),
    max_msm_buffer: usize,
) -> TensorcheckProof<E>
where
    F: Field,
    E: Pairing<ScalarField = F>,
    SG: Iterable,
    SG::Item: Borrow<E::G1Affine>,
    SB: Iterable,
    SB::Item: Borrow<E::ScalarField>,
    SF1: Iterable<Item = F>,
{
    let tensorcheck_challenges = strip_last(body_polynomials.1);
    let tensorcheck_foldings =
        FoldedPolynomialTree::new(body_polynomials.0, tensorcheck_challenges);
    let folded_polynomials_commitments = ck.commit_folding(&tensorcheck_foldings, max_msm_buffer);

    // add commitments to transcript
    folded_polynomials_commitments
        .iter()
        .for_each(|c| transcript.append_serializable(b"commitment", c));
    let eval_chal = transcript.get_challenge::<E::ScalarField>(b"evaluation-chal");
    let eval_points = [eval_chal.square(), eval_chal, -eval_chal];

    let folded_polynomials_evaluations = evaluate_folding(&tensorcheck_foldings, eval_points[1])
        .into_iter()
        .zip(evaluate_folding(&tensorcheck_foldings, eval_points[2]))
        .map(|(x, y)| [x, y])
        .collect::<Vec<_>>();
    let evaluations_w = [
        evaluate_be(base_polynomial.iter(), &eval_points[0]),
        evaluate_be(base_polynomial.iter(), &eval_points[1]),
        evaluate_be(base_polynomial.iter(), &eval_points[2]),
    ];
    evaluations_w
        .iter()
        .for_each(|e| transcript.append_serializable(b"eval", &e));
    folded_polynomials_evaluations
        .iter()
        .flatten()
        .for_each(|e| transcript.append_serializable(b"eval", e));
    let open_chal = transcript.get_challenge(b"open-chal");
    let open_chal_len = body_polynomials.1.len() + 1;
    let open_chals = powers(open_chal, open_chal_len);

    let (_, proof_w) = ck.open_multi_points(base_polynomial, &eval_points, max_msm_buffer);
    let (_, proof) = ck.open_folding(
        tensorcheck_foldings,
        &eval_points,
        &open_chals[1..],
        max_msm_buffer,
    );
    let evaluation_proof = proof_w + proof;
    TensorcheckProof {
        folded_polynomials_commitments,
        folded_polynomials_evaluations,
        evaluation_proof,
        base_polynomials_evaluations: vec![evaluations_w],
    }
}

impl<E: Pairing> Proof<E> {
    /// Given as input the _streaming_ R1CS instance `r1cs`
    /// and the _streaming_ committer key `ck`,
    /// return a new SNARK using the elastic prover.
    pub fn new_elastic<SM, SG, SZ, SW>(
        r1cs: R1csStream<SM, SZ, SW>,
        ck: CommitterKeyStream<E, SG>,
        max_msm_buffer: usize,
    ) -> Proof<E>
    where
        E: Pairing,
        SM: Iterable + Copy,
        SZ: Iterable + Copy,
        SW: Iterable,
        SG: Iterable,
        SM::Item: Borrow<MatrixElement<E::ScalarField>>,
        SZ::Item: Borrow<E::ScalarField>,
        SW::Item: Borrow<E::ScalarField>,
        SZ::Item: Borrow<E::ScalarField>,
        SZ::Item: Borrow<E::ScalarField>,
        SG::Item: Borrow<E::G1Affine>,
    {
        let snark_time = start_timer!(|| module_path!());

        debug!(
            "features:{};space-time-threshold:{};tensor-expansion:{};msm-buffer:{}",
            crate::misc::_features_enabled(),
            crate::SPACE_TIME_THRESHOLD,
            crate::misc::TENSOR_EXPANSION_LOG,
            max_msm_buffer,
        );

        let mut transcript = merlin::Transcript::new(PROTOCOL_NAME);
        // send the vector w
        let witness_commitment_time = start_timer!(|| "Commitment to w");
        let witness_commitment = ck.commit(&r1cs.witness);
        end_timer!(witness_commitment_time);

        // send witness, receive challenge.
        transcript.append_serializable(b"witness", &witness_commitment);
        let alpha = transcript.get_challenge(b"alpha");

        // send evaluation of zc(alpha)
        let zc_alpha = evaluate_be(r1cs.z_c.iter(), &alpha);
        transcript.append_serializable(b"zc(alpha)", &zc_alpha);

        // run the sumcheck for z_a and z_b with twist alpha
        let first_sumcheck_time = start_timer!(|| "First sumcheck");
        let first_proof = Sumcheck::new_elastic(&mut transcript, r1cs.z_a, r1cs.z_b, alpha);
        end_timer!(first_sumcheck_time);

        // after sumcheck, generate a new challenge
        let eta = transcript.get_challenge::<E::ScalarField>(b"eta");
        // run the second sumcheck
        let b_tensors = &first_proof.challenges;
        let c_tensors = &powers2(alpha, b_tensors.len());
        let a_tensors = &hadamard(b_tensors, c_tensors);

        let len = r1cs.z.len();
        let a_alpha = MatrixTensor::new(r1cs.a_colmaj, a_tensors, len);
        let b_alpha = MatrixTensor::new(r1cs.b_colmaj, b_tensors, len);
        let c_alpha = MatrixTensor::new(r1cs.c_colmaj, c_tensors, len);
        let sumcheck_batch_challenges = powers(eta, 3);
        let lhs = lincomb!((a_alpha, b_alpha, c_alpha), &sumcheck_batch_challenges);

        let second_sumcheck_time = start_timer!(|| "Second sumcheck");
        let second_proof =
            Sumcheck::new_elastic(&mut transcript, lhs, r1cs.z, E::ScalarField::one());
        end_timer!(second_sumcheck_time);

        let batch_challenge = transcript.get_challenge::<E::ScalarField>(b"batch_challenge");

        let tensorcheck_time = start_timer!(|| "Tensorcheck");
        let tensorcheck_batch_challenges = powers(batch_challenge, 2);
        let tensorcheck_polynomials = lincomb!((lhs, r1cs.z), &tensorcheck_batch_challenges);
        let tensorcheck_proof = tensorcheck(
            &mut transcript,
            ck,
            &r1cs.witness,
            (&tensorcheck_polynomials, &second_proof.challenges),
            max_msm_buffer,
        );
        end_timer!(tensorcheck_time);

        end_timer!(snark_time);
        Proof {
            witness_commitment,
            zc_alpha,
            first_sumcheck_msgs: first_proof.prover_messages(),
            second_sumcheck_msgs: second_proof.prover_messages(),
            tensorcheck_proof,
        }
    }
}
