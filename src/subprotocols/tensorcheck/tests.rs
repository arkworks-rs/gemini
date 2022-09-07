use ark_bls12_381::Bls12_381;
use ark_bls12_381::Fr;
use ark_poly::univariate::DensePolynomial;
use ark_poly::DenseUVPolynomial;
use ark_std::test_rng;
use ark_std::vec::Vec;

use crate::kzg::CommitterKey;
use crate::misc::{ip, tensor};
use crate::subprotocols::tensorcheck::TensorcheckProof;
use crate::transcript::GeminiTranscript;
use ark_std::{log2, One, UniformRand, Zero};

const PROTOCOL_NAME: &[u8] = b"LTAPS-2019";

#[test]
fn test_tensor_check() {
    let rng = &mut test_rng();
    let d = 8;
    let rounds = log2(d) as usize;

    let ck = CommitterKey::<Bls12_381>::new(d, 5, rng);
    let vk = (&ck).into();

    let pp = [DensePolynomial::rand(d - 1, rng).coeffs];
    let base_polynomials = [&pp[0]];
    let body_polynomials = [&pp[0]];

    let mut randomnesses = Vec::new();
    for _ in 0..rounds {
        randomnesses.push(Fr::rand(rng));
    }

    let base_polynomials_commitments = ck.batch_commit(base_polynomials);

    let tc_base_polynomials = base_polynomials;
    let tc_body_polynomials = [(&body_polynomials[..], randomnesses.as_slice())];
    let mut transcript = merlin::Transcript::new(PROTOCOL_NAME);
    let tensor_check_proof = TensorcheckProof::new_time(
        &mut transcript,
        &ck,
        tc_base_polynomials,
        tc_body_polynomials,
    );

    let challenges = tensor(&randomnesses);

    let mut asserted_res = Vec::new();
    for p in body_polynomials.iter() {
        asserted_res.push(ip(p, &challenges[0..p.len()]));
    }

    let mut transcript = merlin::Transcript::new(PROTOCOL_NAME);

    // ADD TO TRANSCRIPT ALL POLYNOMIALS
    let batch_challenge = transcript.get_challenge::<Fr>(b"batch_challenge");
    // add commitments to transcript
    tensor_check_proof
        .folded_polynomials_commitments
        .iter()
        .for_each(|c| transcript.append_serializable(b"commitment", c));
    let eval_chal = transcript.get_challenge::<Fr>(b"evaluation-chal");

    let mut direct_base_polynomials_evaluations = Vec::new();
    let mut eval_0 = Fr::zero();
    let mut eval_1 = Fr::zero();
    let mut tmp = Fr::one();
    for evals in tensor_check_proof.base_polynomials_evaluations.iter() {
        eval_0 += tmp * evals[1];
        eval_1 += tmp * evals[2];
        tmp *= batch_challenge;
    }
    direct_base_polynomials_evaluations.push([eval_0, eval_1]);

    assert!(tensor_check_proof
        .verify(
            &mut transcript,
            &vk,
            &[asserted_res],
            &base_polynomials_commitments,
            &direct_base_polynomials_evaluations,
            &[randomnesses],
            eval_chal,
            batch_challenge,
        )
        .is_ok());
}
