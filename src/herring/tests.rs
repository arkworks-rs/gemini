use ark_bls12_381::Fr as F;
use ark_ff::One;
use ark_ff::UniformRand;
use ark_poly::univariate::DensePolynomial;
use ark_poly::DenseUVPolynomial;
use ark_std::boxed::Box;
use ark_std::vec::Vec;

use merlin::Transcript;

use crate::iterable::Reverse;
use crate::misc::fold_polynomial;
use crate::misc::hadamard;
use crate::misc::ip;
use crate::misc::powers;
use crate::subprotocols::sumcheck::proof::Sumcheck;
use crate::subprotocols::sumcheck::prover::Prover;
use crate::subprotocols::sumcheck::space_prover::SpaceProver;
use crate::subprotocols::sumcheck::streams::FoldedPolynomialStream;
use crate::subprotocols::sumcheck::time_prover::{TimeProver, Witness};
use crate::subprotocols::sumcheck::Subclaim;

#[test]
fn test_rounds() {
    let rng = &mut ark_std::test_rng();

    // in the smallest instance (degree-1 polynomials) a single round is necessary.
    let f = DensePolynomial::<F>::rand(1, rng);
    let g = DensePolynomial::<F>::rand(1, rng);
    let witness = Witness::<F>::new(&f, &g, &F::one());
    assert_eq!(witness.required_rounds(), 1);

    // otherwise, it should be the ceil of the log of the coefficients
    let f = DensePolynomial::<F>::rand(16, rng);
    let g = DensePolynomial::<F>::rand(1, rng);
    let witness = Witness::<F>::new(&f, &g, &F::one());
    assert_eq!(witness.required_rounds(), 5);
}

#[test]
fn test_messages_consistency() {
    let rng = &mut ark_std::test_rng();
    let twist = F::one();

    let f = DensePolynomial::<F>::rand(29, rng).coeffs().to_vec();
    let g = DensePolynomial::<F>::rand(29, rng).coeffs().to_vec();
    let witness = Witness::new(&f, &g, &twist);
    let mut time_prover = TimeProver::new(witness);

    let mut rev_f = f.to_vec();
    let mut rev_g = g.to_vec();
    rev_f.reverse();
    rev_g.reverse();
    let f_stream = rev_f.as_slice();
    let g_stream = rev_g.as_slice();

    let mut space_prover = SpaceProver::new(f_stream, g_stream, twist);

    // Run the next-message function on the space and the time prover,
    // Check the returned messages are equal.
    assert_eq!(
        space_prover.next_message(None).unwrap(),
        time_prover.next_message(None).unwrap()
    );

    // Run the next-message function once again on the space and time prover, and check the result is still equal.
    let verifier_message = Some(F::rand(rng));
    assert_eq!(
        space_prover.next_message(verifier_message).unwrap(),
        time_prover.next_message(verifier_message).unwrap()
    );

    // Run the next-message function one last time on the space and time prover, and check the result is still equal.
    let verifier_message = Some(F::one());
    assert_eq!(
        space_prover.next_message(verifier_message).unwrap(),
        time_prover.next_message(verifier_message).unwrap()
    );

    // now check the aggregated data.
    let mut space_transcript = Transcript::new(crate::PROTOCOL_NAME);
    let mut time_transcript = Transcript::new(crate::PROTOCOL_NAME);
    let space_proof = Sumcheck::<F>::new_space(&mut space_transcript, f_stream, g_stream, twist);
    let time_proof = Sumcheck::<F>::new_time(&mut time_transcript, &f, &g, &twist);
    assert_eq!(space_proof.messages, time_proof.messages);
}

#[test]
fn test_consistency_elastic() {
    let rng = &mut ark_std::test_rng();
    let twist = F::one();

    let f = DensePolynomial::<F>::rand(29, rng).coeffs().to_vec();
    let g = DensePolynomial::<F>::rand(29, rng).coeffs().to_vec();

    let mut transcript = Transcript::new(crate::PROTOCOL_NAME);
    let mut time_transcript = Transcript::new(crate::PROTOCOL_NAME);

    let mut rev_f = f.clone();
    let mut rev_g = g.clone();
    rev_f.reverse();
    rev_g.reverse();
    let f_stream = rev_f.as_slice();
    let g_stream = rev_g.as_slice();

    // now check the aggregated data.
    let time_proof = Sumcheck::<F>::new_time(&mut time_transcript, &f, &g, &twist);
    let elastic_proof = Sumcheck::<F>::new_elastic(&mut transcript, f_stream, g_stream, twist);
    assert_eq!(time_proof.messages, elastic_proof.messages);
}

#[test]
fn test_messages_consistency_with_different_lengths() {
    let rng = &mut ark_std::test_rng();
    let twist = F::one();

    let f = DensePolynomial::<F>::rand(92, rng);
    let g = DensePolynomial::<F>::rand(15, rng);
    let witness = Witness::new(&f, &g, &twist);
    let mut time_prover = TimeProver::new(witness);

    let mut rev_f = f.to_vec();
    let mut rev_g = g.to_vec();
    rev_f.reverse();
    rev_g.reverse();
    let f_stream = rev_f.as_slice();
    let g_stream = rev_g.as_slice();

    let mut space_prover = SpaceProver::new(f_stream, g_stream, twist);

    // Run the next-message function on the space and the time prover,
    // Check the returned messages are equal.
    assert_eq!(
        space_prover.next_message(None).unwrap(),
        time_prover.next_message(None).unwrap()
    );
}

#[test]
fn test_folding_consistency() {
    use crate::iterable::Iterable;
    let rng = &mut ark_std::test_rng();

    // Easy folding:
    // test consistency between the time-efficient and the space-efficient algorithm, for vectors of size 2ˆn.
    let f = DensePolynomial::<F>::rand(15, rng);
    let rev_f = Reverse(&f.coeffs);

    let trivial_folded_stream = FoldedPolynomialStream::new(&rev_f, &[]);
    let mut collected_stream = trivial_folded_stream.iter().collect::<Vec<_>>();
    collected_stream.reverse();
    assert_eq!(f.coeffs().to_vec(), collected_stream);

    let mut r = vec![F::rand(rng)];
    let folded_once_stream = FoldedPolynomialStream::new(&rev_f, &r);
    let mut folded_space = folded_once_stream.iter().collect::<Vec<_>>();
    folded_space.reverse();
    let mut folded_time = fold_polynomial(f.coeffs(), r[0]);
    assert_eq!(folded_time, folded_space);

    r.push(F::rand(rng));
    folded_time = fold_polynomial(&folded_time, r[1]);
    let folded_once_stream = FoldedPolynomialStream::new(&rev_f, &r);
    let mut folded_space = folded_once_stream.iter().collect::<Vec<_>>();
    folded_space.reverse();
    assert_eq!(folded_time, folded_space);

    r.push(F::rand(rng));
    folded_time = fold_polynomial(&folded_time, r[2]);
    let folded_once_stream = FoldedPolynomialStream::new(&rev_f, &r);
    let mut folded_space = folded_once_stream.iter().collect::<Vec<_>>();
    folded_space.reverse();
    assert_eq!(folded_time, folded_space);

    // Difficult folding:
    // test consistency between the time-efficiencot and the space-efficient algorithm, for vectors of odd size.
    let f = DensePolynomial::<F>::rand(18, rng);
    let rev_f = Reverse(&f.coeffs);

    let trivial_folded_stream = FoldedPolynomialStream::new(&rev_f, &[]);
    let mut collected_stream = trivial_folded_stream.iter().collect::<Vec<_>>();
    collected_stream.reverse();
    assert_eq!(f.coeffs().to_vec(), collected_stream);

    let mut r = vec![F::rand(rng)];
    let folded_once_stream = FoldedPolynomialStream::new(&rev_f, &r);
    let mut folded_space = folded_once_stream.iter().collect::<Vec<_>>();
    folded_space.reverse();
    let mut folded_time = fold_polynomial(f.coeffs(), r[0]);
    assert_eq!(folded_time, folded_space);

    r.push(F::rand(rng));
    folded_time = fold_polynomial(&folded_time, r[1]);

    let folded_once_stream = FoldedPolynomialStream::new(&rev_f, &r);
    let mut folded_space = folded_once_stream.iter().collect::<Vec<_>>();
    folded_space.reverse();
    assert_eq!(folded_time, folded_space);
}

#[test]
fn test_sumcheck_correctness() {
    let rng = &mut ark_std::test_rng();
    let d = 1 << (10);

    let f = DensePolynomial::<F>::rand(d, rng).coeffs().to_vec();
    let g = DensePolynomial::<F>::rand(d, rng).coeffs().to_vec();
    let twist = F::rand(rng);
    let twist_powers = powers(twist, d + 1);

    // compute the inner product of f, g naively.
    let twisted_f = hadamard(&twist_powers, &f);
    let asserted_sum = ip(&twisted_f, &g);

    // produce the proof for <f, g>
    let mut prover_transcript = Transcript::new(crate::PROTOCOL_NAME);
    let mut verifier_transcript = Transcript::new(crate::PROTOCOL_NAME);

    let sumcheck = Sumcheck::new_time(&mut prover_transcript, &f, &g, &twist);
    let prover_messages = sumcheck.prover_messages();
    let subclaim = Subclaim::new(&mut verifier_transcript, &prover_messages, asserted_sum);
    assert!(subclaim.is_ok())
}

#[test]
fn test_batch_sumcheck_correctness() {
    let rng = &mut ark_std::test_rng();
    let d = 1 << (5);

    let f = DensePolynomial::<F>::rand(d, rng).coeffs().to_vec();
    let g = DensePolynomial::<F>::rand(d, rng).coeffs().to_vec();
    let twist = F::rand(rng);
    let twist_powers = powers(twist, d + 1);

    // compute the inner product of f, g naively.
    let twisted_f = hadamard(&twist_powers, &f);
    let asserted_sum = ip(&twisted_f, &g);

    let d2 = 1 << (10);

    let f2 = DensePolynomial::<F>::rand(d2, rng).coeffs().to_vec();
    let g2 = DensePolynomial::<F>::rand(d2, rng).coeffs().to_vec();
    let twist2 = F::rand(rng);
    let twist_powers2 = powers(twist2, d2 + 1);

    // compute the inner product of f, g naively.
    let twisted_f2 = hadamard(&twist_powers2, &f2);
    let asserted_sum2 = ip(&twisted_f2, &g2);

    // Batched sumcheck
    let witness = Witness::new(&f, &g, &twist);
    let witness2 = Witness::new(&f2, &g2, &twist2);
    let provers = vec![
        Box::new(TimeProver::new(witness)) as Box<dyn Prover<F>>,
        Box::new(TimeProver::new(witness2)) as Box<dyn Prover<F>>,
    ];

    let mut prover_transcript = Transcript::new(crate::PROTOCOL_NAME);
    let mut verifier_transcript = Transcript::new(crate::PROTOCOL_NAME);
    let sumcheck = Sumcheck::prove_batch(&mut prover_transcript, provers);
    let prover_messages = sumcheck.prover_messages();
    let subclaim = Subclaim::new_batch(
        &mut verifier_transcript,
        &prover_messages,
        &[asserted_sum, asserted_sum2],
    );
    assert!(subclaim.is_ok());
}
