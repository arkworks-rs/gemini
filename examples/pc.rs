use ark_bls12_381::{Bls12_381, Fr};

use ark_poly::univariate::DensePolynomial;
use ark_poly::{DenseUVPolynomial, Polynomial};
use ark_std::test_rng;
use ark_std::UniformRand;

use ark_gemini::kzg::CommitterKey;
use ark_gemini::kzg::VerifierKey;

fn main() {
    let mut rng = &mut test_rng();
    let d = 1000000;

    let mut eval_points = Vec::new();
    for _ in 0..5 {
        eval_points.push(Fr::rand(rng));
    }

    let mut polynomials = Vec::new();
    let mut evals = Vec::new();
    for _ in 0..15 {
        let tmp = DensePolynomial::rand(d, rng);
        let mut e = Vec::new();
        for x in eval_points.iter() {
            // e.push(tmp.evaluate(x) + Fr::one());
            e.push(tmp.evaluate(x));
        }
        polynomials.push(tmp.coeffs);
        evals.push(e);
    }
    let time_ck = CommitterKey::<Bls12_381>::new(d + 1, 3, rng);
    let time_vk = VerifierKey::from(&time_ck);

    println!("start committing");
    let time_batched_commitments = time_ck.batch_commit(&polynomials);

    let eta: Fr = u128::rand(&mut rng).into();

    println!("start evalution");
    let proof = time_ck.batch_open_multi_points(
        &polynomials.iter().collect::<Vec<_>>(),
        &eval_points,
        &eta,
    );

    println!("start verifying");
    let verification_result = time_vk.verify_multi_points(
        &time_batched_commitments,
        &eval_points,
        &evals,
        &proof,
        &eta,
    );

    assert!(verification_result.is_ok());
}
