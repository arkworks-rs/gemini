//! An impementation of a time-efficient version of Kate et al's polynomial commitment with optimization from [\[BDFG20\]](https://eprint.iacr.org/2020/081.pdf).
use std::borrow::Borrow;

use ark_ec::msm::FixedBaseMSM;
use ark_ec::PairingEngine;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{PrimeField, Zero};
use ark_poly::{univariate::DensePolynomial, UVPolynomial};
use ark_std::ops::Div;
use ark_std::rand::RngCore;
use ark_std::UniformRand;

use crate::kzg::{msm, Commitment, EvaluationProof, VerifierKey};
use crate::misc::{linear_combination, powers};

use super::vanishing_polynomial;

/// The SRS for the polynomial commitment scheme consists of the consecutive powers of g.
/// It also implements functions for `setup`, `commit` and `open`.
pub struct CommitterKey<E: PairingEngine> {
    pub(crate) powers_of_g: Vec<E::G1Affine>,
    pub(crate) powers_of_g2: Vec<E::G2Affine>,
}

impl<E: PairingEngine> From<&CommitterKey<E>> for VerifierKey<E> {
    fn from(ck: &CommitterKey<E>) -> VerifierKey<E> {
        let max_eval_points = ck.max_eval_points();
        let powers_of_g2 = ck.powers_of_g2[..max_eval_points + 1].to_vec();
        let powers_of_g = ck.powers_of_g[..max_eval_points].to_vec();

        VerifierKey {
            powers_of_g,
            powers_of_g2,
        }
    }
}

impl<E: PairingEngine> CommitterKey<E> {
    /// The setup algorithm for the commitment scheme.
    /// Given a degree bound, an evaluation point bound and a cryptographically-secure random number generator, it will construct the committer key and the verifier key for committing polynomials up to degree `max_degree` and supporting the number of evaluation points up to `max_eval_points`.
    pub fn new(max_degree: usize, max_eval_points: usize, rng: &mut impl RngCore) -> Self {
        // Compute the consecutive powers of an element.
        let tau = E::Fr::rand(rng);
        let powers_of_tau = powers(tau, max_degree + 1);

        let g = E::G1Projective::rand(rng);
        let window_size = FixedBaseMSM::get_mul_window_size(max_degree + 1);
        let scalar_bits = E::Fr::size_in_bits();
        let g_table = FixedBaseMSM::get_window_table(scalar_bits, window_size, g);
        let powers_of_g_proj =
            FixedBaseMSM::multi_scalar_mul(scalar_bits, window_size, &g_table, &powers_of_tau);
        let powers_of_g = E::G1Projective::batch_normalization_into_affine(&powers_of_g_proj);

        let g2 = E::G2Projective::rand(rng).into_affine();
        let powers_of_g2 = powers_of_tau
            .iter()
            .take(max_eval_points + 1)
            .map(|t| g2.mul(t.into_repr()).into_affine())
            .collect::<Vec<_>>();

        CommitterKey {
            powers_of_g,
            powers_of_g2,
        }
    }

    /// Return the supported number of evaluation points.
    #[inline]
    pub fn max_eval_points(&self) -> usize {
        self.powers_of_g2.len() - 1
    }

    /// The commitment procedures, that takes as input a committer key and the coefficients of polynomial, and produces the desired commitment.
    pub fn commit(&self, polynomial: &[E::Fr]) -> Commitment<E> {
        Commitment(msm::<E>(&self.powers_of_g, polynomial))
    }

    /// The batched commitment procedure, that takes as input a committer key and the coefficients of a set of polynomials, and produces the desired commitments for each polynomial.
    pub fn batch_commit<J>(&self, polynomials: J) -> Vec<Commitment<E>>
    where
        J: IntoIterator,
        J::Item: Borrow<Vec<E::Fr>>,
    {
        polynomials
            .into_iter()
            .map(|p| self.commit(p.borrow()))
            .collect::<Vec<_>>()
    }

    /// Evaluate a single polynomial at the point `alpha`, and provide an evaluation proof along with the evaluation.
    pub fn open(&self, polynomial: &[E::Fr], alpha: &E::Fr) -> (E::Fr, EvaluationProof<E>) {
        let mut quotient = Vec::new();

        let mut previous = E::Fr::zero();
        for &c in polynomial.iter().rev() {
            let coefficient = c + previous * alpha;
            quotient.insert(0, coefficient);
            previous = coefficient;
        }

        let (&evaluation, quotient) = quotient.split_first().unwrap_or((&E::Fr::zero(), &[]));
        let evaluation_proof = msm::<E>(&self.powers_of_g, quotient);
        (evaluation, EvaluationProof(evaluation_proof))
    }

    /// Evaluate a single polynomial at a set of points `eval_points`, and provide a single evaluation proof.
    pub fn open_multi_points(
        &self,
        polynomial: &[E::Fr],
        eval_points: &[E::Fr],
    ) -> EvaluationProof<E> {
        // Computing the vanishing polynomial over eval_points
        let z_poly = vanishing_polynomial(eval_points);

        let f_poly = DensePolynomial::from_coefficients_slice(polynomial);
        let q_poly = f_poly.div(&z_poly);
        EvaluationProof(self.commit(&q_poly.coeffs).0)
    }

    /// Evaluate a set of polynomials at a set of points `eval_points`, and provide a single batched evaluation proof.
    /// `eval_chal` is the random challenge for batching evaluation proofs across different polynomials.
    pub fn batch_open_multi_points(
        &self,
        polynomials: &[&Vec<E::Fr>],
        eval_points: &[E::Fr],
        eval_chal: &E::Fr,
    ) -> EvaluationProof<E> {
        assert!(eval_points.len() < self.powers_of_g2.len());
        let etas = powers(*eval_chal, polynomials.len());
        let batched_polynomial =
            linear_combination(polynomials, &etas).unwrap_or_else(|| vec![E::Fr::zero()]);
        self.open_multi_points(&batched_polynomial, eval_points)
    }
}

#[test]
fn test_srs() {
    use ark_bls12_381::Bls12_381;

    let rng = &mut ark_std::test_rng();
    let ck = CommitterKey::<Bls12_381>::new(10, 3, rng);
    let vk = VerifierKey::from(&ck);
    // Make sure that there are enough elements for the entire array.
    assert_eq!(ck.powers_of_g.len(), 11);
    assert_eq!(ck.powers_of_g2, &vk.powers_of_g2[..]);
}

#[test]
fn test_trivial_commitment() {
    use ark_bls12_381::Bls12_381;
    use ark_bls12_381::Fr;
    use ark_poly::univariate::DensePolynomial;
    use ark_poly::UVPolynomial;
    use ark_std::One;

    let rng = &mut ark_std::test_rng();
    let ck = CommitterKey::<Bls12_381>::new(10, 3, rng);
    let vk = VerifierKey::from(&ck);
    let polynomial = DensePolynomial::from_coefficients_slice(&[Fr::zero(), Fr::one(), Fr::one()]);
    let alpha = Fr::zero();

    let commitment = ck.commit(&polynomial);
    let (evaluation, proof) = ck.open(&polynomial, &alpha);
    assert_eq!(evaluation, Fr::zero());
    assert!(vk.verify(&commitment, &alpha, &evaluation, &proof).is_ok())
}

#[test]
fn test_commitment() {
    use ark_bls12_381::Bls12_381;
    use ark_bls12_381::Fr;
    use ark_poly::univariate::DensePolynomial;
    use ark_poly::Polynomial;
    use ark_poly::UVPolynomial;

    let rng = &mut ark_std::test_rng();
    let ck = CommitterKey::<Bls12_381>::new(100, 3, rng);
    let vk = VerifierKey::from(&ck);
    let polynomial = DensePolynomial::rand(100, rng);
    let alpha = Fr::zero();

    let commitment = ck.commit(&polynomial);
    let (evaluation, proof) = ck.open(&polynomial, &alpha);
    let expected_evaluation = polynomial.evaluate(&alpha);
    assert_eq!(evaluation, expected_evaluation);
    assert!(vk.verify(&commitment, &alpha, &evaluation, &proof).is_ok())
}
