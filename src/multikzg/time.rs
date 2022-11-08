//! An impementation of a time-efficient version of Michele's multilinear extension
//! of Kate et al's polynomial commitment,
//! with optimization from [\[BDFG20\]](https://eprint.iacr.org/2020/081.pdf).
use ark_ec::pairing::Pairing;
use ark_ec::scalar_mul::fixed_base::FixedBase;
use ark_ec::{AffineRepr, CurveGroup as ProjectiveCurve};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::borrow::Borrow;
use ark_std::rand::RngCore;
use ark_std::UniformRand;
use ark_std::{ops::Mul, vec::Vec};

use crate::multikzg::{msm, Commitment, EvaluationProofMulti, VerifierKeyMulti};

use crate::misc::{linear_combination, multi_poly_decompose, powers, random_unique_vector, tensor};

/// A time efficient implementation of Michele's multilinear expansion of KZG polynomial committment
///
#[derive(PartialEq, Eq, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct CommitterKeyMulti<E: Pairing> {
    pub(crate) powers_of_g: Vec<E::G1Affine>,
    pub(crate) g2: E::G2Affine,
    pub(crate) powers_of_g2: Vec<E::G2Affine>,
}

// Converts a `CommitterKeyMulti` into a `VerifierKeyMulti`
impl<E: Pairing> From<&CommitterKeyMulti<E>> for VerifierKeyMulti<E> {
    fn from(ck: &CommitterKeyMulti<E>) -> VerifierKeyMulti<E> {
        let powers_of_g2 = ck.powers_of_g2.to_vec();
        let g = ck.powers_of_g[0];
        let g2 = ck.g2;

        VerifierKeyMulti {
            g,
            g2,
            powers_of_g2,
        }
    }
}

impl<E: Pairing> CommitterKeyMulti<E> {
    /// The setup algorithm for the commitment scheme.
    ///
    /// Given a dimension of the polynomial `dim`
    /// and a cryptographically-secure random number generator `rng`,
    /// construct the committer key.
    pub fn new(dim: usize, rng: &mut impl RngCore) -> Self {
        // Generate n *different*  points tau_1, tau_2 ... tau_n.
        // Each tau is in Fr

        let tau: Vec<E::ScalarField> = random_unique_vector(dim, rng);
        let powers_of_tau = tensor(&tau);

        let g = E::G1::rand(rng);
        let window_size = FixedBase::get_mul_window_size(1 << (dim + 1));
        let scalar_bits = E::ScalarField::MODULUS_BIT_SIZE as usize;
        let g_table = FixedBase::get_window_table(scalar_bits, window_size, g);
        let powers_of_g_proj = FixedBase::msm(scalar_bits, window_size, &g_table, &powers_of_tau);
        let powers_of_g = E::G1::normalize_batch(&powers_of_g_proj);

        let g2 = E::G2::rand(rng).into_affine();
        let powers_of_g2 = tau
            .iter()
            .map(|t| g2.mul(t).into_affine())
            .collect::<Vec<_>>();

        CommitterKeyMulti {
            powers_of_g,
            g2,
            powers_of_g2,
        }
    }

    /// Return the bound on evaluation points.
    #[inline]
    pub fn max_eval_points(&self) -> usize {
        self.powers_of_g2.len() - 1
    }

    /// Given a polynomial `polynomial` of degree less than `max_degree`, return a commitment to `polynomial`.
    pub fn commit(&self, polynomial: &[E::ScalarField]) -> Commitment<E> {
        Commitment(msm::<E>(&self.powers_of_g, polynomial))
    }

    /// Obtain a new preprocessed committer key defined by the indices `indices`
    ///
    pub fn index_by(&self, indices: &[usize]) -> Self {
        let mut indexed_powers_of_g = vec![E::G1Affine::zero(); self.powers_of_g.len()];
        indices
            .iter()
            .zip(self.powers_of_g.iter())
            .for_each(|(&i, &g)| {
                indexed_powers_of_g[i] = (indexed_powers_of_g[i] + g).into_affine()
            });
        Self {
            powers_of_g2: self.powers_of_g2.clone(),
            g2: self.g2,
            powers_of_g: indexed_powers_of_g,
        }
    }

    /// Given an iterator over `polynomials`, expressed as vectors of coefficients, return a vector of commitments to all of them.
    pub fn batch_commit<J>(&self, polynomials: J) -> Vec<Commitment<E>>
    where
        J: IntoIterator,
        J::Item: Borrow<Vec<E::ScalarField>>,
    {
        polynomials
            .into_iter()
            .map(|p| self.commit(p.borrow()))
            .collect::<Vec<_>>()
    }

    /// Given a polynomial `polynomial` and an evaluation point `evaluation_point`,
    /// return the evaluation of `polynomial in `evaluation_point`,
    /// together with an evaluation proof (the quotient polynomial).
    pub fn open(
        &self,
        polynomial: &[E::ScalarField],
        eval_point: &[E::ScalarField],
    ) -> (E::ScalarField, EvaluationProofMulti<E>) {
        let (quotients, remainder) = multi_poly_decompose(polynomial, eval_point);
        let proof = quotients
            .into_iter()
            .map(|quotient| msm::<E>(&self.powers_of_g, &quotient))
            .collect::<Vec<_>>();
        (remainder, EvaluationProofMulti(proof))
    }

    /// Evaluate multiple polynomials at a single point `eval_point`, and provide a single evaluation proof.
    pub fn batch_open(
        &self,
        _polynomials: &[&[E::ScalarField]],
        _eval_point: &[E::ScalarField],
        _eval_chal: E::ScalarField,
    ) -> EvaluationProofMulti<E> {
        todo!();
    }

    /// Evaluate a single polynomial at a set of points `eval_points`, and provide a single evaluation proof.
    pub fn open_multi_points(
        &self,
        _polynomial: &[E::ScalarField],
        _eval_points: &[E::ScalarField],
    ) -> EvaluationProofMulti<E> {
        todo!();
    }

    /// Scale multiple multilinear polynomials by powers of `eval_chal`, and linearly combine them.
    pub fn batched_poly(
        &self,
        polynomials: &[Vec<E::ScalarField>],
        eval_chal: &E::ScalarField,
    ) -> Vec<E::ScalarField> {
        let pows = powers(*eval_chal, polynomials.len());
        linear_combination(polynomials, &pows)
    }

    /// Evaluate a set of multilinear polynomials at a single point `eval_point`, and provide a single batched evaluation proof.
    /// `eval_chal` is the random challenge for batching evaluation proofs across different polynomials.
    pub fn batch_open_multi_polys(
        &self,
        polynomials: &[Vec<E::ScalarField>],
        eval_point: &[E::ScalarField],
        eval_chal: &E::ScalarField,
    ) -> (E::ScalarField, EvaluationProofMulti<E>) {
        self.open(&self.batched_poly(polynomials, eval_chal), eval_point)
    }

    /// Evaluate a set of polynomials at a set of points `eval_points`, and provide a single batched evaluation proof.
    /// `eval_chal` is the random challenge for batching evaluation proofs across different polynomials.
    pub fn batch_open_multi_points(
        &self,
        _polynomials: &[&Vec<E::ScalarField>],
        _eval_points: &[E::ScalarField],
        _eval_chal: &[E::ScalarField],
    ) -> EvaluationProofMulti<E> {
        todo!();
    }
}

#[test]
fn test_time_open() {
    use crate::misc::random_vector;
    use ark_bls12_381::Bls12_381;

    let dim = 15;
    let rng = &mut ark_std::test_rng();
    let ck = CommitterKeyMulti::<Bls12_381>::new(dim, rng);

    let poly = random_vector(1 << dim, rng);
    let evaluation_point = random_vector(dim, rng);
    assert_eq!(
        ck.open(&poly, &evaluation_point),
        ck.open(&poly.as_slice(), &evaluation_point.as_slice())
    );
}

/// an end to end test for the commitment scheme
/// generates a random polynomial, random evaluation point, and ensures that a correct evaluation proof
/// verifies to ok.
///
#[test]
fn test_end_to_end() {
    use crate::misc::{evaluate_multi_poly, random_vector};
    use ark_bls12_381::Bls12_381;
    use ark_bls12_381::Fr;

    let dim = 11;
    let rng = &mut ark_std::test_rng();
    let ck = CommitterKeyMulti::<Bls12_381>::new(dim, rng);
    let vk = VerifierKeyMulti::from(&ck);

    let polynomial_flat: Vec<Fr> = random_vector(1 << dim, rng);

    let alpha: Vec<Fr> = random_vector(dim, rng);
    let commitment = ck.commit(&polynomial_flat);
    let (evaluation, proof) = ck.open(&polynomial_flat, &alpha);
    let expected_evaluation = evaluate_multi_poly(&polynomial_flat, &alpha);
    assert_eq!(evaluation, expected_evaluation);
    assert!(vk.verify(&commitment, &alpha, &evaluation, &proof).is_ok())
}

#[test]
fn test_serialize() {
    use ark_bls12_381::Bls12_381;

    let dim = 11;
    let rng = &mut ark_std::test_rng();
    let ck = CommitterKeyMulti::<Bls12_381>::new(dim, rng);
    let vk = VerifierKeyMulti::from(&ck);

    let mut ck_buf = Vec::new();
    assert!(ck.serialize_compressed(&mut ck_buf).is_ok());
    let deserialized_ck = CommitterKeyMulti::deserialize_compressed(ck_buf.as_slice()).unwrap();
    assert_eq!(deserialized_ck, ck);

    let mut vk_buf = Vec::new();
    assert!(vk.serialize_compressed(&mut vk_buf).is_ok());
    let deserialized_vk = VerifierKeyMulti::deserialize_compressed(vk_buf.as_slice()).unwrap();
    assert_eq!(deserialized_vk, vk)
}

#[test]
fn test_batched_polys() {
    use crate::misc::{evaluate_multi_poly, random_vector};
    use ark_bls12_381::Bls12_381;
    use ark_bls12_381::Fr;

    let dim = 11;
    let rng = &mut ark_std::test_rng();
    let ck = CommitterKeyMulti::<Bls12_381>::new(dim, rng);
    let vk = VerifierKeyMulti::from(&ck);

    let num_polys = 5;
    let polynomials: Vec<Vec<Fr>> = (0..num_polys)
        .map(|_| random_vector(1 << dim, rng))
        .collect::<Vec<_>>();
    let chal = Fr::rand(rng);
    let alpha: Vec<Fr> = random_vector(dim, rng);

    let batched_proof = ck.batch_open_multi_polys(&polynomials, &alpha, &chal);

    let commitments = ck.batch_commit(&polynomials);
    let evaluations = polynomials
        .iter()
        .map(|p| evaluate_multi_poly(p, &alpha))
        .collect::<Vec<_>>();
    assert!(vk
        .batch_verify(&commitments, &alpha, &evaluations, &batched_proof.1, &chal)
        .is_ok())
}
