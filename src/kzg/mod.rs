pub mod msm;
pub mod space;
pub mod time;

use ark_ec::ProjectiveCurve;
pub use space::CommitterKeyStream;
pub use time::CommitterKey;

#[cfg(test)]
pub mod tests;

use ark_ff::{Field, One, PrimeField, Zero};
use ark_poly::{univariate::DensePolynomial, UVPolynomial};
use ark_std::io::Write;
use ark_std::ops::{Add, Mul};

use ark_std::fmt;

use ark_ec::{msm::VariableBaseMSM, AffineCurve, PairingEngine};

use crate::misc::{linear_combination, powers};
/// Struct of a Kate polynomial commitment over a bilinear group, represented as a single G1 element.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Commitment<E: PairingEngine>(pub(crate) E::G1Affine);

#[inline]
fn msm<E: PairingEngine>(bases: &[E::G1Affine], scalars: &[E::Fr]) -> E::G1Affine {
    let scalars = scalars.iter().map(|x| x.into_repr()).collect::<Vec<_>>();
    let sp = VariableBaseMSM::multi_scalar_mul(bases, &scalars);
    sp.into_affine()
}

impl<E: PairingEngine> ark_ff::ToBytes for Commitment<E> {
    #[inline]
    fn write<W: Write>(&self, writer: W) -> ark_std::io::Result<()> {
        self.0.write(writer)
    }
}

/// Proof of a correct polynomial evaluation, represented as a single G1 element.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvaluationProof<E: PairingEngine>(pub E::G1Affine);

impl<E: PairingEngine> Add for EvaluationProof<E> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        EvaluationProof(self.0 + rhs.0)
    }
}

/// Error type denoting an incorrect evaluation proof.
#[derive(Debug, Clone)]
pub struct VerificationError;

impl fmt::Display for VerificationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Error in stream.")
    }
}

pub(crate) type VerificationResult = Result<(), VerificationError>;

// XXX.  add const generic argument for the size.
/// The verification key for the polynomial commitment scheme.
/// It also implements verification functions for the evaluation proof.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifierKey<E: PairingEngine> {
    /// The generator of  \\(\GG_1\\)
    powers_of_g: Vec<E::G1Affine>,
    /// The generator og \\(\GG_2\\), together with its multiplication by the trapdoor.
    powers_of_g2: Vec<E::G2Affine>,
}

impl<E: PairingEngine> VerifierKey<E> {
    /// The verification procedure for the EvaluationProof with a single polynomial evaluated at a single evaluation point.
    /// The polynomial are evaluated at the point ``alpha`` and is committed as ``commitment``.
    /// The evaluation proof can be obtained either in a space-efficient or a time-efficient flavour.
    pub fn verify(
        &self,
        commitment: &Commitment<E>,
        &alpha: &E::Fr,
        evaluation: &E::Fr,
        proof: &EvaluationProof<E>,
    ) -> VerificationResult {
        let scalars = [(-alpha).into_repr(), E::Fr::one().into_repr()];
        let ep = VariableBaseMSM::multi_scalar_mul(&self.powers_of_g2, &scalars);
        let lhs = commitment.0.into_projective() - self.powers_of_g[0].mul(evaluation.into_repr());
        let g2 = self.powers_of_g2[0];

        if E::pairing(lhs, g2) == E::pairing(proof.0, ep) {
            Ok(())
        } else {
            Err(VerificationError)
        }
    }

    /// The verification procedure for the EvaluationProof with a set of polynomials evaluated at a set of evaluation points.
    /// All the polynomials are evaluated at the set of points ``eval_points`` and are committed as ``commitments``.
    /// ``evaluations`` contains evaluations of each polynomial at each point in ``eval_points``.
    /// ``evaluations`` follows the same polynomial order as ``commitments`` and the same evaluation point order as ``eval_points``.
    /// The evaluation proof can be obtained either in a space-efficient or a time-efficient flavour.
    /// ``open_chal`` is a random challenge for batching evaluation proofs across different polynomials.
    pub fn verify_multi_points(
        &self,
        commitments: &[Commitment<E>],
        eval_points: &[E::Fr],
        evaluations: &[Vec<E::Fr>],
        proof: &EvaluationProof<E>,
        open_chal: &E::Fr,
    ) -> VerificationResult {
        // Computing the vanishing polynomial over eval_points
        let zeros = vanishing_polynomial(eval_points);
        let zeros_repr = zeros.iter().map(|x| x.into_repr()).collect::<Vec<_>>();
        let zeros = VariableBaseMSM::multi_scalar_mul(&self.powers_of_g2, &zeros_repr);

        // Computing the inverse for the interpolation
        let mut sca_inverse = Vec::new();
        for (j, x_j) in eval_points.iter().enumerate() {
            let mut sca = E::Fr::one();
            for (k, x_k) in eval_points.iter().enumerate() {
                if j == k {
                    continue;
                }
                sca *= *x_j - x_k;
            }
            sca = sca.inverse().unwrap();
            sca_inverse.push(sca);
        }

        // Computing the lagrange polynomial for the interpolation
        let mut lang = Vec::new();
        for (j, _x_j) in eval_points.iter().enumerate() {
            let mut l_poly = DensePolynomial::from_coefficients_vec(vec![E::Fr::one()]);
            for (k, x_k) in eval_points.iter().enumerate() {
                if j == k {
                    continue;
                }
                let tmp_poly = DensePolynomial::from_coefficients_vec(vec![-(*x_k), E::Fr::one()]);
                l_poly = l_poly.mul(&tmp_poly);
            }
            lang.push(l_poly);
        }

        // Computing the commitment for the interpolated polynomials
        let etas = powers(*open_chal, evaluations.len());
        let interpolated_polynomials = evaluations
            .iter()
            .map(|e| interpolate_poly::<E>(eval_points, e, &sca_inverse, &lang).coeffs)
            .collect::<Vec<_>>();
        let i_poly = linear_combination(&interpolated_polynomials[..], &etas).unwrap();

        let i_comm = msm::<E>(&self.powers_of_g, &i_poly);

        // Gathering commitments
        let comm_vec = commitments.iter().map(|x| x.0).collect::<Vec<_>>();
        let etas_repr = etas.iter().map(|e| e.into_repr()).collect::<Vec<_>>();
        let f_comm = VariableBaseMSM::multi_scalar_mul(&comm_vec, &etas_repr);

        let g2 = self.powers_of_g2[0];

        if E::pairing(f_comm - i_comm.into_projective(), g2) == E::pairing(proof.0, zeros) {
            Ok(())
        } else {
            Err(VerificationError)
        }
    }
}

fn interpolate_poly<E: PairingEngine>(
    eval_points: &[E::Fr],
    evals: &[E::Fr],
    sca_inverse: &[E::Fr],
    lang: &[DensePolynomial<E::Fr>],
) -> DensePolynomial<E::Fr> {
    let mut res = DensePolynomial::from_coefficients_vec(vec![E::Fr::zero()]);
    for (j, (_x_j, y_j)) in eval_points.iter().zip(evals.iter()).enumerate() {
        let l_poly = lang[j].mul(sca_inverse[j] * y_j);
        res = (&res).add(&l_poly);
    }
    res
}

/// The polynomial in \\(\FF\\) that vanishes in all the points `points`.
fn vanishing_polynomial<F: Field>(points: &[F]) -> DensePolynomial<F> {
    let one = DensePolynomial::from_coefficients_vec(vec![F::one()]);
    points
        .iter()
        .map(|&point| DensePolynomial::from_coefficients_vec(vec![-point, F::one()]))
        .fold(one, |x, y| x.naive_mul(&y))
}

#[test]
fn test_vanishing_polynomial() {
    use crate::misc::evaluate_le;
    use ark_bls12_381::Fr as F;
    use ark_ff::Zero;

    let points = [F::from(10), F::from(5), F::from(13)];
    let zeros = vanishing_polynomial(&points);
    assert_eq!(evaluate_le(&zeros, &points[0]), F::zero());
    assert_eq!(evaluate_le(&zeros, &points[1]), F::zero());
    assert_eq!(evaluate_le(&zeros, &points[2]), F::zero());
}
