mod space;
mod time;
mod division_stream;

use crate::errors::{VerificationError, VerificationResult};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;
pub use space::CommitterKeyMultiStream;
pub use time::CommitterKeyMulti;

use ark_ff::{One, PrimeField};
use ark_std::ops::Mul;

use ark_ec::{
    pairing::Pairing, scalar_mul::variable_base::VariableBaseMSM, AffineRepr,
    CurveGroup,
};

/// A MultiKZG polynomial commitment over a bilinear group, represented as a single $\GG_1$ element.
///
/// The `Commitment
///
/// Given $\Tau \in \Z_p$, a prime field element, and $G \in \GG_1$ is a generator for affine group $\GG_1$. \
/// Given $H$ is a generator for the affine group $\GG_2$. $\GG_1$ and $\GG_2$ are pairing-friendly. \
/// The commitment key is defined as $ck = \(G, \tau G, \tau^2 G, ..., \tau^{n-1} G \)$. \
/// The commitment step returns $C = \Sigma_i f_i \cdot ck_i$ in $\GG_1$. \
///
/// Where `polynomial_flat` points to a vector of type `Vec<Fr>`, `ck.commit(&polynomial_flat)` returns the commitment to $f(x)$.
///
/// This commitment scheme is homomorphic on elements of $\GG_1$.
#[derive(Debug, Copy, Clone, PartialEq, Eq, CanonicalDeserialize, CanonicalSerialize)]
pub struct Commitment<E: Pairing>(pub(crate) E::G1Affine);

#[inline]
fn msm<E: Pairing>(bases: &[E::G1Affine], scalars: &[E::ScalarField]) -> E::G1Affine {
    let scalars = scalars.iter().map(|x| x.into_bigint()).collect::<Vec<_>>();
    let sp: E::G1 = VariableBaseMSM::msm_bigint(bases, &scalars);
    sp.into_affine()
}

/// A polynomial evaluation proof, represented as a `dim` dimensional vector of $\GG_1$ elements.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvaluationProofMulti<E: Pairing>(pub(crate) Vec<E::G1Affine>);

/// The verification key type for the polynomial commitment scheme.
///
/// `VerifierKeyMulti` implements the verification function `verify` for the evaluation proof.
///
#[derive(Debug, PartialEq, Eq, CanonicalDeserialize, CanonicalSerialize)]
pub struct VerifierKeyMulti<E: Pairing> {
    /// The generator of  \\(\GG_1\\)
    g: E::G1Affine,
    /// The generator of \\(\GG_2\\).
    g2: E::G2Affine,
    /// generator of G2 multiplied by the trapdoor vector.
    powers_of_g2: Vec<E::G2Affine>,
}

impl<E: Pairing> VerifierKeyMulti<E> {
    /// The verification procedure for the EvaluationProof with a single polynomial evaluated at a single evaluation point.
    /// The polynomials are evaluated at the point ``alpha`` and is committed as ``commitment``.
    /// The evaluation remainder (`evaluation`) and the respective polynomial quotients (the ``proof``),
    /// can be obtained either in a space-efficient or a time-efficient manner.
    /// To use the space-efficient implementation, see `CommitterKeyMultiStream` and respective functions.
    /// To use the time-efficient implementation, see `CommitterKeyMulti` and respective functions.
    pub fn verify(
        &self,
        commitment: &Commitment<E>,
        alpha: &[E::ScalarField],
        evaluation: &E::ScalarField,
        proof: &EvaluationProofMulti<E>,
    ) -> VerificationResult {
        let lhs = E::pairing(
            (commitment.0.into_group() - self.g.mul(evaluation)).into_affine(),
            self.g2,
        )
        .0;
        // turn this into a fold, so it doesnt have to be mutable?
        let mut rhs = E::TargetField::one();

        assert_eq!(self.powers_of_g2.len(), alpha.len());
        assert_eq!(self.powers_of_g2.len(), proof.0.len());
        for (i, alpha_i) in alpha.iter().enumerate() {
            rhs *= E::pairing(
                proof.0[i],
                (self.powers_of_g2[i].into_group() - self.g2.mul(alpha_i)).into_affine(),
            )
            .0;
        }
        if lhs == rhs {
            Ok(())
        } else {
            Err(VerificationError)
        }
    }

    pub fn batch_verify(
        &self,
        commitments: &[Commitment<E>],
        alpha: &[E::ScalarField],
        evaluations: &[E::ScalarField],
        proof: &EvaluationProofMulti<E>,
        batch_chal: &E::ScalarField,
    ) -> VerificationResult {
        use crate::misc::powers;

        let pows = powers(*batch_chal, commitments.len());
        let commitment = commitments
            .iter()
            .zip(&pows)
            .map(|(&p, &ch)| p.0 * ch)
            .reduce(|x, y| x + y)
            .map(|x| Commitment::<E>(x.into_affine()))
            .unwrap_or_else(|| Commitment::<E>(E::G1Affine::zero()));
        let evaluation = evaluations.iter().zip(pows).map(|(&p, e)| p * e).sum();
        self.verify(&commitment, alpha, &evaluation, proof)
    }
}
