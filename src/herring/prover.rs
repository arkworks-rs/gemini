//! Common data structures for the prover algorith in the scalar-product sub-argument.
use ark_serialize::*;
use ark_std::iter::Sum;
use ark_std::ops::{Add, Mul};
use ark_std::vec::Vec;

use super::module::{BilinearModule, Module};

/// Each message from the prover in a sumcheck protocol is a pair of FF-elements.
#[derive(CanonicalSerialize, Copy, Clone, Debug, PartialEq, Eq)]
pub struct SumcheckMsg<M: Module>(pub(crate) M, pub(crate) M);

/// Messages sent by the prover throughout the protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProverMsgs<M: BilinearModule>(
    pub(crate) Vec<SumcheckMsg<M::Target>>,
    pub(crate) Vec<(M::Lhs, M::Rhs)>,
);

impl<M: Module> Add<Self> for SumcheckMsg<M> {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        SumcheckMsg(self.0 + other.0, self.1 + other.1)
    }
}
impl<M: Module> Sum for SumcheckMsg<M> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|fst, snd| SumcheckMsg(fst.0 + snd.0, fst.1 + snd.1))
            .unwrap_or_else(|| SumcheckMsg(M::zero(), M::zero()))
    }
}

impl<M: Module> SumcheckMsg<M> {
    pub(crate) fn ip<I: Iterator<Item = Self>, J: Iterator<Item = M::ScalarField>>(
        iter: I,
        scalars: J,
    ) -> Self {
        iter.zip(scalars)
            .fold(SumcheckMsg(M::zero(), M::zero()), |acc, (snd, scalar)| {
                Self(acc.0 + snd.0 * scalar, acc.1 + snd.1 * scalar)
            })
    }
}

impl<M: Module> Mul<&M::ScalarField> for SumcheckMsg<M> {
    type Output = Self;

    fn mul(self, rhs: &M::ScalarField) -> Self {
        SumcheckMsg(self.0 * rhs, self.1 * rhs)
    }
}

/// Prover trait interface for both time-efficient and space-efficient prover.
pub trait Prover<M>: Send + Sync
where
    M: BilinearModule,
{
    /// Return the next prover message (if any).
    fn next_message(
        &mut self,
        verifier_message: Option<M::ScalarField>,
    ) -> Option<SumcheckMsg<M::Target>>;
    /// Peform even/odd folding of the instance using the challenge `challenge`.
    fn fold(&mut self, challenge: M::ScalarField);
    // Return the total number of rouds in the protocol.
    fn rounds(&self) -> usize;
    /// Current round number.
    fn round(&self) -> usize;
    /// Return the fully-folded isntances if at the final round,
    /// otherwise return None.
    fn final_foldings(&self) -> Option<(M::Lhs, M::Rhs)>;
}
