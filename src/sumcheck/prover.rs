//! Common data structures for the prover algorith in the scalar-product sub-argument.
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Read, SerializationError, Write};
use ark_std::iter::Sum;

/// Each message from the prover in a sumcheck protocol is a pair of FF-elements.
#[derive(CanonicalSerialize, CanonicalDeserialize, Copy, Clone, Debug, PartialEq, Eq)]
pub struct ProverMsg<F: Field>(pub(crate) F, pub(crate) F);

impl<F: Field> Sum for ProverMsg<F> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|fst, snd| ProverMsg(fst.0 + snd.0, fst.1 + snd.1))
            .unwrap_or_else(|| ProverMsg(F::zero(), F::zero()))
    }
}

impl<F: Field> ProverMsg<F> {
    pub(crate) fn mul(self, rhs: &F) -> Self {
        ProverMsg(self.0 * rhs, self.1 * rhs)
    }
}

/// Prover trait interface for both time-efficient and space-efficient prover.
pub trait Prover<F>
where
    F: Field,
{
    /// Return the next prover message (if any).
    fn next_message(&mut self) -> Option<ProverMsg<F>>;
    /// Peform even/odd folding of the instance using the challenge `challenge`.
    fn fold(&mut self, challenge: F);
    // Return the total number of rouds in the protocol.
    fn rounds(&self) -> usize;
    /// Current round number.
    fn round(&self) -> usize;
    /// Return the fully-folded isntances if at the final round,
    /// otherwise return None.
    fn final_foldings(&self) -> Option<[F; 2]>;
}
