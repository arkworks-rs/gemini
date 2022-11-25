//!
//!

use ark_ff::Field;
use ark_ff::{One, Zero};
use ark_std::log2;
use ark_std::vec::Vec;

use crate::herring::prover::{Prover, SumcheckMsg};

use super::module::{BilinearModule, Module};

/// The witness for the Twisted Scalar product relation.
#[derive(Clone)]
pub(crate) struct Witness<M: BilinearModule> {
    /// The left hand side
    f: Vec<M::Lhs>,
    /// The right-hand side
    g: Vec<M::Rhs>,
    /// The twist
    twist: M::ScalarField,
}

/// The witness for the proving algorithm.
impl<M: BilinearModule> Witness<M> {
    /// Instantiate a new Witness isntance from polynomials f, g.
    /// The instance also accepts a `twist`.
    pub(crate) fn new(f: &[M::Lhs], g: &[M::Rhs], twist: &M::ScalarField) -> Witness<M> {
        Witness {
            f: f.to_vec(),
            g: g.to_vec(),
            twist: *twist,
        }
    }

    /// Output the number of rounds required for the given scalar product.
    pub fn required_rounds(&self) -> usize {
        let min_len = usize::min(self.f.len(), self.g.len());
        log2(min_len) as usize
    }
}

/// The state of the time prover in the scalar product protocol.
pub struct TimeProver<M: BilinearModule> {
    /// The polynomial `f` in the scalar product.
    pub f: Vec<M::Lhs>,
    /// The polynomial `g` in the scalar product.
    pub g: Vec<M::Rhs>,
    /// Round counter.
    pub round: usize,
    pub twist: M::ScalarField,
    /// Total number of rounds.
    pub tot_rounds: usize,
}

impl<M: BilinearModule> TimeProver<M> {
    /// Create a new time prover.
    /// This will cause a copy of the witness.
    pub(crate) fn new(witness: Witness<M>) -> Self {
        // let twists = powers(witness.twist, witness.f.len());
        // let f = hadamard(&twists, &witness.f);
        TimeProver {
            f: witness.f.to_vec(),
            g: witness.g.to_vec(),
            round: 0usize,
            twist: witness.twist,
            tot_rounds: witness.required_rounds(),
        }
    }
}

#[inline]
pub(crate) fn split_fold<M: Module>(f: &[M], r: M::ScalarField) -> Vec<M> {
    f.chunks(2)
        .map(|pair| pair[0] + *pair.get(1).unwrap_or(&M::zero()) * r)
        .collect()
}

#[inline]
pub(crate) fn split_fold_into<'a, M: Module>(
    dst: &mut Vec<M>,
    f: &[M],
    challenge: &M::ScalarField,
) {
    let folded_len = f.len() / 2;
    for i in 0..folded_len {
        dst[i] = f[i * 2] + *f.get(i * 2 + 1).unwrap_or(&M::zero()) * challenge
    }
    dst.truncate(folded_len)
}

#[inline]
pub(crate) fn halve<'a, M: Module>(dst: &mut Vec<M>) {
    let folded_len = dst.len() / 2 + dst.len() % 2;
    dst.truncate(folded_len);
}

impl<M> Prover<M> for TimeProver<M>
where
    M: BilinearModule,
{
    /// Fold the sumcheck instance (inplace).
    fn fold(&mut self, r: M::ScalarField) {
        // Fold the polynonomials f, g in the scalar product.
        self.f = split_fold(&self.f, r * self.twist);
        self.g = split_fold(&self.g, r);
        self.twist.square_in_place();
    }

    /// Time-efficient, next-message function.
    fn next_message(
        &mut self,
        verifier_message: Option<M::ScalarField>,
    ) -> Option<SumcheckMsg<M::Target>> {
        assert!(self.round <= self.tot_rounds, "More rounds than needed.");
        // debug!("Round: {}", self.round);

        // If the verifier sent a message, fold according to it.
        if let Some(challenge) = verifier_message {
            self.fold(challenge);
        }

        // If we already went through tot_rounds, no message must be sent.
        if self.round == self.tot_rounds {
            return None;
        }

        // Compute the polynomial of the partial sum q = a + bx + c x2,
        // For the evaluations, send only the coefficients a, b of the polynomial .
        let mut a = M::Target::zero();
        let mut b = M::Target::zero();
        let twist2 = self.twist.square();
        let lhs_zero = M::Lhs::zero();
        let rhs_zero = M::Rhs::zero();

        let mut twist_runner = M::ScalarField::one();
        for (f_pair, g_pair) in self.f.chunks(2).zip(self.g.chunks(2)) {
            // The even part of the polynomial must always be unwrapped.
            let f_even = f_pair[0];
            let g_even = g_pair[0];

            // For the right part, we might obtain zero if the degree is not a multiple of 2.
            let f_odd = f_pair.get(1).unwrap_or(&lhs_zero);
            let g_odd = g_pair.get(1).unwrap_or(&rhs_zero);

            // Add to the partial sum
            a += M::p(f_even, g_even * twist_runner);
            b += (M::p(f_even, *g_odd) + M::p(*f_odd * self.twist, g_even)) * twist_runner;
            twist_runner *= twist2;
        }
        // Increment the round counter
        self.round += 1;

        Some(SumcheckMsg(a, b))
    }

    /// The number of rounds this prover is supposed to run on.
    #[inline]
    fn rounds(&self) -> usize {
        self.tot_rounds
    }

    fn round(&self) -> usize {
        self.round
    }

    fn final_foldings(&self) -> Option<(M::Lhs, M::Rhs)> {
        (self.round == self.tot_rounds).then(|| (self.f[0], self.g[0]))
    }
}
