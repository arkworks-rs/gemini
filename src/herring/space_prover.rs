// #[cfg(feature = "parallel")]
// use rayon::{
//     iter::{IndexedParallelIterator, ParallelIterator},
//     slice::ParallelSlice,
// };

use super::module::BilinearModule;
use ark_ff::Field;
use ark_std::borrow::Borrow;
use ark_std::cmp::Ordering;
use ark_std::log2;
use ark_std::vec::Vec;
use ark_std::Zero;

use super::prover::SumcheckMsg;
use super::{prover::Prover, time_prover::TimeProver};
use crate::herring::streams::FoldedPolynomialStream;
use crate::iterable::Iterable;

/// This is the streaming alter-ego of `Witness`.
/// The witness for the twisted scalar product, where the vectors are stored as streams.
pub struct WitnessStream<M, SF, SG>
where
    M: BilinearModule,
    SF: Iterable,
    SF::Item: Borrow<M::Lhs>,
    SG: Iterable,
    SG::Item: Borrow<M::Rhs>,
{
    /// The left-hand side.
    pub f: SF,
    /// The right-hand side.
    pub g: SG,
    /// The twist.
    pub twist: M::ScalarField,
}

/// The space-efficient prover.
pub struct SpaceProver<M, SF, SG>
where
    M: BilinearModule,
    SF: Iterable,
    SF::Item: Borrow<M::Lhs>,
    SG: Iterable,
    SG::Item: Borrow<M::Rhs>,
{
    /// Randomness given by the verifier, used to fold the right-hand side.
    challenges: Vec<M::ScalarField>,
    /// Twisted randomness, used to fold the left-hand side of the scalar product.
    twisted_challenges: Vec<M::ScalarField>,
    /// Batched sumcheck instance.
    witness: WitnessStream<M, SF, SG>,
    /// Round counter.
    round: usize,
    /// Total number of rounds.
    tot_rounds: usize,
    /// Current twist.
    twist: M::ScalarField,
}

// A Stream that will produce the folded polynomial
// given references to the initial stream and randomness.
impl<M, SF, SG> WitnessStream<M, SF, SG>
where
    M: BilinearModule,
    SF: Iterable,
    SF::Item: Borrow<M::Lhs>,
    SG: Iterable,
    SG::Item: Borrow<M::Rhs>,
{
    /// Initialize a new witness stream.
    pub fn new(f: SF, g: SG, twist: M::ScalarField) -> Self {
        Self { f, g, twist }
    }

    /// Output the number of rounds required for the given scalar product.
    fn required_rounds(&self) -> usize {
        let max_len = usize::min(self.f.len(), self.g.len());
        log2(max_len) as usize
    }
}

impl<M, SF, SG> SpaceProver<M, SF, SG>
where
    M: BilinearModule,
    SF: Iterable,
    SF::Item: Borrow<M::Lhs>,
    SG: Iterable,
    SG::Item: Borrow<M::Rhs>,
{
    /// Create a new space prover.
    /// This will move the witness within the instance, but never modify the initial instance.
    pub fn new(f: SF, g: SG, twist: M::ScalarField) -> Self {
        let witness = WitnessStream::new(f, g, twist);
        let tot_rounds = witness.required_rounds();
        let challenges = Vec::with_capacity(tot_rounds);
        let twisted_challenges = Vec::with_capacity(tot_rounds);
        let round = 0;
        SpaceProver {
            challenges,
            twisted_challenges,
            witness,
            round,
            tot_rounds,
            twist,
        }
    }
}

impl<M, S1, S2> Prover<M> for SpaceProver<M, S1, S2>
where
    M: BilinearModule,
    S1: Iterable,
    S1::Item: Borrow<M::Lhs>,
    S2: Iterable,
    S2::Item: Borrow<M::Rhs>,
{
    fn next_message(
        &mut self,
        verifier_message: Option<M::ScalarField>,
    ) -> Option<SumcheckMsg<M::Target>> {
        assert!(self.round <= self.tot_rounds, "More rounds than needed.");
        assert_eq!(
            self.challenges.len(),
            self.round,
            "At the i-th round, randomness.len() = i."
        );

        // If the verifier sent a message, fold according to it.
        if let Some(challenge) = verifier_message {
            self.fold(challenge);
        }

        if self.round == self.tot_rounds {
            return None;
        }

        let folded_f = FoldedPolynomialStream::new(&self.witness.f, &self.twisted_challenges);
        let folded_g = FoldedPolynomialStream::new(&self.witness.g, &self.challenges);

        // // The size of a step in this round.
        // // This corresponds to the number of coefficients to read in the initial stream
        // // in order to compute the next coefficient.
        let mut f_coefficients = folded_f.len();
        let mut g_coefficients = folded_g.len();

        let mut f_it = folded_f.iter();
        let mut g_it = folded_g.iter();

        // Align the streams: if one stream is much larger than the other,
        // some positions must be skipped.
        match f_coefficients.cmp(&g_coefficients) {
            Ordering::Greater => {
                let delta = f_coefficients - g_coefficients + (g_coefficients % 2);
                f_it.advance_by(delta).unwrap();
                f_coefficients -= delta;
            }
            Ordering::Less => {
                let delta = g_coefficients - f_coefficients + (f_coefficients % 2);
                g_it.advance_by(delta).unwrap();
                g_coefficients -= delta;
            }
            Ordering::Equal => (),
        }

        // Complete alignment: as we process coefficients two by two,
        // we have to start either from an odd coefficient (and set the even to zero),
        // or vice-versa.
        let (f_odd, f_even) = if f_coefficients & 1 != 0 {
            (M::Lhs::zero(), f_it.next().unwrap())
        } else {
            (f_it.next().unwrap(), f_it.next().unwrap())
        };

        let (g_odd, g_even) = if g_coefficients & 1 != 0 {
            (M::Rhs::zero(), g_it.next().unwrap())
        } else {
            (g_it.next().unwrap(), g_it.next().unwrap())
        };

        // // Compute the pairs of coefficients that will be used.
        let f_pairs = (f_coefficients - 2 + f_coefficients % 2) / 2;
        let g_pairs = (g_coefficients - 2 + g_coefficients % 2) / 2;
        assert_eq!(f_pairs, g_pairs);

        // Compute the polynomial of the partial sum q = a + bx + c x2,
        // For the evaluations, send only the coefficients a, b of the polynomial.
        let twist2inv = self.twist.square().inverse().unwrap();
        let mut twist_runner = self.twist.pow(&[(f_pairs * 2) as u64]);

        let mut a = M::p(f_even, g_even) * twist_runner;
        let mut b = (M::p(f_even, g_odd) + M::p(f_odd, g_even * self.twist)) * twist_runner;
        twist_runner *= twist2inv;

        // #[cfg(not(feature = "parallel"))]
        for _i in 0..f_pairs {
            let f_odd = f_it.next().unwrap();
            let g_odd = g_it.next().unwrap();

            let f_even = f_it.next().unwrap();
            let g_even = g_it.next().unwrap();

            // Add to the partial sum
            a += M::p(f_even, g_even * twist_runner);
            b += (M::p(f_even, g_odd) + M::p(f_odd, g_even * self.twist)) * twist_runner;
            twist_runner *= twist2inv;
        }

        // #[cfg(feature = "parallel")]
        // for _i in 0..ceil_div(f_pairs, SUMCHECK_BUF_SIZE) {
        //     let f_buf = (&mut f_it).take(SUMCHECK_BUF_SIZE).collect::<Vec<_>>();
        //     let g_buf = (&mut g_it).take(SUMCHECK_BUF_SIZE).collect::<Vec<_>>();
        //     let mut twist_runner_a = twist_runner;
        //     let twist = self.twist;
        //     a += f_buf
        //         .par_chunks(2)
        //         .zip(g_buf.par_chunks(2))
        //         .map(|(f_chunk, g_chunk)| {
        //             let _f_odd = f_chunk[0];
        //             let f_even = f_chunk[1];
        //             let _g_odd = g_chunk[0];
        //             let g_even = g_chunk[1];

        //             let result = f_even * g_even * twist_runner;
        //             twist_runner_a *= twist2inv;
        //             result
        //         })
        //         .sum::<F>();

        //     let mut twist_runner_b = twist_runner;
        //     b += f_buf
        //         .par_chunks(2)
        //         .zip(g_buf.par_chunks(2))
        //         .map(|(f_chunk, g_chunk)| {
        //             let f_odd = f_chunk[0];
        //             let f_even = f_chunk[1];
        //             let g_odd = g_chunk[0];
        //             let g_even = g_chunk[1];

        //             let result = (f_even * g_odd + f_odd * g_even * twist) * twist_runner;
        //             twist_runner_b *= twist2inv;
        //             result
        //         })
        //         .sum::<F>();
        // }

        // Increment the round counter.
        self.round += 1;
        Some(SumcheckMsg(a, b))
    }

    /// Fold the current instance with the randomness r.
    /// For the space prover, this simply means storing the randomness aside.
    /// Twist the randomness, to avoid computing twist * r on the polynomial
    fn fold(&mut self, r: M::ScalarField) {
        self.challenges.push(r);
        self.twisted_challenges.push(r * self.twist);
        self.twist.square_in_place();
    }

    #[inline]
    fn rounds(&self) -> usize {
        self.tot_rounds
    }

    fn round(&self) -> usize {
        self.round
    }

    fn final_foldings(&self) -> Option<(M::Lhs, M::Rhs)> {
        let folded_f = FoldedPolynomialStream::new(&self.witness.f, &self.twisted_challenges);
        let folded_g = FoldedPolynomialStream::new(&self.witness.g, &self.challenges);
        let lhs = folded_f.iter().next()?;
        let rhs = folded_g.iter().next()?;
        (self.round == self.tot_rounds).then_some((lhs, rhs))
    }
}

impl<M, S1, S2> From<&SpaceProver<M, S1, S2>> for TimeProver<M>
where
    M: BilinearModule,
    S1: Iterable,
    S1::Item: Borrow<M::Lhs>,
    S2: Iterable,
    S2::Item: Borrow<M::Rhs>,
{
    fn from(sp: &SpaceProver<M, S1, S2>) -> Self {
        // define the streams of folded polynomials for the current round
        let folded_f = FoldedPolynomialStream::new(&sp.witness.f, sp.twisted_challenges.as_slice());
        let folded_g = FoldedPolynomialStream::new(&sp.witness.g, sp.challenges.as_slice());

        // fill (in reverse) with the folded polynomials
        let mut f = vec![M::Lhs::zero(); folded_f.len()];
        let mut g = vec![M::Rhs::zero(); folded_g.len()];
        f.iter_mut()
            .rev()
            .zip(folded_f.iter())
            .for_each(|(dst, src)| *dst = src);
        g.iter_mut()
            .rev()
            .zip(folded_g.iter())
            .for_each(|(dst, src)| *dst = src);

        // copy other informations such us round(s) and twist.
        let round = sp.round;
        let tot_rounds = sp.tot_rounds;
        let twist = sp.twist;

        TimeProver {
            f,
            g,
            round,
            twist,
            tot_rounds,
        }
    }
}
