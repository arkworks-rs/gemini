use ark_ff::Field;
use ark_std::borrow::Borrow;

use crate::{iterable::Iterable, SPACE_TIME_THRESHOLD};

use super::prover::RoundMsg;
use super::{Prover, SpaceProver, TimeProver};

/// Specifier of the prover type (time-efficient or space-efficient).
pub enum ElasticProver<S, T> {
    Space(S),
    Time(T),
}

impl<F, S1, S2, T> ElasticProver<SpaceProver<F, S1, S2>, T>
where
    F: Field,
    S1: Iterable,
    S2: Iterable,
    S1::Item: Borrow<F>,
    S2::Item: Borrow<F>,
{
    /// Initialize the elastic prover.
    pub fn new(f: S1, g: S2, twist: F) -> Self {
        Self::Space(SpaceProver::new(f, g, twist))
    }
}

impl<F, S1, S2> Prover<F> for ElasticProver<SpaceProver<F, S1, S2>, TimeProver<F>>
where
    F: Field,
    S1: Iterable,
    S2: Iterable,
    S1::Item: Borrow<F>,
    S2::Item: Borrow<F>,
{
    fn next_message(&mut self, verifier_message: Option<F>) -> Option<RoundMsg<F>> {
        match self {
            Self::Space(p) => p.next_message(verifier_message),
            Self::Time(p) => p.next_message(verifier_message),
        }
    }

    fn fold(&mut self, challenge: F) {
        match self {
            Self::Space(p) => {
                if p.rounds() - p.round() < SPACE_TIME_THRESHOLD {
                    let mut time_prover = TimeProver::from(&*p);
                    time_prover.fold(challenge);
                    *self = Self::Time(time_prover);
                } else {
                    p.fold(challenge);
                }
            }
            Self::Time(p) => p.fold(challenge),
        }
    }

    fn rounds(&self) -> usize {
        match self {
            Self::Space(p) => p.rounds(),
            Self::Time(p) => p.rounds(),
        }
    }

    fn round(&self) -> usize {
        match self {
            Self::Space(p) => p.round(),
            Self::Time(p) => p.round(),
        }
    }

    fn final_foldings(&self) -> Option<[F; 2]> {
        match self {
            Self::Space(p) => p.final_foldings(),
            Self::Time(p) => p.final_foldings(),
        }
    }
}
