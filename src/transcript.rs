//! Transcript utilities for the scalar product sub-protocol.
use merlin::Transcript;

use ark_ec::{group::Group, PairingEngine};
use ark_ff::{to_bytes, Field};

use crate::kzg::Commitment;
use crate::sumcheck::prover::RoundMsg;

/// A Transcript with some shorthands for feeding scalars, group elements, and obtaining challenges as field elements.
pub trait GeminiTranscript {
    /// Append a Prover message, with the given label.
    fn append_prover_message<F: Field>(&mut self, label: &'static [u8], msg: &RoundMsg<F>);

    /// Append a `Field` instance  with the given lebel.
    fn append_scalar<F: Field>(&mut self, label: &'static [u8], scalar: &F);

    /// Append a `Group` with the given label.
    fn append_point<G: Group>(&mut self, label: &'static [u8], point: &G);

    /// Compute a `label`ed challenge scalar from the given commitments and the choice bit.
    fn get_challenge<F: Field>(&mut self, label: &'static [u8]) -> F;

    /// Add a `Commitment` with the given label.
    fn append_commitment<E: PairingEngine>(
        &mut self,
        label: &'static [u8],
        commitment: &Commitment<E>,
    );
}

impl GeminiTranscript for Transcript {
    fn append_prover_message<F: Field>(&mut self, label: &'static [u8], msg: &RoundMsg<F>) {
        self.append_message(label, &to_bytes!(msg.0, msg.1).unwrap())
    }

    fn append_point<G: Group>(&mut self, label: &'static [u8], point: &G) {
        self.append_message(label, &to_bytes!(point).unwrap());
    }

    fn append_commitment<E: PairingEngine>(
        &mut self,
        label: &'static [u8],
        commitment: &Commitment<E>,
    ) {
        self.append_message(label, &to_bytes!(commitment.0).unwrap())
    }

    fn append_scalar<F: Field>(&mut self, label: &'static [u8], scalar: &F) {
        self.append_message(label, &to_bytes!(scalar).unwrap())
    }

    fn get_challenge<F: Field>(&mut self, label: &'static [u8]) -> F {
        loop {
            let mut bytes = [0; 64];
            self.challenge_bytes(label, &mut bytes);
            if let Some(e) = F::from_random_bytes(&bytes) {
                return e;
            }
        }
    }
}
