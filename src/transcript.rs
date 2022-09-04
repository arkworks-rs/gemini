//! Transcript utilities for the scalar product sub-protocol.
use ark_std::vec::Vec;
use merlin::Transcript;

use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::Field;
use ark_serialize::CanonicalSerialize;

use crate::kzg::{Commitment, EvaluationProof};
use crate::subprotocols::sumcheck::prover::RoundMsg;

/// A Transcript with some shorthands for feeding scalars, group elements, and obtaining challenges as field elements.
pub trait GeminiTranscript {
    /// Append a Prover message, with the given label.
    fn append_prover_message<F: Field>(&mut self, label: &'static [u8], msg: &RoundMsg<F>);

    /// Append a `Field` instance  with the given lebel.
    fn append_scalar<F: Field>(&mut self, label: &'static [u8], scalar: &F);

    /// Append a `Group` with the given label.
    fn append_point<G: AffineRepr>(&mut self, label: &'static [u8], point: &G);

    /// Compute a `label`ed challenge scalar from the given commitments and the choice bit.
    fn get_challenge<F: Field>(&mut self, label: &'static [u8]) -> F;

    /// Add a `Commitment` with the given label.
    fn append_commitment<E: Pairing>(&mut self, label: &'static [u8], commitment: &Commitment<E>);

    // Add an `EvaluationProof` with the given label.
    fn append_evaluation_proof<E: Pairing>(
        &mut self,
        label: &'static [u8],
        proof: &EvaluationProof<E>,
    );
}

impl GeminiTranscript for Transcript {
    fn append_prover_message<F: Field>(&mut self, label: &'static [u8], msg: &RoundMsg<F>) {
        let mut message = Vec::new();
        msg.0.serialize_uncompressed(&mut message).unwrap();
        msg.1.serialize_uncompressed(&mut message).unwrap();
        self.append_message(label, &message)
    }

    fn append_point<G: AffineRepr>(&mut self, label: &'static [u8], point: &G) {
        let mut message = Vec::new();
        point.serialize_uncompressed(&mut message).unwrap();
        self.append_message(label, &message);
    }

    fn append_commitment<E: Pairing>(&mut self, label: &'static [u8], commitment: &Commitment<E>) {
        let mut message = Vec::new();
        commitment.0.serialize_uncompressed(&mut message).unwrap();
        self.append_message(label, &message)
    }

    fn append_scalar<F: Field>(&mut self, label: &'static [u8], scalar: &F) {
        let mut message = Vec::new();
        scalar.serialize_uncompressed(&mut message).unwrap();
        self.append_message(label, &message)
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

    fn append_evaluation_proof<E: Pairing>(
        &mut self,
        label: &'static [u8],
        proof: &EvaluationProof<E>,
    ) {
        let mut message = Vec::new();
        proof.0.serialize_uncompressed(&mut message).unwrap();
        self.append_message(label, &message)
    }
}
