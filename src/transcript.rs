//! Transcript utilities for the scalar product sub-protocol.
use ark_ff::Field;
use ark_serialize::CanonicalSerialize;
use ark_std::vec::Vec;
use merlin::Transcript;

/// A Transcript with some shorthands for feeding scalars, group elements, and obtaining challenges as field elements.
pub trait GeminiTranscript {
    fn append_serializable<S: CanonicalSerialize>(&mut self, label: &'static [u8], msg: &S);

    /// Compute a `label`ed challenge scalar from the given commitments and the choice bit.
    fn get_challenge<F: Field>(&mut self, label: &'static [u8]) -> F;
}

impl GeminiTranscript for Transcript {
    fn append_serializable<S: CanonicalSerialize>(
        &mut self,
        label: &'static [u8],
        serializable: &S,
    ) {
        let mut message = Vec::new();
        serializable.serialize_uncompressed(&mut message).unwrap();
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
}
