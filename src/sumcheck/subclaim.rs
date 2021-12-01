use ark_ff::Field;
use merlin::Transcript;

use crate::sumcheck::prover::ProverMsg;
use crate::transcript::GeminiTranscript;

/// The sumcheck verifier protocol reduces a claim \\( \langle f, g \rangle = u\\)
/// to a `Subclaim` that:
/// \\(f(\rho_0, \rho_{n-1}) \cdot g(\rho_0, \dots, \rho_{n-1}) = t\\).
pub struct Subclaim<F: Field> {
    /// the verifier's challenges \\(\rho_0, \dots, \rho_{n-1}\\)
    pub challenges: Vec<F>,
    /// the subclaim \\(t\\).
    pub reduced_claim: F,
}

impl<F: Field> Subclaim<F> {
    /// Generate a new `Subclaim` from the non-oracle messages from the prover.
    pub fn new(transcript: &mut Transcript, messages: &[ProverMsg<F>], asserted_sum: F) -> Self {
        let mut reduced_claim = asserted_sum;
        let mut challenges = Vec::with_capacity(messages.len());
        // reduce to a subclaim using the prover's messages.
        for message in messages {
            // compute the next challenge from the previous coefficients.
            transcript.append_prover_message(b"evaluations", message);
            let r = transcript.get_challenge::<F>(b"challenge");
            challenges.push(r);

            let ProverMsg(a, b) = message;
            let c = reduced_claim - a;
            // evaluate (a + bx + cx2) at r
            reduced_claim = *a + r * b + c * r.square();
        }
        Self {
            challenges,
            reduced_claim,
        }
    }
}
