use ark_ff::Field;
use ark_serialize::*;
use ark_std::vec::Vec;
use merlin::Transcript;

use crate::errors::VerificationError;
use crate::transcript::GeminiTranscript;

use super::module::BilinearModule;
use super::prover::SumcheckMsg;

/// The subclaim of the sumcheck.
pub struct Subclaim<M: BilinearModule> {
    /// The verifier's challenges \\(\rho_0, \dots, \rho_{n-1}\\)
    pub challenges: Vec<M::ScalarField>,
    /// The subclaim \\(t_0, t_1\\).
    pub final_foldings: Vec<(M::Lhs, M::Rhs)>,
}

/// Messages sent by the prover throughout the protocol.
#[derive(CanonicalSerialize, Clone, Debug, PartialEq, Eq)]
pub struct SumcheckMsgs<M: BilinearModule>(
    pub(crate) Vec<SumcheckMsg<M::Target>>,
    pub(crate) Vec<(M::Lhs, M::Rhs)>,
);

impl<M: BilinearModule> Subclaim<M> {
    /// Generate a new subclaim
    /// from the non-oracle messages from the prover.
    pub fn new(
        transcript: &mut Transcript,
        prover_messages: &SumcheckMsgs<M>,
        asserted_sum: M::Target,
    ) -> Result<Self, VerificationError> {
        let SumcheckMsgs(messages, final_foldings) = prover_messages;
        let (challenges, reduced_claim) = Self::reduce(transcript, messages, asserted_sum);

        // Add the final foldings to the transcript
        transcript.append_serializable(b"final-folding", &final_foldings[0].0);
        transcript.append_serializable(b"final-folding", &final_foldings[0].1);

        if final_foldings[0].0 ^ final_foldings[0].1 == reduced_claim {
            Ok(Self {
                challenges,
                final_foldings: final_foldings.to_vec(),
            })
        } else {
            Err(VerificationError)
        }
    }

    //     pub fn new_batch(
    //         transcript: &mut Transcript,
    //         prover_messages: &ProverMsgs<M>,
    //         asserted_sums: &[M],
    //     ) -> Result<Self, VerificationError> {
    //         let ProverMsgs(messages, final_foldings) = prover_messages;
    //         let coefficients = (0..asserted_sums.len())
    //             .map(|_| transcript.get_challenge::<M::ScalarField>(b"batch-sumcheck"))
    //             .collect::<Vec<_>>();
    //         let asserted_sum = ip(&coefficients, asserted_sums);
    //         let (challenges, reduced_claim) =
    //             Self::reduce(transcript, messages.as_slice(), asserted_sum);

    //         let expected_reduced_claim: M::ScalarField = final_foldings
    //             .iter()
    //             .zip(coefficients.iter())
    //             .map(|(final_folding, coefficient)| {
    //                 transcript.append_serializable(b"final-folding-lhs", &final_folding[0]);
    //                 transcript.append_serializable(b"final-folding-rhs", &final_folding[1]);
    //                 final_folding[0] * final_folding[1] * coefficient
    //             })
    //             .sum();

    //         if expected_reduced_claim == reduced_claim {
    //             Ok(Self {
    //                 challenges,
    //                 final_foldings: final_foldings.to_vec(),
    //             })
    //         } else {
    //             Err(VerificationError)
    //         }
    //     }

    fn reduce(
        transcript: &mut Transcript,
        messages: &[SumcheckMsg<M::Target>],
        asserted_sum: M::Target,
    ) -> (Vec<M::ScalarField>, M::Target) {
        let mut reduced_claim = asserted_sum;
        let mut challenges = Vec::with_capacity(messages.len());
        // reduce to a subclaim using the prover's messages.
        for message in messages {
            // compute the next challenge from the previous coefficients.
            transcript.append_serializable(b"evaluations", message);
            let r = transcript.get_challenge::<M::ScalarField>(b"challenge");
            challenges.push(r);

            let SumcheckMsg(a, b) = message;
            let c = reduced_claim - *a;
            // evaluate (a + bx + cx2) at r
            reduced_claim = *a + *b * r + c * r.square();
        }
        (challenges, reduced_claim)
    }
}
