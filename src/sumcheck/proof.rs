//! Scalar-product proof implementation.
use std::borrow::Borrow;

use ark_ff::Field;
use merlin::Transcript;

use crate::stream::Streamer;

use super::prover::{ProverMsgs, RoundMsg};
use super::Prover;
use crate::sumcheck::{time_prover::Witness, ElasticProver, SpaceProver, TimeProver};
use crate::transcript::GeminiTranscript;

/// A scalar product proof, containing non-oracle messages, and oracle messages together with their queries and evaluations.
#[derive(Debug, PartialEq, Eq)]
pub struct Sumcheck<F: Field> {
    /// The non-oracle messages sent througout the protocol.
    pub messages: Vec<RoundMsg<F>>,
    /// The challenges sent thropughout the protocol.
    pub challenges: Vec<F>,
    /// The number of rounds in the protocol.
    rounds: usize,
    // Folded statements
    final_foldings: Vec<[F; 2]>,
}

impl<F: Field> Sumcheck<F> {
    /// Prove function for the scalar product.
    /// The input contains a randomness generator and a prover struct.
    /// The prover struct can be either time-efficient or space-efficient
    /// depending on the configuration.
    pub fn prove<P: Prover<F>>(transcript: &mut Transcript, mut prover: P) -> Self {
        let rounds = prover.rounds();
        let mut messages = Vec::with_capacity(rounds);
        let mut challenges = Vec::with_capacity(rounds);

        while let Some(message) = prover.next_message() {
            // add the message sent to the transcript
            transcript.append_prover_message(b"evaluations", &message);
            // compute the challenge for the next round
            let challenge = transcript.get_challenge::<F>(b"challenge");
            // Extract current randomness and fold the polynomials.
            prover.fold(challenge);

            // add the message to the final proof
            messages.push(message);
            challenges.push(challenge);
        }

        let rounds = prover.rounds();
        let final_foldings = vec![prover.final_foldings().unwrap()];
        // Add the final foldings to the transcript
        transcript.append_scalar(b"final-folding", &final_foldings[0][0]);
        transcript.append_scalar(b"final-folding", &final_foldings[0][1]);

        Sumcheck {
            messages,
            challenges,
            rounds,
            final_foldings,
        }
    }



    /// Prove function for a batch of scalar product instances.
    pub fn prove_batch<'a>(
        transcript: &mut Transcript,
        mut provers: Vec<Box<dyn Prover<F> + 'a>>,
    ) -> Sumcheck<F> {
        let rounds = provers.iter().map(|p| p.rounds()).fold(0, usize::max);
        let mut messages = Vec::with_capacity(rounds);
        let mut challenges = Vec::with_capacity(rounds);

        let coefficients = (0..provers.len())
            .map(|_| transcript.get_challenge::<F>(b"batch-sumcheck"))
            .collect::<Vec<_>>();

        for _ in 0..rounds {
            // obtain next messages from each of the provers
            let round_messages = provers.iter_mut().map(|p| p.next_message());
            // compute the non-oracle messagein the sumcheck:
            let message = round_messages
                .zip(coefficients.iter()) // take the combination of messages and coefficients
                .filter_map(|(m, c)| m.map(|m| m.mul(c))) // multiply them if there's an actual message
                .sum(); // finally, add them up.
            messages.push(message); // add the message sent to the transcript
            transcript.append_prover_message(b"evaluations", &message);
            // compute the challenge for the next round
            let challenge: F = transcript.get_challenge(b"challenge");
            challenges.push(challenge);
            // Extract current randomness and fold the polynomials.
            provers.iter_mut().for_each(|prover| prover.fold(challenge));
        }
        let final_foldings = provers
            .iter()
            .map(|p| {
                let final_folding = p.final_foldings().unwrap();
                transcript.append_scalar(b"final-folding-lhs", &final_folding[0]);
                transcript.append_scalar(b"final-folding-rhs", &final_folding[1]);
                final_folding
            })
            .collect::<Vec<_>>();
        Sumcheck {
            messages,
            challenges,
            rounds,
            final_foldings,
        }
    }

    /// Create a new Proof using the Time prover.
    pub fn new_time(transcript: &mut Transcript, f: &[F], g: &[F], twist: &F) -> Self {
        let witness = Witness::new(f, g, twist);
        let prover = TimeProver::new(witness);

        Self::prove(transcript, prover)
    }

    /// Construct a new Proof using the space prover.
    pub fn new_space<SF1, SF2>(transcript: &mut Transcript, f: SF1, g: SF2, twist: F) -> Self
    where
        SF1: Streamer,
        SF2: Streamer,
        SF1::Item: Borrow<F>,
        SF2::Item: Borrow<F>,
    {
        let prover = SpaceProver::new(f, g, twist);
        Self::prove(transcript, prover)
    }

    /// Construct a new Proof using the Elastic prover
    pub fn new_elastic<SF1, SF2>(transcript: &mut Transcript, f: SF1, g: SF2, twist: F) -> Self
    where
        SF1: Streamer,
        SF2: Streamer,
        SF1::Item: Borrow<F>,
        SF2::Item: Borrow<F>,
    {
        let prover = ElasticProver::new(f, g, twist);
        Self::prove(transcript, prover)
    }

    /// Return the prover's messages.
    pub fn prover_messages(&self) -> ProverMsgs<F> {
        ProverMsgs(self.messages.clone(), self.final_foldings.clone())
    }
}
