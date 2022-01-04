use ark_ec::PairingEngine;
use ark_ff::Field;
use merlin::Transcript;

use super::{EntryProduct, ProverMsgs};
use crate::misc::evaluate_le;
use crate::sumcheck::time_prover::Witness;
use crate::transcript::GeminiTranscript;
use crate::{kzg::CommitterKey, sumcheck::TimeProver};

/// Perform the right notation of a vector `v`.
fn right_rotation<T: Clone>(v: &[T]) -> Vec<T> {
    match v.split_last() {
        Some((head, tail)) => {
            let mut rrot_v = vec![head.clone()];
            rrot_v.extend_from_slice(tail);
            rrot_v
        }
        None => vec![],
    }
}

/// Given as input a vector  \\(\vec f \in \FF^n\\) of the form:
/// \\[
/// (f_0 , f_1, f_2, \dots, f_i, \dots, f_{n-2}, f_{n-1} )
/// \\]
/// return the vector \\(\vec g \in \FF^n\\) of the accumulated products:
/// \\[
/// (f_0f_1\cdots f_{n-1} , f_1f_2\cdots f_{n-1}, \dots, \prod_{j \leq i }f_j, \dots, f_{n-2}f_{n-1}, f_{n-1})
/// \\]
fn accumulated_product<F: Field>(v: &[F]) -> Vec<F> {
    let mut acc_v = v
        .iter()
        .rev()
        .scan(F::one(), |state, elt| {
            *state = *state * elt;
            Some(*state)
        })
        .collect::<Vec<_>>();
    acc_v.reverse();
    acc_v
}

/// Given as input \\(f(x) \in \FF[x]\\) of degree \\(N\\)
/// represented as a vector of its coefficient (in little-endian),
/// return \\(f(x) + x^N\\).
fn monic<F: Field>(v: &[F]) -> Vec<F> {
    let mut monic_v = v.to_vec();
    monic_v.push(F::one());
    monic_v
}

impl<E: PairingEngine> EntryProduct<E, TimeProver<E::Fr>> {
    /// Creates a new grand product argument using the time prover.
    pub fn new_time(
        transcript: &mut Transcript,
        ck: &CommitterKey<E>,
        v: &[E::Fr],
        claimed_product: E::Fr,
    ) -> Self {
        let monic_v = monic(v);
        let rrot_v = right_rotation(&monic_v);
        let acc_v = accumulated_product(&monic_v);

        // the prover commits to rrot_v
        let acc_v_commitments = vec![ck.commit(&acc_v)];
        transcript.append_commitment(b"acc_v", &acc_v_commitments[0]);

        let chal = transcript.get_challenge::<E::Fr>(b"ep-chal");
        let claimed_sumchecks = vec![
            chal * evaluate_le(&acc_v, &chal) + claimed_product - chal.pow(&[acc_v.len() as u64]),
        ];

        let witness = Witness::new(&rrot_v, &acc_v, &chal);
        let provers = vec![TimeProver::new(witness)];
        let msgs = ProverMsgs {
            acc_v_commitments,
            claimed_sumchecks,
        };
        EntryProduct { msgs, chal, provers }
    }
}
