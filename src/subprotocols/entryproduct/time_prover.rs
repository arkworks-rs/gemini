use ark_ec::pairing::Pairing;
use ark_ff::Field;
use ark_std::boxed::Box;
use ark_std::vec::Vec;
use merlin::Transcript;

use super::{EntryProduct, ProverMsgs};
use crate::kzg::CommitterKey;
use crate::misc::evaluate_le;
use crate::subprotocols::sumcheck::time_prover::Witness;
use crate::subprotocols::sumcheck::{Prover, TimeProver};
use crate::transcript::GeminiTranscript;

/// Perform the right notation of a vector `v`.
pub(crate) fn right_rotation<T: Clone>(v: &[T]) -> Vec<T> {
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
pub(crate) fn accumulated_product<F: Field>(v: &[F]) -> Vec<F> {
    let mut acc_v = v
        .iter()
        .rev()
        .scan(F::one(), |state, elt| {
            *state *= elt;
            Some(*state)
        })
        .collect::<Vec<_>>();
    acc_v.reverse();
    acc_v
}

/// Given as input \\(f(x) \in \FF[x]\\) of degree \\(N\\)
/// represented as a vector of its coefficient (in little-endian),
/// return \\(f(x) + x^N\\).
pub(crate) fn monic<F: Field>(v: &[F]) -> Vec<F> {
    let mut monic_v = v.to_vec();
    monic_v.push(F::one());
    monic_v
}

impl<E: Pairing> EntryProduct<E, Box<dyn Prover<E::ScalarField>>> {
    /// Creates a new grand product argument using the time prover.
    ///
    /// # Panics
    /// If the length of the claimed products differs from the length of `vs`.
    pub fn new_time_batch(
        transcript: &mut Transcript,
        ck: &CommitterKey<E>,
        vs: &[Vec<E::ScalarField>],
        claimed_products: &[E::ScalarField],
    ) -> Self {
        assert_eq!(vs.len(), claimed_products.len());

        // XXX. we do not really need to store monic_vs, we can just extend every element of vs with 1.
        let monic_vs = vs.iter().map(|v| monic(v)).collect::<Vec<_>>();
        let rrot_vs = monic_vs
            .iter()
            .map(|v| right_rotation(v))
            .collect::<Vec<_>>();
        let acc_vs = monic_vs
            .iter()
            .map(|v| accumulated_product(v))
            .collect::<Vec<_>>();
        let acc_v_commitments = ck.batch_commit(&acc_vs);
        acc_v_commitments.iter().for_each(|acc_v_commitment| {
            transcript.append_serializable(b"acc_v", acc_v_commitment)
        });

        let chal = transcript.get_challenge::<E::ScalarField>(b"ep-chal");

        let provers = rrot_vs
            .iter()
            .zip(acc_vs.iter())
            .map(|(rrot_v, acc_v)| {
                let witness = Witness::new(acc_v, rrot_v, &chal);
                Box::new(TimeProver::new(witness)) as Box<dyn Prover<E::ScalarField>>
            })
            .collect::<Vec<_>>();
        let claimed_sumchecks = claimed_products
            .iter()
            .zip(acc_vs.iter())
            .map(|(cp, acc_v)| {
                let acc_v_chal = evaluate_le(acc_v, &chal);
                let chal_n = chal.pow(&[acc_v.len() as u64]);
                acc_v_chal * chal + cp - chal_n
            })
            .collect::<Vec<_>>();

        let msgs = ProverMsgs {
            acc_v_commitments,
            claimed_sumchecks,
        };

        EntryProduct {
            msgs,
            chal,
            provers,
        }
    }

    /// Creates a new grand product argument using the time prover.
    pub fn new_time(
        transcript: &mut Transcript,
        ck: &CommitterKey<E>,
        v: &[E::ScalarField],
        claimed_product: E::ScalarField,
    ) -> Self {
        let monic_v = monic(v);
        let rrot_v = right_rotation(&monic_v);
        let acc_v = accumulated_product(&monic_v);

        // the prover commits to rrot_v
        let acc_v_commitments = vec![ck.commit(&acc_v)];
        transcript.append_serializable(b"acc_v", &acc_v_commitments[0]);

        let chal = transcript.get_challenge::<E::ScalarField>(b"ep-chal");
        let claimed_sumchecks = vec![
            chal * evaluate_le(&acc_v, &chal) + claimed_product - chal.pow(&[acc_v.len() as u64]),
        ];

        let witness = Witness::new(&acc_v, &rrot_v, &chal);
        let provers = vec![Box::new(TimeProver::new(witness)) as Box<dyn Prover<E::ScalarField>>];
        let msgs = ProverMsgs {
            acc_v_commitments,
            claimed_sumchecks,
        };
        EntryProduct {
            msgs,
            chal,
            provers,
        }
    }
}
