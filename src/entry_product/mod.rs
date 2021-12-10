//! Implementation of entry product.
//!
//!
//!

use ark_ec::PairingEngine;
use ark_ff::Field;
use merlin::Transcript;
use crate::stream::Streamer;
use ark_std::borrow::Borrow;

use self::streams::ProductStream;
use self::streams::RightRotationStreamer;
use self::streams::entry_product_streams;

use crate::{
    kzg::{Commitment, CommitterKey, CommitterKeyStream},
    misc::{evaluate_be, evaluate_le},
    sumcheck::{time_prover::Witness, ElasticProver, SpaceProver, TimeProver},
    transcript::GeminiTranscript,
};

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
/// \[
/// (f_0 , f_1, f_2, \dots, f_i, \dots, f_{n-2}, f_{n-1} )
/// \]
/// return the vector \\(\vec g \in \FF^n\\) of the accumulated products:
/// \[
/// (f_0f_1\cdots f_{n-1} , f_1f_2\cdots f_{n-1}, \dots, \prod_{j \leq i }f_j, \dots, f_{n-2}f_{n-1}, f_{n-1})
/// \]
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

fn monic<F: Field>(v: &[F]) -> Vec<F> {
    let mut monic_v = v.to_vec();
    monic_v.push(F::one());
    monic_v
}

pub mod streams;

#[derive(Debug, PartialEq, Eq)]
pub struct ProverMsgs<E: PairingEngine> {
    acc_v_commitment: Commitment<E>,
    claimed_sumcheck: E::Fr,
}

pub fn ep_time<E: PairingEngine>(
    transcript: &mut Transcript,
    ck: &CommitterKey<E>,
    v: &[E::Fr],
    claimed_product: E::Fr,
) -> (ProverMsgs<E>, TimeProver<E::Fr>) {
    let monic_v = monic(v);
    let rrot_v = right_rotation(&monic_v);
    let acc_v = accumulated_product(&monic_v);

    // the prover commits to rrot_v
    let acc_v_commitment = ck.commit(&acc_v);
    transcript.append_commitment(b"acc_v", &acc_v_commitment);

    let chal = transcript.get_challenge::<E::Fr>(b"ep-chal");
    let claimed_sumcheck =
        chal * evaluate_le(&acc_v, &chal) + claimed_product - chal.pow(&[acc_v.len() as u64]);

    let witness = Witness::new(&rrot_v, &acc_v, &chal);
    let sumcheck_prover = TimeProver::new(witness);
    let prover_messages = ProverMsgs {
        acc_v_commitment,
        claimed_sumcheck,
    };
    (prover_messages, sumcheck_prover)
}


pub fn ep_elastic<'a, E, S, SG>(
    transcript: &mut Transcript,
    ck: &CommitterKeyStream<E, SG>,
    v: &'a S,
    claimed_product: E::Fr,
) -> (
    ProverMsgs<E>,
    ElasticProver<
        SpaceProver<E::Fr, RightRotationStreamer<'a, E::Fr, S>, ProductStream<'a, E::Fr, S>>,
        E::Fr,
    >,
)
where
    E: PairingEngine,
    S: Streamer<Item = E::Fr>,
    SG: Streamer,
    SG::Item: Borrow<E::G1Affine>,
{
    let (rrot_v, acc_v) = entry_product_streams(v);

    let acc_v_commitment = ck.commit(&acc_v);
    transcript.append_commitment(b"acc_v", &acc_v_commitment);

    let chal = transcript.get_challenge::<E::Fr>(b"ep-chal");
    let claimed_sumcheck = chal * evaluate_be(acc_v.stream(), &chal) + claimed_product
        - chal.pow(&[acc_v.len() as u64]);
    let sumcheck_prover: ElasticProver<SpaceProver<E::Fr, RightRotationStreamer<'_, E::Fr, S>, ProductStream<'_, E::Fr, S>>, E::Fr> = ElasticProver::new(rrot_v, acc_v, chal);
    let prover_messages = ProverMsgs {
        acc_v_commitment,
        claimed_sumcheck,
    };
    (prover_messages, sumcheck_prover)
}

#[test]
fn test_entry_product_relation() {
    use ark_bls12_381::Fr as F;
    use ark_ff::One;
    use ark_std::UniformRand;

    use crate::misc::{hadamard, powers, scalar_prod};

    let rng = &mut ark_std::test_rng();
    let n = 1000usize;
    let v = (0..n).map(|_| F::rand(rng)).collect::<Vec<_>>();
    let monic_v = monic(&v);
    let rrot_v = right_rotation(&monic_v);
    let acc_v = accumulated_product(&monic_v);
    let entry_product = monic_v.iter().product::<F>();
    let chal = F::one();
    let twist = powers(chal, rrot_v.len());
    let lhs = scalar_prod(&hadamard(&rrot_v, &twist), &acc_v);
    assert_eq!(
        lhs,
        chal * evaluate_le(&acc_v, &chal) + entry_product - chal.pow(&[acc_v.len() as u64])
    );
}

#[test]
fn test_entry_product_consistency() {
    use crate::stream::dummy::DummyStreamer;
    use ark_bls12_381::Bls12_381;
    use ark_bls12_381::Fr as F;
    use ark_std::UniformRand;

    let rng = &mut ark_std::test_rng();
    let n = 1000usize;
    let r = F::rand(rng);
    let v = std::iter::repeat(r).take(n).collect::<Vec<_>>();
    let v_stream = DummyStreamer::new(r, n);
    let product = v.iter().product::<F>();
    let ck = CommitterKey::<Bls12_381>::new(n + 1, 1, rng);
    let stream_ck = CommitterKeyStream::from(&ck);

    let time_transcript = &mut Transcript::new(b"test");
    let ep_time = ep_time(time_transcript, &ck, &v, product);
    let elastic_transcript = &mut Transcript::new(b"test");
    let ep_space = ep_elastic(elastic_transcript, &stream_ck, &v_stream, product);
    assert_eq!(ep_time.0, ep_space.0)
}
