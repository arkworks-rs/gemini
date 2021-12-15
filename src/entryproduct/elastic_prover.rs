use ark_ec::PairingEngine;
use ark_ff::Field;
use ark_std::borrow::Borrow;
use ark_std::One;
use merlin::Transcript;

use crate::kzg::CommitterKeyStream;
use crate::misc::evaluate_be;
use crate::stream::Streamer;
use crate::sumcheck::{ElasticProver, Prover, SpaceProver, TimeProver};

use super::streams::{entry_product_streams, ProductStream, RightRotationStreamer};
use super::{EntryProduct, ProverMsgs};
use crate::transcript::GeminiTranscript;

impl<'a, E: PairingEngine, S: Streamer<Item = E::Fr>>
    EntryProduct<
        E,
        ElasticProver<
            SpaceProver<E::Fr, RightRotationStreamer<'a, E::Fr, S>, ProductStream<'a, E::Fr, S>>,
            TimeProver<E::Fr>,
        >,
    >
{
    /// Create a new (single) entry product arugment
    /// using the commiter key `ck` and the stream `v`, whose grand product is `claimed_product`.
    pub fn new_elastic<SG>(
        transcript: &mut Transcript,
        ck: &CommitterKeyStream<E, SG>,
        v: &'a S,
        claimed_product: E::Fr,
    ) -> Self
    where
        SG: Streamer,
        SG::Item: Borrow<E::G1Affine>,
    {
        let (rrot_v, acc_v) = entry_product_streams(v);

        let acc_v_commitments = vec![ck.commit(&acc_v)];
        transcript.append_commitment(b"acc_v", &acc_v_commitments[0]);

        let chal = transcript.get_challenge::<E::Fr>(b"ep-chal");
        let claimed_sumchecks = vec![
            chal * evaluate_be(acc_v.stream(), &chal) + claimed_product
                - chal.pow(&[acc_v.len() as u64]),
        ];
        let provers = vec![ElasticProver::new(rrot_v, acc_v, chal)];
        let msgs = ProverMsgs {
            acc_v_commitments,
            claimed_sumchecks,
        };
        EntryProduct { provers, msgs }
    }
}

#[inline]
fn sumcheck_subclaim<F, S>(claimed_product: &F, acc_v: &S, chal: &F) -> F
where
    F: Field,
    S: Streamer<Item = F>,
{
    let acc_v_chal = evaluate_be(acc_v.stream(), &chal);
    let chal_n = chal.pow(&[acc_v.len() as u64]);
    acc_v_chal * chal + claimed_product - chal_n
}

macro_rules! impl_elastic_batch {
    ($name: ident; $($B:ident), *) => {
        #[allow(non_snake_case)]
        #[allow(unused_assignments)]
        pub fn $name<SG, $($B),*>(
            transcript: &mut Transcript,
            ck: &CommitterKeyStream<E, SG>,
            vs: ($(&'a $B,)*),
            claimed_products: &[E::Fr],
        ) -> Self
        where
            SG: Streamer,
            SG::Item: Borrow<E::G1Affine>,
            $(
                $B: crate::stream::Streamer<Item=E::Fr>,
            )*

        {
            let ($($B,)*) = vs;
            let mut acc_v_commitments = Vec::new();
            $(
                let acc_v = ProductStream::new($B);
                let acc_v_commitment = ck.commit(&acc_v);
                transcript.append_commitment(b"acc_v", &acc_v_commitment);
                acc_v_commitments.push(acc_v_commitment);
            )*

            let chal = transcript.get_challenge::<E::Fr>(b"ep-chal");

            let mut claimed_sumchecks = vec![];
            let mut provers = Vec::<Box<dyn Prover<E::Fr> + 'a>>::new();
            let mut claimed_products_it = claimed_products.into_iter();

            $(
                let rrot_v = RightRotationStreamer::new($B, E::Fr::one());
                let acc_v = ProductStream::new($B);
                let claimed_product = claimed_products_it.next().expect("mismatch in claimed prod len");
                let claimed_sumcheck = sumcheck_subclaim(claimed_product, &acc_v, &chal);

                claimed_sumchecks.push(claimed_sumcheck);
                let sumcheck_prover = ElasticProver::new(rrot_v, acc_v, chal);
                provers.push(Box::new(sumcheck_prover));
            )*

            let msgs = ProverMsgs {
                acc_v_commitments,
                claimed_sumchecks

            };
            EntryProduct { msgs, provers }
        }
    };
}

impl<'a, E: PairingEngine> EntryProduct<E, Box<dyn Prover<E::Fr> + 'a>> {
    // lets gooooo
    // impl_elastic_batch!(A0, A1, A2);
    // impl_elastic_batch!(A0, A1, A2, A3);
    // impl_elastic_batch!(A0, A1, A2, A3, A4);
    // impl_elastic_batch!(A0, A1, A2, A3, A4, A5);
    // impl_elastic_batch!(A0, A1, A2, A3, A4, A5, A6);
    // impl_elastic_batch!(A0, A1, A2, A3, A4, A5, A6, A7);
    impl_elastic_batch!(new_elastic_batch; A0, A1, A2, A3, A4, A5, A6, A7, A8);
}
