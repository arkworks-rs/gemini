use ark_ff::{Field, One};
use ark_std::vec::Vec;
use ark_bls12_381::{Bls12_381, Fr as F};
use ark_std::UniformRand;

use merlin::Transcript;

use super::time_prover::{accumulated_product, right_rotation, monic};
use super::EntryProduct;
use crate::kzg::{CommitterKeyStream, CommitterKey};
use crate::misc::{evaluate_le, hadamard, powers, ip};
use crate::iterable::dummy::DummyStreamer;


#[test]
fn test_entry_product_relation() {
    let rng = &mut ark_std::test_rng();
    let n = 1000usize;
    let v = (0..n).map(|_| F::rand(rng)).collect::<Vec<_>>();
    let monic_v = monic(&v);
    let rrot_v = right_rotation(&monic_v);
    let acc_v = accumulated_product(&monic_v);
    let entry_product = monic_v.iter().product::<F>();
    let chal = F::one();
    let twist = powers(chal, rrot_v.len());
    let lhs = ip(&hadamard(&rrot_v, &twist), &acc_v);
    assert_eq!(
        lhs,
        chal * evaluate_le(&acc_v, &chal) + entry_product - chal.pow(&[acc_v.len() as u64])
    );
}

// #[test]
// fn test_entry_product_consistency() {
//     let rng = &mut ark_std::test_rng();
//     let n = 1000usize;
//     let r = F::rand(rng);
//     let v = ark_std::iter::repeat(r).take(n).collect::<Vec<_>>();
//     let v_stream = DummyStreamer::new(r, n);
//     let product = v.iter().product::<F>();
//     let ck = CommitterKey::<Bls12_381>::new(n + 1, 1, rng);
//     let stream_ck = CommitterKeyStream::from(&ck);

//     let time_transcript = &mut Transcript::new(b"test");
//     let ep_time = EntryProduct::new_time(time_transcript, &ck, &v, product);
//     let elastic_transcript = &mut Transcript::new(b"test");
//     let ep_space = EntryProduct::new_elastic(elastic_transcript, &stream_ck, &v_stream, product);
//     assert_eq!(ep_time.msgs, ep_space.msgs)
// }

