use ark_bls12_381::{Bls12_381, Fr as F};
use ark_ff::{Field, One};
use ark_std::vec::Vec;
use ark_std::UniformRand;
use merlin::Transcript;

use super::time_prover::{accumulated_product, monic, right_rotation};
use super::EntryProduct;
use crate::kzg::{CommitterKey, CommitterKeyStream};
use crate::misc::{evaluate_le, hadamard, ip, powers};

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
        chal * evaluate_le(&acc_v, &chal) + entry_product - chal.pow(&[n as u64])
    );
}

#[test]
fn test_entry_product_consistency() {
    let rng = &mut ark_std::test_rng();
    let n = 1000usize;
    let r = F::rand(rng);
    let v = ark_std::iter::repeat(r).take(n).collect::<Vec<_>>();
    let v_stream = DummyStreamer::new(r, n);
    let product = v.iter().product::<F>();
    let ck = CommitterKey::<Bls12_381>::new(n + 1, 1, rng);
    let stream_ck = CommitterKeyStream::from(&ck);

    let time_transcript = &mut Transcript::new(b"test");
    let ep_time = EntryProduct::new_time(time_transcript, &ck, &v, product);
    let elastic_transcript = &mut Transcript::new(b"test");
    let ep_space = EntryProduct::new_elastic(elastic_transcript, &stream_ck, &v_stream, product);
    assert_eq!(ep_time.msgs, ep_space.msgs)
}

#[test]
fn test_sumcheck_inputs_consistency() {
    use super::streams::{ProductStream, RightRotationStreamer};
    use crate::iterable::Iterable;
    use crate::iterable::Reversed;
    use ark_bls12_381::Fr as F;
    use ark_ff::UniformRand;
    use ark_std::test_rng;
    use ark_std::vec::Vec;
    use ark_std::One;

    let rng = &mut test_rng();
    let e = F::rand(rng);

    let vector = ark_std::iter::repeat(e).take(5).collect::<Vec<_>>();

    // time-efficient
    let monic_v = monic(&vector);
    let rrot_v = right_rotation(&monic_v);
    let acc_v = accumulated_product(&monic_v);

    // space-efficient
    let vector_stream = Reversed::new(&vector[..]);
    let mut rrot_v_stream = RightRotationStreamer::new(&vector_stream, &F::one())
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    let mut acc_v_stream = ProductStream::<F, _>::new(&vector_stream)
        .iter()
        .collect::<Vec<_>>();
    acc_v_stream.reverse();
    rrot_v_stream.reverse();

    assert_eq!(&acc_v_stream, &acc_v);
    assert_eq!(&rrot_v_stream, &rrot_v);
}
