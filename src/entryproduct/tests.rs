
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
    let ep_time = EntryProduct::new_time(time_transcript, &ck, &v, product);
    let elastic_transcript = &mut Transcript::new(b"test");
    let ep_space = EntryProduct::new_elastic(elastic_transcript, &stream_ck, &v_stream, product);
    assert_eq!(ep_time.msgs, ep_space.msgs)
}

