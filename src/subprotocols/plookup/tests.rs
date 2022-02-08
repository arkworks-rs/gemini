use ark_bls12_381::Fr as F;
use ark_std::Zero;

use crate::iterable::Iterable;
use crate::subprotocols::plookup::{
    streams::{LookupSetStreamer, LookupSortedStreamer, LookupSubsetStreamer},
    time_prover::plookup,
};

#[test]
fn test_consistency() {
    let set = [
        F::from(10u64),
        F::from(12u64),
        F::from(13u64),
        F::from(14u64),
        F::from(15u64),
        F::from(42u64),
    ];
    let subset = [
        F::from(10u64),
        F::from(13u64),
        F::from(15u64),
        F::from(42u64),
    ];
    let indices = [5, 3, 1, 0];
    let indices_time = [0, 2, 4, 5];
    let y = F::from(0u64);
    let z = F::from(1u64);

    let lookup_vec = plookup(&subset, &set, &indices_time, &y, &z, &F::zero());
    let time_products = [
        lookup_vec[0].iter().product::<F>(),
        lookup_vec[1].iter().product(),
        lookup_vec[2].iter().product(),
    ];

    let set_stream = &set[..];
    let subset_stream = &subset[..];
    let indices_stream = &indices[..];
    let pl_set = LookupSetStreamer::new(&set_stream, y, z);
    let pl_subset = LookupSubsetStreamer::new(&subset_stream, y);
    let pl_sorted = LookupSortedStreamer::new(&set_stream, &indices_stream, y, z);
    let space_products = [
        pl_set.iter().product::<F>(),
        pl_subset.iter().product::<F>(),
        pl_sorted.iter().product::<F>(),
    ];

    assert_eq!(space_products[0], time_products[0]);
    // test sorted beforehand as it internally relies on the same sub-procedure as set.
    assert_eq!(space_products[2], time_products[2]);
    assert_eq!(space_products[1], time_products[1]);
}
