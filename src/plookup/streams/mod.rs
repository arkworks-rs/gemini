mod set_stream;
mod sorted_stream;
mod subset_stream;

use ark_ff::Field;
use ark_std::borrow::Borrow;
pub use set_stream::LookupSetStreamer;
pub use sorted_stream::LookupSortedStreamer;
pub use subset_stream::LookupSubsetStreamer;

use crate::iterable::Iterable;

/// Given a lookup instance of the form
/// `subset` (denoted \\(\vec f^*\\)),
///  `set` (denoted \\(\vec f\\) of length \\(n\\)),
/// and the `index` (denoted \\(I\\), whose entries are decreasing in `0..n`)
/// Return streams for the _entry product_ of the following terms:
/// - set: streaming for the vector \\((\f_i +  )\)
/// - subset: streaming for the vector \\(f_i^* + z\\)
/// - sorted: constructs \\(\vec w\\)
///   the merged vectors of \\((f^*, f)\\) and streams the vector \\(y(1+z) + w_i + z \cdot w_{i+1 \pmod{n}}\\)
pub fn plookup_streams<'a, SET, SUB, IND, F>(
    subset: &'a SUB,
    set: &'a SET,
    index: &'a IND,
    y: F,
    z: F,
) -> (
    LookupSetStreamer<'a, F, SET>,
    LookupSubsetStreamer<'a, F, SUB>,
    LookupSortedStreamer<'a, F, SET, IND>,
)
where
    F: Field,
    SET: Iterable,
    SET::Item: Borrow<F>,
    SUB: Iterable,
    SUB::Item: Borrow<F>,
    IND: Iterable<Item = usize>,
{
    let pl_set = LookupSetStreamer::new(set, y, z);
    let pl_subset = LookupSubsetStreamer::new(subset, y);
    let pl_sorted = LookupSortedStreamer::new(set, index, y, z);

    (pl_set, pl_subset, pl_sorted)
}

#[test]
fn test_consistency() {
    use super::time_prover::plookup_set;
    use ark_bls12_381::Fr as F;
    use ark_std::Zero;

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
    let y = F::from(0u64);
    let z = F::from(0u64);

    let set = plookup_set(&set, &y, &z, &F::zero());
    let mut set_stream = LookupSetStreamer::new(&&set[..], y, z)
        .iter()
        .collect::<Vec<_>>();
    set_stream.reverse();

    assert_eq!(set.len(), set_stream.len());
    assert_eq!(set.iter().product::<F>(), set_stream.iter().product::<F>());
}

#[test]
fn test_plookup_relation() {
    use crate::ark_std::UniformRand;
    use ark_bls12_381::Fr as F;
    use ark_ff::One;
    use ark_std::test_rng;

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

    let rng = &mut test_rng();
    let indices = [5, 3, 1, 0];
    let set_stream = &set[..];
    let subset_stream = &subset[..];
    let indices_stream = &indices[..];
    let y = F::rand(rng);
    let z = F::rand(rng);
    let pl_set = LookupSetStreamer::new(&set_stream, y, z);
    let pl_subset = LookupSubsetStreamer::new(&subset_stream, y);
    let pl_sorted = LookupSortedStreamer::new(&set_stream, &indices_stream, y, z);
    let entry_product_pl_set = pl_set.iter().product::<F>();
    let entry_product_pl_subset = pl_subset.iter().product::<F>();
    let entry_product_pl_merged = pl_sorted.iter().product::<F>();

    assert_eq!(
        entry_product_pl_merged,
        entry_product_pl_set * entry_product_pl_subset * (F::one() + z).pow(&[subset.len() as u64])
    );
}
