mod set_stream;
mod sorted_stream;
mod subset_stream;

use ark_ff::Field;
pub use set_stream::LookupSetStreamer;
pub use sorted_stream::LookupSortedStreamer;
pub use subset_stream::LookupSubsetStreamer;

use crate::stream::Streamer;

use super::entry_product::{entry_product_streams, ProductStream, RightRotationStreamer};

type Eps<F, S> = (RightRotationStreamer<F, S>, ProductStream<F, S>);

/// Given a lookup instance of the form
/// `subset` (denoted \\(\vec f^*\\)),
///  `set` (denoted \\(\vec f\\) of length \\(n\\)),
/// and the `index` (denoted \\(I\\), whose entries are decreasing in `0..n`)
/// Return streams for the _entry product_ of the following terms:
/// - set: streaming for the vector \\((\f_i +  )\)
/// - subset: streaming for the vector \\(f_i^* + z\\)
/// - sorted: constructs \\(\vec w\\)
///   the merged vectors of \\((f^*, f)\\) and streams the vector \\(y(1+z) + w_i + z \cdot w_{i+1 \pmod{n}}\\)
pub fn plookup_streams<SET, SUB, IND, F>(
    subset: SUB,
    set: SET,
    index: IND,
    y: F,
    z: F,
) -> (
    Eps<F, LookupSetStreamer<F, SET>>,
    Eps<F, LookupSubsetStreamer<F, SUB>>,
    Eps<F, LookupSortedStreamer<F, SET, IND>>,
)
where
    F: Field,
    SET: Streamer<Item = F>,
    SUB: Streamer<Item = F>,
    IND: Streamer<Item = usize>,
{
    let pl_set = LookupSetStreamer::new(set, y, z);
    let (sh_set, acc_set) = entry_product_streams(pl_set);
    let pl_subset = LookupSubsetStreamer::new(subset, z);
    let (sh_subset, acc_subset) = entry_product_streams(pl_subset);
    let pl_sorted = LookupSortedStreamer::new(set, index, y, z);
    let (sh_sorted, acc_sorted) = entry_product_streams(pl_sorted);

    (
        (sh_set, acc_set),
        (sh_subset, acc_subset),
        (sh_sorted, acc_sorted),
    )
}

#[test]
fn test_plookup_relation() {
    use ark_bls12_381::Fr as F;
    use ark_ff::One;
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
    let set_stream = &set[..];
    let subset_stream = &subset[..];
    let indices_stream = &indices[..];
    let y = F::zero();
    let z = F::zero();
    let pl_set = LookupSetStreamer::new(set_stream, y, z);
    let pl_subset = LookupSubsetStreamer::new(subset_stream, z);
    let pl_sorted = LookupSortedStreamer::new(set_stream, indices_stream, y, z);
    let entry_product_pl_set = pl_set.stream().fold(F::one(), |x, y| x * y);
    let entry_product_pl_subset = pl_subset.stream().fold(F::one(), |x, y| x * y);
    let entry_product_pl_merged = pl_sorted.stream().fold(F::one(), |x, y| x * y);

    assert_eq!(
        entry_product_pl_merged,
        entry_product_pl_set * entry_product_pl_subset * (F::one() + z).pow(&[set.len() as u64])
    );
}
