use ark_ff::Field;

#[inline]
pub fn lookup<T: Copy>(v: &[T], index: &Vec<usize>) -> Vec<T> {
    index.iter().map(|&i| v[i]).collect()
}

#[inline]
fn alg_hash<F: Field>(v: &[F], chal: &F) -> Vec<F> {
    v.iter()
        .enumerate()
        .map(|(i, &v_i)| v_i + F::from(i as u64) * chal)
        .collect()
}

pub(crate) fn plookup_set<F: Field>(v: &[F], y: &F, z: &F, zeta: &F) -> Vec<F> {
    let y1z = (F::one() + z) * y;
    let len = v.len();
    (0..len)
        .map(|i| y1z + v[i] * z + v[(i + len - 1) % len])
        .collect::<Vec<_>>()
}

fn plookup_subset<F: Field>(v: &[F], index: &[usize], y: &F, zeta: &F) -> Vec<F> {
    v.iter()
        .zip(index.iter())
        .map(|(e, f)| *e + *zeta * F::from(*f as u64) + y)
        .collect()
}

fn sorted<F: Field>(set: &[F], index: &[usize]) -> Vec<F> {
    let mut frequency = vec![1; set.len()];
    index.iter().for_each(|i| frequency[*i] += 1);
    frequency.reverse();
    let mut sorted = Vec::new();
    frequency
        .iter()
        .zip(set.iter())
        .for_each(|(f, e)| sorted.append(&mut vec![*e; *f]));
    sorted
}

pub fn plookup<F: Field>(
    subset: &[F],
    set: &[F],
    index: &[usize],
    y: &F,
    z: &F,
    zeta: &F,
) -> ([Vec<F>; 3], Vec<F>) {
    // let (set, subset) = if zeta != F::zero() {
    //     (alg_hash(set, zeta), alg_hash(subset, zeta))
    // } else {
    //     (set.to_vec(), subset.to_vec())
    // };

    let lookup_set = plookup_set(set, y, z, zeta);
    let lookup_subset = plookup_subset(subset, index, y, zeta);
    let sorted = sorted(set, index);
    let lookup_sorted = plookup_set(&sorted, y, z, zeta);
    ([lookup_set, lookup_subset, lookup_sorted], sorted)
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
    let y = F::from(47u64);
    let z = F::from(52u64);

    let (lookup_vec, _sorted) = plookup(&subset, &set, &indices, &y, &z, &F::zero());
    let prod_vec = [
        lookup_vec[0].iter().product::<F>(),
        lookup_vec[1].iter().product(),
        lookup_vec[2].iter().product(),
    ];
    assert_eq!(
        prod_vec[2],
        prod_vec[0] * prod_vec[1] * (F::one() + z).pow(&[subset.len() as u64])
    );
}
