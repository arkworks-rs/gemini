use crate::misc::compute_entry_prod;
use ark_ff::Field;

#[inline]
pub fn lookup<T: Copy>(v: &[T], index: &Vec<usize>) -> Vec<T> {
    index.iter().map(|&i| v[i]).collect()
}

#[inline]
fn alg_hash<F: Field>(v: &[F], w: &[F], chal: &F) -> Vec<F> {
    assert_eq!(v.len(), w.len());
    v.iter()
        .zip(w)
        .map(|(&v_i, &w_i)| v_i + w_i * chal)
        .collect()
}

#[inline]
fn compute_lookup_vector_with_shift<F: Field>(v: &[F], y: &F, z: &F, zeta: &F) -> Vec<F> {
    let mut res = Vec::new();
    let tmp = (F::one() + z) * y;
    let mut prev = *v.last().unwrap() + F::from(v.len() as u64) * zeta;
    v.iter().enumerate().for_each(|(i, &e)| {
        let curr = e + F::from(i as u64) * zeta;
        res.push(tmp + curr + prev * z);
        prev = curr
    });
    res
}

#[inline]
pub fn plookup<F: Field>(
    subset: &[F],
    set: &[F],
    index: &[usize],
    y: &F,
    z: &F,
    zeta: &F,
) -> (Vec<Vec<F>>, Vec<F>) {
    let mut lookup_vec = Vec::new();

    // Compute the lookup vector for the subset
    let mut lookup_subset = Vec::new();
    subset.iter().zip(index.iter()).for_each(|(e, f)| {
        let x = *e + *zeta * F::from(*f as u64) + y;
        lookup_subset.push(x);
    });

    // Compute the lookup vector for the set
    let lookup_set = compute_lookup_vector_with_shift(set, y, z, zeta);

    // Compute the sorted vector
    let mut frequency = vec![1; set.len()];
    index.iter().for_each(|i| frequency[*i] += 1);
    frequency.reverse();
    let mut sorted = Vec::new();
    frequency
        .iter()
        .zip(set.iter())
        .for_each(|(f, e)| sorted.append(&mut vec![*e; *f]));

    // Compute the lookup vector for the sorted vector
    let lookup_sorted = compute_lookup_vector_with_shift(&sorted, y, z, zeta);
    lookup_vec.push(lookup_set);
    lookup_vec.push(lookup_subset);
    lookup_vec.push(lookup_sorted);

    (lookup_vec, sorted)
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

    let (lookup_vec, sorted) = plookup(&subset, &set, &indices, &y, &z, &F::zero());
    let (accumulated_vec, prod_vec) = compute_entry_prod(&lookup_vec);
    assert_eq!(
        prod_vec[2],
        prod_vec[0] * prod_vec[1] * (F::one() + z).pow(&[subset.len() as u64])
    );
}
