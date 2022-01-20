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
fn compute_lookup_vector_with_shift<F: Field>(v: &[F], gamma: &F, chi: &F, zeta: &F) -> Vec<F> {
    let mut res = Vec::new();
    let tmp = (F::one() + chi) * gamma;
    let mut prev = *v.last().unwrap() + F::from(v.len() as u64) * zeta;
    v.iter().enumerate().for_each(|(i, &e)| {
        let curr = e + F::from(i as u64) * zeta;
        res.push(tmp + curr + prev * chi);
        prev = curr
    });
    res
}

#[inline]
pub fn plookup<F: Field>(
    subset: &[F],
    set: &[F],
    index_f: &[F],
    index: &[usize],
    gamma: &F,
    chi: &F,
    zeta: &F,
) -> (Vec<Vec<F>>, Vec<F>) {
    let mut lookup_vec = Vec::new();

    // Compute the lookup vector for the subset
    let mut lookup_subset = Vec::new();
    subset.iter().zip(index_f.iter()).for_each(|(e, f)| {
        let x = *e + *zeta * f + gamma;
        lookup_subset.push(x);
    });
    lookup_vec.push(lookup_subset);

    // Compute the lookup vector for the set
    let lookup_set = compute_lookup_vector_with_shift(set, gamma, chi, zeta);
    lookup_vec.push(lookup_set);

    // Compute the sorted vector
    let mut frequency = vec![1; set.len()];
    index.iter().for_each(|i| frequency[*i] += 1);
    let mut sorted = Vec::new();
    frequency
        .iter()
        .zip(set.iter())
        .for_each(|(f, e)| sorted.append(&mut vec![*e; *f]));

    // Compute the lookup vector for the sorted vector
    let lookup_sorted = compute_lookup_vector_with_shift(&sorted, gamma, chi, zeta);
    lookup_vec.push(lookup_sorted);

    (lookup_vec, sorted)
}
