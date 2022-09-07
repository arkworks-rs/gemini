use ark_ff::Field;
use ark_std::borrow::Borrow;
use ark_std::vec::Vec;

#[inline]
pub fn lookup<T: Copy>(v: &[T], index: &[usize]) -> Vec<T> {
    index.iter().map(|&i| v[i]).collect()
}

#[inline]
pub(crate) fn alg_hash<F, J>(v: &[F], index: J, chal: &F) -> Vec<F>
where
    J: IntoIterator,
    J::Item: Borrow<usize>,
    F: Field,
{
    v.iter()
        .zip(index)
        .map(|(&v_i, i)| v_i + F::from(*i.borrow() as u64) * chal)
        .collect()
}

pub(crate) fn plookup_set<F: Field>(v: &[F], y: &F, &z: &F) -> Vec<F> {
    let y1z = (F::one() + z) * y;
    let len = v.len();
    if len == 0 {
        Vec::new()
    } else {
        let head = Some(y1z + z * v[0]).into_iter();
        let trunk = (0..len - 1).map(|i| y1z + v[i] + z * v[i + 1]);
        let last = Some(y1z + v[len - 1]);
        head.chain(trunk).chain(last).collect()
    }
}

#[test]
fn test_plookup_set_correct() {
    use crate::misc::evaluate_le;
    use ark_bls12_381::Fr as F;
    use ark_ff::One;
    use ark_std::test_rng;
    use ark_std::UniformRand;

    let rng = &mut test_rng();
    let set = (0..3).map(|_| F::rand(rng)).collect::<Vec<_>>();
    let y = F::rand(rng);
    let z = F::rand(rng);

    let pl_set = plookup_set(&set, &y, &z);
    // evaluate pl_set in a random point.
    let chal = F::rand(rng);
    let expected = evaluate_le(&pl_set, &chal);
    let y1z = (F::one() + z) * y;
    let chal_n = chal.pow(&[(set.len() + 1) as u64]);
    let first = y1z * (chal_n - F::one()) / (chal - F::one());
    let set_chal = evaluate_le(&set, &chal);
    let got = first + set_chal * (chal + z);
    assert_eq!(got, expected);
}

fn plookup_subset<F: Field>(v: &[F], y: &F) -> Vec<F> {
    v.iter().map(|e| *e + y).collect()
}

pub(crate) fn compute_frequency(set_len: usize, index: &[usize]) -> Vec<usize> {
    let mut frequency = vec![1; set_len];
    index.iter().for_each(|&i| frequency[i] += 1);
    frequency
}

pub(crate) fn extend_frequency(frequency: &[usize]) -> Vec<usize> {
    let mut res = Vec::new();
    frequency
        .iter()
        .enumerate()
        .for_each(|(i, f)| res.append(&mut vec![i; *f]));
    res
}

pub(crate) fn sorted<F: Field>(set: &[F], frequency: &[usize]) -> Vec<F> {
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
) -> [Vec<F>; 3] {
    let (set, subset) = if zeta != &F::zero() {
        (
            alg_hash(set, 0..set.len(), zeta),
            alg_hash(subset, index, zeta),
        )
    } else {
        (set.to_vec(), subset.to_vec())
    };

    let lookup_set = plookup_set(&set, y, z);
    let lookup_subset = plookup_subset(&subset, y);
    let frequency = compute_frequency(set.len(), index);
    let sorted = sorted(&set, &frequency);
    let lookup_sorted = plookup_set(&sorted, y, z);
    [lookup_set, lookup_subset, lookup_sorted]
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
    let indices = [0, 2, 4, 5];
    let y = F::from(47u64);
    let z = F::from(52u64);

    let lookup_vec = plookup(&subset, &set, &indices, &y, &z, &F::zero());
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
