//! Implementation of Peppinger's algorithm.
use ark_ec::{AffineRepr, Group};
use ark_ff::Zero;
use ark_ff::{BigInteger, PrimeField};
use ark_std::cmp::Ordering;
use ark_std::ops::AddAssign;
use ark_std::vec::Vec;

// #[cfg(feature = "parallel")]
// use rayon::prelude::*;

/// The result of this function is only approximately `ln(a)`
/// [`Explanation of usage`]
///
/// [`Explanation of usage`]: https://github.com/scipr-lab/zexe/issues/79#issue-556220473
fn ln_without_floats(a: usize) -> usize {
    // log2(a) * ln(2)
    (ark_std::log2(a) * 69 / 100) as usize
}

fn digits(a: &impl BigInteger, w: usize, num_bits: usize) -> Vec<i64> {
    let scalar = a.as_ref();
    let radix: u64 = 1 << w;
    let window_mask: u64 = radix - 1;

    let mut carry = 0u64;
    let num_bits = if num_bits == 0 {
        a.num_bits() as usize
    } else {
        num_bits
    };
    let digits_count = (num_bits + w - 1) / w;
    let mut digits = vec![0i64; digits_count];
    for (i, digit) in digits.iter_mut().enumerate() {
        // Construct a buffer of bits of the scalar, starting at `bit_offset`.
        let bit_offset = i * w;
        let u64_idx = bit_offset / 64;
        let bit_idx = bit_offset % 64;
        // Read the bits from the scalar
        let bit_buf: u64;
        if bit_idx < 64 - w || u64_idx == scalar.len() - 1 {
            // This window's bits are contained in a single u64,
            // or it's the last u64 anyway.
            bit_buf = scalar[u64_idx] >> bit_idx;
        } else {
            // Combine the current u64's bits with the bits from the next u64
            bit_buf = (scalar[u64_idx] >> bit_idx) | (scalar[1 + u64_idx] << (64 - bit_idx));
        }

        // Read the actual coefficient value from the window
        let coef = carry + (bit_buf & window_mask); // coef = [0, 2^r)

        // Recenter coefficients from [0,2^w) to [-2^w/2, 2^w/2)
        carry = (coef + radix / 2) >> w;
        *digit = (coef as i64) - (carry << w) as i64;
    }

    digits[digits_count - 1] += (carry << w) as i64;

    digits
}

#[test]
fn test_radix() {
    use ark_bls12_381::Fr;
    use ark_ff::One;
    use ark_std::test_rng;
    use ark_std::UniformRand;

    let w = 3;

    let rng = &mut test_rng();
    let scalar = Fr::rand(rng);
    let digits = digits(&scalar.into_bigint(), w, 0);

    let radix = Fr::from(1 << w);
    let mut term = Fr::one();
    let mut recovered_scalar = Fr::zero();
    for digit in &digits {
        let digit = *digit;
        if digit != 0 {
            let sdigit = if digit < 0 {
                -Fr::from((-digit) as u64)
            } else {
                Fr::from(digit as u64)
            };
            recovered_scalar += term * sdigit;
        }
        term *= radix;
    }
    // When the input is unreduced, we may only recover the scalar mod l.
    assert_eq!(recovered_scalar, scalar);
}
/// An object that does not need to be here but that allows for performing multi-scalar multiplication.
pub struct VariableBaseMSM;

impl VariableBaseMSM {
    /// Multi-scalar multiplciaiton of bases and scalars.
    pub fn multi_scalar_mul<G: AffineRepr>(
        bases: &[G],
        scalars: &[<G::ScalarField as PrimeField>::BigInt],
    ) -> G::Group {
        let size = scalars.len();

        let c = if size < 32 {
            3
        } else {
            ln_without_floats(size) + 2
        };

        let num_bits = <G::ScalarField as PrimeField>::MODULUS_BIT_SIZE as usize;
        let digits_count = (num_bits + c - 1) / c;

        let scalar_digits = scalars
            .iter()
            .map(|s| digits(s, c, num_bits))
            .collect::<Vec<_>>();

        let zero = G::Group::zero();

        // Each window is of size `c`.
        // We divide up the bits 0..num_bits into windows of size `c`, and
        // in parallel process each such window.

        let mut window_sums = (0..digits_count)
            .map(|i| {
                // We only have 2 ^ (c-1) buckets.
                let mut buckets = vec![zero; 1 << c];
                // This clone is cheap, because the iterator contains just a
                // pointer and an index into the original vectors.
                for (digits, base) in scalar_digits.iter().zip(bases) {
                    let scalar = digits[i];
                    match scalar.cmp(&0) {
                        Ordering::Greater => buckets[(scalar - 1) as usize].add_assign(base),
                        Ordering::Less => {
                            let basem = -base.into_group();
                            buckets[(-scalar - 1) as usize].add_assign(&basem);
                        }
                        Ordering::Equal => (),
                    }
                }
                // Compute sum_{i in 0..num_buckets} (sum_{j in i..num_buckets} bucket[j])
                // This is computed below for b buckets, using 2b curve additions.
                //
                // We could first normalize `buckets` and then use mixed-addition
                // here, but that's slower for the kinds of groups we care about
                // (Short Weierstrass curves and Twisted Edwards curves).
                // In the case of Short Weierstrass curves,
                // mixed addition saves ~4 field multiplications per addition.
                // However normalization (with the inversion batched) takes ~6
                // field multiplications per element,
                // hence batch normalization is a slowdown.

                // `running_sum` = sum_{j in i..num_buckets} bucket[j],
                // where we iterate backward from i = num_buckets to 0.
                let buckets = buckets.into_iter();
                let mut running_sum = G::Group::zero();

                let mut res = zero;
                buckets.into_iter().rev().for_each(|b| {
                    running_sum += &b;
                    res += &running_sum;
                });
                res
            })
            .rev();

        // We're traversing windows from high to low.
        let first = window_sums.next().unwrap();
        window_sums.fold(first, |mut total, sum_i| {
            for _ in 0..c {
                total.double_in_place();
            }
            total + sum_i
        })
    }
}

#[test]
fn test_var_base_msm() {
    use ark_ec::CurveGroup;
    use ark_ff::{One, PrimeField, UniformRand, Zero};

    fn naive_var_base_msm<G: AffineRepr>(
        bases: &[G],
        scalars: &[<G::ScalarField as PrimeField>::BigInt],
    ) -> G::Group {
        let mut acc = G::Group::zero();

        for (base, scalar) in bases.iter().zip(scalars.iter()) {
            acc += &base.mul_bigint(*scalar);
        }
        acc
    }

    const SAMPLES: usize = 1 << 10;
    use ark_bls12_381::{Fr, G1Projective};

    let mut rng = ark_std::test_rng();

    let mut v = (0..SAMPLES)
        .map(|_| Fr::rand(&mut rng).into_bigint())
        .collect::<Vec<_>>();
    v.push(Fr::one().into_bigint());
    let g = (0..SAMPLES + 1)
        .map(|_| G1Projective::rand(&mut rng))
        .collect::<Vec<_>>();

    let g = <G1Projective as CurveGroup>::normalize_batch(&g);

    let naive = naive_var_base_msm(g.as_slice(), v.as_slice());
    let fast = VariableBaseMSM::multi_scalar_mul(g.as_slice(), v.as_slice());

    assert_eq!(naive.into_affine(), fast.into_affine());
}
