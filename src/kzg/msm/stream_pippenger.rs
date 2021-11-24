//! A space-efficient implementation of Pippenger's algorithm.
use std::ops::AddAssign;

use ark_ff::{BigInteger, PrimeField};
use ark_ff::{FpParameters, Zero};

use ark_ec::{AffineCurve, ProjectiveCurve};

use ark_std::borrow::Borrow;

use crate::stream::Streamer;

use super::{bounded_ln_without_floats, MAX_MSM_BUFFER};

pub fn msm<G, F, I, J>(bases_stream: J, scalars_stream: I) -> G::Projective
where
    G: AffineCurve,
    I: Streamer,
    F: PrimeField,
    I::Item: Borrow<F>,
    J: Streamer,
    J::Item: Borrow<G>,
{
    assert!(scalars_stream.len() <= bases_stream.len());

    // remove offset
    let mut bases = bases_stream.stream();
    let scalars = scalars_stream.stream();

    // align the streams
    bases
        .advance_by(bases_stream.len() - scalars_stream.len())
        .expect("bases not long enough");
    msm_internal(bases, scalars, scalars_stream.len())
}

pub fn msm_chunks<G, F, I, J>(bases_stream: J, scalars_stream: I) -> G::Projective
where
    G: AffineCurve<ScalarField = F>,
    I: Streamer,
    F: PrimeField,
    I::Item: Borrow<F>,
    J: Streamer,
    J::Item: Borrow<G>,
{
    assert!(scalars_stream.len() <= bases_stream.len());

    // remove offset
    let mut bases = bases_stream.stream();
    let mut scalars = scalars_stream.stream();

    // align the streams
    bases
        .advance_by(bases_stream.len() - scalars_stream.len())
        .expect("bases not long enough");
    let step: usize = 1 << 20;
    let mut result = G::Projective::zero();
    for _ in 0..(scalars_stream.len() + step - 1) / step {
        let bases_step = (&mut bases)
            .take(step)
            .map(|b| *b.borrow())
            .collect::<Vec<_>>();
        let scalars_step = (&mut scalars)
            .take(step)
            .map(|s| s.borrow().into_repr())
            .collect::<Vec<_>>();
        result.add_assign(ark_ec::msm::VariableBaseMSM::multi_scalar_mul(
            bases_step.as_slice(),
            scalars_step.as_slice(),
        ));
    }
    result
}

/// Add a chunk of bases and scalars into the multiscalar multiplication state.
/// XXX. Rust sometimes gets confused if I use G::ScalarField instead of F, so despite it's not really necessary I'm keeping the scalar field as a type parameter.
pub fn msm_internal<G, F, I, J>(bases: J, scalars: I, n: usize) -> G::Projective
where
    G: AffineCurve,
    I: IntoIterator,
    F: PrimeField,
    I::Item: Borrow<F>,
    J: IntoIterator,
    J::Item: Borrow<G>,
{
    let c = bounded_ln_without_floats(n);
    let num_bits = <G::ScalarField as PrimeField>::Params::MODULUS_BITS as usize;
    // split `num_bits` into steps of `c`, but skip window 0.
    let windows = (0..num_bits).step_by(c);
    let buckets_num = 1 << c;

    let mut window_buckets = Vec::with_capacity(windows.len());
    for window in windows {
        window_buckets.push((window, vec![G::Projective::zero(); buckets_num]));
    }

    for (scalar, base) in scalars.into_iter().zip(bases) {
        for (w, bucket) in window_buckets.iter_mut() {
            let mut scalar = scalar.borrow().into_repr();
            // We right-shift by `w`, thus getting rid of the lower bits.
            scalar.divn(*w as u32);
            // We mod the remaining bits by 2^{window size}, thus taking `c` bits.
            let scalar = scalar.as_ref()[0] % (1 << c);
            // If the scalar is non-zero, we update the corresponding bucket.
            // (Recall that `buckets` doesn't have a zero bucket.)
            if scalar != 0 {
                bucket[(scalar - 1) as usize].add_assign_mixed(base.borrow());
            }
        }
    }

    let mut window_sums = window_buckets.iter().rev().map(|(_w, bucket)| {
        // `running_sum` = sum_{j in i..num_buckets} bucket[j],
        // where we iterate backward from i = num_buckets to 0.
        let mut bucket_sum = G::Projective::zero();
        let mut bucket_running_sum = G::Projective::zero();
        bucket.iter().rev().for_each(|b| {
            bucket_running_sum += b;
            bucket_sum += &bucket_running_sum;
        });
        bucket_sum
    });

    // We're traversing windows from high to low.
    let first = window_sums.next().unwrap();
    window_sums.fold(first, |mut total, sum_i| {
        for _ in 0..c {
            total.double_in_place();
        }
        total + sum_i
    })
}

use hashbrown::HashMap;
//use ark_std::collections::HashMap;


pub struct HashMapPippenger<G: AffineCurve> {
    pub buffer: HashMap<G, G::ScalarField>,
    pub result: G::Projective,
}

impl<G: AffineCurve> HashMapPippenger<G> {
    pub fn new() -> Self {
        Self {
            buffer: HashMap::with_capacity(MAX_MSM_BUFFER),
            result: G::Projective::zero(),
        }
    }

    #[inline(always)]
    pub fn add<B, S>(&mut self, base: B, scalar: S)
    where
        B: Borrow<G>,
        S: Borrow<G::ScalarField>,
    {
        // update the entry, guarding the possibility that it has been already set.
        let entry = self
            .buffer
            .entry(*base.borrow())
            .or_insert(G::ScalarField::zero());
        *entry += *scalar.borrow();
        if self.buffer.len() == MAX_MSM_BUFFER {
            let bases = self.buffer.keys().cloned().collect::<Vec<_>>();
            let scalars = self
                .buffer
                .values()
                .map(|s| s.into_repr())
                .collect::<Vec<_>>();
            self.result
                .add_assign(ark_ec::msm::VariableBaseMSM::multi_scalar_mul(
                    &bases, &scalars,
                ));
            self.buffer.clear();
        }
    }

    #[inline(always)]
    pub fn finalize(mut self) -> G::Projective {
        if !self.buffer.is_empty() {
            let bases = self.buffer.keys().cloned().collect::<Vec<_>>();
            let scalars = self
                .buffer
                .values()
                .map(|s| s.into_repr())
                .collect::<Vec<_>>();

            self.result
                .add_assign(ark_ec::msm::VariableBaseMSM::multi_scalar_mul(
                    &bases, &scalars,
                ));
        }
        self.result
    }
}

pub struct ChunkedPippenger<G: AffineCurve> {
    pub scalars_buffer: Vec<<G::ScalarField as PrimeField>::BigInt>,
    pub bases_buffer: Vec<G>,
    pub result: G::Projective,
    pub buf_size: usize,
}

impl<G: AffineCurve> ChunkedPippenger<G> {
    pub fn new() -> Self {
        Self {
            scalars_buffer: Vec::with_capacity(MAX_MSM_BUFFER),
            bases_buffer: Vec::with_capacity(MAX_MSM_BUFFER),
            result: G::Projective::zero(),
            buf_size: MAX_MSM_BUFFER,
        }
    }
    pub fn with_size(buf_size: usize) -> Self {
        Self {
            scalars_buffer: Vec::with_capacity(buf_size),
            bases_buffer: Vec::with_capacity(buf_size),
            result: G::Projective::zero(),
            buf_size,
        }
    }

    #[inline(always)]
    pub fn add<B, S>(&mut self, base: B, scalar: S)
    where
        B: Borrow<G>,
        S: Borrow<<G::ScalarField as PrimeField>::BigInt>,
    {
        self.scalars_buffer.push(*scalar.borrow());
        self.bases_buffer.push(*base.borrow());
        if self.scalars_buffer.len() == self.buf_size {
            self.result
                .add_assign(ark_ec::msm::VariableBaseMSM::multi_scalar_mul(
                    self.bases_buffer.as_slice(),
                    self.scalars_buffer.as_slice(),
                ));
            self.scalars_buffer.clear();
            self.bases_buffer.clear();
        }
    }

    #[inline(always)]
    pub fn finalize(mut self) -> G::Projective {
        if !self.scalars_buffer.is_empty() {
            self.result
                .add_assign(ark_ec::msm::VariableBaseMSM::multi_scalar_mul(
                    self.bases_buffer.as_slice(),
                    self.scalars_buffer.as_slice(),
                ));
        }
        self.result
    }
}
/// A space-efficient multi-scalar multiplication algorithm that does not require
/// to hold in memory the entire vector of scalars and bases.
pub struct StreamPippenger<G: AffineCurve> {
    c: usize,
    window_buckets: Vec<(usize, Vec<G::Projective>)>,
}

impl<G: AffineCurve> StreamPippenger<G> {
    /// Prepare a multi-scalar multiplication.
    pub fn new(size: usize) -> Self {
        let num_bits = <G::ScalarField as PrimeField>::Params::MODULUS_BITS as usize;
        let c = bounded_ln_without_floats(size);
        // split `num_bits` into steps of `c`, but skip window 0.
        let windows = (0..num_bits).step_by(c);
        let buckets_num = 1 << c;

        let mut window_buckets = Vec::with_capacity(windows.len());
        for window in windows {
            window_buckets.push((window, vec![G::Projective::zero(); buckets_num]));
        }
        Self { c, window_buckets }
    }

    /// Add a new multiplication of scalar * base into the multi-scalar multiplication.
    #[inline]
    pub fn add<B, S>(&mut self, base: B, scalar: S)
    where
        S: Borrow<<G::ScalarField as PrimeField>::BigInt>,
        B: Borrow<G>,
    {
        for (w, bucket) in self.window_buckets.iter_mut() {
            let mut scalar = *scalar.borrow();
            // We right-shift by `w`, thus getting rid of the lower bits.
            scalar.divn(*w as u32);
            // We mod the remaining bits by 2^{window size}, thus taking `c` bits.
            let scalar = scalar.as_ref()[0] % (1 << self.c);
            // If the scalar is non-zero, we update the corresponding bucket.
            // (Recall that `buckets` doesn't have a zero bucket.)
            if scalar != 0 {
                bucket[(scalar - 1) as usize].add_assign_mixed(base.borrow());
            }
        }
    }

    /// Add a chunk of bases and scalars into the multiscalar multiplication state.
    pub fn add_chunk<I, J>(&mut self, bases: J, scalars: I)
    where
        I: IntoIterator,
        I::Item: Borrow<<G::ScalarField as PrimeField>::BigInt>,
        J: IntoIterator,
        J::Item: Borrow<G>,
    {
        for (scalar, base) in scalars.into_iter().zip(bases) {
            self.add(base, scalar)
        }
    }

    /// Output the result of the multi-scalar multiplication as performed so far.
    pub fn finalize(self) -> G::Projective {
        // Compute sum_{i in 0..num_buckets} (sum_{j in i..num_buckets} bucket[j])
        // This is computed below for b buckets, using 2b curve additions.
        let mut window_sums = self.window_buckets.iter().rev().map(|(_w, bucket)| {
            // `running_sum` = sum_{j in i..num_buckets} bucket[j],
            // where we iterate backward from i = num_buckets to 0.
            let mut bucket_sum = G::Projective::zero();
            let mut bucket_running_sum = G::Projective::zero();
            bucket.iter().rev().for_each(|b| {
                bucket_running_sum += b;
                bucket_sum += &bucket_running_sum;
            });
            bucket_sum
        });

        // We're traversing windows from high to low.
        let first = window_sums.next().unwrap();
        window_sums.fold(first, |mut total, sum_i| {
            for _ in 0..self.c {
                total.double_in_place();
            }
            total + sum_i
        })
    }
}

#[cfg(test)]
mod test {
    use crate::kzg::msm::ChunkedPippenger;

    use super::StreamPippenger;
    use ark_ec::{AffineCurve, ProjectiveCurve};
    use ark_ff::PrimeField;

    fn test_var_base_msm<G: AffineCurve>() {
        use ark_ec::msm::VariableBaseMSM;
        use ark_ff::UniformRand;

        const SAMPLES: usize = 1 << 2;

        let mut rng = ark_std::test_rng();

        let v = (0..SAMPLES)
            .map(|_| G::ScalarField::rand(&mut rng).into_repr())
            .collect::<Vec<_>>();
        let g = (0..SAMPLES)
            .map(|_| G::Projective::rand(&mut rng))
            .collect::<Vec<_>>();
        let g = <G::Projective as ProjectiveCurve>::batch_normalization_into_affine(&g);

        let arkworks = VariableBaseMSM::multi_scalar_mul(g.as_slice(), v.as_slice());

        let mut p = StreamPippenger::<G>::new(3);
        p.add_chunk(&g, v.into_iter());
        let mine = p.finalize();
        assert_eq!(arkworks.into_affine(), mine.into_affine());
    }

    fn test_chunked_pippenger<G: AffineCurve>() {
        use ark_ec::msm::VariableBaseMSM;
        use ark_ff::UniformRand;

        const SAMPLES: usize = 1 << 10;

        let mut rng = ark_std::test_rng();

        let v = (0..SAMPLES)
            .map(|_| G::ScalarField::rand(&mut rng).into_repr())
            .collect::<Vec<_>>();
        let g = (0..SAMPLES)
            .map(|_| G::Projective::rand(&mut rng))
            .collect::<Vec<_>>();
        let g = <G::Projective as ProjectiveCurve>::batch_normalization_into_affine(&g);

        let arkworks = VariableBaseMSM::multi_scalar_mul(g.as_slice(), v.as_slice());

        let mut p = ChunkedPippenger::<G>::new();
        for (s, g) in v.iter().zip(g) {
            p.add(g, s);
        }
        let mine = p.finalize();
        assert_eq!(arkworks.into_affine(), mine.into_affine());
    }

    #[test]
    fn test_var_base_msm_bls12() {
        test_var_base_msm::<ark_bls12_381::G1Affine>();

        test_chunked_pippenger::<ark_bls12_381::G1Affine>();
    }
}
