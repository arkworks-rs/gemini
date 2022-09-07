#[macro_use]
extern crate criterion;

use ark_ec::msm::VariableBaseMSM as ArkworksMSM;
use ark_ec::ProjectiveCurve;
use ark_std::test_rng;
use ark_std::UniformRand;
use criterion::{BenchmarkId, Criterion};

// use curve25519_dalek::ristretto::RistrettoPoint;
// use curve25519_dalek::scalar::Scalar;
// use curve25519_dalek::traits::MultiscalarMul;

use ark_bls12_381::G1Projective;

fn bench_msm(c: &mut Criterion) {
    let rng = &mut test_rng();

    let mut group = c.benchmark_group("msm");
    for d in 12..17 {
        let size = 1 << d;
        let scalars = (0..size)
            .map(|_| ark_bls12_381::Fr::rand(rng))
            .collect::<Vec<_>>();
        let bases = (0..size)
            .map(|_| ark_bls12_381::G1::rand(rng).into_affine())
            .collect::<Vec<_>>();

        group
            .sample_size(10)
            .bench_with_input(BenchmarkId::new("arkworks", d), &d, |b, _| {
                b.iter(|| G1Projective::msm(&bases, &scalars))
            });

        // group
        //     .sample_size(10)
        //     .bench_with_input(BenchmarkId::new("chunks", d), &d, |b, _| {
        //         b.iter(|| msm_chunks::<G1Affine, F, _, _>(&bases.as_slice(), &scalars.as_slice()))
        //     });

        // group.bench_with_input(BenchmarkId::new("dalek", d), &d, |b, &d| {
        //     let size = 1 << d;
        //     let scalars = (0..size)
        //         .map(|_| Scalar::random(&mut OsRng))
        //         .collect::<Vec<_>>();
        //     let bases = (0..size)
        //         .map(|_| RistrettoPoint::random(&mut OsRng))
        //         .collect::<Vec<_>>();
        //     b.iter(|| RistrettoPoint::multiscalar_mul(scalars.iter(), bases.iter()))
        // });
    }
}

criterion_group! {
    name=msm_benchmarks;
    config=Criterion::default();
    targets=bench_msm,
}

criterion_main! {msm_benchmarks}
