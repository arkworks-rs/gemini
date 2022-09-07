#[macro_use]
extern crate criterion;
// extern crate curve25519_dalek;
extern crate rand;

use ark_std::test_rng;
use ark_std::UniformRand;

use criterion::{BenchmarkId, Criterion};

use ark_bls12_381::Fr;
use ark_bls12_381::G1Projective as G1;
use ark_ec::ProjectiveCurve;
use ark_ff::fields::PrimeField;


fn bench_add(c: &mut Criterion) {
    let rng = &mut test_rng();
    let mut group = c.benchmark_group("add");

    group.bench_function(BenchmarkId::new("ark-bls12-381::Fr", 1), |b| {
        let first = Fr::rand(rng);
        let second = Fr::rand(rng);

        b.iter(|| first + second)
    });

    // group.bench_function(BenchmarkId::new("curve25519_dalek::Scalar", 1), |b| {
    //     let first = Scalar::random(&mut OsRng);
    //     let second = Scalar::random(&mut OsRng);

    //     b.iter(|| first + second)
    // });
}

fn bench_mul(c: &mut Criterion) {
    let rng = &mut test_rng();
    let mut group = c.benchmark_group("mul");

    group.bench_function(BenchmarkId::new("ark-bls12-381::Fr", 1), |b| {
        let first = Fr::rand(rng);
        let second = Fr::rand(rng);

        b.iter(|| first * second)
    });

    // group.bench_function(BenchmarkId::new("curve25519_dalek::Scalar", 1), |b| {
    //     let first = Scalar::random(&mut OsRng);
    //     let second = Scalar::random(&mut OsRng);

    //     b.iter(|| first * second)
    // });
}

fn bench_exp(c: &mut Criterion) {
    // let rng = &mut OsRng;
    let mut group = c.benchmark_group("sm");

    group.bench_function(BenchmarkId::new("ark-bls12-381::G1", 1), |b| {
        let scalar = Fr::rand(&mut test_rng());
        let point = G1::rand(&mut test_rng());

        b.iter(|| point * scalar)
    });
}

criterion_group! {
    name=coreops_bench;
    config=Criterion::default();
    targets=
            bench_add,
            bench_mul,
            bench_exp,
}

criterion_main! {coreops_bench}
