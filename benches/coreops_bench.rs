#[macro_use]
extern crate criterion;
extern crate curve25519_dalek;
extern crate rand;

use ark_std::test_rng;
use ark_std::UniformRand;

use criterion::{BenchmarkId, Criterion};

use ark_bls12_381::Fr;
use ark_bls12_381::G1Projective;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::fields::PrimeField;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::OsRng;

fn bench_add(c: &mut Criterion) {
    let rng = &mut test_rng();
    let mut group = c.benchmark_group("add");

    group.bench_function(BenchmarkId::new("ark-bls12-381::Fr", 1), |b| {
        let first = Fr::rand(rng);
        let second = Fr::rand(rng);

        b.iter(|| first + second)
    });

    group.bench_function(BenchmarkId::new("curve25519_dalek::Scalar", 1), |b| {
        let first = Scalar::random(&mut OsRng);
        let second = Scalar::random(&mut OsRng);

        b.iter(|| first + second)
    });
}

fn bench_mul(c: &mut Criterion) {
    let rng = &mut test_rng();
    let mut group = c.benchmark_group("mul");

    group.bench_function(BenchmarkId::new("ark-bls12-381::Fr", 1), |b| {
        let first = Fr::rand(rng);
        let second = Fr::rand(rng);

        b.iter(|| first * second)
    });

    group.bench_function(BenchmarkId::new("curve25519_dalek::Scalar", 1), |b| {
        let first = Scalar::random(&mut OsRng);
        let second = Scalar::random(&mut OsRng);

        b.iter(|| first * second)
    });
}

fn bench_exp(c: &mut Criterion) {
    let rng = &mut OsRng;
    let mut group = c.benchmark_group("sm");

    group.bench_function(BenchmarkId::new("ark-bls12-381::G1", 1), |b| {
        let scalar = Fr::rand(&mut test_rng());
        let point = G1Projective::rand(&mut test_rng()).into_affine();

        b.iter(|| point.mul(scalar.into_bigint()))
    });

    group.bench_function(BenchmarkId::new("curve25519::RistrettoPoint", 1), |b| {
        let scalar = Scalar::random(rng);
        let point = RistrettoPoint::random(rng);

        b.iter(|| scalar * point)
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
