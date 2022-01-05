#[macro_use]
extern crate criterion;
extern crate merlin;

use ark_bls12_381::{Bls12_381, Fr};
use ark_poly::univariate::DensePolynomial;
use ark_poly::UVPolynomial;
use criterion::{BenchmarkId, Criterion};
use ark_gemini::kzg::CommitterKey;
use ark_gemini::kzg::CommitterKeyStream;

fn bench_commit(c: &mut Criterion) {
    let mut group = c.benchmark_group("commit");

    let rng = &mut ark_std::test_rng();
    let ck = CommitterKey::<Bls12_381>::new(1 << 22, 3, rng);
    let ck_stream = CommitterKeyStream::from(&ck);

    for d in 15..22 {
        group
            .sample_size(10)
            .bench_with_input(BenchmarkId::new("time", d), &d, |b, &d| {
                let rng = &mut ark_std::test_rng();
                let polynomial = DensePolynomial::rand(1 << d, rng);
                b.iter(|| ck.commit(&polynomial));
            });

        group
            .sample_size(10)
            .bench_with_input(BenchmarkId::new("space", d), &d, |b, &d| {
                let rng = &mut ark_std::test_rng();
                let polynomial = DensePolynomial::<Fr>::rand(1 << d, rng);
                let be_polynomial = polynomial
                    .coeffs()
                    .iter()
                    .rev()
                    .cloned()
                    .collect::<Vec<_>>();
                let polynomial_stream = be_polynomial.as_slice();
                b.iter(|| ck_stream.commit(&polynomial_stream));
            });
    }
}

criterion_group! {
    name=commit_benchmarks;
    config=Criterion::default();
    targets=
            bench_commit,
}

criterion_main! {commit_benchmarks}
