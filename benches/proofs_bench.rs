#[macro_use]
extern crate criterion;
extern crate merlin;

use criterion::{BenchmarkId, Criterion};

use ark_bls12_381::Fr;
use ark_ff::One;
use ark_poly::univariate::DensePolynomial;
use ark_poly::UVPolynomial;

use ark_gemini::subprotocols::sumcheck::proof::Sumcheck;

fn bench_sumcheck(c: &mut Criterion) {
    let mut group = c.benchmark_group("sumcheck");

    for d in 12..17 {
        group.bench_with_input(BenchmarkId::new("time", d), &d, |b, &d| {
            let rng = &mut ark_std::test_rng();

            b.iter(|| {
                let f = DensePolynomial::<Fr>::rand(1 << d, rng).coeffs;
                let g = DensePolynomial::<Fr>::rand(1 << d, rng).coeffs;
                let mut transcript = merlin::Transcript::new(b"LTAPS");
                Sumcheck::new_time(&mut transcript, &f, &g, &Fr::one());
            });
        });

        group.bench_with_input(BenchmarkId::new("space", d), &d, |b, &d| {
            let rng = &mut ark_std::test_rng();

            let f = DensePolynomial::<Fr>::rand(1 << d, rng);
            let g = DensePolynomial::<Fr>::rand(1 << d, rng);
            let mut f_rev = f.coeffs().to_vec();
            let mut g_rev = g.coeffs().to_vec();
            f_rev.reverse();
            g_rev.reverse();
            let f_stream = f_rev.as_slice();
            let g_stream = g_rev.as_slice();

            b.iter(|| {
                let mut transcript = merlin::Transcript::new(b"LTAPS");
                Sumcheck::new_space(&mut transcript, f_stream, g_stream, Fr::one());
            });
        });
    }
}

criterion_group! {
    name=proofs_benchmarks;
    config=Criterion::default();
    targets=
        bench_sumcheck,
}

criterion_main! {proofs_benchmarks}
