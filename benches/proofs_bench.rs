#[macro_use]
extern crate criterion;
extern crate merlin;

use ark_bls12_381::Fr;
use ark_ff::One;
use ark_poly::univariate::DensePolynomial;
use ark_poly::UVPolynomial;
use criterion::{BenchmarkId, Criterion};
use gemini::sumcheck::proof::Sumcheck;

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

// fn bench_ark(c: &mut Criterion) {
//     use ark_ff::Zero;
//     use gemini::circuit::random_circuit;

//     let mut group = c.benchmark_group("ark");

//     for d in 12..20 {
//         let rng = &mut ark_std::test_rng();
//         let num_constraints = 1 << d;
//         let num_variables = 1 << (d - 1);

//         let circuit = random_circuit(rng, num_constraints, num_variables);

//         let r1cs = generate_relation(circuit);
//         let time_ck = CommitterKey::<Bls12_381>::new(r1cs.z.len() + 1, 3, rng);
//         let space_ck = CommitterKeyStream::from(&time_ck);

//         group
//             .sample_size(10)
//             .bench_with_input(BenchmarkId::new("space", d), &d, |b, &_d| {
//                 let mut z_a = vec![Fr::zero(); r1cs.z.len()];

//                 for (row, elements) in r1cs.a.iter().enumerate() {
//                     for &(val, col) in elements {
//                         z_a[row] += val * r1cs.z[col];
//                     }
//                 }

//                 let mut z_b = vec![Fr::zero(); r1cs.z.len()];
//                 for (row, elements) in r1cs.b.iter().enumerate() {
//                     for &(val, col) in elements {
//                         z_b[row] += val * r1cs.z[col];
//                     }
//                 }

//                 let mut z_c = vec![Fr::zero(); r1cs.z.len()];
//                 for (row, elements) in r1cs.c.iter().enumerate() {
//                     for &(val, col) in elements {
//                         z_c[row] += val * r1cs.z[col];
//                     }
//                 }
//                 let a_rowm_flat = matrix_into_row_major_slice(&r1cs.a, r1cs.z.len());
//                 let b_rowm_flat = matrix_into_row_major_slice(&r1cs.b, r1cs.z.len());
//                 let c_rowm_flat = matrix_into_row_major_slice(&r1cs.c, r1cs.z.len());
//                 let a_colm_flat = matrix_into_col_major_slice(&r1cs.a, r1cs.z.len());
//                 let b_colm_flat = matrix_into_col_major_slice(&r1cs.b, r1cs.z.len());
//                 let c_colm_flat = matrix_into_col_major_slice(&r1cs.c, r1cs.z.len());

//                 let mut z_stream = r1cs.z.clone();
//                 // XXX this should be the witness
//                 let w_stream = r1cs.w.clone();

//                 z_a.reverse();
//                 z_b.reverse();
//                 z_stream.reverse();

//                 b.iter(|| {
//                     let r1cs_stream = R1CStream {
//                         a_rowm: &a_rowm_flat[..],
//                         b_rowm: &b_rowm_flat[..],
//                         c_rowm: &c_rowm_flat[..],
//                         a_colm: &a_colm_flat[..],
//                         b_colm: &b_colm_flat[..],
//                         c_colm: &c_colm_flat[..],
//                         z: &z_stream[..],
//                         witness: &w_stream[..],
//                         nonzero: num_constraints,
//                         z_a: &z_a[..],
//                         z_b: &z_b[..],
//                         z_c: &z_c[..],
//                     };
//                     let _proof = Proof::new_space(r1cs_stream, space_ck);
//                 });
//             });
//     }
// }

criterion_group! {
    name=proofs_benchmarks;
    config=Criterion::default();
    targets=
        bench_sumcheck,
}

criterion_main! {proofs_benchmarks}
