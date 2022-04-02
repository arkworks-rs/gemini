// env RAYON_NUM_THREADS=1 RUSTFLAGS="-C target_cpu=native" cargo +nightly bench --all-features
#[macro_use]
extern crate criterion;

use ark_bls12_381::{Bls12_381, Fr as BlsFr};
use ark_ff::PrimeField;
use ark_gemini::iterable::dummy::{dummy_r1cs_stream, DummyStreamer};
use ark_gemini::kzg::CommitterKeyStream;
use ark_gemini::misc::{joint_matrices, product_matrix_vector, sum_matrices};
use ark_gemini::psnark::Proof;
use ark_poly::univariate::DensePolynomial;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_std::ops::Range;
use ark_std::test_rng;
use ark_std::{ops::Mul, UniformRand};
use criterion::{black_box, BenchmarkId, Criterion};

const NUM_VERIFY_REPEATITIONS: usize = 50;

const NUM_DOMAIN_RANGE: Range<usize> = 12..21;

// const NUM_CONSTRAINTS: usize = 65536;
fn batch_verify_bench() {
    let mut rng = test_rng();

    for d in NUM_DOMAIN_RANGE {
        let size = 1 << d;

        let r1cs = ark_gemini::circuit::dummy_r1cs(&mut rng, size);
        let joint_matrix = sum_matrices(&r1cs.a, &r1cs.b, &r1cs.c, size);
        let (row, col, _row_index, _col_index, val_a, val_b, val_c) =
            joint_matrices(&joint_matrix, size, size, &r1cs.a, &r1cs.b, &r1cs.c);

        let ck = ark_gemini::kzg::CommitterKey::<ark_bls12_381::Bls12_381>::new(
            size + size + size,
            5,
            &mut rng,
        );
        let vk = (&ck).into();
        let index_comms = ck.batch_commit(&vec![row, col, val_a, val_b, val_c]);

        let proof = Proof::new_time(&r1cs, &ck);

        println!("Proof Size in Bytes: {}", proof.size_in_bytes());

        proof.verify(&r1cs, &vk, &index_comms, size);
    }
}

fn main() {
    batch_verify_bench();
}
