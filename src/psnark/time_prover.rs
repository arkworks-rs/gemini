use ark_ec::PairingEngine;
use ark_std::One;

use crate::circuit::{Matrix, R1CS};
use crate::kzg::time::CommitterKey;
use crate::misc::{hadamard, powers, product_matrix_vector, tensor};
use crate::sumcheck::proof::Sumcheck;
use crate::transcript::GeminiTranscript;

use crate::PROTOCOL_NAME;

use super::proof::Proof;

#[inline]
fn lookup<T: Copy>(v: &[T], index: &[usize]) -> Vec<T> {
    index.iter().map(|&i| v[i]).collect()
}

#[inline]
fn val<F: Copy>(m: &Matrix<F>) -> Vec<F> {
    m.iter()
        .map(|col| col.iter().map(|(elt, _i)| *elt))
        .flatten()
        .collect()
}

#[inline]
fn row<F>(m: &Matrix<F>) -> Vec<usize> {
    m.iter()
        .enumerate()
        .filter_map(|(i, row)| (!row.is_empty()).then(|| i))
        .collect()
}

#[inline]
fn col<F>(m: &Matrix<F>) -> Vec<usize> {
    m.iter()
        .map(|col| col.iter().map(|(_elt, i)| *i))
        .flatten()
        .collect()
}

pub fn prove_time<E>(r1cs: &R1CS<E::Fr>, _ck: &CommitterKey<E>) -> Proof<E>
where
    E: PairingEngine,
{
    let z_a = product_matrix_vector(&r1cs.a, &r1cs.z);
    let z_b = product_matrix_vector(&r1cs.b, &r1cs.z);

    let mut transcript = merlin::Transcript::new(PROTOCOL_NAME);
    // let _witness_commitment = ck.commit(&r1cs.w);

    let alpha = transcript.get_challenge(b"alpha");
    let first_proof =
        crate::sumcheck::proof::Sumcheck::new_time(&mut transcript, &z_a, &z_b, &alpha);

    let num_constraints = r1cs.z.len();
    let tensor_challenges = tensor(&first_proof.challenges);
    let alpha_powers = powers(alpha, num_constraints);

    let r_a = hadamard(&alpha_powers, &tensor_challenges);
    // let r_b = tensor_challenges;
    // let r_c = alpha_powers;

    let col_a = col(&r1cs.a);
    let row_a = row(&r1cs.a);
    let val_a = val(&r1cs.a);
    let z_a_star = lookup(&r1cs.z, &col_a);
    let r_a_star = lookup(&r_a, &row_a);
    let rz_a_star = hadamard(&z_a_star, &r_a_star);
    let _second_sumcheck1 = Sumcheck::new_time(&mut transcript, &val_a, &rz_a_star, &E::Fr::one());

    todo!()
}
