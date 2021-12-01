use ark_bls12_381::Bls12_381;
use ark_std::test_rng;

use crate::circuit::{generate_relation, random_circuit, R1csStream};
use crate::kzg::space::CommitterKeyStream;
use crate::kzg::time::CommitterKey;
use crate::misc::matrix_into_row_major_slice;
use crate::misc::product_matrix_vector;
use crate::misc::{evaluate_be, matrix_into_col_major_slice};
use crate::snark::Proof;
use crate::stream::{Reversed, Streamer};

#[test]
fn test_ark_consistency() {
    let rng = &mut test_rng();
    let num_constraints = 8;
    let num_variables = 8;

    let circuit = random_circuit(rng, num_constraints, num_variables);
    let r1cs = generate_relation(circuit);
    let ck = CommitterKey::<Bls12_381>::new(num_constraints + num_variables, 3, rng);

    let z_a = product_matrix_vector(&r1cs.a, &r1cs.z);
    let z_b = product_matrix_vector(&r1cs.b, &r1cs.z);
    let z_c = product_matrix_vector(&r1cs.c, &r1cs.z);

    let n = z_a.len();

    let time_proof = Proof::new_time(&r1cs, &ck);

    let a_rowm = matrix_into_row_major_slice(&r1cs.a, n);
    let b_rowm = matrix_into_row_major_slice(&r1cs.b, n);
    let c_rowm = matrix_into_row_major_slice(&r1cs.c, n);
    let a_colm = matrix_into_col_major_slice(&r1cs.a, n);
    let b_colm = matrix_into_col_major_slice(&r1cs.b, n);
    let c_colm = matrix_into_col_major_slice(&r1cs.c, n);

    let r1cs_stream = R1csStream {
        z: Reversed::new(r1cs.z.as_slice()),
        a_rowm: a_rowm.as_slice(),
        b_rowm: b_rowm.as_slice(),
        c_rowm: c_rowm.as_slice(),
        a_colm: a_colm.as_slice(),
        b_colm: b_colm.as_slice(),
        c_colm: c_colm.as_slice(),
        witness: Reversed::new(r1cs.w.as_slice()),
        z_a: Reversed::new(z_a.as_slice()),
        z_b: Reversed::new(z_b.as_slice()),
        z_c: Reversed::new(z_c.as_slice()),
        nonzero: num_constraints,
    };
    let ck_stream = CommitterKeyStream::from(&ck);
    let space_proof = Proof::new_elastic(r1cs_stream, ck_stream);

    assert_eq!(
        time_proof.witness_commitment,
        space_proof.witness_commitment
    );

    assert_eq!(
        time_proof.first_sumcheck_msgs,
        space_proof.first_sumcheck_msgs
    );

    assert_eq!(time_proof.ra_a_z, space_proof.ra_a_z);

    assert_eq!(
        time_proof.second_sumcheck_msgs,
        space_proof.second_sumcheck_msgs
    );

    assert_eq!(time_proof.tensor_evaluation, space_proof.tensor_evaluation);

    assert_eq!(
        time_proof.tensor_check_proof.evaluation_proof.0,
        space_proof.tensor_check_proof.evaluation_proof.0,
    )
}

#[test]
fn test_ark_verify() {
    let rng = &mut test_rng();
    let num_constraints = 20;
    let num_variables = 20;

    let circuit = random_circuit(rng, num_constraints, num_variables);
    let r1cs = generate_relation(circuit);
    let ck = CommitterKey::<Bls12_381>::new(num_constraints + num_variables, 5, rng);
    let vk = (&ck).into();

    let time_proof = Proof::new_time(&r1cs, &ck);

    assert!(time_proof.verify(&r1cs, &vk).is_ok())
}

#[test]
fn test_relation() {
    use ark_bls12_381::Fr;
    use ark_ff::{One, Zero};
    use ark_std::test_rng;
    use ark_std::UniformRand;

    use crate::circuit::generate_relation;
    use crate::circuit::random_circuit;
    use crate::circuit::R1CS;
    use crate::misc::matrix_into_row_major_slice;
    use crate::misc::matrix_slice_naive;

    type F = Fr;

    let rng = &mut test_rng();
    let num_constraints = 1 << 13;
    let num_variables = 1 << 12;
    let circuit = random_circuit(rng, num_constraints, num_variables);

    let R1CS {
        a,
        b,
        c,
        z,
        w: _w,
        x: _,
    } = generate_relation(circuit);
    let mut z_a = vec![F::zero(); z.len()];

    for (row, elements) in a.iter().enumerate() {
        for &(val, col) in elements {
            z_a[row] += val * z[col];
        }
    }

    let mut z_b = vec![F::zero(); z.len()];
    for (row, elements) in b.iter().enumerate() {
        for &(val, col) in elements {
            z_b[row] += val * z[col];
        }
    }

    let mut z_c = vec![F::zero(); z.len()];
    for (row, elements) in c.iter().enumerate() {
        for &(val, col) in elements {
            z_c[row] += val * z[col];
        }
    }

    let aa_row_flat = matrix_into_row_major_slice(&a, z.len());

    let a_row_flat = matrix_slice_naive(&a, z.len());
    assert_eq!(
        a_row_flat
            .iter()
            .zip(&aa_row_flat)
            .filter(|&(x, y)| x != y)
            .count(),
        0
    );

    let mut z_stream = z.clone();

    assert_eq!(z_a[1] * z_b[1], z_c[1]);
    //  ok now we know that they are equal.
    z_a.reverse();
    z_b.reverse();
    z_c.reverse();
    z_stream.reverse();

    // receive alpha from the verifier
    let alpha = F::rand(rng);

    // prover: engage in the first sumcheck of z_a, z_b and z_c
    let _space_prover =
        crate::sumcheck::space_prover::SpaceProver::new(z_a.as_slice(), z_b.as_slice(), alpha);

    // verifier: send beta
    let beta = F::rand(rng);
    let mut acc = F::one();
    let beta_pows = (0..z.len())
        .map(|_| {
            let res = acc;
            acc *= beta;
            res
        })
        .collect::<Vec<_>>();

    let mut a_beta_expected = vec![F::zero(); z.len()];
    let mut aa = vec![vec![F::zero(); z.len()]; z.len()];
    for (row, elements) in a.iter().enumerate() {
        for &(val, col) in elements {
            aa[row][col] = val;
        }
    }
    for (i, row) in aa.iter().enumerate() {
        for (j, val) in row.iter().enumerate() {
            a_beta_expected[j] += *val * beta_pows[i];
        }
    }
    a_beta_expected.reverse();

    let expected_evaluation = a_beta_expected
        .iter()
        .zip(z_stream.as_slice().stream())
        .map(|(x, y)| *x * y)
        .sum();

    assert_eq!(evaluate_be(z_a.as_slice(), &beta), expected_evaluation);
}
