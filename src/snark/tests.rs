use ark_bls12_381::Bls12_381;
use ark_std::test_rng;

use crate::circuit::matrix_into_colmaj;
use crate::circuit::matrix_into_rowmaj;
use crate::circuit::{generate_relation, random_circuit, R1csStream};
use crate::iterable::Reverse;
use crate::kzg::CommitterKey;
use crate::kzg::CommitterKeyStream;
use crate::misc::product_matrix_vector;
use crate::snark::Proof;

#[test]
fn test_snark_consistency() {
    let rng = &mut test_rng();
    let num_constraints = 8;
    let num_variables = 8;
    let max_msm_buffer = 20;

    let circuit = random_circuit(rng, num_constraints, num_variables);
    let r1cs = generate_relation(circuit);
    let ck = CommitterKey::<Bls12_381>::new(num_constraints + num_variables, 3, rng);

    let z_a = product_matrix_vector(&r1cs.a, &r1cs.z);
    let z_b = product_matrix_vector(&r1cs.b, &r1cs.z);
    let z_c = product_matrix_vector(&r1cs.c, &r1cs.z);

    let rows = r1cs.z.len();
    let time_proof = Proof::new_time(&r1cs, &ck);

    let a_rowm = matrix_into_colmaj(&r1cs.a, rows);
    let b_rowm = matrix_into_colmaj(&r1cs.b, rows);
    let c_rowm = matrix_into_colmaj(&r1cs.c, rows);
    let a_colm = matrix_into_rowmaj(&r1cs.a);
    let b_colm = matrix_into_rowmaj(&r1cs.b);
    let c_colm = matrix_into_rowmaj(&r1cs.c);

    let r1cs_stream = R1csStream {
        z: Reverse(r1cs.z.as_slice()),
        a_colmaj: a_rowm.as_slice(),
        b_colmaj: b_rowm.as_slice(),
        c_colmaj: c_rowm.as_slice(),
        a_rowmaj: a_colm.as_slice(),
        b_rowmaj: b_colm.as_slice(),
        c_rowmaj: c_colm.as_slice(),
        witness: Reverse(r1cs.w.as_slice()),
        z_a: Reverse(z_a.as_slice()),
        z_b: Reverse(z_b.as_slice()),
        z_c: Reverse(z_c.as_slice()),
        nonzero: num_constraints,
        joint_len: num_constraints,
    };
    let ck_stream = CommitterKeyStream::from(&ck);
    let space_proof = Proof::new_elastic(r1cs_stream, ck_stream, max_msm_buffer);

    assert_eq!(time_proof, space_proof);
}

#[test]
fn test_snark_correctness() {
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
