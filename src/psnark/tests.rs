use super::Proof;
use crate::circuit::{
    generate_relation, matrix_into_col_major_slice, matrix_into_row_major_slice, random_circuit,
    Circuit, R1csStream,
};
use crate::iterable::dummy::Mat;
use crate::iterable::Reversed;

use crate::kzg::{CommitterKey, CommitterKeyStream};
use crate::misc::product_matrix_vector;
use ark_bls12_381::{Bls12_381, Fr};
use ark_std::test_rng;

#[test]
fn test_consistency() {
    let rng = &mut test_rng();
    let num_constraints = 128;
    let num_variables = 128;
    let circuit: Circuit<Fr> = random_circuit(rng, num_constraints, num_variables);
    let r1cs = generate_relation(circuit);

    let z_a = product_matrix_vector(&r1cs.a, &r1cs.z);
    let z_b = product_matrix_vector(&r1cs.b, &r1cs.z);
    let z_c = product_matrix_vector(&r1cs.c, &r1cs.z);

    let rows = 128;
    let a_rowm = matrix_into_row_major_slice(&r1cs.a, rows);
    let b_rowm = matrix_into_row_major_slice(&r1cs.b, rows);
    let c_rowm = matrix_into_row_major_slice(&r1cs.c, rows);
    let a_colm = matrix_into_col_major_slice(&r1cs.a);
    let b_colm = matrix_into_col_major_slice(&r1cs.b);
    let c_colm = matrix_into_col_major_slice(&r1cs.c);

    let r1cs_stream = R1csStream {
        z: Reversed::new(r1cs.z.as_slice()),
        a_rowm: Mat(a_rowm.as_slice(), rows),
        b_rowm: Mat(b_rowm.as_slice(), rows),
        c_rowm: Mat(c_rowm.as_slice(), rows),
        a_colm: Mat(a_colm.as_slice(), rows),
        b_colm: Mat(b_colm.as_slice(), rows),
        c_colm: Mat(c_colm.as_slice(), rows),
        witness: Reversed::new(r1cs.w.as_slice()),
        z_a: Reversed::new(z_a.as_slice()),
        z_b: Reversed::new(z_b.as_slice()),
        z_c: Reversed::new(z_c.as_slice()),
        nonzero: num_constraints,
        joint_len: 384,
    };

    let ck = CommitterKey::<Bls12_381>::new(num_constraints * 100 + num_variables, 3, rng);
    let ck_stream = CommitterKeyStream::from(&ck);

    let time_proof = Proof::new_time(&r1cs, &ck);
    let elastic_proof = Proof::new_elastic(&r1cs_stream, &ck_stream);

    assert_eq!(
        elastic_proof.witness_commitment,
        time_proof.witness_commitment
    );
    assert_eq!(
        elastic_proof.z_star_commitment,
        time_proof.z_star_commitment
    );

    assert_eq!(
        elastic_proof.r_star_commitments[0],
        time_proof.r_star_commitments[0]
    );

    assert_eq!(
        elastic_proof.r_star_commitments[1],
        time_proof.r_star_commitments[1]
    );
    assert_eq!(
        elastic_proof.r_star_commitments[2],
        time_proof.r_star_commitments[2]
    );
    assert_eq!(elastic_proof.second_sumcheck_msgs,
        time_proof.second_sumcheck_msgs);

    assert_eq!(elastic_proof.set_r_ep,
        time_proof.set_r_ep)
}
