use super::Proof;
use crate::circuit::{
    generate_relation, matrix_into_colmaj, matrix_into_rowmaj, random_circuit, Circuit, R1csStream,
};
use crate::iterable::dummy::Mat;
use crate::iterable::Reverse;

use crate::kzg::{CommitterKey, CommitterKeyStream};
use crate::misc::product_matrix_vector;
use ark_bls12_381::{Bls12_381, Fr};
use ark_std::test_rng;

#[test]
fn test_consistency() {
    let rng = &mut test_rng();
    let num_constraints = 128;
    let num_variables = 128;
    let max_msm_buffer = 1 << 20;
    let circuit: Circuit<Fr> = random_circuit(rng, num_constraints, num_variables);
    let r1cs = generate_relation(circuit);

    let z_a = product_matrix_vector(&r1cs.a, &r1cs.z);
    let z_b = product_matrix_vector(&r1cs.b, &r1cs.z);
    let z_c = product_matrix_vector(&r1cs.c, &r1cs.z);

    let rows = 128;
    let a_colmaj = matrix_into_colmaj(&r1cs.a, rows);
    let b_colmaj = matrix_into_colmaj(&r1cs.b, rows);
    let c_colmaj = matrix_into_colmaj(&r1cs.c, rows);
    let a_rowmaj = matrix_into_rowmaj(&r1cs.a);
    let b_rowmaj = matrix_into_rowmaj(&r1cs.b);
    let c_rowmaj = matrix_into_rowmaj(&r1cs.c);

    let r1cs_stream = R1csStream {
        z: Reverse(r1cs.z.as_slice()),
        a_colmaj: Mat(a_colmaj.as_slice(), rows),
        b_colmaj: Mat(b_colmaj.as_slice(), rows),
        c_colmaj: Mat(c_colmaj.as_slice(), rows),
        a_rowmaj: Mat(a_rowmaj.as_slice(), rows),
        b_rowmaj: Mat(b_rowmaj.as_slice(), rows),
        c_rowmaj: Mat(c_rowmaj.as_slice(), rows),
        witness: Reverse(r1cs.w.as_slice()),
        z_a: Reverse(z_a.as_slice()),
        z_b: Reverse(z_b.as_slice()),
        z_c: Reverse(z_c.as_slice()),
        nonzero: num_constraints,
        joint_len: 384,
    };

    let ck = CommitterKey::<Bls12_381>::new(num_constraints * 100 + num_variables, 3, rng);
    let ck_stream = CommitterKeyStream::from(&ck);
    let index = Proof::index(&ck, &r1cs);

    let time_proof = Proof::new_time(&ck, &r1cs, &index);
    let elastic_proof = Proof::new_elastic(&ck_stream, &r1cs_stream, &index, max_msm_buffer);

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
    assert_eq!(
        elastic_proof.second_sumcheck_msgs,
        time_proof.second_sumcheck_msgs
    );

    assert_eq!(elastic_proof.set_r_ep, time_proof.set_r_ep);
    assert_eq!(elastic_proof.subset_r_ep, time_proof.subset_r_ep);
    assert_eq!(
        elastic_proof.sorted_r_commitment,
        time_proof.sorted_r_commitment
    );
    assert_eq!(elastic_proof.ep_msgs, time_proof.ep_msgs);
    assert_eq!(
        elastic_proof.ralpha_star_acc_mu_proof,
        time_proof.ralpha_star_acc_mu_proof
    );
    assert_eq!(
        elastic_proof.third_sumcheck_msgs,
        time_proof.third_sumcheck_msgs
    );

    assert_eq!(
        elastic_proof
            .tensorcheck_proof
            .folded_polynomials_commitments,
        time_proof.tensorcheck_proof.folded_polynomials_commitments
    );

    assert_eq!(
        elastic_proof
            .tensorcheck_proof
            .folded_polynomials_evaluations,
        time_proof.tensorcheck_proof.folded_polynomials_evaluations
    );

    assert_eq!(
        elastic_proof.tensorcheck_proof.base_polynomials_evaluations,
        time_proof.tensorcheck_proof.base_polynomials_evaluations
    );

    assert_eq!(
        elastic_proof.tensorcheck_proof.evaluation_proof,
        time_proof.tensorcheck_proof.evaluation_proof
    );

    assert!(elastic_proof == time_proof);
}

#[test]
fn test_psnark_correctness() {
    let rng = &mut test_rng();
    let num_constraints = 10024;
    let num_variables = 10024;

    let circuit = random_circuit(rng, num_constraints, num_variables);
    let r1cs = generate_relation(circuit);
    let num_non_zero = 3*num_constraints;

    let ck = CommitterKey::<Bls12_381>::new(num_non_zero + num_variables + num_constraints, 5, rng);
    let vk = (&ck).into();

    let index = Proof::index(&ck, &r1cs);

    let time_proof = Proof::new_time(&ck, &r1cs, &index);

    assert!(time_proof
        .verify(&r1cs, &vk, &index, num_non_zero)
        .is_ok())
}
