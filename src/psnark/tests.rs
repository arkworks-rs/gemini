use super::Proof;
use crate::circuit::{generate_relation, random_circuit, Circuit, R1csStream};
use crate::iterable::dummy::dummy_r1cs_stream;
use crate::kzg::{CommitterKey, CommitterKeyStream};
use ark_bls12_381::{Bls12_381, Fr};
use ark_std::test_rng;

#[test]
fn test_consistency() {
    let rng = &mut test_rng();
    let num_constraints = 128;
    let num_variables = 128;
    let circuit: Circuit<Fr> = random_circuit(rng, num_constraints, num_variables);
    let r1cs = generate_relation(circuit);
    let ck = CommitterKey::<Bls12_381>::new(num_variables * 2 + 1, num_variables, rng);

    // let ck_stream = CommitterKeyStream::from(&ck);
    // let r1cs_stream = dummy_r1cs_stream(rng, num_constraints);
    // let _proof = Proof::new_elastic(&r1cs_stream, &ck_stream);

    let _proof = Proof::new_time(&r1cs, &ck);
}
