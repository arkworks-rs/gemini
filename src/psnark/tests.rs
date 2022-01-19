use ark_bls12_381::Bls12_381;
use ark_std::test_rng;
use crate::circuit::{random_circuit, generate_relation};
use crate::kzg::CommitterKey;
use super::Proof;


#[test]
fn test_consistency() {
    let rng = &mut test_rng();
    let num_constraints  = 128;
    let num_variables= 128;
    let circuit = random_circuit(rng, num_constraints, num_variables);
    let r1cs = generate_relation(circuit);
    let ck = CommitterKey::<Bls12_381>::new(num_variables, 10, rng);

    let _proof = Proof::new_time(&r1cs, &ck);

}