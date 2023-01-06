use crate::{circuit::R1cs, herring::proof::Sumcheck, misc::product_matrix_vector};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_std::vec::Vec;
use merlin::Transcript;

use super::{ipa::Crs, module::FModule};

struct Proof<P: Pairing> {
    sumcheck: Sumcheck<FModule<P>>,
}

#[derive(Clone, Copy)]
struct GtCommitment<P: Pairing>(PairingOutput<P>);
struct G1Commitment<P: Pairing>(P::G1);

#[allow(non_snake_case)]
struct VerificationKey<P: Pairing> {
    A: GtCommitment<P>,
    B: GtCommitment<P>,
    C: GtCommitment<P>,
}

#[allow(non_snake_case)]
struct ProvingKey<P: Pairing> {
    A: GtCommitment<P>,
    B: GtCommitment<P>,
    C: GtCommitment<P>,
    R_A: Vec<G1Commitment<P>>,
    R_B: Vec<G1Commitment<P>>,
    R_C: Vec<G1Commitment<P>>,
    // encoding of the matrix A
    val_a: Vec<P::ScalarField>,
    row_a: Vec<usize>,
    col_a: Vec<usize>,
    // encoding of the matrix B
    val_b: Vec<P::ScalarField>,
    row_b: Vec<usize>,
    col_b: Vec<usize>,
    // encoding of the matrix C
    val_c: Vec<P::ScalarField>,
    row_c: Vec<usize>,
    col_c: Vec<usize>,
}

impl<P: Pairing> ProvingKey<P> {
    fn new(crs: &Crs<P>, r1cs: &R1cs<P::ScalarField>) -> Self {
        todo!();
    }
}

impl<'a, P: Pairing> From<&'a ProvingKey<P>> for VerificationKey<P> {
    fn from(pk: &'a ProvingKey<P>) -> Self {
        VerificationKey {
            A: pk.A,
            B: pk.B,
            C: pk.C,
        }
    }
}

impl<P: Pairing> Proof<P> {
    fn new(
        transcript: &mut Transcript,
        crs: &Crs<P>,
        pk: &ProvingKey<P>,
        r1cs: &R1cs<P::ScalarField>,
    ) -> Self {
        let z_a = product_matrix_vector(&r1cs.a, &r1cs.z);
        let z_b = product_matrix_vector(&r1cs.b, &r1cs.z);
        let z_c = product_matrix_vector(&r1cs.c, &r1cs.z);

        let z_comm = crs.commit_g1(&r1cs.z);

        todo!()
    }
}
