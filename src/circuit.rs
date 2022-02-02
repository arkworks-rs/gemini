//! This code was blatantly stolen from arkworks test suite.
use ark_ff::{Field, PrimeField};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::{
    lc,
    r1cs::{
        ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, OptimizationGoal,
        SynthesisError,
    },
};
use ark_std::rand::RngCore;
use ark_std::vec::Vec;

use crate::iterable::dummy::{RepeatMatrixStreamer, RepeatStreamer};
use crate::iterable::Iterable;
use crate::misc::MatrixElement;

#[derive(Copy, Clone)]
pub struct Circuit<F: Field> {
    a: Option<F>,
    b: Option<F>,
    num_constraints: usize,
    num_variables: usize,
}

pub struct R1csStream<SM, SZ, SW> {
    pub a_colmaj: SM,
    pub b_colmaj: SM,
    pub c_colmaj: SM,
    pub a_rowmaj: SM,
    pub b_rowmaj: SM,
    pub c_rowmaj: SM,
    pub z: SZ,
    pub witness: SW,
    pub z_a: SZ,
    pub z_b: SZ,
    pub z_c: SZ,
    pub nonzero: usize,
    pub joint_len: usize,
}

/// Represents a matrix.
pub type Matrix<F> = Vec<Vec<(F, usize)>>;

pub struct R1cs<F: Field> {
    pub a: Matrix<F>,
    pub b: Matrix<F>,
    pub c: Matrix<F>,
    pub z: Vec<F>,
    pub w: Vec<F>,
    pub x: Vec<F>,
}

impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for Circuit<ConstraintF> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            let mut a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

            a.mul_assign(&b);
            Ok(a)
        })?;
        let d = cs.new_input_variable(|| {
            let mut a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

            a.mul_assign(&b);
            a.mul_assign(&b);
            Ok(a)
        })?;

        for _ in 0..(self.num_variables - 4) {
            let _ = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        }

        for _ in 0..(self.num_constraints - 1) {
            cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        }
        cs.enforce_constraint(lc!() + c, lc!() + b, lc!() + d)?;

        Ok(())
    }
}

#[derive(Clone)]
/// Define a constraint system that would trigger outlining.
struct OutlineTestCircuit;

impl<F: Field> ConstraintSynthesizer<F> for OutlineTestCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // This program checks if the input elements are between 0 and 9.
        //
        // Note that this constraint system is neither the most intuitive way nor
        // the most efficient way for such a task. It is for testing purposes,
        // as we want to trigger the outlining.
        //
        let mut inputs = Vec::new();
        for i in 0..5 {
            inputs.push(cs.new_input_variable(|| Ok(F::from(i as u128)))?);
        }

        for (i, &input) in inputs.iter().enumerate().take(5) {
            let mut total_count_for_this_input = cs.new_lc(lc!()).unwrap();

            for bucket in 0..10 {
                let count_increment_for_this_bucket =
                    cs.new_witness_variable(|| Ok(F::from(i == bucket)))?;

                total_count_for_this_input = cs
                    .new_lc(
                        lc!()
                            + (F::one(), total_count_for_this_input)
                            + (F::one(), count_increment_for_this_bucket),
                    )
                    .unwrap();

                // Only when `input[i]` equals `bucket` can `count_increment_for_this_bucket` be nonzero.
                //
                // A malicious prover can make `count_increment_for_this_bucket` neither 0 nor 1.
                // But the constraint on `total_count_for_this_input` will reject such case.
                //
                // At a high level, only one of the `count_increment_for_this_bucket` among all the buckets
                // could be nonzero, which equals `total_count_for_this_input`. Thus, by checking whether
                // `total_count_for_this_input` is 1, we know this input number is in the range.
                //
                cs.enforce_constraint(
                    lc!() + (F::one(), input)
                        - (F::from(bucket as u128), ark_relations::r1cs::Variable::One),
                    lc!() + (F::one(), count_increment_for_this_bucket),
                    lc!(),
                )?;
            }

            // Enforce `total_count_for_this_input` to be one.
            cs.enforce_constraint(
                lc!(),
                lc!(),
                lc!() + (F::one(), total_count_for_this_input)
                    - (F::one(), ark_relations::r1cs::Variable::One),
            )?;
        }

        Ok(())
    }
}

pub fn generate_relation<F: PrimeField, C: ConstraintSynthesizer<F>>(circuit: C) -> R1cs<F> {
    let pcs = ConstraintSystem::new_ref();
    pcs.set_optimization_goal(OptimizationGoal::Weight);
    // pcs.set_optimization_goal(OptimizationGoal::Constraints);
    pcs.set_mode(ark_relations::r1cs::SynthesisMode::Prove {
        construct_matrices: true,
    });
    circuit.generate_constraints(pcs.clone()).unwrap();
    pad_input_for_indexer_and_prover(pcs.clone());
    pcs.finalize();
    // make_matrices_square_for_prover(pcs.clone());
    let pcs = pcs.borrow().unwrap();
    let statement = pcs.instance_assignment.as_slice();
    let witness = pcs.witness_assignment.as_slice();
    let matrices = pcs.to_matrices().expect("should not be `None`");
    R1cs {
        a: matrices.a,
        b: matrices.b,
        c: matrices.c,
        z: statement.iter().chain(witness).cloned().collect(),
        w: witness.to_vec(),
        x: statement.to_vec(),
    }
}

/// Return a matrix stream, col major.
/// XXX. can this be done without the hint for the number of columns?
pub(crate) fn matrix_into_colmaj<F: Field>(
    a: &[Vec<(F, usize)>],
    col_number: usize,
) -> Vec<MatrixElement<F>> {
    use ark_std::cmp::Ordering;
    let mut a_row_flat = Vec::new();

    for column in (0..col_number).rev() {
        for (row, elements) in a.iter().enumerate().rev() {
            for &(val, col) in elements.iter().rev() {
                match col.cmp(&column) {
                    Ordering::Equal => {
                        a_row_flat.push(MatrixElement::Element((val, row)));
                    }
                    Ordering::Less => {
                        break;
                    }
                    Ordering::Greater => {
                        continue;
                    }
                }
            }
        }
        a_row_flat.push(MatrixElement::EOL);
    }
    a_row_flat
}

// Return a matrix stream, row major.
pub fn matrix_into_rowmaj<F: Field>(a: &[Vec<(F, usize)>]) -> Vec<MatrixElement<F>> {
    let mut a_row_flat = Vec::new();

    for (_row, elements) in a.iter().enumerate().rev() {
        for &(val, col) in elements.iter().rev() {
            a_row_flat.push(MatrixElement::Element((val, col)));
        }
        a_row_flat.push(MatrixElement::EOL);
    }
    a_row_flat
}

pub fn repeat_r1cs<'a, F: PrimeField>(
    r1cs: &'a R1cs<F>,
    repeat: usize,
    [z_a, z_b, z_c]: [&'a [F]; 3],
) -> R1csStream<
    impl Iterable<Item = MatrixElement<F>>,
    impl Iterable<Item = &'a F> + 'a,
    impl Iterable<Item = &'a F> + 'a,
> {
    // XXX. change this
    let nonzero = 0;
    let block_size = 0;
    let joint_len = 0;

    let a_colm = RepeatMatrixStreamer::new(matrix_into_rowmaj(&r1cs.a), repeat, block_size);
    let b_colm = RepeatMatrixStreamer::new(matrix_into_rowmaj(&r1cs.b), repeat, block_size);
    let c_colm = RepeatMatrixStreamer::new(matrix_into_rowmaj(&r1cs.c), repeat, block_size);

    let col_number = a_colm.len();
    let a_rowm =
        RepeatMatrixStreamer::new(matrix_into_colmaj(&r1cs.a, col_number), repeat, block_size);
    let b_rowm =
        RepeatMatrixStreamer::new(matrix_into_colmaj(&r1cs.b, col_number), repeat, block_size);
    let c_rowm =
        RepeatMatrixStreamer::new(matrix_into_colmaj(&r1cs.c, col_number), repeat, block_size);

    let z = RepeatStreamer::new(&r1cs.z, repeat);
    let witness = RepeatStreamer::new(&r1cs.w, repeat);
    let z_a = RepeatStreamer::new(z_a, repeat);
    let z_b = RepeatStreamer::new(z_b, repeat);
    let z_c = RepeatStreamer::new(z_c, repeat);

    R1csStream {
        a_rowmaj: a_colm,
        b_rowmaj: b_colm,
        a_colmaj: a_rowm,
        b_colmaj: b_rowm,
        c_colmaj: c_rowm,
        c_rowmaj: c_colm,
        z,
        witness,
        z_a,
        z_b,
        z_c,
        nonzero,
        joint_len,
    }
}

pub(crate) fn pad_input_for_indexer_and_prover<F: PrimeField>(cs: ConstraintSystemRef<F>) {
    let formatted_input_size = cs.num_instance_variables();

    let domain_x = GeneralEvaluationDomain::<F>::new(formatted_input_size);
    assert!(domain_x.is_some());

    let padded_size = domain_x.unwrap().size();

    if padded_size > formatted_input_size {
        for _ in 0..(padded_size - formatted_input_size) {
            cs.new_input_variable(|| Ok(F::zero())).unwrap();
        }
    }
}

pub fn random_circuit<F: Field>(
    rng: &mut impl RngCore,
    num_constraints: usize,
    num_variables: usize,
) -> Circuit<F> {
    let a = F::rand(rng);
    let b = F::rand(rng);
    let mut c = a;
    c.mul_assign(&b);
    let mut d = c;
    d.mul_assign(&b);

    Circuit {
        a: Some(a),
        b: Some(b),
        num_constraints,
        num_variables,
    }
}

#[test]
fn test_repeated_r1cs() {
    use ark_bls12_381::Fr;

    use crate::misc::evaluate_be;
    use crate::misc::ip;
    use crate::misc::product_matrix_vector;
    use ark_std::{One, Zero};

    let rng = &mut ark_std::test_rng();
    let num_constraints = 1 << 4;
    let num_variables = 1 << 4;
    let repeat = 10;
    let circuit = random_circuit(rng, num_constraints, num_variables);
    let r1cs = generate_relation(circuit);
    let za = product_matrix_vector(&r1cs.a, &r1cs.z);
    let zb = product_matrix_vector(&r1cs.b, &r1cs.z);
    let zc = product_matrix_vector(&r1cs.c, &r1cs.z);
    let repeated_r1cs = repeat_r1cs(&r1cs, repeat, [&za, &zb, &zc]);

    // test that <z_a, z_b> = z_c(1)
    assert_eq!(ip(&za, &zb), evaluate_be(zc.iter(), &Fr::one()));
    assert_eq!(
        repeated_r1cs
            .z_a
            .iter()
            .zip(repeated_r1cs.z_b.iter())
            .map(|(x, y)| *x * y)
            .sum::<Fr>(),
        evaluate_be(repeated_r1cs.z_c.iter(), &Fr::one())
    );

    // test that [Az](1) = z_a(1)
    let expected = za.iter().sum::<Fr>() * Fr::from(repeat as u64);
    let mut got = Fr::zero();
    for matrix_element in repeated_r1cs.a_rowmaj.iter() {
        match matrix_element {
            MatrixElement::EOL => { /* do nothing here, all is being added up */ }
            MatrixElement::Element((e, i)) => got += r1cs.z[i] * e,
        }
    }

    assert_eq!(got, expected)
}

pub fn dummy_r1cs<F: Field>(rng: &mut impl RngCore, n: usize) -> R1cs<F> {
    let e = F::rand(rng);
    let inv_e = e.inverse().expect("Buy a lottery ticket and retry");
    let z = vec![e; n];
    let w = vec![e; n - 1];
    let x = vec![e];

    let diagonal_matrix = (0..n).map(|i| vec![(inv_e, i)]).collect::<Vec<_>>();
    R1cs {
        a: diagonal_matrix.clone(),
        b: diagonal_matrix.clone(),
        c: diagonal_matrix,
        z,
        w,
        x,
    }
}
