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

#[derive(Copy, Clone)]
pub struct Circuit<F: Field> {
    a: Option<F>,
    b: Option<F>,
    num_constraints: usize,
    num_variables: usize,
}

pub struct R1csStream<SM, SZ, SW> {
    pub a_rowm: SM,
    pub b_rowm: SM,
    pub c_rowm: SM,
    pub a_colm: SM,
    pub b_colm: SM,
    pub c_colm: SM,
    pub z: SZ,
    pub witness: SW,
    pub z_a: SZ,
    pub z_b: SZ,
    pub z_c: SZ,
    pub nonzero: usize,
}

/// Represents a matrix.
pub type Matrix<F> = Vec<Vec<(F, usize)>>;

pub struct R1CS<F: Field> {
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

pub fn generate_relation<F: PrimeField, C: ConstraintSynthesizer<F>>(circuit: C) -> R1CS<F> {
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
    R1CS {
        a: matrices.a,
        b: matrices.b,
        c: matrices.c,
        z: statement.iter().chain(witness).cloned().collect(),
        w: witness.to_vec(),
        x: statement.to_vec(),
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

pub fn dummy_r1cs<F: Field>(rng: &mut impl RngCore, n: usize) -> R1CS<F> {
    let e = F::rand(rng);
    let inv_e = e.inverse().expect("Buy a lottery ticket and retry");
    let z = vec![e; n];
    let w = vec![e; n - 1];
    let x = vec![e];

    let diagonal_matrix = (0..n).map(|i| vec![(inv_e, i)]).collect::<Vec<_>>();
    R1CS {
        a: diagonal_matrix.clone(),
        b: diagonal_matrix.clone(),
        c: diagonal_matrix.clone(),
        z,
        w,
        x,
    }
}
