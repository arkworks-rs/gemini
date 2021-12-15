#![allow(non_snake_case)]

use crate::ahp::indexer::Matrix;
use crate::ahp::*;

// use crate::{BTreeMap, ToString};
use ark_ff::{Field, PrimeField};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, GeneralEvaluationDomain, UVPolynomial,
};
use ark_relations::{
    lc,
    r1cs::{ConstraintMatrices, ConstraintSystemRef},
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_std::io::{Read, Write};
use derivative::Derivative;


pub(crate) fn balance_matrices<F: Field>(a_matrix: &mut Matrix<F>, b_matrix: &mut Matrix<F>) {
    let mut a_density: usize = a_matrix.iter().map(|row| row.len()).sum();
    let mut b_density: usize = b_matrix.iter().map(|row| row.len()).sum();
    let mut max_density = core::cmp::max(a_density, b_density);
    let mut a_is_denser = a_density == max_density;
    for (a_row, b_row) in a_matrix.iter_mut().zip(b_matrix) {
        if a_is_denser {
            let a_row_size = a_row.len();
            let b_row_size = b_row.len();
            core::mem::swap(a_row, b_row);
            a_density = a_density - a_row_size + b_row_size;
            b_density = b_density - b_row_size + a_row_size;
            max_density = core::cmp::max(a_density, b_density);
            a_is_denser = a_density == max_density;
        }
    }
}

pub(crate) fn num_non_zero_not_used<F: PrimeField>(matrices: &ConstraintMatrices<F>) -> usize {
    *[
        matrices.a_num_non_zero,
        matrices.b_num_non_zero,
        matrices.c_num_non_zero,
    ]
    .iter()
    .max()
    .unwrap()
}

pub(crate) fn make_matrices_square_for_indexer<F: PrimeField>(cs: ConstraintSystemRef<F>) {
    let num_variables = cs.num_instance_variables() + cs.num_witness_variables();
    let matrix_dim = padded_matrix_dim(num_variables, cs.num_constraints());

    make_matrices_square(cs.clone(), num_variables);
    assert_eq!(
        cs.num_instance_variables() + cs.num_witness_variables(),
        cs.num_constraints(),
        "padding failed!"
    );
    assert_eq!(
        cs.num_instance_variables() + cs.num_witness_variables(),
        matrix_dim,
        "padding does not result in expected matrix size!"
    );
}

/// This must *always* be in sync with `make_matrices_square`.
pub(crate) fn padded_matrix_dim(num_formatted_variables: usize, num_constraints: usize) -> usize {
    let maximum = core::cmp::max(num_formatted_variables, num_constraints);
    let mut two_pow = 1;
    while two_pow < maximum {
        two_pow <<= 1;
    }
    two_pow
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

pub(crate) fn make_matrices_square<F: Field>(
    cs: ConstraintSystemRef<F>,
    num_formatted_variables: usize,
) {
    let num_constraints = cs.num_constraints();

    let maximum = if num_constraints > num_formatted_variables {
        num_constraints
    } else {
        num_formatted_variables
    };

    let mut two_pow = 1;
    while two_pow < maximum {
        two_pow <<= 1;
    }

    // let matrix_padding = ((num_formatted_variables as isize) - (num_constraints as isize)).abs();
    let constraints_padding = two_pow - num_constraints;
    let variables_padding = two_pow - num_formatted_variables;

    // Add dummy constraints of the form 0 * 0 == 0
    for _ in 0..constraints_padding {
        cs.enforce_constraint(lc!(), lc!(), lc!())
            .expect("enforce 0 * 0 == 0 failed");
    }

    // Add dummy unconstrained variables
    for _ in 0..variables_padding {
        let _ = cs
            .new_witness_variable(|| Ok(F::one()))
            .expect("alloc failed");
    }
}

// /// Contains information about the arithmetization of the matrix M.
#[derive(Derivative, CanonicalSerialize, CanonicalDeserialize)]
#[derivative(Clone(bound = "F: PrimeField"))]
pub struct MatrixArithmetization<F: PrimeField> {
    /// Vector of the row indices of M.
    pub row_vec_index: Vec<usize>,
    pub row_vec: Vec<F>,
    /// Vector of the column indices of M.
    pub col_vec_index: Vec<usize>,
    pub col_vec: Vec<F>,
    /// Vector of the value
    pub val_vec: Vec<F>,
    /// Vector of timestamp
    pub read_ts_row_vec: Vec<F>,
    pub write_ts_row_vec: Vec<F>,
    pub audit_ts_row_vec: Vec<F>,
    pub read_ts_col_vec: Vec<F>,
    pub write_ts_col_vec: Vec<F>,
    pub audit_ts_col_vec: Vec<F>,
    /// Polynomial of the non-zero entries of M.
    pub row_poly: Vec<LabeledPolynomial<F>>,
    pub col_poly: Vec<LabeledPolynomial<F>>,
    pub val_poly: Vec<LabeledPolynomial<F>>,
    /// Polynomials for time stamps in the memory checking
    pub read_ts_row: Vec<LabeledPolynomial<F>>,
    pub write_ts_row: Vec<LabeledPolynomial<F>>,
    pub audit_ts_row: Vec<LabeledPolynomial<F>>,
    pub read_ts_col: Vec<LabeledPolynomial<F>>,
    pub write_ts_col: Vec<LabeledPolynomial<F>>,
    pub audit_ts_col: Vec<LabeledPolynomial<F>>,
}

impl<F: PrimeField> MatrixArithmetization<F> {
    /// Iterate over the indexed polynomials.
    pub fn iter(&self) -> impl Iterator<Item = &LabeledPolynomial<F>> {
        self.row_poly
            .iter()
            .chain(self.col_poly.iter())
            .chain(self.val_poly.iter())
            .chain(self.read_ts_row.iter())
            .chain(self.write_ts_row.iter())
            .chain(self.audit_ts_row.iter())
            .chain(self.read_ts_col.iter())
            .chain(self.write_ts_col.iter())
            .chain(self.audit_ts_col.iter())
    }

    /// The number of oracles
    pub fn num_oracles(&self) -> usize {
        self.row_poly.len()
            + self.col_poly.len()
            + self.val_poly.len()
            + self.read_ts_row.len()
            + self.write_ts_row.len()
            + self.audit_ts_row.len()
            + self.read_ts_col.len()
            + self.write_ts_col.len()
            + self.audit_ts_col.len()
    }
}

pub(crate) fn arithmetize_matrix<F: PrimeField>(
    matrix_name: &str,
    matrix: &Matrix<F>,
) -> (MatrixArithmetization<F>, usize) {
    let matrix_time = start_timer!(|| "Computing row, col, and val");

    let mut row_vec: Vec<F> = Vec::new();
    let mut col_vec: Vec<F> = Vec::new();
    let mut val_vec: Vec<F> = Vec::new();
    let mut row_vec_index: Vec<usize> = Vec::new();
    let mut col_vec_index: Vec<usize> = Vec::new();
    let mut count = 0;

    let mut tmp = F::one();
    let two = F::one().double();
    let mut pow = Vec::new();
    for _ in 0..matrix.len() {
        pow.push(tmp);
        tmp *= two;
    }
    // Recall that we are computing the arithmetization of M.
    for (r, row) in matrix.into_iter().enumerate() {
        for (val, c) in row.iter() {
            row_vec_index.push(r);
            row_vec.push(pow[r]);
            col_vec_index.push(*c);
            col_vec.push(pow[*c]);
            val_vec.push(*val);
            count += 1;
        }
    }
    end_timer!(matrix_time);

    let non_zero = count;
    let num_constraints = matrix.len();

    let memory_checking_time = start_timer!(|| "Computing timestamps for memory-checking");
    let (read_ts_row, write_ts_row, audit_ts_row) =
        compute_timestamp(non_zero, num_constraints, &row_vec_index);
    let (read_ts_col, write_ts_col, audit_ts_col) =
        compute_timestamp(non_zero, num_constraints, &col_vec_index);
    end_timer!(memory_checking_time);

    let m_name = matrix_name.to_string();
    (
        MatrixArithmetization {
            row_vec_index: row_vec_index,
            row_vec: row_vec.clone(),
            col_vec_index: col_vec_index,
            col_vec: col_vec.clone(),
            val_vec: val_vec.clone(),
            row_poly: get_even_odd_poly(&(m_name.clone() + "_row"), &row_vec),
            col_poly: get_even_odd_poly(&(m_name.clone() + "_col"), &col_vec),
            val_poly: get_even_odd_poly(&(m_name.clone() + "_val"), &val_vec),
            read_ts_row_vec: read_ts_row.clone(),
            write_ts_row_vec: write_ts_row.clone(),
            audit_ts_row_vec: audit_ts_row.clone(),
            read_ts_col_vec: read_ts_col.clone(),
            write_ts_col_vec: write_ts_col.clone(),
            audit_ts_col_vec: audit_ts_col.clone(),
            read_ts_row: get_even_odd_poly(&(m_name.clone() + "_read_row_ts"), &read_ts_row),
            write_ts_row: get_even_odd_poly(&(m_name.clone() + "_write_row_ts"), &write_ts_row),
            audit_ts_row: get_even_odd_poly(&(m_name.clone() + "_audit_row_ts"), &audit_ts_row),
            read_ts_col: get_even_odd_poly(&(m_name.clone() + "_read_col_ts"), &read_ts_col),
            write_ts_col: get_even_odd_poly(&(m_name.clone() + "_write_col_ts"), &write_ts_col),
            audit_ts_col: get_even_odd_poly(&(m_name.clone() + "_audit_col_ts"), &audit_ts_col),
        },
        non_zero,
    )
}

fn compute_timestamp<F: PrimeField>(
    non_zero: usize,
    num_constraints: usize,
    addrs: &Vec<usize>,
) -> (Vec<F>, Vec<F>, Vec<F>) {
    let mut read_ts = vec![F::one(); non_zero];
    let mut write_ts = vec![F::one(); non_zero];
    let mut audit_ts = vec![F::one(); num_constraints];

    let mut ts = F::one();
    let two = F::one().double();
    for (i, addr) in addrs.iter().enumerate() {
        ts = ts * two;                     // 2^i
        let r_ts = audit_ts[*addr];

        read_ts[i] = r_ts;                // (min j st row_j is the same to row_i)    x^i
        write_ts[i] = ts;                // 2^i
        audit_ts[*addr] = ts;            // 2^i  -- max i such that row_i is the same
    }

    (read_ts, write_ts, audit_ts)
}

fn is_in_ascending_order<T: Ord>(x_s: &[T], is_less_than: impl Fn(&T, &T) -> bool) -> bool {
    if x_s.is_empty() {
        true
    } else {
        let mut i = 0;
        let mut is_sorted = true;
        while i < (x_s.len() - 1) {
            is_sorted &= is_less_than(&x_s[i], &x_s[i + 1]);
            i += 1;
        }
        is_sorted
    }
}

/* ************************************************************************* */
/* ************************************************************************* */
/* ************************************************************************* */

/// Formats the public input according to the requirements of the constraint
/// system
pub(crate) fn format_public_input<F: PrimeField>(public_input: &[F]) -> Vec<F> {
    let mut input = vec![F::one()];
    input.extend_from_slice(public_input);
    input
}

/// Takes in a previously formatted public input and removes the formatting
/// imposed by the constraint system.
pub(crate) fn unformat_public_input<F: PrimeField>(input: &[F]) -> Vec<F> {
    input[1..].to_vec()
}

pub(crate) fn make_matrices_square_for_prover<F: PrimeField>(cs: ConstraintSystemRef<F>) {
    let num_variables = cs.num_instance_variables() + cs.num_witness_variables();
    make_matrices_square(cs.clone(), num_variables);
    assert_eq!(
        cs.num_instance_variables() + cs.num_witness_variables(),
        cs.num_constraints(),
        "padding failed!"
    );
}

