use ark_ff::Field;
use ark_poly::univariate::DensePolynomial;
use ark_poly::UVPolynomial;
use ark_std::borrow::Borrow;

use crate::circuit::Matrix;
use ark_std::collections::{BTreeMap, BTreeSet};

pub(crate) const TENSOR_EXPANSION_LOG: usize = 16;
pub(crate) const TENSOR_EXPANSION: usize = (1 << TENSOR_EXPANSION_LOG) - 1;

/// Return a string will all the feature tags enabled so far.
pub(crate) fn _features_enabled() -> String {
    let parallel_enabled = if cfg!(feature = "parallel") {
        "parallel"
    } else {
        ""
    };
    let asm_enabled = if cfg!(feature = "asm") { "asm" } else { "" };
    return [parallel_enabled, asm_enabled].join(", ");
}

/// Given the slice `v` as input,
/// return a slice of length `v.len()-1` with all elements of `v` but the last.
pub fn strip_last<T>(v: &[T]) -> &[T] {
    v.split_last().map(|(_, x)| x).unwrap_or(&[])
}

/// Return ceil(x / y).
#[inline]
pub fn ceil_div(x: usize, y: usize) -> usize {
    // XXX. warning: this expression can overflow.
    (x + y - 1) / y
}

/// Return the scalar product of `scalar * v`.
pub fn scalar_prod<F: Field>(scalar: &F, v: &[F]) -> Vec<F> {
    v.iter().map(|&x| x * scalar).collect()
}

/// Compute a linear combination of the polynomials `polynomials` with the given challenges.
pub fn linear_combination<F: Field, PP>(polynomials: &[PP], challenges: &[F]) -> Option<Vec<F>>
where
    PP: Borrow<Vec<F>>,
{
    polynomials
        .iter()
        .zip(challenges.iter())
        .map(|(p, &c)| &DensePolynomial::from_coefficients_vec(p.borrow().to_vec()) * c)
        .reduce(|x, y| x + y)?
        .coeffs
        .into()
}

#[test]
fn test_linear_combination() {
    use ark_bls12_381::Fr;

    let polynomials = [
        vec![Fr::from(100), Fr::from(101), Fr::from(102), Fr::from(103)],
        vec![Fr::from(100), Fr::from(100), Fr::from(100), Fr::from(100)],
    ];
    let challenges = [Fr::from(1), Fr::from(10)];
    let got = linear_combination(&polynomials, &challenges);
    let expected = vec![
        Fr::from(1100),
        Fr::from(1101),
        Fr::from(1102),
        Fr::from(1103),
    ];
    assert!(got.is_some());
    assert_eq!(got.unwrap(), expected);
}

/// Helper function for folding single polynomial.
#[inline]
pub(crate) fn fold_polynomial<F: Field>(f: &[F], r: F) -> Vec<F> {
    f.chunks(2)
        .map(|pair| pair[0] + r * pair.get(1).unwrap_or(&F::zero()))
        .collect()
}

/// Return a vector of length `len` containing the consecutive powers of element.
pub(crate) fn powers<F: Field>(element: F, len: usize) -> Vec<F> {
    let mut powers = vec![F::one(); len];
    for i in 1..len {
        powers[i] = element * powers[i - 1];
    }
    powers
}

/// Return a vector of length `len` containing the 2^j-th powers of element.
pub(crate) fn powers2<F: Field>(element: F, len: usize) -> Vec<F> {
    let mut powers = vec![F::one(); len];
    if len > 0 {
        powers[0] = element;
    }
    for i in 1..len {
        powers[i] = powers[i - 1].square();
    }
    powers
}

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum MatrixElement<T> {
    EOL,
    Element((T, usize)),
}

impl<T> MatrixElement<T> {
    pub fn is_eol(&self) -> bool {
        match self {
            Self::EOL => true,
            Self::Element(_) => false,
        }
    }
}

pub fn product_matrix_vector<F: Field>(matrix: &[Vec<(F, usize)>], z: &[F]) -> Vec<F> {
    let inner_prod_fn = |row: &[(F, usize)]| {
        let mut acc = F::zero();
        for &(ref coeff, i) in row {
            acc += if coeff.is_one() { z[i] } else { z[i] * coeff };
        }
        acc
    };

    matrix.iter().map(|row| inner_prod_fn(row)).collect()
}

#[allow(unused)]
pub fn product_vector_matrix<F: Field>(z: &[F], matrix: &[Vec<(F, usize)>]) -> Vec<F> {
    let mut res = vec![F::zero(); z.len()];
    for (row_index, row) in matrix.iter().enumerate() {
        for &(ref coeff, i) in row {
            res[i] += if coeff.is_one() {
                z[row_index]
            } else {
                z[row_index] * coeff
            };
        }
    }

    res
}

/// Given as input `elements`, an array of field elements
/// \\(\rho_0, \dots, \rho_{n-1}\\)
/// compute the tensor product
/// \\( \otimes_j (1, \rho_j )\\)
pub fn tensor<F: Field>(elements: &[F]) -> Vec<F> {
    assert!(!elements.is_empty());
    let mut tensor = vec![F::one(); 1 << elements.len()];
    let mut elements_iterator = elements.iter().enumerate();

    tensor[1] = *elements_iterator
        .next()
        .expect("Expecting at lest one element in the tensor product.")
        .1;
    // guaranteed to have at least one element.

    for (i, element) in elements_iterator {
        for j in 0..1 << i {
            tensor[(1 << i) + j] = tensor[j] * element;
        }
    }
    tensor
}

pub(crate) type PartialTensor<F> = Vec<Vec<F>>;

/// Partially expand the tensor product
/// \\(\otimes (1, \rho_j)\\)
/// XXX TODO: This function is pub(crate) as in a previous version of this library,
/// Iterable: Copy and hence couldn't store vectors itself.
/// This is not anymore the case thus it can be moved inside init.
pub fn expand_tensor<F: Field>(elements: &[F]) -> PartialTensor<F> {
    // expected_len = ceil(tensor_len / N)
    let expected_len = ceil_div(elements.len(), TENSOR_EXPANSION_LOG);
    let mut expanded_tensor = Vec::with_capacity(expected_len);

    for i in 0..expected_len {
        let mut got = if (i + 1) * TENSOR_EXPANSION_LOG <= elements.len() {
            tensor(&elements[i * TENSOR_EXPANSION_LOG..(i + 1) * TENSOR_EXPANSION_LOG])
        } else {
            tensor(&elements[i * TENSOR_EXPANSION_LOG..])
        };
        // remove the first element (1) that is the tensor with no element.
        got.remove(0);
        expanded_tensor.push(got);
    }

    expanded_tensor
}

/// Polynomial evaluation, assuming that the
/// coeffients are in big-endian.
#[inline]
pub fn evaluate_be<I, F>(polynomial: I, x: &F) -> F
where
    F: Field,
    I: IntoIterator,
    I::Item: Borrow<F>,
{
    polynomial
        .into_iter()
        .fold(F::zero(), |previous, c| previous * x + c.borrow())
}

/// Polynomial evaluation, assuming that the
/// coefficients are in little-endian.
#[inline]
pub fn evaluate_le<F>(polynomial: &[F], x: &F) -> F
where
    F: Field,
{
    evaluate_be(polynomial.iter().rev(), x)
}

/// Return the hadamard product of `lhs` and `rhs`.
/// # Panics
// If the length of `lhs` is different from `rhs`.
#[inline]
pub fn hadamard<F: Field>(lhs: &[F], rhs: &[F]) -> Vec<F> {
    assert_eq!(lhs.len(), rhs.len());
    lhs.iter().zip(rhs).map(|(&x, y)| x * y).collect()
}

/// Return the inner product of `lhs` with `rhs`.
///
/// # Panics
/// If the length of `lhs` and `rhs` are different.
#[inline]
pub fn ip<F: Field>(lhs: &[F], rhs: &[F]) -> F {
    assert_eq!(lhs.len(), rhs.len());
    ip_unsafe(lhs.iter(), rhs.iter())
}

pub fn ip_unsafe<F: Field, I, J>(lhs: I, rhs: J) -> F
where
    I: Iterator,
    J: Iterator,
    I::Item: Borrow<F>,
    J::Item: Borrow<F>,
{
    lhs.zip(rhs).map(|(x, y)| *x.borrow() * y.borrow()).sum()
}

#[inline]
#[allow(unused)]
pub fn sum_matrices<F: Field>(a: &Matrix<F>, b: &Matrix<F>, c: &Matrix<F>) -> Vec<Vec<usize>> {
    a.iter()
        .zip(b)
        .zip(c)
        .map(|((row_a, row_b), row_c)| {
            row_a
                .iter()
                .map(|(_, i)| *i)
                .chain(row_b.iter().map(|(_, i)| *i))
                .chain(row_c.iter().map(|(_, i)| *i))
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        })
        .collect()
}

#[inline]
#[allow(unused)]
pub fn joint_matrices<F: Field>(
    joint_matrix: &Vec<Vec<usize>>,
    num_constraints: usize,
    num_variables: usize,
    a: &Matrix<F>,
    b: &Matrix<F>,
    c: &Matrix<F>,
) -> (
    Vec<F>,
    Vec<F>,
    Vec<usize>,
    Vec<usize>,
    Vec<F>,
    Vec<F>,
    Vec<F>,
) {
    let mut row_vec = Vec::new();
    let mut col_vec = Vec::new();
    let mut row_index_vec = Vec::new();
    let mut col_index_vec = Vec::new();
    let mut val_a_vec = Vec::new();
    let mut val_b_vec = Vec::new();
    let mut val_c_vec = Vec::new();

    let a = a
        .iter()
        .enumerate()
        .map(|(r, row)| row.iter().map(move |(f, i)| ((r, *i), *f)))
        .flatten()
        .collect::<BTreeMap<(usize, usize), F>>();

    let b = b
        .iter()
        .enumerate()
        .map(|(r, row)| row.iter().map(move |(f, i)| ((r, *i), *f)))
        .flatten()
        .collect::<BTreeMap<(usize, usize), F>>();

    let c = c
        .iter()
        .enumerate()
        .map(|(r, row)| row.iter().map(move |(f, i)| ((r, *i), *f)))
        .flatten()
        .collect::<BTreeMap<(usize, usize), F>>();

    for (r, row) in joint_matrix.into_iter().enumerate() {
        for i in row {
            let row_val = F::from((num_constraints - r) as u64);
            let col_val = F::from((num_variables - *i) as u64);

            row_index_vec.push(num_constraints - r);
            col_index_vec.push(num_variables - *i);
            row_vec.push(row_val);
            col_vec.push(col_val);
            // We insert zeros if a matrix doesn't contain an entry at the given (row, col) location.
            val_a_vec.push(a.get(&(r, *i)).copied().unwrap_or(F::zero()));
            val_b_vec.push(b.get(&(r, *i)).copied().unwrap_or(F::zero()));
            val_c_vec.push(c.get(&(r, *i)).copied().unwrap_or(F::zero()));
        }
    }

    (
        row_vec,
        col_vec,
        row_index_vec,
        col_index_vec,
        val_a_vec,
        val_b_vec,
        val_c_vec,
    )
}

#[inline]
pub fn compute_entry_prod<F: Field>(vec: &Vec<Vec<F>>) -> (Vec<Vec<F>>, Vec<F>) {
    let mut acc = Vec::new();
    let mut prod = Vec::new();
    for v in vec.iter() {
        let mut a = Vec::new();
        let mut tmp = F::one();
        v.iter().for_each(|x| {
            tmp *= x;
            a.push(tmp)
        });
        prod.push(tmp);
        acc.push(a);
    }

    (acc, prod)
}

// #[cfg(test)]
// pub fn matrix_slice_naive<F: Field>(a: &[Vec<(F, usize)>], n: usize) -> Vec<MatrixElement<F>> {
//     let mut aa = vec![vec![F::zero(); n]; n];
//     for (row, elements) in a.iter().enumerate() {
//         for &(val, col) in elements {
//             aa[row][col] = val;
//         }
//     }

//     let mut a_row_flat = Vec::new();
//     for j in (0..n).rev() {
//         for i in (0..n).rev() {
//             if aa[i][j] != F::zero() {
//                 a_row_flat.push(MatrixElement::Element((aa[i][j], i)))
//             }
//         }
//         a_row_flat.push(MatrixElement::EOL);
//     }
//     a_row_flat
// }
