use ark_ff::{Field, PrimeField};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use ark_poly::multivariate::SparsePolynomial;
use ark_poly::multivariate::Term;
use ark_std::borrow::Borrow;
use ark_std::vec::Vec;

use crate::circuit::Matrix;
use ark_std::collections::{BTreeMap, BTreeSet, HashSet};
use ark_std::rand::RngCore;

pub(crate) const TENSOR_EXPANSION_LOG: usize = 16;
pub(crate) const TENSOR_EXPANSION: usize = (1 << TENSOR_EXPANSION_LOG) - 1;

/// Return a string will all the feature tags enabled so far.
pub(crate) fn _features_enabled() -> ark_std::string::String {
    let parallel_enabled = if cfg!(feature = "parallel") {
        "parallel"
    } else {
        ""
    };
    let asm_enabled = if cfg!(feature = "asm") { "asm" } else { "" };
    [parallel_enabled, asm_enabled].join(", ")
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

/// Compute a linear combination of the polynomials `polynomials` with the given challenges.
pub fn linear_combination<F: Field, PP>(polynomials: &[PP], challenges: &[F]) -> Vec<F>
where
    PP: Borrow<Vec<F>>,
{
    polynomials
        .iter()
        .zip(challenges.iter())
        .map(|(p, &c)| &DensePolynomial::from_coefficients_vec(p.borrow().to_vec()) * c)
        .reduce(|x, y| x + y)
        .map(|x| x.coeffs.into())
        .unwrap_or_else(|| Vec::new())
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
        .expect("Expecting at least one element in the tensor product.")
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

/// For a slice x, multiply the components of x that correlate to the bits of idx.
/// From Michele's expression of multivariate polynomial in single dimension vector
///
pub fn mul_components<F>(x: &[F], idx: usize) -> F
where
    F: Field,
{
    let mut result = F::one();
    for (i, x_i) in x.iter().enumerate() {
        if (idx >> i) & 1 == 1 {
            result = result.mul(x_i);
        }
    }
    result
}

/// Generate a random vector of field elements such that they're all different
pub fn random_unique_vector<F>(size: usize, rng: &mut impl RngCore) -> Vec<F>
where
    F: Field,
{
    let mut result = HashSet::new();
    while result.len() < size {
        result.insert(F::rand(rng));
    }
    result.into_iter().collect::<Vec<_>>()
}

pub fn random_vector<F>(size: usize, rng: &mut impl RngCore) -> Vec<F>
where
    F: Field,
{
    let mut result = Vec::with_capacity(size);
    for _ in 0..size {
        result.push(F::rand(rng));
    }
    result
}

/// Polynomial evaluation for a multidimensional polynomial, encoded as Michele described.
/// TODO: faster implementation using multi_poly_vector_expand
///
pub fn evaluate_multi_poly<F>(polynomial: &[F], x: &[F]) -> F
where
    F: Field,
{
    // check that lengths line up
    assert_eq!(polynomial.len(), 1 << x.len());
    let polynomial_iterator = polynomial.iter().enumerate();
    let mut result = F::zero();
    let tensor_x = tensor(x);
    for (i, polynomial_i) in polynomial_iterator {
        result += tensor_x[i] * polynomial_i;
    }
    result
}

#[test]
fn test_evaluate_multi_poly() {
    use crate::ark_std::One;
    use ark_bls12_381::Fr;
    let coefs_ones = [Fr::one(); 16];
    let point_ones = [Fr::one(); 4];
    let mut result = evaluate_multi_poly(&coefs_ones, &point_ones);
    assert_eq!(result, Fr::from(16));
    println!("result: {}", evaluate_multi_poly(&coefs_ones, &point_ones));

    // This evaluation should be 112. I chose these
    let coefs = [0_u64, 6, 9, 2, 4, 8, 5, 1];
    let point = [4_u64, 2, 1];
    // How can I turn this into a function
    let coefs_fr = coefs.into_iter().map(|x| Fr::from(x)).collect::<Vec<_>>();
    let point_fr = point.into_iter().map(|x| Fr::from(x)).collect::<Vec<_>>();

    let expected_evaluation = coefs_fr[0]
        + coefs_fr[1] * point_fr[0]
        + coefs_fr[2] * point_fr[1]
        + coefs_fr[3] * point_fr[0] * point_fr[1]
        + coefs_fr[4] * point_fr[2]
        + coefs_fr[5] * point_fr[2] * point_fr[0]
        + coefs_fr[6] * point_fr[2] * point_fr[1]
        + coefs_fr[7] * point_fr[2] * point_fr[1] * point_fr[0];

    result = evaluate_multi_poly(&coefs_fr, &point_fr);
    assert_eq!(result, expected_evaluation);
}

/// divide polynomials
/// for evaluation point \\(alpha_1, alpha_2, ... alpha_n\\)
/// get some polynomials \\(q_1, ... q_n\\) such that polynomial = \\(\sum_i{q_i(x)(x_i - \alpha_i)} + f(\alpha)\\)
/// polynomial is ordered f0, f1, f2, .... f_N
/// Take the binary expansion of i: b0, b1, ... bn. If b_j is 1, then multiply f_i by x_j.
///
pub fn multi_poly_decompose<F: PrimeField>(polynomial: &[F], eval_point: &[F]) -> (Vec<Vec<F>>, F) {
    let mut results = Vec::new();
    for _i in 0..eval_point.len() {
        results.push(vec![F::zero(); polynomial.len()]);
    }
    let mut evaluation = F::zero();
    for (ind, item) in polynomial.iter().enumerate() {
        // if the i'th bit of j is 1, that means it shouldn't be in the quotient
        let mut term = *item;
        let mut ind_shifted = ind;
        let _counter = 0;
        for dim in 0..eval_point.len() {
            if ind_shifted == 0 {
                break;
            }
            if ind_shifted & 1 == 1 {
                let dim_bit_off = (ind_shifted >> 1) << (1 + dim);
                results[dim][dim_bit_off] += term;
                term *= eval_point[dim];
            }
            ind_shifted >>= 1;
        }
        evaluation += term;
    }

    // assert_eq!(evaluate_multi_poly(&remainder, evaluation_point), remainder[0]);
    (results, evaluation)
}

/// Converts a sparse_polynomial from ark_poly into a vector of coefficients
pub fn multi_poly_flatten<F: Field, T: Term>(sparse_polynomial: &SparsePolynomial<F, T>) -> Vec<F> {
    let mut f = vec![F::zero(); 1 << sparse_polynomial.num_vars];
    for term in &sparse_polynomial.terms {
        let mut idx: usize = 0;
        for term_idx in term.1.vars() {
            idx += 1 << term_idx;
        }
        f[idx] = term.0;
    }
    f
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

/// The elements of a matrix stream.
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum MatrixElement<T> {
    /// A matrix element.
    Element((T, usize)),
    /// A new line in the matrix stream.
    EOL,
}

impl<T> MatrixElement<T> {
    /// Return `true` is the current element is indicating a new line,
    /// `false` otherwise.
    pub fn is_eol(&self) -> bool {
        match self {
            Self::EOL => true,
            Self::Element(_) => false,
        }
    }
}

/// Given a sparse matrix `matrix` and a vector `z`, compute `matrix * z`.
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

/// Given a vector `z` and a sparse matrix `matrix`, compute `z * matrix`.
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
    hadamard_unsafe(lhs, rhs)
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

pub(crate) fn hadamard_unsafe<F: Field, I, J>(lhs: I, rhs: J) -> Vec<F>
where
    I: IntoIterator,
    J: IntoIterator,
    I::Item: Borrow<F>,
    J::Item: Borrow<F>,
{
    lhs.into_iter()
        .zip(rhs)
        .map(|(x, y)| *x.borrow() * y.borrow())
        .collect()
}

/// Return the inner product of two iterators `lhs` and `rhs`,
/// assuming that the elements have the same length.
pub(crate) fn ip_unsafe<F: Field, I, J>(lhs: I, rhs: J) -> F
where
    I: IntoIterator,
    J: IntoIterator,
    I::Item: Borrow<F>,
    J::Item: Borrow<F>,
{
    lhs.into_iter()
        .zip(rhs)
        .map(|(x, y)| *x.borrow() * y.borrow())
        .sum()
}

#[inline]
pub fn sum_matrices<F: Field>(
    a: &Matrix<F>,
    b: &Matrix<F>,
    c: &Matrix<F>,
    num_variables: usize,
) -> Vec<Vec<usize>> {
    let mut new_matrix = vec![BTreeSet::new(); num_variables];
    a.iter()
        .zip(b)
        .zip(c)
        .enumerate()
        .for_each(|(row, ((row_a, row_b), row_c))| {
            row_a
                .iter()
                .map(|(_, i)| *i)
                .chain(row_b.iter().map(|(_, i)| *i))
                .chain(row_c.iter().map(|(_, i)| *i))
                .for_each(|col| {
                    new_matrix[col].insert(row);
                });
        });
    let mut res = Vec::new();
    new_matrix
        .iter()
        .for_each(|set| res.push(set.iter().cloned().collect()));
    res
}

#[inline]
#[allow(unused)]
pub fn joint_matrices<F: Field>(
    joint_matrix: &[Vec<usize>],
    _num_constraints: usize,
    _num_variables: usize,
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
        .flat_map(|(r, row)| row.iter().map(move |(f, i)| ((r, *i), *f)))
        .collect::<BTreeMap<(usize, usize), F>>();

    let b = b
        .iter()
        .enumerate()
        .flat_map(|(r, row)| row.iter().map(move |(f, i)| ((r, *i), *f)))
        .collect::<BTreeMap<(usize, usize), F>>();

    let c = c
        .iter()
        .enumerate()
        .flat_map(|(r, row)| row.iter().map(move |(f, i)| ((r, *i), *f)))
        .collect::<BTreeMap<(usize, usize), F>>();

    for (cc, col) in joint_matrix.iter().enumerate() {
        for i in col {
            let row_val = F::from(*i as u64);
            let col_val = F::from(cc as u64);

            row_index_vec.push(*i);
            col_index_vec.push(cc);
            row_vec.push(row_val);
            col_vec.push(col_val);
            // We insert zeros if a matrix doesn't contain an entry at the given (row, col) location.
            val_a_vec.push(a.get(&(*i, cc)).copied().unwrap_or_else(F::zero));
            val_b_vec.push(b.get(&(*i, cc)).copied().unwrap_or_else(F::zero));
            val_c_vec.push(c.get(&(*i, cc)).copied().unwrap_or_else(F::zero));
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

/// Efficient evluation for polynomials of the form:
/// \\[
/// f(x) = \sum_{i = (b_0, \dots, b_n)} x^i \prod_j \text{elements}_j^{b_j}
/// \\]
#[inline]
pub fn evaluate_tensor_poly<F: Field>(elements: &[F], x: F) -> F {
    let mut res = F::one();
    let mut s = x;
    for element in elements {
        let tmp = F::one() + *element * s;
        res *= tmp;
        s = s.square();
    }
    res
}

/// Efficient evaluation for polynomials of the form:
/// 1 + rx x + rx^2 x^2 + rx^3 x^3 + rx^4 x^4 + ... + n rx^n.
#[inline]
pub fn evaluate_geometric_poly<F: Field>(rx: F, n: usize) -> F {
    (rx.pow(&[n as u64]) - F::one()) / (rx - F::one())
}

/// Efficient evaluation for polynomials of the form:
/// 0 + x + 2 x^2 + 3 x^3 + 4 x^4 + 5 x^5 + .. + n x^n.
#[inline]
pub fn evaluate_index_poly<F: Field>(x: F, n: usize) -> F {
    assert_ne!(F::one(), x);
    let x1 = F::one() - x;
    let x_n = x.pow(&[(n - 1) as u64]);
    x * (F::one() - x_n) / x1.square() - F::from((n - 1) as u64) * x_n * x / x1
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
    assert_eq!(got, expected);
    assert_eq!(linear_combination(&Vec::<Vec<Fr>>::new(), &Vec::<Fr>::new()), Vec::<Fr>::new());
}

#[test]
fn test_evaluate_index_poly() {
    use ark_bls12_381::Fr as F;
    use ark_ff::UniformRand;

    let rng = &mut ark_std::test_rng();
    let x = F::rand(rng);
    let n = 147;
    let index_polynomial = (0..n as u64).map(F::from).collect::<Vec<_>>();

    let got = evaluate_index_poly(x, n);
    let expected = evaluate_le(&index_polynomial, &x);
    assert_eq!(got, expected);
}

#[test]
fn test_multi_poly_decompose() {
    use crate::ark_std::Zero;
    use ark_bls12_381::Fr;
    let polynomial_small = vec![Fr::from(2_i32), Fr::from(3_i32)];
    let eval_point_small: Vec<Fr> = vec![Fr::from(6_i32)];
    let (quotients_small, remainder_small) =
        multi_poly_decompose(&polynomial_small, &eval_point_small);
    println!("testing small values");
    assert_eq!(quotients_small[0][0], Fr::from(3_i32));
    assert_eq!(remainder_small, Fr::from(20_i32));
    println!("testing random values");
    let reps = 3;
    let dim = 12;
    let rng = &mut ark_std::test_rng();
    let polynomial: Vec<Fr> = random_vector(1 << dim, rng);
    let eval_point: Vec<Fr> = random_vector(dim, rng);

    let (quotients, remainder) = multi_poly_decompose(&polynomial, &eval_point);
    for _ in 0..reps {
        let test_point: Vec<Fr> = random_unique_vector(dim, rng);
        let mut sum = Fr::zero();
        for (idx, quotient) in quotients.iter().enumerate() {
            let eval_quotient = evaluate_multi_poly(quotient, &test_point);

            // sum (q_i(x) * (x_i - alpha_i)) + remainder = f(x)
            sum += eval_quotient * (test_point[idx] - eval_point[idx]);
        }
        assert_eq!(
            sum + remainder,
            evaluate_multi_poly(&polynomial, &test_point)
        );
    }
}
