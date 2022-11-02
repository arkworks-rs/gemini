use ark_ff::Field;
use ark_std::borrow::Borrow;
use ark_std::vec::Vec;

use crate::iterable::Iterable;

/// A `Streamer` that repeatedly divides an n dimensional multilinear polynomial with binomial terms
/// of the form \\((x_i - \alpha_i)\\), for some n dimensional \\(\alpha\\).
/// Produces a stream that describes \\(q_i\\) where \\(\sum_i{q_i(x)(x_i - \alpha_i)} + f(\alpha)\\)
/// Outputs pairs of the form \\((i, x)\\), where \\(i\\) is which quotient is being referred to,
/// and \\(x\\) is the next nonzero coefficient in that quotient. Coefficients are outputted in order.
///
/// There is a special case at the end, where \\(i\\) is equal to the dimension of the polynomial.
/// Then, the corresponding \\(x\\) is the evaluation of the polynomial at \\(\alpha\\).
///
/// The stream can produce all quotient coefficients in the tree with a single pass over the initial stream.
#[derive(Clone, Copy)]
pub struct MultiPolynomialTree<'a, F, S> {
    eval_point: &'a [F],
    coefficients: &'a S,
}

impl<'a, F, S> MultiPolynomialTree<'a, F, S>
where
    S: Iterable,
    F: Field,
    S::Item: Borrow<F>,
{
    /// Initialize a new polynomial tree.
    pub fn new(coefficients: &'a S, eval_point: &'a [F]) -> Self {
        Self {
            coefficients,
            eval_point,
        }
    }

    /// Outputs the depth of the polynomial tree.
    #[inline]
    pub fn depth(&self) -> usize {
        self.eval_point.len()
    }
}

impl<'a, F, S> Iterable for MultiPolynomialTree<'a, F, S>
where
    S: Iterable,
    F: Field,
    S::Item: Borrow<F>,
{
    type Item = (usize, F);

    type Iter = MultiPolynomialTreeIter<'a, F, S::Iter>;

    fn iter(&self) -> Self::Iter {
        MultiPolynomialTreeIter::new(
            self.coefficients.iter(),
            self.coefficients.len(),
            self.eval_point,
        )
    }

    fn len(&self) -> usize {
        self.coefficients.len()
    }
}

/// Iterator of the polynomial division tree.
pub struct MultiPolynomialTreeIter<'a, F, I> {
    eval_point: &'a [F],
    iterator: I,
    stack: Vec<(usize, F)>,
    parities: Vec<bool>,
}

fn init_stack<F: Field>(n: usize, dim: usize) -> Vec<(usize, F)> {
    let mut stack = Vec::with_capacity(dim);

    // generally we expect the size to be a power of two.
    // If not, we are going to fill the stack as if the array was padded to zero up to the expected size.
    let chunk_size = 1 << dim;
    if n % chunk_size != 0 {
        let mut delta = chunk_size - n % chunk_size;
        for i in (0..dim).rev() {
            if delta >= 1 << i {
                stack.push((i, F::zero()));
                delta -= 1 << i
            }
        }
    }
    stack
}

impl<'a, F, I> MultiPolynomialTreeIter<'a, F, I>
where
    F: Field,
    I: Iterator,
    I::Item: Borrow<F>,
{
    fn new(iterator: I, n: usize, eval_point: &'a [F]) -> Self {
        let stack = init_stack(n, eval_point.len());
        let parities = vec![false; eval_point.len()];

        Self {
            eval_point,
            iterator,
            stack,
            parities,
        }
    }
}

/// Each time we call next, a tuple (i, x) means that the next nonzero coefficient in the
/// i'th quotient is x. Note that the 0'th quotient has nonzero coeffients at the 0, 2, 4, ... indices,
/// the 1'th quotient has nonzero coefficients at the 0, 4, 8, ... indices, and so on.
///
impl<'a, F, I> Iterator for MultiPolynomialTreeIter<'a, F, I>
where
    F: Field,
    I: Iterator,
    I::Item: Borrow<F>,
{
    type Item = (usize, F);

    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        let len = self.stack.len();
        let stack_item = if len > 1 && self.stack[len - 1].0 == self.stack[len - 2].0 {
            // pop the last two elements from the stack.
            // we could also use .pop() twice but truncate is slightly faster.
            let (_level, lhs) = self.stack[len - 1];
            let (level, rhs) = self.stack[len - 2];
            self.stack.truncate(len - 2);

            let folded_coefficient = lhs * self.eval_point[level] + rhs;
            (level + 1, folded_coefficient)
        } else {
            (0, *self.iterator.next()?.borrow())
        };

        // do not add to the stack the coefficient of the max-depth folded polynomial.
        // instead, just return it as is.
        if stack_item.0 != self.eval_point.len() {
            self.stack.push(stack_item)
        } else {
            return Some(stack_item);
        }
        // for each quotient, only yield every other coefficient.
        self.parities[stack_item.0] = !self.parities[stack_item.0];
        if self.parities[stack_item.0] {
            self.next()
        } else {
            Some(stack_item)
        }
    }
}

#[test]
fn test_polynomial_divide_randomized() {
    use crate::misc::{evaluate_multi_poly, mul_components, random_vector};
    use ark_bls12_381::Fr as F;
    use ark_ff::Zero;

    let dim = 4;
    let rng = &mut ark_std::test_rng();
    let coefficients: Vec<F> = random_vector(1 << dim, rng);
    let alpha: Vec<F> = random_vector(dim, rng); // the evaluation point
    let test_point: Vec<F> = random_vector(dim, rng);
    let coefficients_stream = coefficients.as_slice();
    let foldstream = MultiPolynomialTree::new(&coefficients_stream, alpha.as_slice());
    let mut result = F::zero();
    let alpha_eval = evaluate_multi_poly(&coefficients, &alpha);
    let mut quotient_evals: Vec<F> = vec![F::zero(); dim];
    let mut quotient_idxs = vec![0; dim];
    for (quotient_num, quotient_coefficient) in foldstream.iter() {
        if quotient_num != dim {
            quotient_evals[quotient_num] +=
                quotient_coefficient * mul_components(&test_point, quotient_idxs[quotient_num]);
            quotient_idxs[quotient_num] += 1 << (quotient_num + 1);
        } else {
            assert_eq!(quotient_coefficient, alpha_eval);
        }
    }
    for i in 0..dim {
        result += quotient_evals[i] * (test_point[i] - alpha[i])
    }
    assert_eq!(
        result,
        evaluate_multi_poly(&coefficients, &test_point) - alpha_eval
    );
}
