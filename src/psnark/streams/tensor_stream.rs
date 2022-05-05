use ark_ff::{BitIteratorLE, Field};
use ark_std::borrow::Borrow;
use ark_std::vec::Vec;

use crate::iterable::Iterable;
use crate::misc::{expand_tensor, PartialTensor, TENSOR_EXPANSION, TENSOR_EXPANSION_LOG};

const T: usize = TENSOR_EXPANSION;

pub struct TensorIter<F: Field> {
    /// The carry elements that determine the next element.
    carries: Vec<F>,
    /// The elements constituting the tensor product.
    /// This attribute is needed only for fast-forwarding to another position.
    elements: Vec<F>,
    /// The last element produced by the iterator.
    current: F,
    /// The last index produced by the iterator.
    current_index: u64,
}

impl<F: Field> TensorIter<F> {
    /// Create a new Tensoriterator starting from index start_index.
    pub fn new(tensor: &[F]) -> Self {
        let mut inverses = tensor.to_vec();
        ark_ff::batch_inversion(&mut inverses);

        let mut accumulated_product = F::one();
        let mut carries = Vec::new();
        for (elt, inv_elt) in tensor.iter().zip(inverses) {
            // the i-th carry is setting the i-th bit to zero and all successive bits to one.
            carries.push(accumulated_product * inv_elt);
            accumulated_product *= elt;
        }
        // the most significant (artificial) carry, to multiply when all bits are set,
        // is the inverse of 1 times the product of all elements.
        carries.push(accumulated_product);

        Self {
            carries,
            elements: tensor.to_vec(),
            current: F::one(),
            current_index: 1 << tensor.len(),
        }
    }
}

impl<F: Field> Iterator for TensorIter<F> {
    type Item = F;

    fn next(&mut self) -> Option<Self::Item> {
        // Find the least significant bit set in the current index (that must be decremented).
        // If no such bit is found, then `self.current_index` must be 0 and thus we should return None.
        // Otherwise, decrement `self.current_index`, and produce the next element of the stream.
        BitIteratorLE::new(&[self.current_index])
            .position(|x| x)
            .map(|nz_lsb_index| {
                // nz_lsb index is the index of
                self.current_index -= 1;
                self.current *= self.carries[nz_lsb_index];
                self.current
            })
    }

    fn advance_by(&mut self, n: usize) -> Result<(), usize> {
        // XXX:throw the error appropriatedly
        self.current_index -= n as u64;
        self.current = BitIteratorLE::new(&[self.current_index])
            .zip(&self.elements)
            .filter_map(|(bit, &elt)| bit.then(|| elt))
            .product();
        Ok(())
    }
}

#[test]
fn test_tensoriter() {
    use crate::misc::tensor;
    use ark_bls12_381::Fr as F;
    use ark_std::{test_rng, UniformRand};

    let rng = &mut test_rng();
    let challenges = (0..10).map(|_| F::rand(rng)).collect::<Vec<_>>();
    let expected = tensor(&challenges);
    let mut got = TensorIter::new(&challenges).collect::<Vec<_>>();
    got.reverse();
    assert_eq!(got, expected);
}

#[derive(Clone)]
pub struct Tensor<'a, F>(pub &'a [F])
where
    F: Field;

impl<'a, F> Iterable for Tensor<'a, F>
where
    F: Field,
{
    type Item = F;
    type Iter = TensorIter<F>;

    fn iter(&self) -> Self::Iter {
        TensorIter::new(self.0)
    }

    fn len(&self) -> usize {
        1 << self.0.len()
    }
}

#[derive(Clone)]
pub struct LookupTensorStreamer<'a, F, S>
where
    F: Field,
    S: Iterable,
    S::Item: Borrow<usize>,
{
    tensor: PartialTensor<F>,
    index: &'a S,
}

pub struct TensorIIter<F, I>
where
    F: Field,
    I: Iterator,
    I::Item: Borrow<usize>,
{
    index: I,
    tensor: PartialTensor<F>,
}
impl<'a, F, S> LookupTensorStreamer<'a, F, S>
where
    F: Field,
    S: Iterable,
    S::Item: Borrow<usize>,
{
    pub fn new(v: &[F], index: &'a S) -> Self {
        let tensor = expand_tensor(v);
        Self { tensor, index }
    }
}

impl<'a, F, S> Iterable for LookupTensorStreamer<'a, F, S>
where
    F: Field,
    S: Iterable,
    S::Item: Borrow<usize>,
{
    type Item = F;
    type Iter = TensorIIter<F, S::Iter>;

    fn iter(&self) -> Self::Iter {
        Self::Iter {
            index: self.index.iter(),
            tensor: self.tensor.clone(),
        }
    }

    fn len(&self) -> usize {
        self.index.len()
    }
}

impl<'a, F, I> Iterator for TensorIIter<F, I>
where
    F: Field,
    I: Iterator,
    I::Item: Borrow<usize>,
{
    type Item = F;

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        let index = *self.index.next()?.borrow();
        let mut value = F::one();
        for (i, r) in self.tensor.iter().enumerate() {
            let selection_index = (index >> (i * TENSOR_EXPANSION_LOG)) & T;
            if selection_index != 0 {
                value *= r[selection_index - 1];
            }
        }
        Some(value)
    }

    fn advance_by(&mut self, n: usize) -> Result<(), usize> {
        self.index.advance_by(n)
    }
}

#[test]
fn test_tensor() {
    use crate::misc::powers;
    use ark_bls12_381::Fr;
    use ark_ff::One;
    use ark_std::test_rng;
    use ark_std::vec::Vec;
    use ark_std::UniformRand;

    let rng = &mut test_rng();
    let a = Fr::rand(rng);

    let v = [
        a,
        a.square(),
        a.square().square(),
        a.square().square().square(),
    ];
    let len = 1 << v.len();
    let tensor_streamer = Tensor(&v);
    let mut tensor = tensor_streamer.iter().collect::<Vec<_>>();
    tensor.reverse();

    assert_eq!(tensor[0], Fr::one());

    let expected = powers(a, len);
    assert_eq!(expected[1], tensor[1]);
    assert_eq!(tensor, expected);
}
