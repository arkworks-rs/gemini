use ark_ff::Field;
use ark_std::borrow::Borrow;

use crate::iterable::Iterable;
use crate::misc::{expand_tensor, PartialTensor, TENSOR_EXPANSION, TENSOR_EXPANSION_LOG};

const T: usize = TENSOR_EXPANSION;

#[derive(Clone)]
pub struct TensorStreamer<F>
where
    F: Field,
{
    tensor: PartialTensor<F>,
    len: usize,
}

pub struct TensorIter<F>
where
    F: Field,
{
    tensor: PartialTensor<F>,
    index: usize,
}
impl<F> TensorStreamer<F>
where
    F: Field,
{
    pub fn new(v: &[F], len: usize) -> Self {
        let tensor = expand_tensor(v);
        Self { tensor, len }
    }
}

impl<F> Iterable for TensorStreamer<F>
where
    F: Field,
{
    type Item = F;
    type Iter = TensorIter<F>;

    fn iter(&self) -> Self::Iter {
        TensorIter {
            index: self.len(),
            tensor: self.tensor.clone(),
        }
    }

    fn len(&self) -> usize {
        self.len
    }
}

impl<F> Iterator for TensorIter<F>
where
    F: Field,
{
    type Item = F;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.index == 0 {
            None
        } else {
            self.index -= 1;
            let mut value = F::one();
            for (i, r) in self.tensor.iter().enumerate() {
                let selection_index = (self.index >> (i * TENSOR_EXPANSION_LOG)) & T;
                if selection_index != 0 {
                    value *= r[selection_index - 1];
                }
            }
            Some(value)
        }
    }

    fn advance_by(&mut self, n: usize) -> Result<(), usize> {
        self.index -= n;
        Ok(())
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

    #[inline]
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
    let tensor_streamer = TensorStreamer::new(&v, len);
    let mut tensor = tensor_streamer.iter().collect::<Vec<_>>();
    tensor.reverse();

    assert_eq!(tensor[0], Fr::one());

    let expected = powers(a, len);
    assert_eq!(expected[1], tensor[1]);
    assert_eq!(tensor, expected);
}
