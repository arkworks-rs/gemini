use ark_ff::Field;

use crate::misc::{PartialTensor, TENSOR_EXPANSION, TENSOR_EXPANSION_LOG};
use crate::iterable::Iterable;

const T: usize = TENSOR_EXPANSION;

#[derive(Clone, Copy)]
pub struct TensorStreamer<'a, F>
where
    F: Field,
{
    tensor: &'a PartialTensor<F>,
    len: usize,
}

pub struct TensorIter<'a, F>
where
    F: Field,
{
    tensor: &'a PartialTensor<F>,
    index: usize,
}
impl<'a, F> TensorStreamer<'a, F>
where
    F: Field,
{
    pub fn new(tensor: &'a PartialTensor<F>, len: usize) -> Self {
        Self { tensor, len }
    }
}

impl<'a, F> Iterable for TensorStreamer<'a, F>
where
    F: Field,
{
    type Item = F;
    type Iter = TensorIter<'a, F>;

    fn iter(&self) -> Self::Iter {
        TensorIter {
            index: self.len(),
            tensor: self.tensor,
        }
    }

    fn len(&self) -> usize {
        self.len
    }
}

impl<'a, F> Iterator for TensorIter<'a, F>
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

//////////////////////////////////////////////\

use ark_std::borrow::Borrow;

#[derive(Clone, Copy)]
pub struct TensorIStreamer<'a, F, S>
where
    F: Field,
    S: Iterable,
    S::Item: Borrow<usize>,
{
    tensor: &'a PartialTensor<F>,
    index: S,
    len: usize,
}

pub struct TensorIIter<'a, F, I>
where
    F: Field,
    I: Iterator,
    I::Item: Borrow<usize>,
{
    index: I,
    tensor: &'a PartialTensor<F>,
}
impl<'a, F, S> TensorIStreamer<'a, F, S>
where
    F: Field,
    S: Iterable,
    S::Item: Borrow<usize>,
{
    pub fn new(tensor: &'a PartialTensor<F>, index: S, len: usize) -> Self {
        Self { tensor, index, len }
    }
}

impl<'a, F, S> Iterable for TensorIStreamer<'a, F, S>
where
    F: Field,
    S: Iterable,
    S::Item: Borrow<usize>,
{
    type Item = F;
    type Iter = TensorIIter<'a, F, S::Iter>;

    fn iter(&self) -> Self::Iter {
        Self::Iter {
            index: self.index.iter(),
            tensor: self.tensor,
        }
    }

    fn len(&self) -> usize {
        self.len
    }
}

impl<'a, F, I> Iterator for TensorIIter<'a, F, I>
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
    use crate::misc::{expand_tensor, powers};
    use ark_bls12_381::Fr;
    use ark_ff::One;
    use ark_std::test_rng;
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
    let v = expand_tensor(&v);
    let tensor_streamer = TensorStreamer::new(&v, len);
    let mut tensor = tensor_streamer.iter().collect::<Vec<_>>();
    tensor.reverse();

    assert_eq!(tensor[0], Fr::one());

    let expected = powers(a, len);
    assert_eq!(expected[1], tensor[1]);
    assert_eq!(tensor, expected);
}
