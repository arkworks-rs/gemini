use std::marker::PhantomData;

use crate::{misc::MatrixElement, iterable::Iterable};
use ark_ff::Field;
use ark_std::borrow::Borrow;

#[derive(Clone, Copy)]
pub struct IndexStream<S, T> {
    matrix: S,
    _t: PhantomData<T>,
}

pub struct IndexIter<I, T> {
    matrix_stream: I,
    _t: PhantomData<T>,
}

impl<S, T> IndexStream<S, T>
where
    S: Iterable,
    S::Item: Borrow<MatrixElement<T>>,
    T: Field,
{
    pub fn new(matrix: S) -> Self {
        let _t = PhantomData;
        Self { matrix, _t }
    }
}

impl<S, T> Iterable for IndexStream<S, T>
where
    S: Iterable,
    S::Item: Borrow<MatrixElement<T>>,
    T: Field,
{
    type Item = usize;

    type Iter = IndexIter<S::Iter, T>;

    fn iter(&self) -> Self::Iter {
        let matrix_stream = self.matrix.iter();
        let _t = PhantomData;
        IndexIter { matrix_stream, _t }
    }

    fn len(&self) -> usize {
        // XXXX. I am assuming here that the matrix stream returns the number of non-zero entries. Hope this does not create a problem.
        self.matrix.len()
    }
}

impl<I, T> Iterator for IndexIter<I, T>
where
    I: Iterator,
    I::Item: Borrow<MatrixElement<T>>,
    T: Field,
{
    type Item = usize;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let e = self.matrix_stream.next();
            if e.is_none() {
                return None;
            } else if let Some(e) = e {
                match *e.borrow() {
                    MatrixElement::EOL => continue,
                    MatrixElement::Element((_value, index)) => return Some(index),
                }
            }
        }
    }
}

#[test]
fn test_index_stream() {
    use crate::iterable::dummy::DiagonalMatrixStreamer;
    use ark_bls12_381::Fr as F;
    use ark_ff::One;

    let n: usize = 1200;
    let matrix = DiagonalMatrixStreamer::new(F::one(), n);
    let index_stream = IndexStream::new(matrix);
    let indices = index_stream.iter().collect::<Vec<_>>();
    assert_eq!(indices.last(), Some(&0));
    assert_eq!(indices.len(), n);
}
