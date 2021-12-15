use std::marker::PhantomData;

use crate::{misc::MatrixElement, iterable::Iterable};
use ark_ff::Field;
use ark_std::borrow::Borrow;

#[derive(Clone, Copy)]
pub struct LineStream<S, T> {
    matrix: S,
    _t: PhantomData<T>,
}

pub struct LineIter<I, T> {
    matrix_stream: I,
    count: usize,
    _t: PhantomData<T>,
}

impl<S, T> LineStream<S, T>
where
    S: Iterable,
    S::Item: Borrow<MatrixElement<T>>,
    T: ark_ff::Field,
{
    pub fn new(matrix: S) -> Self {
        let _t = PhantomData;
        Self { matrix, _t }
    }
}

impl<S, T> Iterable for LineStream<S, T>
where
    S: Iterable,
    S::Item: Borrow<MatrixElement<T>>,
    T: ark_ff::Field,
{
    type Item = usize;

    type Iter = LineIter<S::Iter, T>;

    fn iter(&self) -> Self::Iter {
        let matrix_stream = self.matrix.iter();
        let _t = PhantomData;
        // XXX: here we assume that the number of lines is the same as the number of non-zero entries.
        let count = self.matrix.len();
        Self::Iter {
            matrix_stream,
            count,
            _t,
        }
    }

    fn len(&self) -> usize {
        // XXX: here we assume that the number of lines is the same as the number of non-zero entries.
        self.matrix.len()
    }
}

impl<I, T> Iterator for LineIter<I, T>
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
                    MatrixElement::EOL => self.count -= 1,
                    MatrixElement::Element((_value, _index)) => return Some(self.count - 1),
                }
            }
        }
    }
}

#[test]
fn test_line_stream() {
    use crate::iterable::dummy::DiagonalMatrixStreamer;
    use ark_bls12_381::Fr as F;
    use ark_ff::One;

    let n: usize = 1200;
    let matrix = DiagonalMatrixStreamer::new(F::one(), n);
    let index_stream = LineStream::new(matrix);
    let indices = index_stream.iter().collect::<Vec<_>>();
    assert_eq!(indices.last(), Some(&0));
    assert_eq!(indices.len(), n);
}
