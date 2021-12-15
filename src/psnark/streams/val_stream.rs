use crate::misc::MatrixElement;
use crate::iterable::Iterable;
use ark_ff::Field;
use ark_std::borrow::Borrow;
use ark_std::marker::PhantomData;

#[derive(Clone, Copy)]
pub struct ValStream<F, S> {
    matrix: S,
    nonzero: usize,
    _field: PhantomData<F>,
}

pub struct ValStreamIter<F, I> {
    matrix_iter: I,
    _field: PhantomData<F>,
}

impl<F, S> ValStream<F, S>
where
    S: Iterable,
    S::Item: Borrow<MatrixElement<F>>,
    F: Field,
{
    pub fn new(matrix: S, nonzero: usize) -> Self {
        Self {
            matrix,
            nonzero,
            _field: PhantomData,
        }
    }
}
impl<F, S> Iterable for ValStream<F, S>
where
    S: Iterable,
    S::Item: Borrow<MatrixElement<F>>,
    F: Field,
{
    type Item = F;

    type Iter = ValStreamIter<F, S::Iter>;

    fn iter(&self) -> Self::Iter {
        let matrix_iter = self.matrix.iter();
        let _field = PhantomData;
        ValStreamIter {
            matrix_iter,
            _field,
        }
    }

    fn len(&self) -> usize {
        self.nonzero
    }
}

impl<F, I> Iterator for ValStreamIter<F, I>
where
    I: Iterator,
    I::Item: Borrow<MatrixElement<F>>,
    F: Field,
{
    type Item = F;
    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        loop {
            let e = self.matrix_iter.next();
            if e.is_none() {
                return None;
            } else if let Some(e) = e {
                match *e.borrow() {
                    MatrixElement::EOL => continue,
                    MatrixElement::Element((e, _i)) => return Some(e),
                }
            }
        }
    }
}
