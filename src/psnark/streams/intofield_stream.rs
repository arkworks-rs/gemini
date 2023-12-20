use core::num::NonZeroUsize;

use ark_ff::Field;
use ark_std::borrow::Borrow;
use ark_std::marker::PhantomData;

use crate::iterable::Iterable;

pub struct IntoField<'a, S, F> {
    iterable: &'a S,
    _field: PhantomData<F>,
}

pub struct IntoFieldIter<I, F> {
    it: I,
    _field: PhantomData<F>,
}

impl<I, F> Iterator for IntoFieldIter<I, F>
where
    I: Iterator,
    I::Item: Borrow<usize>,
    F: Field,
{
    type Item = F;

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        // self.it.next().map(|x| F::from(2u64).pow(&[*x.borrow() as u64]))
        self.it.next().map(|x| F::from(*x.borrow() as u64))
    }

    fn advance_by(&mut self, n: usize) -> Result<(), NonZeroUsize> {
        self.it.advance_by(n)
    }
}

impl<'a, S, F> IntoField<'a, S, F>
where
    S: Iterable,
    F: Field,
    S::Item: Borrow<usize>,
{
    pub(crate) fn new(iterable: &'a S) -> Self {
        Self {
            iterable,
            _field: PhantomData,
        }
    }
}

impl<'a, S, F> Iterable for IntoField<'a, S, F>
where
    S: Iterable,
    F: Field,
    S::Item: Borrow<usize>,
{
    type Item = F;

    type Iter = IntoFieldIter<S::Iter, F>;

    #[inline]
    fn iter(&self) -> Self::Iter {
        Self::Iter {
            it: self.iterable.iter(),
            _field: PhantomData,
        }
    }

    #[inline]
    fn len(&self) -> usize {
        self.iterable.len()
    }
}
