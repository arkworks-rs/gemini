use ark_ff::Field;
use ark_std::borrow::Borrow;

use crate::iterable::Iterable;

pub struct AlgebraicHash<'a, F, EltS, IdxS> {
    chal: F,
    elt_stream: &'a EltS,
    idx_stream: &'a IdxS,
}

pub struct AlgebraicHashIterator<EltI, IdxI, F> {
    elt_it: EltI,
    idx_it: IdxI,
    chal: F,
}

impl<'a, F, EltS, IdxS> AlgebraicHash<'a, F, EltS, IdxS>
where
    IdxS: Iterable,
    IdxS::Item: Borrow<usize>,
    EltS: Iterable,
    EltS::Item: Borrow<F>,
    F: Field,
{
    pub fn new(elt_stream: &'a EltS, idx_stream: &'a IdxS, chal: F) -> Self {
        // assert_eq!(elt_stream.len(), idx_stream.len());
        Self {
            elt_stream,
            idx_stream,
            chal,
        }
    }
}

impl<'a, F, EltS, IdxS> Iterable for AlgebraicHash<'a, F, EltS, IdxS>
where
    IdxS: Iterable,
    IdxS::Item: Borrow<usize>,
    EltS: Iterable,
    EltS::Item: Borrow<F>,
    F: Field,
{
    type Item = F;

    type Iter = AlgebraicHashIterator<EltS::Iter, IdxS::Iter, F>;

    fn iter(&self) -> Self::Iter {
        let elt_it = self.elt_stream.iter();
        let idx_it = self.idx_stream.iter();
        let chal = self.chal;
        AlgebraicHashIterator {
            elt_it,
            idx_it,
            chal,
        }
    }

    fn len(&self) -> usize {
        self.elt_stream.len()
    }
}

impl<EltI, IdxI, F> Iterator for AlgebraicHashIterator<EltI, IdxI, F>
where
    IdxI: Iterator,
    IdxI::Item: Borrow<usize>,
    EltI: Iterator,
    EltI::Item: Borrow<F>,
    F: Field,
{
    type Item = F;

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        let index = self.idx_it.next()?;
        let index = *index.borrow() as u64;
        let element = self.elt_it.next()?;
        Some(self.chal * F::from(index) + element.borrow())
    }
}
