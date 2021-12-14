use ark_ff::Field;
use ark_std::borrow::Borrow;

use crate::stream::Streamer;

struct AlgebraicHash<'a, F, EltS, IdxS> {
    chal: F,
    elt_stream: &'a EltS,
    idx_stream: &'a IdxS,
}

struct AlgebraicHashIterator<EltI, IdxI, F> {
    elt_it: EltI,
    idx_it: IdxI,
    chal: F,
}

impl<'a, F, EltS, IdxS> AlgebraicHash<'a, F, EltS, IdxS>
where
    IdxS: Streamer,
    IdxS::Item: Borrow<usize>,
    EltS: Streamer,
    EltS::Item: Borrow<F>,
    F: Field,
{
    fn new(elt_stream: &'a EltS, idx_stream: &'a IdxS, chal: F) -> Self {
        assert_eq!(elt_stream.len(), idx_stream.len());
        Self {
            elt_stream,
            idx_stream,
            chal,
        }
    }
}

impl<'a, F, EltS, IdxS> Streamer for AlgebraicHash<'a, F, EltS, IdxS>
where
    IdxS: Streamer,
    IdxS::Item: Borrow<usize>,
    EltS: Streamer,
    EltS::Item: Borrow<F>,
    F: Field,
{
    type Item = F;

    type Iter = AlgebraicHashIterator<EltS::Iter, IdxS::Iter, F>;

    fn stream(&self) -> Self::Iter {
        let elt_it = self.elt_stream.stream();
        let idx_it = self.idx_stream.stream();
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
        Some(F::from(index) + self.chal * element.borrow())
    }
}

