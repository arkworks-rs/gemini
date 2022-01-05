use crate::iterable::Iterable;
use ark_std::borrow::Borrow;

#[derive(Clone, Copy)]
pub struct MergeStream<'a, S0, S1> {
    lhs: &'a S0,
    rhs: &'a S1,
}

pub struct MergeStreamIter<I0, I1>
where
    I0: Iterator,
    I1: Iterator,
{
    lhs: I0,
    rhs: I1,
    current_lhs: Option<I0::Item>,
    current_rhs: Option<I1::Item>,
}

impl<'a, S0, S1> MergeStream<'a, S0, S1>
where
    S0: Iterable,
    S1: Iterable,
    S0::Item: Borrow<S0::Item>,
    S1::Item: Borrow<S1::Item>,
{
    pub fn new(lhs: &'a S0, rhs: &'a S1) -> Self {
        Self { lhs, rhs }
    }
}

impl<'a, S0, S1> Iterable for MergeStream<'a, S0, S1>
where
    S0: Iterable,
    S1: Iterable,
    S0::Item: Borrow<usize>,
    S1::Item: Borrow<usize>,
{
    type Item = usize;

    type Iter = MergeStreamIter<S0::Iter, S1::Iter>;

    fn iter(&self) -> Self::Iter {
        let mut lhs = self.lhs.iter();
        let mut rhs = self.rhs.iter();

        let current_lhs = lhs.next();
        let current_rhs = rhs.next();

        Self::Iter {
            lhs,
            rhs,
            current_lhs,
            current_rhs,
        }
    }

    fn len(&self) -> usize {
        usize::max(self.lhs.len(), self.rhs.len())
    }
}

impl<'a, I0, I1> Iterator for MergeStreamIter<I0, I1>
where
    I0: Iterator,
    I1: Iterator,
    I0::Item: Borrow<usize>,
    I1::Item: Borrow<usize>,
{
    type Item = usize;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let a = self.current_lhs.take();
        let b = self.current_rhs.take();

        match (a, b) {
            (None, None) => None,
            (Some(e), None) => Some(*e.borrow()),
            (None, Some(e)) => Some(*e.borrow()),
            (Some(a), Some(b)) => match a.borrow().cmp(b.borrow()) {
                std::cmp::Ordering::Equal => {
                    self.current_lhs = self.lhs.next();
                    self.current_rhs = self.rhs.next();
                    Some(*a.borrow())
                }
                std::cmp::Ordering::Less => {
                    self.current_rhs = self.rhs.next();
                    Some(*b.borrow())
                }
                std::cmp::Ordering::Greater => {
                    self.current_lhs = self.lhs.next();
                    Some(*a.borrow())
                }
            },
        }
    }
}
