//! Stream implementation for Rust slice.
use super::Iterable;

/// Reversed stream for Rust slice.
/// It outputs elements in the slice in reversed order.
#[derive(Clone, Copy)]
pub struct Reverse<I>(pub I)
where
    I: Iterable,
    I::Iter: DoubleEndedIterator;

impl<I> Iterable for Reverse<I>
where
    I: Iterable,
    I::Iter: DoubleEndedIterator,
{
    type Item = I::Item;
    type Iter = ark_std::iter::Rev<I::Iter>;

    #[inline]
    fn iter(&self) -> Self::Iter {
        self.0.iter().rev()
    }

    #[inline]
    fn len(&self) -> usize {
        self.0.len()
    }
}

// So my understa
pub struct IterableRange(pub usize);

impl Iterable for IterableRange {
    type Item = usize;
    type Iter = ark_std::iter::Rev<ark_std::ops::Range<usize>>;

    fn iter(&self) -> Self::Iter {
        (0..self.0).into_iter().rev()
    }

    fn len(&self) -> usize {
        self.0
    }
}
