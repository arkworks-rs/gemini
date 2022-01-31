//! Stream implementation for Rust slice.
use super::Iterable;

/// Reversed stream for Rust slice.
/// It outputs elements in the slice in reversed order.
#[derive(Clone, Copy)]
pub struct Reversed<'a, T>(&'a [T]);

impl<'a, T> Reversed<'a, T> {
    /// Initialize a new stream for the slice.
    pub fn new(slice: &'a [T]) -> Self {
        Self(slice)
    }
}

impl<'a, T> Iterable for Reversed<'a, T>
where
    T: Copy,
{
    type Item = &'a T;

    type Iter = ark_std::iter::Rev<std::slice::Iter<'a, T>>;

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
