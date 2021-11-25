//! Stream implementation for Rust slice.
use ark_std::iter::Rev;

use super::Streamer;

impl<'a, T> Streamer for &'a [T] {
    type Item = &'a T;
    type Iter = std::slice::Iter<'a, T>;

    #[inline]
    fn stream(&self) -> Self::Iter {
        self.iter()
    }

    #[inline]
    fn len(&self) -> usize {
        <[T]>::len(self)
    }
}

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

impl<'a, T> Streamer for Reversed<'a, T>
where
    T: Copy,
{
    type Item = &'a T;

    type Iter = Rev<std::slice::Iter<'a, T>>;

    #[inline]
    fn stream(&self) -> Self::Iter {
        self.0.iter().rev()
    }

    #[inline]
    fn len(&self) -> usize {
        self.0.len()
    }
}
