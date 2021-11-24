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

#[derive(Clone, Copy)]
pub struct Reversed<'a, T>(&'a [T]);

impl<'a, T> Reversed<'a, T> {
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
