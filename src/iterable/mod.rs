//! The streaming model is essentially implemented as a wrapper around an iterator,
//! with one additional method for obtaining the length.
//!
//!

// DummyStream
pub mod dummy;
mod slice;

pub use slice::Reversed;

/// The trait representing a streamable object.
pub trait Iterable {
    /// The type of the element being streamed.
    type Item;
    /// The type of the iterator being generated.
    type Iter: Iterator<Item = Self::Item>;

    // Returns an iterator of type `Iter`.
    fn iter(&self) -> Self::Iter;

    /// Return the length of the stream.
    /// Careful: different objects might have different indications of what _length_ means;
    /// this might not be the actual size in terms of elements.
    fn len(&self) -> usize;

    /// Return `true` if the stream is empty, else `false`.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<I: IntoIterator + Copy> Iterable for I {
    type Item = <I as IntoIterator>::Item;
    type Iter = <I as IntoIterator>::IntoIter;

    fn iter(&self) -> Self::Iter {
        self.into_iter()
    }

    fn len(&self) -> usize {
        self.into_iter().size_hint().0
    }
}
