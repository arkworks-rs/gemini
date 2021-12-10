//!
//! The streaming model is essentially implemented as a wrapper around an iterator,
//! with one additional method for obtaining the length.
//!
//! Streams must be [Copy][std::marker::Copy].
//! This is necessary in order to compose streams and return them from subroutines,
//! as well as starting multiple streams of the same object at once.
use std::marker::PhantomData;

use ark_ff::Field;
use memmap::Mmap;

// DummyStream
pub mod dummy;
mod slice;

pub use slice::Reversed;

/// The trait representing a streamable object.
pub trait Streamer {
    type Item;
    type Iter: Iterator<Item = Self::Item>;

    /// Return a new stream for the given object.
    fn stream(&self) -> Self::Iter;

    /// Return the length of the stream.
    /// Careful: different objects might have different indications of what _length_ means;
    /// this might not be the actual size in terms of elements.
    fn len(&self) -> usize;

    /// Return `true` if the stream is empty, else `false`.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<S: Streamer + ?Sized> Streamer for Box<S> {
    type Item = S::Item;
    type Iter = S::Iter;

    /// Return a new stream for the given object.
    fn stream(&self) -> Self::Iter {
        todo!()
    }

    /// Return the length of the stream.
    /// Careful: different objects might have different indications of what _length_ means;
    /// this might not be the actual size in terms of elements.
    fn len(&self) -> usize {
        todo!()
    }

    /// Return `true` if the stream is empty, else `false`.
    fn is_empty(&self) -> bool {
        todo!()
    }
}

/// A memory-mapped buffer for field elements.
#[derive(Clone, Copy)]
pub struct FieldMmap<'a, F>
where
    F: Field,
{
    mmap: &'a Mmap,
    _field: PhantomData<F>,
}

impl<'a, F> FieldMmap<'a, F>
where
    F: Field,
{
    /// Initialize a new memory map buffer.
    pub fn new(mmap: &'a Mmap) -> Self {
        Self {
            mmap,
            _field: PhantomData,
        }
    }
}

impl<'a, F> Streamer for FieldMmap<'a, F>
where
    F: Field,
{
    type Item = &'a F;

    type Iter = std::slice::Iter<'a, F>;

    fn stream(&self) -> Self::Iter {
        let source =
            unsafe { std::slice::from_raw_parts_mut(self.mmap.as_ptr() as *mut F, self.len()) }
                as &[F];
        source.iter()
    }

    fn len(&self) -> usize {
        self.mmap.len() / std::mem::size_of::<F>()
    }
}

// #[test]
// fn write_ck<G: AffineCurve>() {
//     let length = std::mem::size_of::G
//         let file = std::fs::OpenOptions::new()
//             .read(true)
//             .write(true)
//             .create(true)
//             .open(path)
//             .unwrap();
//         file.set_len(length as u64).unwrap();
//         let mut mmap = unsafe { MmapOptions::new().map_mut(&file).unwrap() };
//         let dst =
//             unsafe { std::slice::from_raw_parts_mut(mmap.as_mut_ptr() as *mut F, self.len()) };
//         let src = self.stream().cloned().collect::<Vec<_>>();

// }
// impl<'a, F: Fields> FieldStreamer<'a, F> {
//     pub fn from_file(path: &str) -> Result<(Mmap, Self)> {
//         let file = std::fs::File::open(path).map_err(|_e| StreamError).unwrap();

//         let mmap = unsafe { MmapOptions::new().map(&file).unwrap() };
//         let source = unsafe {
//             std::slice::from_raw_parts_mut(
//                 mmap.as_ptr() as *mut F,
//                 mmap.len() / std::mem::size_of::<F>(),
//             )
//         } as &[F];

//         Ok((mmap, source))
//     }

//     pub fn to_file(&self, path: &str) -> Result<()> {
//         let length = std::mem::size_of::<F>() * self.len();

//         let file = std::fs::OpenOptions::new()
//             .read(true)
//             .write(true)
//             .create(true)
//             .open(path)
//             .unwrap();
//         file.set_len(length as u64).unwrap();
//         let mut mmap = unsafe { MmapOptions::new().map_mut(&file).unwrap() };
//         let dst =
//             unsafe { std::slice::from_raw_parts_mut(mmap.as_mut_ptr() as *mut F, self.len()) };
//         let src = self.stream().cloned().collect::<Vec<_>>();

//         dst.copy_from_slice(&src);
//         Ok(())
//     }
// }

// #[test]
// fn test_stream_from_file() {
//     use ark_ff::{One, Zero};
//     type F = ark_bls12_381::Fr;
//     let a = [F::one(), F::one(), F::zero()];
//     let stream_a = &a[..];
//     assert!(stream_a.to_file("/tmp/test.mmap").is_ok());

//     let (mmap, read_stream_a) = FieldStreamer::<F>::from_file("/tmp/test.mmap").unwrap();
//     assert_eq!(stream_a.stream().next(), read_stream_a.stream().next());
// }
