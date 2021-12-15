//! DummyStream: A stream that comes in handy for testing purposes.
//! This stream will always return the same element `e`.
use ark_ff::{PrimeField, Zero};
use ark_std::{iter, rand::RngCore};

use crate::{circuit::R1csStream, iterable::Iterable, misc::MatrixElement};

/// A DummyStream is the stream that returns the same element `e`, `len` times.
#[derive(Clone, Copy)]
pub struct DummyStreamer<T> {
    e: T,
    len: usize,
}

impl<T: Copy> DummyStreamer<T> {
    /// Creates new stream that will repeat `len` times the same element `e`.
    pub fn new(e: T, len: usize) -> Self {
        Self { e, len }
    }
}

/// Dummy stream for the diagonal matrix.
#[derive(Clone, Copy)]
pub struct DiagonalMatrixStreamer<T> {
    e: T,
    len: usize,
}

/// Iterator for the diagonal matrix.
pub struct DiagonalMatrixIter<T> {
    e: T,
    len: usize,
}

/// A dummy stream with only a single element.
#[derive(Clone, Copy)]
pub struct SingleEntryStream<T> {
    e: T,
    len: usize,
}

impl<T: Copy + Zero> Iterable for SingleEntryStream<T> {
    type Item = T;
    type Iter = iter::Chain<iter::Take<iter::Repeat<T>>, iter::Take<iter::Repeat<T>>>;

    fn len(&self) -> usize {
        self.len
    }
    fn iter(&self) -> Self::Iter {
        iter::repeat(T::zero())
            .take(self.len - 1)
            .chain(iter::repeat(self.e).take(1))
    }
}
impl<T: Copy> DiagonalMatrixStreamer<T> {
    /// Creates new stream that will repeat `len` times the same element `e`.
    pub fn new(e: T, len: usize) -> Self {
        Self { e, len }
    }
}

impl<T: PrimeField> Iterable for DiagonalMatrixStreamer<T> {
    type Item = MatrixElement<T>;
    type Iter = DiagonalMatrixIter<T>;

    #[inline]
    fn len(&self) -> usize {
        self.len
    }

    #[inline]
    fn iter(&self) -> Self::Iter {
        DiagonalMatrixIter {
            e: self.e,
            len: self.len * 2,
        }
    }
}

impl<T: PrimeField> Iterator for DiagonalMatrixIter<T> {
    type Item = MatrixElement<T>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.len == 0 {
            None
        } else if self.len % 2 == 1 {
            self.len -= 1;
            Some(MatrixElement::EOL)
        } else {
            self.len -= 1;
            Some(MatrixElement::Element((self.e, self.len >> 1)))
        }
    }
}

impl<T: Copy> Iterable for DummyStreamer<T> {
    type Item = T;
    type Iter = iter::Take<iter::Repeat<T>>;

    fn iter(&self) -> Self::Iter {
        iter::repeat(self.e).take(self.len)
    }

    fn len(&self) -> usize {
        self.len
    }
}

type DummyR1CStream<F> = R1csStream<DiagonalMatrixStreamer<F>, DummyStreamer<F>, DummyStreamer<F>>;

/// Output a stream for the dummy R1CS instance.
pub fn dumym_r1cs_relation<F: PrimeField, R: RngCore>(rng: &mut R, n: usize) -> DummyR1CStream<F> {
    let e = F::rand(rng);
    let inv_e = e.inverse().expect("Buy a lottery ticket and retry");
    R1csStream {
        a_rowm: DiagonalMatrixStreamer::new(inv_e, n),
        b_rowm: DiagonalMatrixStreamer::new(inv_e, n),
        c_rowm: DiagonalMatrixStreamer::new(inv_e, n),
        a_colm: DiagonalMatrixStreamer::new(inv_e, n),
        b_colm: DiagonalMatrixStreamer::new(inv_e, n),
        c_colm: DiagonalMatrixStreamer::new(inv_e, n),
        witness: DummyStreamer::new(e, n - 1),
        z: DummyStreamer::new(e, n),
        z_a: DummyStreamer::new(F::one(), n),
        z_b: DummyStreamer::new(F::one(), n),
        z_c: DummyStreamer::new(F::one(), n),
        nonzero: n,
    }
}

#[test]
fn test_dummy_streamer() {
    let e = 1;
    let dummy = DummyStreamer::new(e, 1);
    let mut stream = dummy.iter();

    assert_eq!(stream.next(), Some(1));
    assert_eq!(stream.next(), None);
}

#[test]
fn test_dummy_matrix_streamer() {
    use ark_bls12_381::Fr;
    use ark_ff::One;
    type F = Fr;

    let e = F::one();
    let dummy = DiagonalMatrixStreamer::new(e, 2);
    let mut stream = dummy.iter();

    assert_eq!(stream.next(), Some(MatrixElement::Element((e, 1))));
    assert_eq!(stream.next(), Some(MatrixElement::EOL));
    assert_eq!(stream.next(), Some(MatrixElement::Element((e, 0))));
    assert_eq!(stream.next(), Some(MatrixElement::EOL));
}
