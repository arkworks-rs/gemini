use ark_ff::Field;
use ark_std::borrow::Borrow;
use ark_std::marker::PhantomData;

use crate::iterable::Iterable;

const LEN_MISMATCH_ERRMSG: &str = "Iterable::len mismatch with actual stream length.";

#[derive(Clone, Copy)]
pub struct HadamardStreamer<'a, F, S0, S1>(&'a S0, &'a S1, PhantomData<F>);

impl<'a, F, S0, S1> HadamardStreamer<'a, F, S0, S1>
where
    S0: Iterable,
    F: Field,
    S1: Iterable,
    S0::Item: Borrow<F>,
    S1::Item: Borrow<F>,
{
    pub fn new(s0: &'a S0, s1: &'a S1) -> Self {
        Self(s0, s1, PhantomData)
    }
}
pub struct HadamardIter<F, I0, I1>(I0, I1, PhantomData<F>);

impl<F, I0, I1> Iterator for HadamardIter<F, I0, I1>
where
    I0: Iterator,
    I1: Iterator,
    I0::Item: Borrow<F>,
    I1::Item: Borrow<F>,
    F: Field,
{
    type Item = F;

    #[inline(always)]
    fn next(&mut self) -> Option<Self::Item> {
        let first = self.0.next()?;
        let second = self.1.next()?;
        Some(*first.borrow() * second.borrow())
    }

    fn advance_by(&mut self, n: usize) -> Result<(), usize> {
        self.0.advance_by(n).and_then(|()| self.1.advance_by(n))
    }
}

impl<'a, S0, S1, F> Iterable for HadamardStreamer<'a, F, S0, S1>
where
    S0: Iterable,
    S1: Iterable,
    S0::Item: Borrow<F>,
    S1::Item: Borrow<F>,
    F: Field,
{
    type Item = F;

    type Iter = HadamardIter<F, S0::Iter, S1::Iter>;

    fn iter(&self) -> Self::Iter {
        let mut iter0 = self.0.iter();
        let mut iter1 = self.1.iter();

        // align the streams to the shortest one.
        // If attempting to align the stream fails, this means that Iterable::len is providing
        // unccurate information about the actual length.
        // In this unfortunate event, fail panicking.
        if self.0.len() > self.1.len() {
            iter0
                .advance_by(self.0.len() - self.1.len())
                .expect(LEN_MISMATCH_ERRMSG)
        } else if self.1.len() > self.0.len() {
            iter1
                .advance_by(self.1.len() - self.0.len())
                .expect(LEN_MISMATCH_ERRMSG)
        }
        HadamardIter(iter0, iter1, PhantomData)
    }

    fn len(&self) -> usize {
        usize::min(self.0.len(), self.1.len())
    }
}

#[test]
fn test_hadamard_stream() {
    use ark_test_curves::bls12_381::Fr;
    use ark_std::test_rng;
    use ark_std::vec::Vec;
    use ark_std::UniformRand;

    let rng = &mut test_rng();
    let lhs = &(0..100).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
    let rhs = &(0..100).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
    let hadamard_product = lhs
        .iter()
        .zip(rhs.iter())
        .map(|(&x, y)| x * y)
        .collect::<Vec<_>>();
    let hadamard_stream = HadamardStreamer::<Fr, _, _>::new(&lhs, &rhs);
    let hadamard_stream_collected = hadamard_stream.iter().collect::<Vec<_>>();
    assert_eq!(hadamard_stream_collected, hadamard_product);
}
