use ark_ff::Field;
use ark_std::borrow::Borrow;
use ark_std::marker::PhantomData;

use crate::iterable::Iterable;

pub struct ProductStream<'a, F, S: ?Sized> {
    streamer: &'a S,
    _field: PhantomData<F>,
}

pub struct ProductIter<F, I> {
    stream: I,
    current: Option<F>,
}

impl<'a, F, S> ProductStream<'a, F, S>
where
    S: Iterable,
    S::Item: Borrow<F>,
    F: Field,
{
    pub fn new(streamer: &'a S) -> Self {
        let _field = PhantomData;
        Self { streamer, _field }
    }
}

impl<'a, F, S> Iterable for ProductStream<'a, F, S>
where
    S: Iterable,
    S::Item: Borrow<F>,
    F: Field,
{
    type Item = F;

    type Iter = ProductIter<F, S::Iter>;

    fn iter(&self) -> Self::Iter {
        let stream = self.streamer.iter();
        let current = Some(F::one());
        ProductIter { stream, current }
    }

    fn len(&self) -> usize {
        self.streamer.len() + 1
    }
}

impl<F, I> Iterator for ProductIter<F, I>
where
    I: Iterator,
    I::Item: Borrow<F>,
    F: Field,
{
    type Item = F;

    #[inline(always)]
    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        let previous = self.current;
        if let Some(e) = self.stream.next() {
            self.current = self.current.map(|c| c * e.borrow());
        } else {
            self.current = None;
        }
        previous
    }
}

#[test]
fn test_product_stream() {
    use crate::iterable::dummy::DummyStreamer;
    use ark_bls12_381::Fr as F;
    use ark_ff::UniformRand;
    use ark_std::test_rng;
    use ark_std::vec::Vec;
    use ark_std::One;

    let rng = &mut test_rng();
    let n = 1200usize;
    let e = F::rand(rng);

    let vector = DummyStreamer::new(e, n);
    let accumulated_product = ProductStream::new(&vector).iter().collect::<Vec<_>>();
    assert_eq!(accumulated_product[0], F::one());
    assert_eq!(accumulated_product[1], e);
    assert_eq!(accumulated_product[2], e.square());
    assert_eq!(accumulated_product.last(), Some(&e.pow(&[n as u64])))
}
