use crate::iterable::Iterable;
use ark_ff::Field;
use ark_std::borrow::Borrow;

#[derive(Clone, Copy)]
pub struct LookupSubsetStreamer<'a, F, S> {
    base_streamer: &'a S,
    y: F,
}

pub struct LookupSubsetIterator<F, I> {
    base_iterator: I,
    y: F,
}

impl<'a, F, S> LookupSubsetStreamer<'a, F, S> {
    pub fn new(base_streamer: &'a S, y: F) -> Self {
        Self { base_streamer, y }
    }
}

impl<'a, F, S> Iterable for LookupSubsetStreamer<'a, F, S>
where
    S: Iterable,
    S::Item: Borrow<F>,
    F: Field,
{
    type Item = F;

    type Iter = LookupSubsetIterator<F, S::Iter>;

    fn iter(&self) -> Self::Iter {
        let base_iterator = self.base_streamer.iter();
        let y = self.y;
        Self::Iter { base_iterator, y }
    }

    fn len(&self) -> usize {
        self.base_streamer.len()
    }
}

impl<F, I> Iterator for LookupSubsetIterator<F, I>
where
    F: Field,
    I: Iterator,
    I::Item: Borrow<F>,
{
    type Item = F;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        Some(self.y + self.base_iterator.next()?.borrow())
    }
}

#[test]
fn test_subset_stream() {
    use ark_bls12_381::Fr;
    use ark_std::vec::Vec;
    use ark_std::UniformRand;

    let rng = &mut ark_std::test_rng();
    let size = 1000;
    let test_vector = (0..size).map(|_| Fr::rand(rng)).collect::<Vec<_>>();

    let z = Fr::rand(rng);
    let expected = (0..size).map(|i| test_vector[i] + z).collect::<Vec<_>>();

    let test_vector_stream = test_vector.as_slice();
    let st = LookupSubsetStreamer::new(&test_vector_stream, z);
    let got = st.iter().collect::<Vec<_>>();
    assert_eq!(got, expected);
}
