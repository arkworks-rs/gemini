use crate::stream::Streamer;
use ark_ff::Field;
use ark_std::borrow::Borrow;

#[derive(Clone, Copy)]
pub struct LookupSubsetStreamer<F, S> {
    base_streamer: S,
    gamma: F,
}

pub struct LookupSubsetIterator<F, I> {
    base_iterator: I,
    gamma: F,
}

impl<F, S> LookupSubsetStreamer<F, S> {
    pub fn new(base_streamer: S, gamma: F) -> Self {
        Self {
            base_streamer,
            gamma,
        }
    }
}

impl<F, S> Streamer for LookupSubsetStreamer<F, S>
where
    S: Streamer,
    S::Item: Borrow<F>,
    F: Field,
{
    type Item = F;

    type Iter = LookupSubsetIterator<F, S::Iter>;

    fn stream(&self) -> Self::Iter {
        let base_iterator = self.base_streamer.stream();
        let gamma = self.gamma;
        Self::Iter {
            base_iterator,
            gamma,
        }
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
        Some(self.gamma + self.base_iterator.next()?.borrow())
    }
}

#[test]
fn test_subset_stream() {
    use ark_bls12_381::Fr;
    use ark_std::UniformRand;

    let rng = &mut ark_std::test_rng();
    let size = 1000;
    let test_vector = (0..size).map(|_| Fr::rand(rng)).collect::<Vec<_>>();

    let z = Fr::rand(rng);
    let expected = (0..size).map(|i| test_vector[i] + z).collect::<Vec<_>>();

    let st = LookupSubsetStreamer::new(test_vector.as_slice(), z);
    let got = st.stream().collect::<Vec<_>>();
    assert_eq!(got, expected);
}
