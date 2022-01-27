use crate::iterable::Iterable;
use ark_ff::Field;
use ark_std::borrow::Borrow;

#[derive(Clone, Copy)]
pub struct LookupSetStreamer<'a, F, S> {
    base_streamer: &'a S,
    z: F,
    y: F,
}

impl<'a, F, S> LookupSetStreamer<'a, F, S> {
    pub fn new(base_streamer: &'a S, y: F, z: F) -> Self {
        Self {
            base_streamer,
            y,
            z,
        }
    }
}

impl<'a, F, S> Iterable for LookupSetStreamer<'a, F, S>
where
    F: Field,
    S: Iterable,
    S::Item: Borrow<F>,
{
    type Item = F;

    type Iter = PlookupSetIterator<F, S::Iter>;

    fn iter(&self) -> Self::Iter {
        PlookupSetIterator::new(self.base_streamer.iter(), self.y, self.z)
    }

    fn len(&self) -> usize {
        self.base_streamer.len()
    }
}

pub struct PlookupSetIterator<F, I>
where
    I: Iterator,
{
    y1z: F,
    z: F,
    first: F,
    previous: Option<F>,
    it: I,
}

impl<F, I> PlookupSetIterator<F, I>
where
    F: Field,
    I: Iterator,
    I::Item: Borrow<F>,
{
    pub fn new(mut it: I, y: F, z: F) -> Self {
        let next = *it.next().unwrap().borrow();
        Self {
            z,
            y1z: y * (F::one() + z),
            it,
            first: next,
            previous: Some(next),
        }
    }
}

impl<F, I> Iterator for PlookupSetIterator<F, I>
where
    F: Field,
    I: Iterator,
    I::Item: Borrow<F>,
{
    type Item = F;

    fn next(&mut self) -> Option<Self::Item> {
        match (self.it.next(), self.previous) {
            (Some(current), Some(previous)) => {
                let current = *current.borrow();
                self.previous = Some(current);
                Some(self.y1z + self.z * previous.borrow() + current)
            }
            (None, Some(previous)) => {
                self.previous = None;
                Some(self.y1z + self.z * previous.borrow() + self.first)
            }
            (None, None) => None,
            (Some(_), None) => panic!(
                "Something wrong with the iterator: previous position is None, current is Some(_)."
            ),
        }
    }
}

#[test]
fn test_set_stream() {
    use ark_bls12_381::Fr;
    use ark_ff::One;
    use ark_std::UniformRand;

    let rng = &mut ark_std::test_rng();
    let size = 1000;
    let test_vector = (0..size).map(|_| Fr::rand(rng)).collect::<Vec<_>>();

    let y = Fr::rand(rng);
    let z = Fr::rand(rng);

    let expected = (0..size)
        .map(|i| y * (Fr::one() + z) + z * test_vector[i] + test_vector[(i + 1) % size])
        .collect::<Vec<_>>();

    let test_vector_stream = test_vector.as_slice();
    let st = LookupSetStreamer::new(&test_vector_stream, y, z);
    let got = st.iter().collect::<Vec<_>>();
    assert_eq!(got, expected);
}
