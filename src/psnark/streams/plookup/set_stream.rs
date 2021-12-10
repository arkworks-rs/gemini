use crate::stream::Streamer;
use ark_ff::Field;
use ark_std::borrow::Borrow;

#[derive(Clone, Copy)]
pub struct LookupSetStreamer<'a, F, S> {
    base_streamer: &'a S,
    gamma: F,
    beta: F,
}

pub struct LookupSetIterator<F, I> {
    base_iterator: I,
    zeta: F,
    y1z: F,
    previous: F,
    first: F,
    len: usize,
    cnt: usize,
}

impl<'a, F, S> LookupSetStreamer<'a, F, S> {
    pub fn new(base_streamer: &'a S, beta: F, gamma: F) -> Self {
        Self {
            base_streamer,
            beta,
            gamma,
        }
    }
}

impl<'a, F, S> Streamer for LookupSetStreamer<'a, F, S>
where
    F: Field,
    S: Streamer,
    S::Item: Borrow<F>,
{
    type Item = F;

    type Iter = LookupSetIterator<F, S::Iter>;

    fn stream(&self) -> Self::Iter {
        let gamma = self.gamma;
        let y1z = self.beta * (F::one() + self.gamma);
        let base_iterator = self.base_streamer.stream();
        LookupSetIterator {
            base_iterator,
            zeta: gamma,
            y1z,
            previous: F::zero(),
            first: F::zero(),
            len: self.len(),
            cnt: 0,
        }
    }

    fn len(&self) -> usize {
        self.base_streamer.len()
    }
}

impl<F, I> Iterator for LookupSetIterator<F, I>
where
    F: Field,
    I: Iterator,
    I::Item: Borrow<F>,
{
    type Item = F;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cnt == 0 {
            let next_element = self.base_iterator.next()?;
            self.first = *next_element.borrow();
            let next_element = self.base_iterator.next()?;

            self.cnt += 1;
            self.previous = *next_element.borrow();

            return Some(self.y1z + self.first + self.zeta * next_element.borrow());
        } else if self.cnt == self.len - 1 {
            self.cnt += 1;
            return Some(self.y1z + self.previous + self.zeta * self.first);
        }

        if self.cnt < self.len {
            self.cnt += 1;
            let next_element = self.base_iterator.next()?;
            let previous = self.previous;
            self.previous = *next_element.borrow();

            Some(self.y1z + previous + self.zeta * next_element.borrow())
        } else {
            None
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
        .map(|i| y * (Fr::one() + z) + test_vector[i] + z * test_vector[(i + 1) % size])
        .collect::<Vec<_>>();

    let test_vector_stream = test_vector.as_slice();
    let st = LookupSetStreamer::new(&test_vector_stream, y, z);
    let got = st.stream().collect::<Vec<_>>();
    assert_eq!(got, expected);
}
