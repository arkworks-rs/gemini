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

    fn next(&mut self) -> Option<Self::Item> {
        let next_element = self.base_iterator.next()?;
        Some(self.gamma + next_element.borrow())
    }
}

#[test]
fn check_subset_stream() {
    use ark_bls12_381::Fr;
    use ark_std::UniformRand;

    for _ in 0..100 {
        let rng = &mut ark_std::test_rng();
        let size = 1000;
        let mut a = Vec::new();
        for _ in 0..size {
            a.push(Fr::rand(rng));
        }

        let z = Fr::rand(rng);

        let mut ans = Vec::new();
        for i in 0..size {
            ans.push(a[size - 1 - i] + z);
        }
        // ans[size - 1] = ((Fr::one() + Z) + a[0] + Z * a[size - 1]);
        // ans.push(Fr::zero());

        a.reverse();
        let st = LookupSubsetStreamer::new(a.as_slice(), z);
        let mut it = st.stream();
        for ans_i in ans {
            let res = it.next();
            assert_eq!(res.unwrap(), ans_i);
        }
    }
}
