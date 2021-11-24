use crate::stream::Streamer;
use ark_ff::Field;
use ark_std::borrow::Borrow;

/// Collections of streams used withing the memory-checking protocols.

#[derive(Clone, Copy)]
pub struct InitStream<F, S> {
    x: F,
    y: F,
    stream: S,
}

pub struct InitIter<F, I> {
    x: F,
    // x2: F,
    y: F,
    // index: F,
    iterator: I,
}

impl<F, S> InitStream<F, S> {
    pub fn new(stream: S, x: F, y: F) -> Self {
        Self { stream, x, y }
    }
}

impl<F, S> Streamer for InitStream<F, S>
where
    F: Field,
    S: Streamer,
    S::Item: Borrow<F>,
{
    type Item = F;

    type Iter = InitIter<F, S::Iter>;

    fn stream(&self) -> Self::Iter {
        let iterator = self.stream.stream();
        let x = self.x;
        let y = self.y;
        // let x2 = self.x.square();
        // let index = F::from(self.stream.len() as u64);
        Self::Iter {
            x,
            // x2,
            y,
            // index,
            iterator,
        }
    }

    fn len(&self) -> usize {
        self.stream.len()
    }
}

impl<F, I> Iterator for InitIter<F, I>
where
    F: Field,
    I: Iterator,
    I::Item: Borrow<F>,
{
    type Item = F;

    #[inline]
    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        let e = self.iterator.next()?;
        // self.index -= F::one();
        Some(self.y - (self.x * e.borrow()))
    }
}

#[test]
fn test_init_stream() {
    use crate::stream::Streamer;
    use ark_bls12_381::Fr;
    use ark_std::UniformRand;

    for _ in 0..100 {
        let rng = &mut ark_std::test_rng();
        let size = 1000;
        let mut a = Vec::new();
        for _ in 0..size {
            a.push(Fr::rand(rng));
        }

        let x = Fr::rand(rng);
        let y = Fr::rand(rng);

        let mut ans = Vec::new();
        for i in 0..size {
            ans.push(y - (x * a[size - 1 - i]));
        }

        a.reverse();
        let st = InitStream::new(a.as_slice(), x, y);
        for (i, res) in st.stream().enumerate() {
            assert_eq!(res, ans[i]);
        }
    }
}
