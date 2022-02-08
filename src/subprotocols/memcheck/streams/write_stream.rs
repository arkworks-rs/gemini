use crate::stream::Streamer;
use ark_ff::Field;
use ark_std::borrow::Borrow;

#[derive(Clone, Copy)]
pub struct WriteStream<F, S, R> {
    x: F,
    y: F,
    base_streamer: S,
    addr_streamer: R,
}

pub struct WriteIter<F, I, J> {
    x: F,
    x2: F,
    y: F,
    index: F,
    base_iter: I,
    addr_iter: J,
}

impl<F, S, R> WriteStream<F, S, R> {
    pub fn new(base_streamer: S, addr_streamer: R, x: F, y: F) -> Self {
        Self {
            base_streamer,
            addr_streamer,
            x,
            y,
        }
    }
}

impl<F, S, R> Streamer for WriteStream<F, S, R>
where
    F: Field,
    S: Streamer,
    S::Item: Borrow<F>,
    R: Streamer,
    R::Item: Borrow<usize>,
{
    type Item = F;

    type Iter = WriteIter<F, S::Iter, R::Iter>;

    fn stream(&self) -> Self::Iter {
        let base_iter = self.base_streamer.stream();
        let x = self.x;
        let y = self.y;
        let x2 = self.x.square();
        let index = F::from(self.len() as u64);
        let addr_iter = self.addr_streamer.stream();
        Self::Iter {
            x,
            x2,
            y,
            index,
            base_iter,
            addr_iter,
        }
    }

    fn len(&self) -> usize {
        self.base_streamer.len()
    }
}

impl<F, I, J> Iterator for WriteIter<F, I, J>
where
    F: Field,
    I: Iterator,
    I::Item: Borrow<F>,
    J: Iterator,
    J::Item: Borrow<usize>,
{
    type Item = F;

    #[inline]
    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        let e = self.base_iter.next()?;
        let write_ts = self.addr_iter.next()?;
        self.index -= F::one();
        Some(self.y - (self.x2 * F::from(*write_ts.borrow() as u64) + self.x * e.borrow()))
    }
}

// #[test]
// fn check_write_stream() {
//     use crate::stream::Streamer;

//     for _ in 0..100 {
//         let rng = &mut ark_std::test_rng();
//         let size = 1000;
//         let mut a = Vec::new();
//         for _ in 0..size {
//             a.push(Fr::rand(rng));
//         }

//         let x = Fr::rand(rng);
//         let y = Fr::rand(rng);

//         let mut ans = Vec::new();
//         for i in 0..size {
//             ans.push(y - (x.square() * Fr::from((size - 1 - i) as u64) + x * a[size - 1 - i]));
//         }

//         a.reverse();
//         let st = WriteStream::new(a.as_slice(), x, y);
//         let mut it = st.stream();
//         for i in 0..size {
//             let res = it.next();
//             assert_eq!(res.unwrap(), ans[i]);
//         }
//     }
// }
