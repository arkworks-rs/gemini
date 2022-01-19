use crate::stream::Streamer;
use ark_ff::Field;
use ark_std::borrow::Borrow;

#[derive(Clone, Copy)]
pub struct ReadStream<F, S, SA> {
    x: F,
    y: F,
    base_streamer: S,
    addr_streamer: SA,
}

pub struct ReadIter<F, I, IA> {
    x: F,
    x2: F,
    y: F,
    cnt: usize,
    len: usize,
    base_iter: I,
    addr_iter: IA,
    nxt_addr: usize,
}

impl<F, S, SA> ReadStream<F, S, SA> {
    pub fn new(base_streamer: S, addr_streamer: SA, x: F, y: F) -> Self {
        Self {
            base_streamer,
            addr_streamer,
            x,
            y,
        }
    }
}

impl<F, S, SA> Streamer for ReadStream<F, S, SA>
where
    F: Field,
    S: Streamer,
    SA: Streamer,
    S::Item: Borrow<F>,
    SA::Item: Borrow<usize>,
{
    type Item = F;

    type Iter = ReadIter<F, S::Iter, SA::Iter>;

    fn stream(&self) -> Self::Iter {
        let base_iter = self.base_streamer.stream();
        let addr_iter = self.addr_streamer.stream();
        let x = self.x;
        let y = self.y;
        let x2 = self.x.square();
        let cnt = 0;
        let len = self.len() - 1;
        Self::Iter {
            x,
            x2,
            y,
            base_iter,
            addr_iter,
            cnt,
            len,
            nxt_addr: 0,
        }
    }

    fn len(&self) -> usize {
        self.base_streamer.len()
    }
}

impl<F, I, IA> Iterator for ReadIter<F, I, IA>
where
    F: Field,
    I: Iterator,
    IA: Iterator,
    I::Item: Borrow<F>,
    IA::Item: Borrow<usize>,
{
    type Item = F;

    #[inline]
    fn next(&mut self) -> Option<<Self as Iterator>::Item> {
        if self.cnt == 0 {
            let cur_addr = *(self.addr_iter.next()?).borrow();
            self.nxt_addr = *(self.addr_iter.next()?).borrow();

            let tmp: F;
            if cur_addr == self.nxt_addr {
                tmp = F::from((self.len - self.cnt - 1) as u64);
            } else {
                tmp = F::zero();
            }

            let cur_ele = *(self.base_iter.next()?).borrow();
            self.cnt += 1;

            return Some(self.y - (self.x2 * tmp + self.x * cur_ele));
        } else if self.cnt == self.len {
            self.cnt += 1;
            let cur_ele = *(self.base_iter.next()?).borrow();
            return Some(self.y - (self.x * cur_ele));
        }

        if self.cnt < self.len {
            let cur_addr = self.nxt_addr;
            self.nxt_addr = *(self.addr_iter.next()?).borrow();
            let tmp: F;
            if cur_addr == self.nxt_addr {
                tmp = F::from((self.len - self.cnt - 1) as u64);
            } else {
                tmp = F::zero();
            }

            let cur_ele = *(self.base_iter.next()?).borrow();
            self.cnt += 1;
            Some(self.y - (self.x2 * tmp + self.x * cur_ele))
        } else {
            None
        }
    }
}

#[test]
fn test_read_stream() {
    use crate::stream::Streamer;
    use ark_bls12_381::Fr;
    use ark_ff::Zero;
    use ark_std::UniformRand;

    for _ in 0..100 {
        let rng = &mut ark_std::test_rng();
        let size = 1000;
        let mut a = Vec::new();
        for _ in 0..size {
            a.push(Fr::rand(rng));
        }

        let mut b = Vec::new();
        let mut w = Vec::new();
        let mut cnt = 0;
        for i in 0..size {
            let mut bit = usize::rand(rng) % 2;
            while bit == 0 {
                cnt += 1;
                bit = usize::rand(rng) % 2;
            }
            b.push(cnt);
            if i == 0 || b[i] != b[i - 1] {
                w.push(Fr::zero());
            } else {
                w.push(Fr::from((i - 1) as u64));
            }
        }

        let x = Fr::rand(rng);
        let y = Fr::rand(rng);
        let mut ans = Vec::new();
        for i in 0..size {
            ans.push(y - (x.square() * w[size - 1 - i] + x * a[size - 1 - i]));
        }
        // ans.push(Y * (Fr::one() + Z) + w[0] + Z * w[len - 1]);
        // ans.push(Fr::zero());

        a.reverse();
        b.reverse();
        let st = ReadStream::new(a.as_slice(), b.as_slice(), x, y);
        for (i, res) in st.stream().enumerate() {
            assert_eq!(res, ans[i]);
        }
    }
}
