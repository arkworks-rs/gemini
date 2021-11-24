use crate::stream::Streamer;
use ark_ff::Field;
use ark_std::borrow::Borrow;

#[derive(Clone, Copy)]
pub struct LookupSortedStreamer<F, S, SA> {
    base_streamer: S,
    addr_streamer: SA,
    beta: F,
    gamma: F,
}

pub struct LookupSortedIterator<F, I, IA> {
    base_iter: I,
    addr_iter: IA,
    y1z: F,
    zeta: F,
    previous: F,
    first: F,
    cnt: usize,
    len: usize,
    //
    cur_ele: F,
    cur_i: usize,
    cur_j: usize,
}

impl<F, S, SA> LookupSortedStreamer<F, S, SA> {
    pub fn new(base_streamer: S, addr_streamer: SA, beta: F, gamma: F) -> Self {
        Self {
            base_streamer,
            addr_streamer,
            beta,
            gamma,
        }
    }
}

impl<F, S, SA> Streamer for LookupSortedStreamer<F, S, SA>
where
    F: Field,
    S: Streamer,
    SA: Streamer,
    S::Item: Borrow<F>,
    SA::Item: Borrow<usize>,
{
    type Item = F;

    type Iter = LookupSortedIterator<F, S::Iter, SA::Iter>;

    fn stream(&self) -> Self::Iter {
        let base_iter = self.base_streamer.stream();
        let addr_iter = self.addr_streamer.stream();
        let y1z = self.beta * (F::one() + self.gamma);
        let zeta = self.gamma;
        Self::Iter {
            base_iter,
            addr_iter,
            previous: F::zero(),
            first: F::zero(),
            y1z,
            zeta,
            cnt: 0,
            len: self.len(),
            cur_ele: F::zero(),
            cur_i: self.base_streamer.len() - 1,
            cur_j: 0,
        }
    }

    fn len(&self) -> usize {
        self.base_streamer.len() + self.addr_streamer.len()
    }
}

impl<F, I, IA> Iterator for LookupSortedIterator<F, I, IA>
where
    F: Field,
    I: Iterator,
    IA: Iterator,
    I::Item: Borrow<F>,
    IA::Item: Borrow<usize>,
{
    type Item = F;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cnt == 0 {
            let next_base = self.base_iter.next()?;
            let next_addr = self.addr_iter.next()?;

            self.cur_ele = *next_base.borrow();
            self.cur_j = *next_addr.borrow();

            self.first = self.cur_ele;
            let tmp: F;
            if self.cur_j == self.cur_i {
                tmp = self.cur_ele;
                let nxt = self.addr_iter.next();
                match nxt {
                    Some(p) => self.cur_j = *p.borrow(),
                    None => self.cur_j = self.len + 1,
                }
            } else {
                self.cur_i -= 1;
                self.cur_ele = *(self.base_iter.next()?).borrow();
                tmp = self.cur_ele;
            }

            self.cnt += 1;
            self.previous = tmp;
            return Some(self.y1z + self.first + self.zeta * tmp);
        } else if self.cnt == self.len - 1 {
            self.cnt += 1;
            return Some(self.y1z + self.previous + self.zeta * self.first);
        }

        if self.cnt < self.len {
            let tmp: F;
            if self.cur_j == self.cur_i {
                tmp = self.cur_ele;
                let nxt = self.addr_iter.next();
                match nxt {
                    Some(p) => self.cur_j = *p.borrow(),
                    None => self.cur_j = self.len + 1,
                }
            } else {
                self.cur_i -= 1;
                self.cur_ele = *(self.base_iter.next()?).borrow();
                tmp = self.cur_ele;
            }

            self.cnt += 1;
            let previous = self.previous;
            self.previous = tmp;

            Some(self.y1z + previous + self.zeta * tmp)
        } else {
            None
        }
    }
}

#[test]
fn test_sorted_stream() {
    use ark_bls12_381::Fr;
    use ark_ff::One;
    use ark_std::UniformRand;

    for _ in 0..100 {
        let rng = &mut ark_std::test_rng();
        let set_size = 1000;
        let subset_size = 2000;
        let mut a = Vec::new();
        for _ in 0..set_size {
            a.push(Fr::rand(rng));
        }

        let mut b = Vec::new();
        let mut w = Vec::new();
        let mut cnt = 0;
        w.push(a[cnt]);
        for _ in 0..subset_size {
            let mut bit = usize::rand(rng) % 2;
            while bit == 0 && cnt < set_size - 1 {
                cnt += 1;
                w.push(a[cnt]);
                bit = usize::rand(rng) % 2;
            }
            b.push(cnt);
            w.push(a[cnt]);
        }

        let y = Fr::rand(rng);
        let z = Fr::rand(rng);
        let mut ans = Vec::new();
        let len = set_size + subset_size;
        for i in 0..len - 1 {
            ans.push(y * (Fr::one() + z) + w[len - 1 - i] + z * w[len - 1 - i - 1]);
        }
        ans.push(y * (Fr::one() + z) + w[0] + z * w[len - 1]);
        // ans.push(Fr::zero());

        a.reverse();
        b.reverse();
        let st = LookupSortedStreamer::new(a.as_slice(), b.as_slice(), y, z);
        let mut it = st.stream();
        for i in 0..set_size + subset_size {
            let res = it.next();
            assert_eq!(res.unwrap(), ans[i]);
        }
    }
}
