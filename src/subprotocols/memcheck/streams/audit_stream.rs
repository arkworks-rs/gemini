use crate::stream::Streamer;
use ark_ff::Field;
use ark_std::borrow::Borrow;

/// Collections of streams used withing the memory-checking protocols.

#[derive(Clone, Copy)]
pub struct AuditStream<F, S, R> {
    x: F,
    y: F,
    stream: S,
    addr: R,
}

pub struct AuditIter<F, I, J> {
    x: F,
    x2: F,
    y: F,
    count: usize,
    index: usize,
    iterator: I,
    addr_iterator: J,
}

impl<F, S, R> AuditStream<F, S, R> {
    pub fn new(stream: S, addr: R, x: F, y: F) -> Self {
        Self { stream, addr, x, y }
    }
}

impl<F, S, R> Streamer for AuditStream<F, S, R>
where
    F: Field,
    S: Streamer,
    S::Item: Borrow<F>,
    R: Streamer,
    R::Item: Borrow<usize>,
{
    type Item = F;

    type Iter = AuditIter<F, S::Iter, R::Iter>;

    fn stream(&self) -> Self::Iter {
        let iterator = self.stream.stream();
        let addr_iterator = self.addr.stream();
        let x = self.x;
        let y = self.y;
        let x2 = self.x.square();
        let index = self.stream.len();
        Self::Iter {
            x,
            x2,
            y,
            iterator,
            index,
            addr_iterator,
            count: self.addr.len() - 1,
        }
    }

    fn len(&self) -> usize {
        self.stream.len()
    }
}

impl<F, I, J> Iterator for AuditIter<F, I, J>
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
        let e = self.iterator.next()?;
        let counter = self.count;

        if self.index == 0 {
            return None;
        }

        self.index -= 1;

        while self.addr_iterator.next().map(|x| *x.borrow()) == Some(counter) {
            self.count -= 1
        }

        // convert indices to their respective field elements
        let audit_ts = F::from(counter as u64);

        Some(self.y - (self.x2 * F::from(self.index as u64) + self.x * e.borrow() + audit_ts))
    }
}

// #[test]
// fn test_audit_stream() {
//     use ark_std::UniformRand;
//     use ark_bls12_381::Fr;
//     use ark_ff::One;

//     for _ in 0..100 {
//         let rng = &mut ark_std::test_rng();
//         let size = 1000;
//         let mut a = Vec::new();
//         let mut b = Vec::new();
//         for _ in 0..size {
//             a.push(Fr::rand(rng));
//             b.push(usize::rand(rng));
//         }

//         let x = Fr::rand(rng);
//         let y = Fr::rand(rng);
//         let mut ans = Vec::new();
//         let mut index = Fr::from(size as u64);
//         for i in 0..size {
//             let tmp = Fr::from(b[size - 1 - i] as u64);
//             index -= Fr::one();
//             ans.push(y - (x.square() * index + x * a[size - 1 - i] + tmp));
//         }
//         // ans.push(Y * (Fr::one() + Z) + w[0] + Z * w[len - 1]);
//         // ans.push(Fr::zero());

//         a.reverse();
//         b.reverse();
//         let st = AuditStream::new(a.as_slice(), b.as_slice(), x, y);
//         let mut it = st.stream();
//         for i in 0..size {
//             let res = it.next();
//             assert_eq!(res.unwrap(), ans[i]);
//         }
//     }
// }
