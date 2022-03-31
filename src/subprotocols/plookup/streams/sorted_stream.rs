use core::marker::PhantomData;

use ark_ff::Field;
use ark_std::borrow::Borrow;

use crate::iterable::Iterable;

use super::set_stream::PlookupSetIterator;

#[derive(Clone, Copy)]
pub struct LookupSortedStreamer<'a, F, S, SA> {
    base_streamer: &'a S,
    addr_streamer: &'a SA,
    y: F,
    z: F,
}

impl<'a, F, S, SA> LookupSortedStreamer<'a, F, S, SA> {
    pub fn new(base_streamer: &'a S, addr_streamer: &'a SA, y: F, z: F) -> Self {
        Self {
            base_streamer,
            addr_streamer,
            y,
            z,
        }
    }
}

impl<'a, F, S, SA> Iterable for LookupSortedStreamer<'a, F, S, SA>
where
    F: Field,
    S: Iterable,
    SA: Iterable,
    S::Item: Borrow<F> + Clone,
    SA::Item: Borrow<usize>,
{
    type Item = F;

    type Iter = PlookupSetIterator<F, SortedIterator<S::Item, S::Iter, SA::Iter>>;

    fn iter(&self) -> Self::Iter {
        let base_iter = self.base_streamer.iter();
        let addr_iter = self.addr_streamer.iter();
        PlookupSetIterator::new(
            SortedIterator::new(base_iter, addr_iter, self.base_streamer.len()),
            self.y,
            self.z,
        )
    }

    fn len(&self) -> usize {
        self.base_streamer.len() + self.addr_streamer.len() + 1
    }
}

#[derive(Clone, Copy)]
pub struct SortedStreamer<'a, F, S, SA> {
    base_streamer: &'a S,
    addr_streamer: &'a SA,
    _field: PhantomData<F>,
}

impl<'a, F, S, SA> SortedStreamer<'a, F, S, SA> {
    pub fn new(base_streamer: &'a S, addr_streamer: &'a SA) -> Self {
        Self {
            base_streamer,
            addr_streamer,
            _field: PhantomData,
        }
    }
}

impl<'a, F, S, SA> Iterable for SortedStreamer<'a, F, S, SA>
where
    F: Field,
    S: Iterable<Item = F>,
    SA: Iterable,
    SA::Item: Borrow<usize>,
{
    type Item = F;

    type Iter = SortedIterator<F, S::Iter, SA::Iter>;

    fn iter(&self) -> Self::Iter {
        let base_iter = self.base_streamer.iter();
        let addr_iter = self.addr_streamer.iter();
        SortedIterator::new(base_iter, addr_iter, self.base_streamer.len())
    }

    fn len(&self) -> usize {
        self.base_streamer.len() + self.addr_streamer.len()
    }
}

pub struct SortedIterator<T, I, J>
where
    I: Iterator<Item = T>,
    J: Iterator,
    J::Item: Borrow<usize>,
{
    counter: usize,
    cache: Option<T>,
    it: I,
    current_address: Option<J::Item>,
    addresses: J,
}

impl<T, I, J> SortedIterator<T, I, J>
where
    I: Iterator<Item = T>,
    J: Iterator,
    J::Item: Borrow<usize>,
{
    pub(crate) fn new(it: I, mut addresses: J, len: usize) -> Self {
        let counter = len;
        let cache = None;
        let current_address = addresses.next();
        Self {
            counter,
            cache,
            it,
            current_address,
            addresses,
        }
    }
}

impl<T, I, J> Iterator for SortedIterator<T, I, J>
where
    T: Clone,
    I: Iterator<Item = T>,
    J: Iterator,
    J::Item: Borrow<usize>,
{
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        // if we have an element from the previous iteration, return it.
        match &self.current_address {
            None => self.it.next(),
            Some(current_address) => {
                let current_address = *current_address.borrow();
                if self.counter != current_address {
                    assert!(self.counter > current_address);
                    self.counter -= 1;
                    self.cache = self.it.next();
                    self.cache.clone()
                } else {
                    //  self.counter == current_address
                    self.current_address = self.addresses.next();
                    self.cache.clone()
                }
            }
        }
    }
}

#[test]
fn test_sorted_iterator() {
    use ark_std::vec::Vec;

    let base = vec!["1", "2", "3", "4"];
    let addresses = vec![2usize, 2, 2, 1, 0, 0, 0];
    let expected = vec!["4", "3", "3", "3", "3", "2", "2", "1", "1", "1", "1"];
    let sorted_iterator =
        SortedIterator::new(base.iter().rev(), addresses.iter().cloned(), base.len())
            .cloned()
            .collect::<Vec<_>>();
    assert_eq!(sorted_iterator, expected);

    let base = vec!["1", "2", "3", "4", "5", "6"];
    let addresses = vec![4, 3, 3, 2, 1, 1, 1, 1, 0, 0];
    let expected = vec![
        "6", "5", "5", "4", "4", "4", "3", "3", "2", "2", "2", "2", "2", "1", "1", "1",
    ];
    let sorted_iterator =
        SortedIterator::new(base.iter().rev(), addresses.iter().cloned(), base.len())
            .cloned()
            .collect::<Vec<_>>();
    assert_eq!(sorted_iterator, expected);
}

// #[test]
// fn test_sorted_stream() {
//     use ark_bls12_381::Fr;
//     use ark_ff::One;
//     use ark_std::rand::Rng;
//     use ark_std::UniformRand;

//     let rng = &mut ark_std::test_rng();
//     let set_size = 5;
//     let subset_size = 10;
//     let test_vector = (0..set_size).map(|_| Fr::rand(rng)).collect::<Vec<_>>();

//     // assume the subset indices are sorted.
//     let mut subset_indices = (0..subset_size)
//         .map(|_| rng.gen_range(0..set_size))
//         .collect::<Vec<_>>();
//     subset_indices.sort_unstable();
//     // create the array for merged indices and the sorted vector `w `
//     let mut merged_indices = subset_indices.clone();
//     merged_indices.extend(0..set_size);
//     merged_indices.sort_unstable();
//     merged_indices.reverse();
//     let w = merged_indices
//         .iter()
//         .map(|&i| test_vector[i])
//         .collect::<Vec<_>>();

//     let y = Fr::rand(rng);
//     let z = Fr::rand(rng);
//     let len = set_size + subset_size;
//     let ans = (0..len)
//         .map(|i| y * (Fr::one() + z) + z * w[i] + w[(i + 1) % len])
//         .collect::<Vec<_>>();

//     let subset_indices_stream = subset_indices.iter().rev().cloned().collect::<Vec<_>>();
//     let test_vector_stream = test_vector.iter().rev().cloned().collect::<Vec<_>>();
//     let sorted_stream = LookupSortedStreamer::new(
//         &test_vector_stream.as_slice(),
//         &subset_indices_stream.as_slice(),
//         y,
//         z,
//     )
//     .iter()
//     .collect::<Vec<_>>();
//     assert_eq!(sorted_stream, ans);
// }
