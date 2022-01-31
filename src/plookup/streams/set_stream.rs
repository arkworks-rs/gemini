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
                Some(self.y1z + previous.borrow() + self.z * current)
            }
            (None, Some(previous)) => {
                self.previous = None;
                Some(self.y1z + previous.borrow() + self.z * self.first)
            }
            (None, None) => None,
            (Some(_), None) => panic!(
                "Something wrong with the iterator: previous position is None, current is Some(_)."
            ),
        }
    }
}

