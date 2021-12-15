use crate::iterable::Iterable;
use ark_std::borrow::Borrow;

#[derive(Clone, Copy)]
pub struct LookupStreamer<S, I>
where
    S: Iterable,
    I: Iterable,
{
    pub(crate) items: S,
    pub(crate) indices: I,
}

pub struct LookupIter<I, II>
where
    I: Iterator,
    II: Iterator,
    II::Item: Borrow<usize>,
{
    item_stream: I,
    index_stream: II,
    current_height: usize,
    current_item: Option<I::Item>,
}

impl<S, I> LookupStreamer<S, I>
where
    S: Iterable,
    I: Iterable,
    S::Item: Copy,
    I::Item: Borrow<usize>,
{
    pub fn new(items: S, indices: I) -> Self {
        Self { items, indices }
    }
}

impl<S, I> Iterable for LookupStreamer<S, I>
where
    S: Iterable,
    I: Iterable,
    S::Item: Copy,
    I::Item: Borrow<usize>,
{
    type Item = S::Item;

    type Iter = LookupIter<S::Iter, I::Iter>;

    fn iter(&self) -> Self::Iter {
        LookupIter {
            item_stream: self.items.iter(),
            index_stream: self.indices.iter(),
            current_height: self.items.len(),
            current_item: None,
        }
    }

    fn len(&self) -> usize {
        self.indices.len()
    }
}

impl<I, II> Iterator for LookupIter<I, II>
where
    I: Iterator,
    I::Item: Copy,
    II: Iterator,
    II::Item: Borrow<usize>,
{
    type Item = I::Item;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let &index = self.index_stream.next()?.borrow();
        if self.current_height == index {
            self.current_item
        } else {
            let delta = self.current_height - index - 1;
            self.item_stream.advance_by(delta).ok()?;
            let item = self.item_stream.next();
            self.current_height = index;
            self.current_item = item;
            item
        }
    }

    fn advance_by(&mut self, n: usize) -> Result<(), usize> {
        self.index_stream.advance_by(n)
    }
}

#[test]
fn test_index() {
    let indices = vec![4, 4, 3, 2, 1, 0];
    let items = vec![8, 7, 6, 5, 4, 3, 2, 1, 0];

    let stream = LookupStreamer::new(items.as_slice(), indices.as_slice());
    let stream = stream.iter().cloned().collect::<Vec<_>>();
    assert_eq!(stream, indices);
}
