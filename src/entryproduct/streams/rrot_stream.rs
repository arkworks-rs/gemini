use crate::stream::Streamer;

/// Given a stream for F(X),
/// produce a stream for XF(X) + 1
pub struct RightRotationStreamer<'a, F, S>(&'a S, F);

pub struct RightRotationIter<I>
where
    I: Iterator,
{
    end: Option<I::Item>,
    base_iter: I,
}

impl<'a, S> RightRotationStreamer<'a, S::Item, S>
where
    S: Streamer,
    S::Item: Copy,
{
    pub fn new(stream: &'a S, pad: S::Item) -> Self {
        Self(stream, pad)
    }
}

impl<'a, S> Streamer for RightRotationStreamer<'a, S::Item, S>
where
    S: Streamer,
    S::Item: Copy,
{
    type Item = S::Item;

    type Iter = RightRotationIter<S::Iter>;

    fn stream(&self) -> Self::Iter {
        RightRotationIter {
            end: Some(self.1),
            base_iter: self.0.stream(),
        }
    }

    fn len(&self) -> usize {
        self.0.len() + 1
    }
}

impl<I> Iterator for RightRotationIter<I>
where
    I: Iterator,
{
    type Item = I::Item;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        match self.base_iter.next() {
            Some(e) => Some(e),
            None => self.end.take(),
        }
    }
}

#[test]
fn test_rrot() {
    let numbers = (0..100u64).collect::<Vec<_>>();
    let right_rotation = RightRotationStreamer(&numbers.as_slice(), &1)
        .stream()
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(right_rotation[0], 0);
    assert_eq!(right_rotation[1], 1);
    assert_eq!(right_rotation[99], 99);
    assert_eq!(right_rotation[100], 1);
}
