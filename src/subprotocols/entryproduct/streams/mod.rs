mod product_stream;
mod rrot_stream;

pub use product_stream::ProductStream;
pub use rrot_stream::RightRotationStreamer;

use ark_ff::Field;
use ark_std::iter::Skip;

use crate::iterable::Iterable;

pub fn entry_product_streams<'a, S, F>(
    streamer: &'a S,
) -> (RightRotationStreamer<'a, S>, ProductStream<'a, F, S>)
where
    S: crate::iterable::Iterable<Item = F>,
    F: Field,
{
    (
        RightRotationStreamer::new(streamer, F::one()),
        ProductStream::new(streamer),
    )
}

pub struct NMonic<'a, S: Iterable>(pub &'a S);

impl<'a, S: Iterable> Iterable for NMonic<'a, S> {
    type Item = S::Item;

    type Iter = Skip<S::Iter>;

    fn iter(&self) -> Self::Iter {
        self.0.iter().skip(1)
    }

    fn len(&self) -> usize {
        self.0.len() - 1
    }
}
