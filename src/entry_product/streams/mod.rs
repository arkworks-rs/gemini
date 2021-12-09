mod product_stream;
mod rrot_stream;

use ark_ff::Field;

use crate::stream::Streamer;

pub use product_stream::ProductStream;
pub use rrot_stream::RightRotationStreamer;

// pub fn entry_product_streams<S, F>(
//     streamer: S,
// ) -> (RightRotationStreamer<F, S>, ProductStream<F, S>)
// where
//     S: Streamer<Item = F>,
//     F: Field,
// {
//     (
//         RightRotationStreamer::new(streamer, F::one()),
//         ProductStream::new(streamer),
//     )
// }
