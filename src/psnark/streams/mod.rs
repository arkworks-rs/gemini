mod hadamard_stream;
mod index_stream;
mod line_stream;
mod lookup_stream;
mod tensor_stream;
mod val_stream;

pub use hadamard_stream::HadamardStreamer;
pub use index_stream::IndexStream;
pub use line_stream::LineStream;
pub use tensor_stream::TensorStreamer;
// XXX. this struct should probably replace TensorStreamer.
pub use tensor_stream::TensorIStreamer;

pub use lookup_stream::LookupStreamer;

pub use val_stream::ValStream;

pub mod memcheck;
pub mod plookup;
