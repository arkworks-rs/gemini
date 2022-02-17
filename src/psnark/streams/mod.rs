mod algebraic_hash;
mod hadamard_stream;
mod lookup_stream;
mod tensor_stream;
mod val_stream;

mod intofield_stream;

pub use hadamard_stream::HadamardStreamer;
pub use tensor_stream::TensorStreamer;
// XXX. this struct should probably replace TensorStreamer.
pub use tensor_stream::LookupTensorStreamer;
pub use lookup_stream::LookupStreamer;
pub use val_stream::{JointColStream, JointRowStream, JointValStream};
pub use intofield_stream::IntoField;
pub use algebraic_hash::AlgebraicHash;
