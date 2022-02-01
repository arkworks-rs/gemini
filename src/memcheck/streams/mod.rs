mod audit_stream;
mod init_stream;
mod read_stream;
mod write_stream;

use std::borrow::Borrow;

use ark_ff::Field;
pub use audit_stream::AuditStream;
pub use init_stream::InitStream;
pub use read_stream::ReadStream;
pub use write_stream::WriteStream;

use crate::entryproduct::streams::entry_product_streams;
use crate::stream::Streamer;

use crate::entry_product::streams::entry_product_streams;
use crate::entry_product::streams::{ProductStream, RightRotationStreamer};

type Eps<F, S> = (RightRotationStreamer<F, S>, ProductStream<F, S>);

pub fn memcheck_streams<SET, SUB, IND, F>(
    subset: SUB,
    set: SET,
    index: IND,
    y: F,
    z: F,
) -> (
    Eps<F, InitStream<F, SET>>,
    Eps<F, ReadStream<F, SUB, IND>>,
    Eps<F, WriteStream<F, SUB, IND>>,
    Eps<F, AuditStream<F, SET, IND>>,
)
where
    F: Field,
    SET: Streamer,
    SUB: Streamer,
    SET::Item: Borrow<F>,
    SUB::Item: Borrow<F>,
    IND: Streamer<Item = usize>,
{
    let memcheck_init = InitStream::new(set, y, z);
    let (memcheck_init_sh, memcheck_init_acc) = entry_product_streams(memcheck_init);
    let memcheck_read = ReadStream::new(subset, index, y, z);
    let (memcheck_read_sh, memcheck_read_acc) = entry_product_streams(memcheck_read);
    let memcheck_write = WriteStream::new(subset, index, y, z);
    let (memcheck_write_sh, memcheck_write_acc) = entry_product_streams(memcheck_write);
    let memcheck_audit = AuditStream::new(set, index, y, z);
    let (memcheck_audit_sh, memcheck_audit_acc) = entry_product_streams(memcheck_audit);

    (
        (memcheck_init_sh, memcheck_init_acc),
        (memcheck_read_sh, memcheck_read_acc),
        (memcheck_write_sh, memcheck_write_acc),
        (memcheck_audit_sh, memcheck_audit_acc),
    )
}
