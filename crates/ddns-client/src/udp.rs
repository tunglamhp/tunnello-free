//! UDP flow plumbing for the mux: downstream message type shared between
//! the WS read loop and the per-flow pump task.

use bytes::Bytes;

/// Messages the WS read loop sends into a flow's pump.
pub enum FlowMsg {
    Data(Bytes),
    Close,
}
