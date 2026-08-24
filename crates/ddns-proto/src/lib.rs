//! Shared wire protocol and pure logic for the DDNS tunnel broker.
//!
//! This crate is deliberately I/O-free: no sockets, no async, no tokio.
//! Every type here is a contract that `ddns-client` and `ddns-server`
//! compile against, so changes to this crate ripple everywhere.

pub const HEARTBEAT_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
pub const MAX_FRAME_PAYLOAD: usize = 1 << 20; // 1 MiB
pub mod control;
pub mod frame;
pub mod http;
pub mod limits;
pub mod open;
pub mod slug;
pub mod ticket;
pub use control::{Control, ErrorCode, KillReason, Usage};
pub use frame::{Frame, FrameError, Opcode};
pub use limits::TokenLimits;
pub use open::{OpenMeta, StreamKind};
pub use slug::random_slug;

/// Constant-time byte comparison (no extra dep).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error("frame error: {0}")]
    Frame(#[from] frame::FrameError),
    #[error("open metadata too large: {len} bytes (max {max})")]
    TooLarge { len: usize, max: usize },
    #[error("truncated open metadata: need {need} bytes, got {got}")]
    Truncated { need: usize, got: usize },
    #[error("invalid stream kind byte: {0}")]
    InvalidKind(u8),
}
