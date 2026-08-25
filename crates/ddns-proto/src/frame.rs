use bytes::Bytes;

use crate::MAX_FRAME_PAYLOAD;

pub const FRAME_HEADER_LEN: usize = 9;
pub const CLOSE_OK: u8 = 0;
pub const CLOSE_APP_ERROR: u8 = 1;
pub const CLOSE_QUOTA: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    #[error("frame shorter than {FRAME_HEADER_LEN}-byte header: got {len}")]
    Truncated { len: usize },
    #[error("unknown opcode byte: {code}")]
    UnknownOpcode { code: u8 },
    #[error("declared length {declared} does not match payload length {actual}")]
    LengthMismatch { declared: u32, actual: usize },
    #[error("payload too large: {len} bytes (max {max})")]
    PayloadTooLarge { len: usize, max: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    Open,
    OpenAck,
    OpenReject,
    Data,
    Close,
    Ping,
    /// UDP flow open (broker -> client): payload = `OpenMeta` with the local
    /// UDP target port. One flow per (visitor addr -> local target) pair.
    UOpen,
    /// UDP datagram (both directions): payload = one datagram, verbatim.
    UData,
    /// UDP flow close (both directions): idle timeout or socket error.
    UClose,
}

impl Opcode {
    pub fn as_u8(&self) -> u8 {
        match self {
            Opcode::Open => 1,
            Opcode::OpenAck => 2,
            Opcode::OpenReject => 3,
            Opcode::Data => 4,
            Opcode::Close => 5,
            Opcode::Ping => 6,
            Opcode::UOpen => 7,
            Opcode::UData => 8,
            Opcode::UClose => 9,
        }
    }

    pub fn from_u8(code: u8) -> Result<Opcode, FrameError> {
        Ok(match code {
            1 => Opcode::Open,
            2 => Opcode::OpenAck,
            3 => Opcode::OpenReject,
            4 => Opcode::Data,
            5 => Opcode::Close,
            6 => Opcode::Ping,
            7 => Opcode::UOpen,
            8 => Opcode::UData,
            9 => Opcode::UClose,
            other => return Err(FrameError::UnknownOpcode { code: other }),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub opcode: Opcode,
    pub stream_id: u32,
    pub payload: Bytes,
}

impl Frame {
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), FrameError> {
        if self.payload.len() > MAX_FRAME_PAYLOAD {
            return Err(FrameError::PayloadTooLarge {
                len: self.payload.len(),
                max: MAX_FRAME_PAYLOAD,
            });
        }
        out.reserve(FRAME_HEADER_LEN + self.payload.len());
        out.push(self.opcode.as_u8());
        out.extend_from_slice(&self.stream_id.to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.payload);
        Ok(())
    }

    pub fn decode(buf: &[u8]) -> Result<Frame, FrameError> {
        if buf.len() < FRAME_HEADER_LEN {
            return Err(FrameError::Truncated { len: buf.len() });
        }
        let opcode = Opcode::from_u8(buf[0])?;
        let stream_id = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
        let declared = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]);
        let actual = buf.len() - FRAME_HEADER_LEN;
        if declared as usize != actual {
            return Err(FrameError::LengthMismatch { declared, actual });
        }
        if actual > MAX_FRAME_PAYLOAD {
            return Err(FrameError::PayloadTooLarge {
                len: actual,
                max: MAX_FRAME_PAYLOAD,
            });
        }
        Ok(Frame {
            opcode,
            stream_id,
            payload: Bytes::copy_from_slice(&buf[FRAME_HEADER_LEN..]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER_LEN: usize = 9;

    #[test]
    fn opcode_roundtrip() {
        for (code, op) in [
            (1u8, Opcode::Open),
            (2, Opcode::OpenAck),
            (3, Opcode::OpenReject),
            (4, Opcode::Data),
            (5, Opcode::Close),
            (6, Opcode::Ping),
            (7, Opcode::UOpen),
            (8, Opcode::UData),
            (9, Opcode::UClose),
        ] {
            assert_eq!(op.as_u8(), code);
            assert_eq!(Opcode::from_u8(code).unwrap(), op);
        }
        assert!(matches!(
            Opcode::from_u8(0),
            Err(FrameError::UnknownOpcode { code: 0 })
        ));
        assert!(matches!(
            Opcode::from_u8(10),
            Err(FrameError::UnknownOpcode { code: 10 })
        ));
    }

    #[test]
    fn encode_writes_header_and_payload() {
        let frame = Frame {
            opcode: Opcode::Data,
            stream_id: 0x0102_0304,
            payload: Bytes::from_static(b"hello"),
        };
        let mut out = Vec::new();
        frame.encode(&mut out).unwrap();
        assert_eq!(out.len(), HEADER_LEN + 5);
        assert_eq!(&out[0..1], &[4]); // opcode
        assert_eq!(&out[1..5], &[0x01, 0x02, 0x03, 0x04]); // stream id BE
        assert_eq!(&out[5..9], &[0, 0, 0, 5]); // length BE
        assert_eq!(&out[9..], b"hello");
    }

    #[test]
    fn encode_rejects_oversized_payload() {
        let frame = Frame {
            opcode: Opcode::Data,
            stream_id: 1,
            payload: Bytes::from(vec![0u8; super::super::MAX_FRAME_PAYLOAD + 1]),
        };
        let mut out = Vec::new();
        let err = frame.encode(&mut out).unwrap_err();
        assert!(matches!(err, FrameError::PayloadTooLarge { .. }));
    }

    #[test]
    fn decode_roundtrip() {
        let frame = Frame {
            opcode: Opcode::Ping,
            stream_id: 7,
            payload: Bytes::from_static(b"xy"),
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf).unwrap();
        let decoded = Frame::decode(&buf).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn decode_rejects_truncated_header() {
        let err = Frame::decode(&[1, 2, 3]).unwrap_err();
        assert!(matches!(err, FrameError::Truncated { .. }));
    }

    #[test]
    fn decode_rejects_length_mismatch() {
        // header declares 10 bytes of payload, only 3 present
        let buf = [1u8, 0, 0, 0, 5, 0, 0, 0, 10, 1, 2, 3];
        let err = Frame::decode(&buf).unwrap_err();
        assert!(matches!(
            err,
            FrameError::LengthMismatch {
                declared: 10,
                actual: 3
            }
        ));
    }

    #[test]
    fn decode_rejects_unknown_opcode() {
        let mut buf = vec![99u8, 0, 0, 0, 1, 0, 0, 0, 0];
        let err = Frame::decode(&buf).unwrap_err();
        assert!(matches!(err, FrameError::UnknownOpcode { code: 99 }));
        // also rejects when header is complete but opcode byte invalid
        buf.push(0);
        assert!(Frame::decode(&buf).is_err());
    }

    #[test]
    fn exact_max_payload_roundtrip() {
        let frame = Frame {
            opcode: Opcode::Data,
            stream_id: 1,
            payload: Bytes::from(vec![0u8; MAX_FRAME_PAYLOAD]),
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf).unwrap();
        assert_eq!(buf.len(), 9 + MAX_FRAME_PAYLOAD);
        let decoded = Frame::decode(&buf).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn empty_payload_roundtrip() {
        let frame = Frame {
            opcode: Opcode::Close,
            stream_id: 0,
            payload: Bytes::new(),
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf).unwrap();
        assert_eq!(buf.len(), 9);
        let decoded = Frame::decode(&buf).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn decode_rejects_payload_too_large() {
        let declared = (MAX_FRAME_PAYLOAD + 1) as u32;
        let mut buf = Vec::with_capacity(9 + MAX_FRAME_PAYLOAD + 1);
        buf.push(Opcode::Data.as_u8());
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&declared.to_be_bytes());
        buf.resize(9 + MAX_FRAME_PAYLOAD + 1, 0);
        let err = Frame::decode(&buf).unwrap_err();
        assert!(matches!(err, FrameError::PayloadTooLarge { .. }));
    }

    #[test]
    fn decode_rejects_8_byte_buffer() {
        let err = Frame::decode(&[0u8; 8]).unwrap_err();
        assert!(matches!(err, FrameError::Truncated { .. }));
    }
    #[test]
    fn udp_frame_roundtrip() {
        let f = Frame {
            opcode: Opcode::UData,
            stream_id: 42,
            payload: Bytes::from_static(b"dns-query-bytes"),
        };
        let mut buf = Vec::new();
        f.encode(&mut buf).unwrap();
        let back = Frame::decode(&buf).unwrap();
        assert_eq!(back.opcode, Opcode::UData);
        assert_eq!(back.stream_id, 42);
        assert_eq!(back.payload.as_ref(), b"dns-query-bytes");
    }
}
