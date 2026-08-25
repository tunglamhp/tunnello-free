use bytes::Bytes;

use crate::{MAX_FRAME_PAYLOAD, ProtoError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamKind {
    Http,
    Tcp,
    Udp,
}

impl StreamKind {
    pub fn as_u8(&self) -> u8 {
        match self {
            StreamKind::Http => 0,
            StreamKind::Tcp => 1,
            StreamKind::Udp => 2,
        }
    }

    pub fn from_u8(code: u8) -> Result<StreamKind, ProtoError> {
        Ok(match code {
            0 => StreamKind::Http,
            1 => StreamKind::Tcp,
            2 => StreamKind::Udp,
            other => return Err(ProtoError::InvalidKind(other)),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenMeta {
    pub kind: StreamKind,
    pub port: u16,
    /// HTTP request head; `Some` iff `kind == StreamKind::Http`.
    pub head: Option<Bytes>,
}

impl OpenMeta {
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), ProtoError> {
        debug_assert!(
            self.head.is_some() == (self.kind == StreamKind::Http),
            "OpenMeta head must be Some iff kind is Http"
        );
        out.reserve(3);
        out.push(self.kind.as_u8());
        out.extend_from_slice(&self.port.to_be_bytes());
        if let Some(head) = &self.head {
            if head.len() > MAX_FRAME_PAYLOAD - 7 {
                return Err(ProtoError::TooLarge {
                    len: head.len() + 7,
                    max: MAX_FRAME_PAYLOAD,
                });
            }
            out.extend_from_slice(&(head.len() as u32).to_be_bytes());
            out.extend_from_slice(head);
        }
        Ok(())
    }

    pub fn decode(buf: &[u8]) -> Result<OpenMeta, ProtoError> {
        let need = |got: usize, want: usize| {
            if got < want {
                Err(ProtoError::Truncated { need: want, got })
            } else {
                Ok(())
            }
        };
        need(buf.len(), 3)?;
        let kind = StreamKind::from_u8(buf[0])?;
        let port = u16::from_be_bytes([buf[1], buf[2]]);
        let mut head = None;
        if kind == StreamKind::Http {
            need(buf.len(), 7)?;
            let head_len = u32::from_be_bytes([buf[3], buf[4], buf[5], buf[6]]) as usize;
            need(buf.len() - 7, head_len)?;
            if head_len > MAX_FRAME_PAYLOAD - 7 {
                return Err(ProtoError::TooLarge {
                    len: head_len + 7,
                    max: MAX_FRAME_PAYLOAD,
                });
            }
            head = Some(Bytes::copy_from_slice(&buf[7..7 + head_len]));
        }
        Ok(OpenMeta { kind, port, head })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    #[test]
    fn kind_roundtrip() {
        assert_eq!(StreamKind::Http.as_u8(), 0);
        assert_eq!(StreamKind::Udp.as_u8(), 2);
        assert_eq!(StreamKind::from_u8(0).unwrap(), StreamKind::Http);
        assert_eq!(StreamKind::from_u8(1).unwrap(), StreamKind::Tcp);
        assert_eq!(StreamKind::from_u8(2).unwrap(), StreamKind::Udp);
        assert!(matches!(
            StreamKind::from_u8(3),
            Err(super::super::ProtoError::InvalidKind(3))
        ));
    }

    #[test]
    fn http_openmeta_roundtrip() {
        let meta = OpenMeta {
            kind: StreamKind::Http,
            port: 8080,
            head: Some(Bytes::from_static(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")),
        };
        let mut out = Vec::new();
        meta.encode(&mut out).unwrap();
        let decoded = OpenMeta::decode(&out).unwrap();
        assert_eq!(decoded, meta);
    }

    #[test]
    fn tcp_openmeta_roundtrip() {
        let meta = OpenMeta {
            kind: StreamKind::Tcp,
            port: 5432,
            head: None,
        };
        let mut out = Vec::new();
        meta.encode(&mut out).unwrap();
        assert_eq!(out.len(), 3); // kind + 2-byte port, no head section
        let decoded = OpenMeta::decode(&out).unwrap();
        assert_eq!(decoded, meta);
    }

    #[test]
    fn decode_rejects_truncation_and_bad_kind() {
        // kind byte present but port truncated
        let err = OpenMeta::decode(&[0, 0x1f]).unwrap_err();
        assert!(matches!(err, super::super::ProtoError::Truncated { .. }));

        let err = OpenMeta::decode(&[9, 0x1f, 0x90]).unwrap_err();
        assert!(matches!(err, super::super::ProtoError::InvalidKind(9)));
    }

    #[test]
    fn http_head_must_fit_in_max_payload() {
        let meta = OpenMeta {
            kind: StreamKind::Http,
            port: 80,
            head: Some(Bytes::from(vec![0u8; super::super::MAX_FRAME_PAYLOAD])),
        };
        let mut out = Vec::new();
        let err = meta.encode(&mut out).unwrap_err();
        assert!(matches!(err, super::super::ProtoError::TooLarge { .. }));
    }
}
