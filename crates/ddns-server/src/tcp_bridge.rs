//! Raw-TCP tunnel: a client connection on the :443 listener with ALPN
//! `ddns-tcp` and SNI `<slug>.<domain>` is bridged to the client's local
//! service over a mux stream. Bytes flow visitor → client as DATA frames;
//! client → visitor DATA frames are written to the socket. Half-close: visitor
//! EOF sends CLOSE(OK); client CLOSE shuts down the socket write side.

use bytes::Bytes;
use ddns_proto::frame::CLOSE_OK;
use ddns_proto::{Frame, Opcode, OpenMeta, StreamKind};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::{Duration, timeout};
use tokio_rustls::server::TlsStream;

use crate::http_app::BrokerState;
use crate::session::{DATA_CHUNK_MAX, STREAM_QUEUE_CAP};

/// How long to wait for the visitor direction to finish after the client closed.
/// The client closes once it has sent everything, so the visitor read normally
/// hits EOF immediately; this only bounds the case where it never does.
const VISITOR_DRAIN_GRACE: Duration = Duration::from_secs(5);

pub async fn handle(tls: TlsStream<TcpStream>, state: BrokerState) {
    let Some(sni) = tls.get_ref().1.server_name().map(|n| n.to_string()) else {
        return; // no SNI → nothing to route on
    };
    let suffix = format!(".{}", state.config.domain);
    let Some(slug) = sni
        .strip_suffix(&suffix)
        .filter(|s| !s.is_empty() && !s.contains('.'))
        .map(str::to_string)
    else {
        return;
    };
    let Some(session) = state.registry.lookup(&slug) else {
        return;
    };
    if !session.want_tcp || !session.register_stream() {
        return;
    }

    let stream_id = session.next_stream_id();
    let (from_client_tx, mut from_client_rx) = mpsc::channel(STREAM_QUEUE_CAP);
    session.streams.insert(stream_id, from_client_tx);

    let mut payload = Vec::new();
    if (OpenMeta {
        kind: StreamKind::Tcp,
        port: 0,
        head: None,
    })
    .encode(&mut payload)
    .is_err()
    {
        session.release_stream();
        session.streams.remove(&stream_id);
        return;
    }
    if !session
        .send_frame(&Frame {
            opcode: Opcode::Open,
            stream_id,
            payload: Bytes::from(payload),
        })
        .await
    {
        session.release_stream();
        session.streams.remove(&stream_id);
        return;
    }

    let (mut rd, mut wr) = tokio::io::split(tls);

    // Visitor → client: read chunks → DATA frames; EOF/error → CLOSE(OK).
    let session_v = session.clone();
    let mut visitor_task = tokio::spawn(async move {
        let mut buf = vec![0u8; DATA_CHUNK_MAX];
        loop {
            match rd.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    session_v.record_tx(n);
                    let f = Frame {
                        opcode: Opcode::Data,
                        stream_id,
                        payload: Bytes::copy_from_slice(&buf[..n]),
                    };
                    if !session_v.send_frame(&f).await {
                        return;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = session_v
            .send_frame(&Frame {
                opcode: Opcode::Close,
                stream_id,
                payload: Bytes::copy_from_slice(&[CLOSE_OK]),
            })
            .await;
    });

    // Client → visitor: DATA frames → socket; CLOSE → shutdown write side.
    while let Some(f) = from_client_rx.recv().await {
        match f.opcode {
            Opcode::Data => {
                session.record_rx(f.payload.len());
                if wr.write_all(&f.payload).await.is_err() {
                    break;
                }
            }
            Opcode::Close => break,
            _ => {}
        }
    }
    let _ = wr.shutdown().await;
    // Give the visitor→client direction a bounded grace period instead of
    // aborting it outright. `abort()` cancels the task at its current await
    // point, so a DATA frame that is mid-`send_frame` when the client closes is
    // discarded rather than relayed. The visitor read normally reaches EOF as
    // soon as the client closes, so this returns immediately in the common case
    // and only waits when the peer never closes.
    if timeout(VISITOR_DRAIN_GRACE, &mut visitor_task)
        .await
        .is_err()
    {
        visitor_task.abort();
    }

    session.streams.remove(&stream_id);
    session.release_stream();
}
