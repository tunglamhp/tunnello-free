//! P2P connector page + Service Worker, served at the tunnel hostname.
//!
//! These are the browser half of the P2P data plane (spec §5.1). The broker
//! serves the connector page for the tunnel's root HTML document; the page
//! registers the Service Worker, opens a WebRTC data channel, and drives the
//! SDP/ICE signaling handshake over `/__p2p/signal`. Once the channel opens,
//! the page hands it to the Service Worker, which intercepts same-origin
//! `fetch()` calls and routes them over the channel (P2P) — or through the
//! broker with an `X-Tunnello-Relay: 1` escape-hatch header (relay fallback).

/// The connector JS runs on the tunnel hostname, so it derives everything
/// (STUN host, signaling WS, SW scope) from `location` at runtime. The slug is
/// embedded only for observability — the server re-derives it from `Host`.
const CONNECTOR_JS: &str = r#"(function () {
  'use strict';

  // §5.1 step 2: capability check — WebRTC + Service Worker are both required
  // for the P2P fast path. Evergreen browsers have both; without them there
  // is no channel to hand off, so we stop (the visitor keeps the broker's
  // connector shell rather than crashing on `new RTCPeerConnection`).
  if (!('RTCPeerConnection' in window) || !('serviceWorker' in navigator)) {
    return;
  }

  // The broker's STUN listens on UDP 3478 — NOT the HTTPS port. The page is
  // served by the broker (which owns the config), so the port is hardcoded.
  var STUN_PORT = 3478;
  var stunUrl = 'stun:' + location.hostname + ':' + STUN_PORT;

  var p2pReady = false;

  function postToSw(msg, transfer) {
    // §5.1 step 3: `ready` resolves once the SW is active; claim() has made it
    // control this page, so its fetch handler will intercept the next load.
    return navigator.serviceWorker.ready.then(function (reg) {
      if (reg.active) {
        reg.active.postMessage(msg, transfer || []);
      }
    });
  }

  function reload() {
    // §5.1 step 4: the SW now controls this page; reloading re-fetches "/"
    // through the SW (P2P when the channel is ready, relay otherwise).
    location.reload();
  }

  // §5.1 step 2: register the Service Worker at /__tunnello/sw.js.
  navigator.serviceWorker.register('/__tunnello/sw.js').catch(function () {
    // No SW: nothing to hand the channel to. The broker still serves the
    // connector shell; a plain reload would loop, so we simply stop here.
  });

  // §5.1 step 2: create the PeerConnection with the self-hosted STUN server.
  var pc = new RTCPeerConnection({ iceServers: [{ urls: stunUrl }] });

  // §5.1 step 3: create the data channel the SW will drive.
  var dc = pc.createDataChannel('http');

  // §5.1 step 3: once the channel opens, hand it to the SW and reload.
  dc.onopen = function () {
    p2pReady = true;
    // The DataChannel is a transferable: the SW takes ownership and can
    // `send()` over it to route fetches.
    postToSw({ type: 'p2p-ready', dc: dc }, [dc]).then(reload);
  };
  dc.onerror = function () {
    postToSw({ type: 'relay-mode' }).then(reload);
  };

  // §5.1 step 2: open the signaling WebSocket on the tunnel host.
  var ws = new WebSocket(
    (location.protocol === 'https:' ? 'wss://' : 'ws://') +
      location.host +
      '/__p2p/signal'
  );

  ws.onopen = function () {
    // §5.1 step 2: trickle gathered candidates, then send the offer.
    pc.onicecandidate = function (e) {
      if (e.candidate) {
        ws.send(JSON.stringify({ type: 'ice', candidate: e.candidate.candidate }));
      }
    };
    pc.createOffer()
      .then(function (o) { return pc.setLocalDescription(o); })
      .then(function () {
        ws.send(JSON.stringify({
          type: 'offer',
          sdp: pc.localDescription.sdp,
          ice: []
        }));
      })
      .catch(function () { postToSw({ type: 'relay-mode' }).then(reload); });
  };

  ws.onmessage = function (ev) {
    var msg = JSON.parse(ev.data);
    if (msg.type === 'answer') {
      // §5.1 step 3: apply the client's answer; the channel-open handoff and
      // reload happen in `dc.onopen` above.
      pc.setRemoteDescription({ type: 'answer', sdp: msg.sdp }).catch(function () {
        postToSw({ type: 'relay-mode' }).then(reload);
      });
    }
  };

  ws.onerror = function () { postToSw({ type: 'relay-mode' }).then(reload); };

  // §5.1 step 5: ICE timeout (5 s hard cap) → relay mode.
  setTimeout(function () {
    if (!p2pReady) {
      postToSw({ type: 'relay-mode' }).then(reload);
    }
  }, 5000);
})();
"#;

/// Service Worker: intercepts same-origin fetches and routes them over the P2P
/// data channel (REQ/RESP/DATA/CLOSE framing, spec §4) when ready, or through
/// the broker with the relay escape hatch otherwise.
const SW_JS: &str = r#"'use strict';

// Data-channel frame opcodes (spec §4) — MUST match ddns-client/src/p2p.rs.
var OP_REQ = 0x01;
var OP_RESP = 0x02;
var OP_DATA = 0x03;
var OP_CLOSE = 0x04;

var p2pReady = false;
var dc = null;
var nextRequestId = 0;
// requestId -> { resolve, reject, status, headers, chunks }
var pending = new Map();

self.addEventListener('install', function () {
  self.skipWaiting();
});

self.addEventListener('activate', function (e) {
  // Claim the already-open connector page so its next fetch is intercepted
  // without a second visit (spec §5.1 step 4).
  e.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', function (e) {
  var req = e.request;
  var url = new URL(req.url);

  // Never intercept the SW script itself.
  if (url.pathname === '/__tunnello/sw.js') {
    return;
  }

  if (!p2pReady || !dc || dc.readyState !== 'open') {
    // §5.1 step 5: relay fallback — every fallback fetch carries the escape
    // hatch so the broker never re-serves the connector page.
    e.respondWith(relay(req));
    return;
  }

  // §5.1 step 4: route over the data channel.
  e.respondWith(routeOverChannel(req, url));
});

self.addEventListener('message', function (e) {
  var d = e.data;
  if (d.type === 'p2p-ready' && d.dc) {
    // §5.1 step 3: the page handed over the opened data channel.
    dc = d.dc;
    p2pReady = true;
    wireDc();
  } else if (d.type === 'relay-mode') {
    // §5.1 step 5: ICE failed or timed out — fall back to the broker relay.
    p2pReady = false;
    dc = null;
  }
});

function wireDc() {
  dc.binaryType = 'arraybuffer';
  dc.onmessage = function (ev) { handleFrame(ev.data); };
  dc.onclose = function () { p2pReady = false; dc = null; };
  dc.onerror = function () { p2pReady = false; dc = null; };
}

// §5.1 step 5: relay the request to the broker, preserving the visitor's
// original headers and adding the escape-hatch header.
function relay(req) {
  var headers = new Headers(req.headers);
  headers.set('X-Tunnello-Relay', '1');
  return fetch(new Request(req, { headers: headers }));
}

// §5.1 step 4: send REQ (+ DATA body) frames and resolve the fetch with the
// Response reconstructed from RESP + DATA frames.
function routeOverChannel(req, url) {
  return new Promise(function (resolve, reject) {
    var requestId = nextRequestId++;
    pending.set(requestId, {
      resolve: resolve,
      reject: reject,
      status: 200,
      headers: {},
      chunks: []
    });

    var head = buildHead(req.method, url, req.headers);
    try {
      dc.send(encodeFrame(OP_REQ, requestId, textEncode(head)));
    } catch (err) {
      pending.delete(requestId);
      relay(req).then(resolve).catch(reject);
      return;
    }

    // v1: forward a request body (if any) as DATA frames.
    if (req.body) {
      req.arrayBuffer().then(function (body) {
        if (body.byteLength > 0) {
          try {
            dc.send(encodeFrame(OP_DATA, requestId, new Uint8Array(body)));
          } catch (err) {
            /* channel died mid-body; onclose flips relay mode */
          }
        }
      }).catch(function () {});
    }
  });
}

function buildHead(method, url, headers) {
  var lines = [method + ' ' + url.pathname + url.search + ' HTTP/1.1'];
  var hasHost = false;
  headers.forEach(function (value, name) {
    lines.push(name + ': ' + value);
    if (name.toLowerCase() === 'host') hasHost = true;
  });
  if (!hasHost) lines.push('host: ' + url.host);
  return lines.join('\r\n') + '\r\n\r\n';
}

function textEncode(s) {
  return new TextEncoder().encode(s);
}

function textDecode(buf) {
  return new TextDecoder().decode(buf);
}

// spec §4 frame layout: opcode(1) ‖ request_id u32 BE ‖ len u32 BE ‖ payload.
function encodeFrame(opcode, requestId, payload) {
  var buf = new ArrayBuffer(9 + payload.length);
  var dv = new DataView(buf);
  dv.setUint8(0, opcode);
  dv.setUint32(1, requestId);
  dv.setUint32(5, payload.length);
  new Uint8Array(buf, 9).set(payload);
  return buf;
}

function decodeFrame(buf) {
  if (buf.byteLength < 9) return null;
  var dv = new DataView(buf);
  var opcode = dv.getUint8(0);
  var requestId = dv.getUint32(1);
  var len = dv.getUint32(5);
  if (buf.byteLength < 9 + len) return null;
  return { opcode: opcode, requestId: requestId, payload: new Uint8Array(buf, 9, len) };
}

function handleFrame(buf) {
  var f = decodeFrame(buf);
  if (!f) return;
  var entry = pending.get(f.requestId);
  if (!entry) return;
  if (f.opcode === OP_RESP) {
    var parsed = parseResponseHead(textDecode(f.payload));
    if (parsed) {
      entry.status = parsed.status;
      entry.headers = parsed.headers;
    }
  } else if (f.opcode === OP_DATA) {
    entry.chunks.push(f.payload);
  } else if (f.opcode === OP_CLOSE) {
    pending.delete(f.requestId);
    resolveEntry(entry);
  }
}

function resolveEntry(entry) {
  var headers = new Headers(entry.headers);
  var body = null;
  if (entry.chunks.length > 0) {
    body = new Blob(entry.chunks, {
      type: headers.get('content-type') || 'application/octet-stream'
    });
  }
  entry.resolve(new Response(body, { status: entry.status, headers: headers }));
}

function parseResponseHead(text) {
  var lines = text.split('\r\n');
  if (lines.length === 0) return null;
  var statusLine = lines[0].split(' ');
  var status = parseInt(statusLine[1], 10);
  if (!(status >= 100 && status <= 599)) return null;
  var headers = {};
  for (var i = 1; i < lines.length; i++) {
    var line = lines[i];
    if (!line) continue;
    var idx = line.indexOf(':');
    if (idx < 0) continue;
    headers[line.slice(0, idx).trim().toLowerCase()] = line.slice(idx + 1).trim();
  }
  return { status: status, headers: headers };
}
"#;

/// Render the connector page for `slug`. The slug is JSON-embedded for
/// observability only; the connector JS derives the STUN host, signaling WS
/// and SW scope from `location`, and the server re-derives the slug from Host.
pub fn connector_page(slug: &str) -> String {
    let slug_json = serde_json::to_string(slug).unwrap_or_else(|_| "null".to_string());
    format!(
        "<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\"><title>tunnel</title></head>\n<body>\
         <script>window.__TUNNELLO_SLUG__={slug_json};</script><script>{CONNECTOR_JS}</script>\
         </body></html>"
    )
}

/// The Service Worker script, served at `/__tunnello/sw.js`.
pub fn service_worker_js() -> &'static str {
    SW_JS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connector_page_embeds_sw_and_slug() {
        let page = connector_page("vivid-otter-72");
        assert!(page.contains("__tunnello/sw.js"), "must register the SW");
        assert!(
            page.contains("\"vivid-otter-72\""),
            "slug must be JSON-embedded"
        );
        assert!(
            page.contains("stun:' + location.hostname"),
            "STUN from hostname"
        );
        assert!(page.contains("3478"), "STUN UDP port hardcoded");
    }

    #[test]
    fn service_worker_carries_relay_hatch_and_frame_opcodes() {
        let sw = service_worker_js();
        assert!(sw.contains("X-Tunnello-Relay"), "relay escape hatch");
        assert!(sw.contains("OP_REQ = 0x01"), "REQ opcode");
        assert!(sw.contains("OP_RESP = 0x02"), "RESP opcode");
        assert!(sw.contains("OP_DATA = 0x03"), "DATA opcode");
        assert!(sw.contains("OP_CLOSE = 0x04"), "CLOSE opcode");
        assert!(sw.contains("clients.claim"), "claim the connector page");
    }
}
