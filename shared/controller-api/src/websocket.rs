// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! RFC 6455, the server half of it, and no more of it than a console needs.
//!
//! # Why by hand
//!
//! A console is a raw HTTP/1.1 upgrade to a byte stream — the right shape for
//! a CLI, and a shape no browser can ask for: `WebSocket` sends only its own
//! upgrade, and `fetch` may not set `Connection` or `Upgrade` at all (they
//! are forbidden header names). So the only console the first foreign client
//! could reach was the one it wrote a paragraph about instead of using.
//!
//! What that needs from this stack is a handshake and a frame header. Both
//! are short and neither has a version to keep up with: the accept key is one
//! SHA-1 over a constant, and the frames a terminal sends are binary, text,
//! ping and close. A crate for that would be a dependency added for eighty
//! lines, and this tree already carries the two primitives (`ring` does the
//! SHA-1, `base64` the encoding) because rustls and the JWT half need them.
//!
//! What is NOT here, deliberately: permessage-deflate (a console is a
//! keystroke at a time), extensions of any kind, and the client half. A
//! server that negotiates nothing is a server with nothing to get wrong.

use base64::Engine as _;

/// The magic the RFC appends to the client's key before hashing. A protocol
/// constant, not a name anybody chose.
const ACCEPT_MAGIC: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// The one frame this stack sends: a whole binary message.
const OP_BINARY: u8 = 0x2;

/// The value of `Sec-WebSocket-Accept` for a client's `Sec-WebSocket-Key`.
///
/// The whole of the handshake's proof: it says "I read your key and I speak
/// this protocol", which is what tells a browser it is not talking to a
/// server that happened to answer 101 to something else. Which is exactly
/// what this API did before — the upgrade token was never looked at, so a
/// WebSocket handshake got a 101 with `Upgrade: meister-console` and no
/// accept header, and the browser threw the connection away.
pub fn accept_key(key: &str) -> String {
    let digest = ring::digest::digest(
        &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
        format!("{}{ACCEPT_MAGIC}", key.trim()).as_bytes(),
    );
    base64::engine::general_purpose::STANDARD.encode(digest.as_ref())
}

/// Is this request a WebSocket handshake, and what does it have to be
/// answered with?
///
/// `None` is every other upgrade, the raw console included — this is the one
/// place the two are told apart, and it is a header and not a route on
/// purpose: one URL, one set of bytes, two framings.
pub fn handshake(headers: &axum::http::HeaderMap) -> Option<String> {
    let upgrade = headers
        .get(axum::http::header::UPGRADE)?
        .to_str()
        .ok()?
        .trim();
    if !upgrade.eq_ignore_ascii_case("websocket") {
        return None;
    }
    // Version 13 is the only one there is; a client asking for another is a
    // client this cannot serve, and answering it with a 101 would be worse
    // than not answering it.
    let version = headers
        .get("sec-websocket-version")
        .and_then(|v| v.to_str().ok())
        .map(str::trim);
    if version.is_some_and(|v| v != "13") {
        return None;
    }
    let key = headers.get("sec-websocket-key")?.to_str().ok()?;
    Some(accept_key(key))
}

/// One whole binary message, framed for a client.
///
/// Never masked: masking is the client's half of the protocol and a server
/// that masked would be one no browser reads.
pub fn binary_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 10);
    out.push(0x80 | OP_BINARY);
    match payload.len() {
        n if n < 126 => out.push(n as u8),
        n if n <= u16::MAX as usize => {
            out.push(126);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            out.push(127);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    out.extend_from_slice(payload);
    out
}

/// A close frame with the normal-closure code, so a browser sees an ending
/// rather than a socket that stopped.
pub fn close_frame() -> Vec<u8> {
    vec![0x88, 0x02, 0x03, 0xe8]
}

/// What one frame off the wire means to a console.
#[derive(Debug, PartialEq, Eq)]
pub enum Incoming {
    /// Bytes for the guest — text and binary both, because a terminal that
    /// sends `ls\n` as text means the same three bytes a terminal that sends
    /// it as binary does.
    Data(Vec<u8>),
    /// Answer this, byte for byte, as a pong.
    Ping(Vec<u8>),
    /// The client is done.
    Close,
}

/// Read one whole message from a client, following continuation frames.
///
/// Cancel-UNSAFE by nature — half a frame read is a stream out of step — so
/// it is called from a task of its own that owns the reader, and the pump
/// selects on the channel that task feeds. That is the same reason the raw
/// console can use `read()` inside a `select!` and this cannot.
pub async fn read_message<R>(reader: &mut R, limit: usize) -> std::io::Result<Incoming>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut message: Vec<u8> = Vec::new();
    loop {
        let mut head = [0u8; 2];
        reader.read_exact(&mut head).await?;
        let fin = head[0] & 0x80 != 0;
        let opcode = head[0] & 0x0f;
        let masked = head[1] & 0x80 != 0;
        let len = match head[1] & 0x7f {
            126 => {
                let mut n = [0u8; 2];
                reader.read_exact(&mut n).await?;
                u16::from_be_bytes(n) as usize
            }
            127 => {
                let mut n = [0u8; 8];
                reader.read_exact(&mut n).await?;
                usize::try_from(u64::from_be_bytes(n)).map_err(|_| oversized())?
            }
            n => n as usize,
        };
        // A client that has not read the RFC, or one that is not a browser at
        // all. Refused rather than tolerated: an unmasked client frame is the
        // one shape a proxy can be made to inject.
        if !masked {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "a client frame must be masked",
            ));
        }
        if len > limit || message.len() + len > limit {
            return Err(oversized());
        }
        let mut mask = [0u8; 4];
        reader.read_exact(&mut mask).await?;
        let mut payload = vec![0u8; len];
        reader.read_exact(&mut payload).await?;
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[i % 4];
        }
        match opcode {
            // A control frame may sit between the fragments of a message, so
            // these answer immediately and do not touch what is accumulated.
            0x8 => return Ok(Incoming::Close),
            0x9 => return Ok(Incoming::Ping(payload)),
            0xa => continue,
            // Continuation, text, binary. The distinction between the last
            // two is about what the bytes MEAN, and to a serial line they
            // mean the same thing.
            0x0..=0x2 => {
                message.extend_from_slice(&payload);
                if fin {
                    return Ok(Incoming::Data(message));
                }
            }
            other => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unknown websocket opcode {other:#x}"),
                ));
            }
        }
    }
}

fn oversized() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "websocket message larger than a console accepts",
    )
}

/// A pong for a ping, which is the whole of what keeps a browser's connection
/// alive through an intermediary.
pub fn pong_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x8a];
    // A control frame's payload is at most 125 bytes by the RFC, so the
    // one-byte length is the only case there is.
    let payload = &payload[..payload.len().min(125)];
    out.push(payload.len() as u8);
    out.extend_from_slice(payload);
    out
}

/// How much of a console travels in one frame. The same bound the node
/// applies to one write, so a browser cannot send something the tier below
/// will refuse.
pub const MAX_MESSAGE: usize = 4096;

/// Turn a framed client into a raw one.
///
/// This is the whole of what the rest of the stack has to know about
/// WebSockets: nothing. What comes back is an ordinary duplex stream, so the
/// console pump that has always spoken raw bytes goes on speaking raw bytes,
/// and so does the socket splice that forwards a console to a sibling
/// replica. One adapter, one place that knows what a frame is, and no second
/// copy of the hardest loop in this tree.
///
/// Two tasks rather than one `select!`, and that is not a preference:
/// `read_message` is cancel-unsafe — half a frame read is a stream out of
/// step — so the reader has to own its half for the whole of its life.
pub fn adapt<S>(ws: S) -> tokio::io::DuplexStream
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (outside, inside) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        let (mut ws_read, ws_write) = tokio::io::split(ws);
        let (mut plain_read, mut plain_write) = tokio::io::split(inside);
        let ws_write = Arc::new(tokio::sync::Mutex::new(ws_write));

        let ponger = ws_write.clone();
        let inbound = tokio::spawn(async move {
            loop {
                match read_message(&mut ws_read, MAX_MESSAGE).await {
                    Ok(Incoming::Data(bytes)) => {
                        if plain_write.write_all(&bytes).await.is_err() {
                            break;
                        }
                    }
                    // Answered here rather than passed on: a ping is about
                    // the connection and not about the guest, and a keepalive
                    // typed into somebody's shell would be a bad day.
                    Ok(Incoming::Ping(payload)) => {
                        let mut out = ponger.lock().await;
                        if out.write_all(&pong_frame(&payload)).await.is_err() {
                            break;
                        }
                    }
                    Ok(Incoming::Close) | Err(_) => break,
                }
            }
            let _ = plain_write.shutdown().await;
        });

        let outbound = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_MESSAGE];
            loop {
                match plain_read.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let mut out = ws_write.lock().await;
                        if out.write_all(&binary_frame(&buf[..n])).await.is_err() {
                            break;
                        }
                    }
                }
            }
            // A close frame rather than a socket that stops: a browser shows
            // the difference to whoever is watching.
            let mut out = ws_write.lock().await;
            let _ = out.write_all(&close_frame()).await;
            let _ = out.shutdown().await;
        });

        let _ = tokio::join!(inbound, outbound);
    });
    outside
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The example from RFC 6455 §1.3, which is the one number that proves
    /// this is the protocol and not something that looks like it.
    #[test]
    fn the_accept_key_is_the_one_the_rfc_prints() {
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    /// One URL, two framings, told apart by a header — and the raw upgrade
    /// the CLI sends must go on being raw.
    #[test]
    fn a_websocket_handshake_is_told_apart_from_the_raw_upgrade() {
        let headers = |pairs: &[(&str, &str)]| {
            let mut map = axum::http::HeaderMap::new();
            for (name, value) in pairs {
                map.insert(
                    axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                    value.parse().unwrap(),
                );
            }
            map
        };

        let browser = headers(&[
            ("upgrade", "websocket"),
            ("sec-websocket-version", "13"),
            ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
        ]);
        assert_eq!(
            handshake(&browser).as_deref(),
            Some("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
        );

        // The CLI's upgrade, which this must not answer as a websocket.
        assert!(handshake(&headers(&[("upgrade", "meister-console")])).is_none());
        // A key-less websocket upgrade is not one.
        assert!(handshake(&headers(&[("upgrade", "websocket")])).is_none());
        // And a version this does not speak is refused rather than answered
        // with a 101 that promises something else.
        assert!(
            handshake(&headers(&[
                ("upgrade", "websocket"),
                ("sec-websocket-version", "8"),
                ("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ=="),
            ]))
            .is_none()
        );
    }

    /// A frame in each direction, which is what the route's test asserts
    /// end to end.
    #[tokio::test]
    async fn a_frame_goes_out_unmasked_and_comes_back_unmasked() {
        assert_eq!(binary_frame(b"hi"), vec![0x82, 0x02, b'h', b'i']);
        // 126 bytes is the first length that needs the two-byte form.
        let long = vec![b'x'; 200];
        let framed = binary_frame(&long);
        assert_eq!(&framed[..4], &[0x82, 126, 0, 200]);

        // What a browser sends: masked, and text where a terminal types.
        let mut wire: Vec<u8> = vec![0x81, 0x80 | 2, 0x01, 0x02, 0x03, 0x04];
        let mask = [0x01, 0x02, 0x03, 0x04];
        for (i, byte) in b"ls".iter().enumerate() {
            wire.push(byte ^ mask[i % 4]);
        }
        let mut reader = std::io::Cursor::new(wire);
        assert_eq!(
            read_message(&mut reader, 4096).await.unwrap(),
            Incoming::Data(b"ls".to_vec())
        );

        // An unmasked client frame is refused: it is the one shape somebody
        // in the middle can be made to inject.
        let mut naked = std::io::Cursor::new(vec![0x82, 0x02, b'h', b'i']);
        assert!(read_message(&mut naked, 4096).await.is_err());
    }

    /// Two fragments and a ping in the middle of them, which is a shape the
    /// RFC allows and a naive reader gets wrong.
    #[tokio::test]
    async fn a_ping_is_answered_and_does_not_join_the_message() {
        let masked = |opcode: u8, fin: bool, payload: &[u8]| {
            let mut out = vec![
                if fin { 0x80 | opcode } else { opcode },
                0x80 | payload.len() as u8,
                9,
                9,
                9,
                9,
            ];
            for (i, byte) in payload.iter().enumerate() {
                out.push(byte ^ [9u8, 9, 9, 9][i % 4]);
            }
            out
        };
        let mut wire = masked(0x9, true, b"beat");
        wire.extend(masked(0x1, false, b"l"));
        wire.extend(masked(0x0, true, b"s"));
        let mut reader = std::io::Cursor::new(wire);

        assert_eq!(
            read_message(&mut reader, 4096).await.unwrap(),
            Incoming::Ping(b"beat".to_vec())
        );
        assert_eq!(pong_frame(b"beat"), vec![0x8a, 4, b'b', b'e', b'a', b't']);
        assert_eq!(
            read_message(&mut reader, 4096).await.unwrap(),
            Incoming::Data(b"ls".to_vec()),
            "the two fragments are one message"
        );
    }

    /// The adapter, end to end: a browser's masked frame comes out as bytes,
    /// and bytes go back as a frame. Everything above this sees a raw
    /// console and cannot tell which kind of client it is talking to, which
    /// is the entire point.
    #[tokio::test]
    async fn a_framed_client_looks_like_a_raw_one_from_above() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // `browser` is the socket a client would hold; `wire` is what the
        // server side of the upgrade would have been handed.
        let (mut browser, wire) = tokio::io::duplex(4096);
        let mut console = adapt(wire);

        // Typed in the browser: a masked text frame.
        let mut typed = vec![0x81, 0x80 | 2, 7, 7, 7, 7];
        for (i, byte) in b"ls".iter().enumerate() {
            typed.push(byte ^ [7u8, 7, 7, 7][i % 4]);
        }
        browser.write_all(&typed).await.unwrap();
        let mut got = [0u8; 2];
        console.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ls", "the frame is gone and the bytes are here");

        // Printed by the guest: plain bytes, framed on the way out.
        console.write_all(b"$ ").await.unwrap();
        let mut framed = [0u8; 4];
        browser.read_exact(&mut framed).await.unwrap();
        assert_eq!(framed, [0x82, 0x02, b'$', b' ']);
    }
}
