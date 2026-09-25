// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Serial-console client using an HTTP upgrade to a bidirectional byte stream.
//! It owns the connection after the handshake. Ctrl-] detaches; RawMode restores
//! the terminal on normal scope exit or unwinding.

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::client::{Transport, transport_for};
use crate::generic::Ctx;

/// What ends a session from this side. `0x1d` is Ctrl-].
const DETACH: u8 = 0x1d;

/// Requested HTTP upgrade protocol.
const CONSOLE_PROTOCOL: &str = "meister-console";

/// Attach to a VM's serial line.
pub async fn connect(ctx: &Ctx<'_>, name: &str) -> Result<()> {
    let path = format!("{}/console", ctx.path("vms", Some(name))?);
    let transport = transport_for(&ctx.endpoint)?;
    let mut stream = dial(&transport, ctx.client.tls()).await?;

    let host = match &transport {
        Transport::Unix(_) => "localhost".to_string(),
        Transport::Http { authority } => authority.clone(),
        Transport::Https { authority, .. } => authority.clone(),
    };
    let mut request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: upgrade\r\n\
         Upgrade: {CONSOLE_PROTOCOL}\r\n"
    );
    if let Some(auth) = ctx.client.authorization() {
        request.push_str(&format!("Authorization: {auth}\r\n"));
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .context("asking for the console")?;

    let (status, body) = read_head(&mut stream).await?;
    if status != 101 {
        // Include the API error message when the refusal body supplies one.
        bail!("{}", refusal(status, &body));
    }

    eprintln!("connected to {name} — Ctrl-] to detach");
    let raw = RawMode::enter()?;
    let outcome = pump(stream).await;
    drop(raw);
    eprintln!();
    outcome
}

/// Open the configured Unix, TCP or TLS transport for the console stream.
async fn dial(
    transport: &Transport,
    tls: Option<std::sync::Arc<tokio_rustls::rustls::ClientConfig>>,
) -> Result<Box<dyn AsyncReadWrite + Unpin + Send>> {
    Ok(match transport {
        Transport::Unix(socket) => {
            let stream = tokio::net::UnixStream::connect(socket)
                .await
                .with_context(|| {
                    format!(
                        "connecting to {} - is the agent running, and do you have permission \
                         on the socket?",
                        socket.display()
                    )
                })?;
            Box::new(stream)
        }
        Transport::Http { authority } => {
            let stream = tokio::net::TcpStream::connect(authority)
                .await
                .with_context(|| format!("connecting to {authority}"))?;
            let _ = stream.set_nodelay(true);
            Box::new(stream)
        }
        Transport::Https { authority, host } => {
            let config = tls.context("an https endpoint with no tls config")?;
            let stream = tokio::net::TcpStream::connect(authority)
                .await
                .with_context(|| format!("connecting to {authority}"))?;
            let _ = stream.set_nodelay(true);
            let server_name = tokio_rustls::rustls::pki_types::ServerName::try_from(host.clone())
                .with_context(|| format!("{host} is not a usable server name"))?;
            let stream = tokio_rustls::TlsConnector::from(config)
                .connect(server_name, stream)
                .await
                .context("tls handshake failed")?;
            Box::new(stream)
        }
    })
}

/// Everything a console needs of a connection.
pub trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> AsyncReadWrite for T {}

/// Read through the response headers without consuming subsequent console bytes.
async fn read_head<S: AsyncRead + Unpin>(stream: &mut S) -> Result<(u16, Vec<u8>)> {
    let mut buf = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        let n = stream.read(&mut byte).await.context("reading the answer")?;
        if n == 0 {
            bail!("the endpoint closed the connection without answering");
        }
        buf.push(byte[0]);
        if buf.len() > 16 * 1024 {
            bail!("the endpoint sent a response head longer than 16 KiB");
        }
    }
    let head = String::from_utf8_lossy(&buf).to_string();
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .context("the endpoint's answer has no status code")?;

    // A refusal carries a body; 101 does not. Read what the content-length
    // promises so the sentence can be printed.
    let length = head
        .lines()
        .find_map(|l| {
            let (name, value) = l.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    let mut body = vec![0u8; length.min(64 * 1024)];
    if !body.is_empty() {
        let _ = stream.read_exact(&mut body).await;
    }
    Ok((status, body))
}

/// The sentence behind a refusal, out of the `Status` object.
fn refusal(status: u16, body: &[u8]) -> String {
    #[derive(serde::Deserialize)]
    struct Status {
        #[serde(default)]
        message: String,
    }
    match serde_json::from_slice::<Status>(body) {
        Ok(s) if !s.message.is_empty() => format!("{status}: {}", s.message),
        _ if body.is_empty() => format!("{status} and nothing more"),
        _ => format!("{status}: {}", String::from_utf8_lossy(body).trim()),
    }
}

/// The session: this terminal and that guest, until one of them stops.
async fn pump<S: AsyncReadWrite + Unpin>(stream: S) -> Result<()> {
    let (mut from_guest, mut to_guest) = tokio::io::split(stream);
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut from_terminal = [0u8; 1024];
    let mut from_line = vec![0u8; 8192];

    loop {
        tokio::select! {
            read = from_guest.read(&mut from_line) => match read {
                Ok(0) => {
                    eprintln!("\r\nthe console was closed by the other end");
                    return Ok(());
                }
                Err(e) => return Err(e).context("reading the guest"),
                Ok(n) => {
                    stdout.write_all(&from_line[..n]).await?;
                    stdout.flush().await?;
                }
            },
            read = stdin.read(&mut from_terminal) => match read {
                // Ctrl-D at the terminal is not the guest's business: it means
                // this client is done, and the guest keeps running.
                Ok(0) => return Ok(()),
                Err(e) => return Err(e).context("reading the terminal"),
                Ok(n) => {
                    if let Some(cut) = from_terminal[..n].iter().position(|b| *b == DETACH) {
                        // Everything before the key still belongs to the guest.
                        if cut > 0 {
                            to_guest.write_all(&from_terminal[..cut]).await?;
                        }
                        return Ok(());
                    }
                    to_guest.write_all(&from_terminal[..n]).await?;
                }
            },
        }
    }
}

/// Restore the terminal on scope exit or unwinding. Process termination can bypass Drop.
struct RawMode {
    original: Option<nix::sys::termios::Termios>,
}

impl RawMode {
    fn enter() -> Result<Self> {
        use nix::sys::termios;
        let stdin = std::io::stdin();
        // Leave pipes and redirected input unchanged.
        if !nix::unistd::isatty(&stdin).unwrap_or(false) {
            return Ok(Self { original: None });
        }
        let original = termios::tcgetattr(&stdin).context("reading the terminal mode")?;
        let mut raw = original.clone();
        termios::cfmakeraw(&mut raw);
        termios::tcsetattr(&stdin, termios::SetArg::TCSANOW, &raw)
            .context("putting the terminal into raw mode")?;
        Ok(Self {
            original: Some(original),
        })
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        if let Some(original) = &self.original {
            let stdin = std::io::stdin();
            let _ =
                nix::sys::termios::tcsetattr(&stdin, nix::sys::termios::SetArg::TCSANOW, original);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The refusal a person reads is the server's sentence, not its number.
    #[test]
    fn a_refusal_prints_what_the_server_said() {
        let body = br#"{"apiVersion":"meister.io/v1","kind":"Status","code":409,
                        "reason":"Conflict","message":"somebody else is holding this console"}"#;
        assert_eq!(
            refusal(409, body),
            "409: somebody else is holding this console"
        );
        // Not this API at all: the body as it stands, rather than a parse
        // error about it.
        assert_eq!(refusal(502, b"<html>nope</html>"), "502: <html>nope</html>");
        assert_eq!(refusal(404, b""), "404 and nothing more");
    }

    /// Header parsing must preserve the guest's first bytes.
    #[tokio::test]
    async fn the_head_is_read_without_eating_the_stream() {
        let wire = b"HTTP/1.1 101 Switching Protocols\r\nupgrade: meister-console\r\n\r\nGUEST";
        let mut cursor = std::io::Cursor::new(wire.to_vec());
        let (status, body) = read_head(&mut cursor).await.unwrap();
        assert_eq!(status, 101);
        assert!(body.is_empty(), "101 carries none");
        // And the guest's first bytes are still there to be read.
        let mut rest = Vec::new();
        cursor.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"GUEST");
    }

    /// A refusal's body is read too, or there would be nothing to print.
    #[tokio::test]
    async fn a_refusal_body_is_read_by_its_length() {
        let wire = b"HTTP/1.1 409 Conflict\r\ncontent-length: 4\r\n\r\nbusy";
        let mut cursor = std::io::Cursor::new(wire.to_vec());
        let (status, body) = read_head(&mut cursor).await.unwrap();
        assert_eq!(status, 409);
        assert_eq!(body, b"busy");
    }
}
