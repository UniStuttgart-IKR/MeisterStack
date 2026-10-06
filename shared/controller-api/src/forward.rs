// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Forward a request to the replica holding the relevant peer session.
//!
//! The holder publishes its endpoint in Node or Cluster status. A forwarded
//! request carries a marker so a stale endpoint cannot cause a forwarding loop.
//! Each tier selects the holder and applies its own route authorization.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;

/// Mark a forwarded request to prohibit a second hop through a stale endpoint.
pub const FORWARDED: &str = "x-meister-forwarded";

/// Total sibling-hop deadline, including connection and response. Bounds
/// blackholed connections as well as slow replies; timeout is uncertainty.
pub const SIBLING_TIMEOUT: Duration = Duration::from_secs(5);

/// Who can answer, and how.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Holder {
    /// This process has the session. Ask it.
    Here,
    /// A sibling replica has it, at this REST address. Ask that, once.
    Sibling(String),
    /// Nobody this replica can reach or name. The sentence says which.
    Nowhere(String),
}

/// Peer and tier names used in shared forwarding diagnostics.
#[derive(Clone, Copy, Debug)]
pub struct About {
    /// What holds the session — `"node"`, `"cluster"`.
    pub peer: &'static str,
    /// Whose replicas these are — `"cluster"`, `"cloud"`.
    pub tier: &'static str,
}

/// Choose the local holder, one sibling hop, or an unavailable result.
pub fn holder(
    about: About,
    has_session: bool,
    session_endpoint: Option<&str>,
    forwarded: bool,
) -> Holder {
    if has_session {
        return Holder::Here;
    }
    if forwarded {
        // A sibling sent this here and this replica does not hold the session
        // either. The peer moved between the write and the read, or two
        // replicas disagree; either way, passing it on again would be a loop.
        return Holder::Nowhere(format!(
            "the replica this request was forwarded to does not hold the {}'s session either; \
             the {} has moved, try again",
            about.peer, about.peer
        ));
    }
    match session_endpoint {
        Some(endpoint) if !endpoint.is_empty() => Holder::Sibling(endpoint.to_string()),
        // Either nobody holds it, or the replica that does could not say
        // where it is. The second is a configuration an operator can fix, so
        // the sentence names the key.
        _ => Holder::Nowhere(format!(
            "no replica of this {} is holding this {}'s session, or the one that is could not \
             say where to reach it (advertise_api)",
            about.tier, about.peer
        )),
    }
}

/// What a replica needs to ask its sibling: how to speak, and with what.
#[derive(Clone)]
pub struct Sibling {
    /// The client config for an `https://` sibling: this tier's own
    /// `system:<kind>:<name>` certificate, verified against the CA it trusts
    /// its own clients with. `None` = plain http, which is what a lab runs.
    pub tls: Option<Arc<tokio_rustls::rustls::ClientConfig>>,
    /// TLS default for endpoints without a scheme, inferred from this replica.
    /// This assumes sibling replicas share transport configuration.
    pub serves_tls: bool,
}

/// Return authority and TLS mode. An explicit scheme wins; otherwise use
/// this replica's serving mode.
pub fn dial(endpoint: &str, serves_tls: bool) -> (&str, bool) {
    if let Some(authority) = endpoint.strip_prefix("https://") {
        return (authority.trim_end_matches('/'), true);
    }
    if let Some(authority) = endpoint.strip_prefix("http://") {
        return (authority.trim_end_matches('/'), false);
    }
    (endpoint.trim_end_matches('/'), serves_tls)
}

/// GET once within the sibling deadline and return the body unchanged.
/// Convert a non-success status into an error with its message. Writes
/// use `relay` to preserve their response semantics.
pub async fn ask(sibling: &Sibling, endpoint: &str, path: &str) -> anyhow::Result<Bytes> {
    let answer = relay(sibling, endpoint, hyper::Method::GET, path, Bytes::new()).await?;
    if !answer.status.is_success() {
        // Extract the API error message rather than quoting its JSON envelope.
        bail!(
            "the replica at {endpoint} answered {}: {}",
            answer.status,
            refusal_in(&answer.body).message
        );
    }
    Ok(answer.body)
}

/// Sibling response status and body. Forwarded writes preserve both so a
/// permanent refusal is not converted into a retryable transport error.
pub struct Answer {
    pub status: hyper::StatusCode,
    pub body: Bytes,
}

/// Perform one sibling hop, preserving response status and body.
/// `ask` wraps this for GET requests with its own error conversion.
pub async fn relay(
    sibling: &Sibling,
    endpoint: &str,
    method: hyper::Method,
    path: &str,
    body: Bytes,
) -> anyhow::Result<Answer> {
    match tokio::time::timeout(
        SIBLING_TIMEOUT,
        relay_once(sibling, endpoint, method, path, body),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => bail!(
            "the replica at {endpoint} did not answer within {}s",
            SIBLING_TIMEOUT.as_secs()
        ),
    }
}

async fn relay_once(
    sibling: &Sibling,
    endpoint: &str,
    method: hyper::Method,
    path: &str,
    body: Bytes,
) -> anyhow::Result<Answer> {
    let (authority, tls) = dial(endpoint, sibling.serves_tls);

    let stream = tokio::net::TcpStream::connect(authority)
        .await
        .with_context(|| format!("connecting to the replica at {authority}"))?;
    // The other end of the same measurement the REST edge makes: a handshake
    // is several small writes and a request follows immediately, which is
    // exactly the shape Nagle plus delayed ACK turns into a 40ms stall.
    let _ = stream.set_nodelay(true);

    let request = hyper::Request::builder()
        .method(method)
        .uri(path)
        .header("Host", authority)
        .header("Accept", "application/json")
        // The one content type this API takes on a write, and harmless on a
        // GET whose body is empty.
        .header("Content-Type", "application/json")
        // Once, and only once. See FORWARDED.
        .header(FORWARDED, "1")
        .body(Full::new(body))?;

    let response = if tls {
        let config = sibling.tls.clone().with_context(|| {
            format!("the replica at {endpoint} is https and this one has no client certificate")
        })?;
        let host = authority.rsplit_once(':').map_or(authority, |(h, _)| h);
        let server_name = tokio_rustls::rustls::pki_types::ServerName::try_from(host.to_string())
            .with_context(|| format!("{host} is not a usable server name"))?;
        let stream = tokio_rustls::TlsConnector::from(config)
            .connect(server_name, stream)
            .await
            .with_context(|| format!("tls handshake with the replica at {authority} failed"))?;
        send(TokioIo::new(stream), request).await?
    } else {
        send(TokioIo::new(stream), request).await?
    };

    let status = response.status();
    let body = response.into_body().collect().await?.to_bytes();
    Ok(Answer { status, body })
}

/// The `message` and `reason` of this API's `Status` refusal, or the body as
/// it stands and no reason when it is not one.
///
/// Both halves of a forward read a sibling's refusal with this. A read needs
/// only the message; a forwarded write also needs the reason, so that a
/// node's typed refusal (`CannotServe`, `CannotSend`) survives the hop as a
/// word rather than as prose.
pub fn refusal_in(body: &Bytes) -> crate::Refusal {
    #[derive(serde::Deserialize)]
    struct Status {
        message: String,
        #[serde(default)]
        reason: String,
    }
    match serde_json::from_slice::<Status>(body) {
        Ok(status) => crate::Refusal::new(status.message, status.reason),
        Err(_) => crate::Refusal::plain(String::from_utf8_lossy(body).trim()),
    }
}

async fn send<I>(
    io: I,
    request: hyper::Request<Full<Bytes>>,
) -> anyhow::Result<hyper::Response<hyper::body::Incoming>>
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok(sender.send_request(request).await?)
}

/// Percent-encode every non-unreserved UTF-8 byte in a query value so filters
/// containing separators cannot introduce sibling query parameters.
pub fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three outcomes, and the one that is a rule rather than a lookup:
    /// a request that was already forwarded never forwards again.
    #[test]
    fn a_forward_happens_once_and_only_when_somebody_else_holds_it() {
        let about = About {
            peer: "node",
            tier: "cluster",
        };
        assert_eq!(holder(about, true, None, false), Holder::Here);
        assert_eq!(
            holder(about, true, Some("10.0.0.2:3001"), true),
            Holder::Here,
            "holding it outranks everything else"
        );
        assert_eq!(
            holder(about, false, Some("10.0.0.2:3001"), false),
            Holder::Sibling("10.0.0.2:3001".into())
        );

        // Forwarded here and this replica does not hold it either: a loop
        // starts exactly here, and this is where it does not.
        let Holder::Nowhere(sentence) = holder(about, false, Some("10.0.0.2:3001"), true) else {
            panic!("a second hop would be a loop");
        };
        assert!(sentence.contains("node has moved"), "{sentence}");

        // Nobody published an endpoint. The sentence names the key an
        // operator would have to set.
        let Holder::Nowhere(sentence) = holder(about, false, None, false) else {
            panic!("nobody can answer");
        };
        assert!(sentence.contains("advertise_api"), "{sentence}");
        assert!(sentence.contains("cluster"), "whose replicas: {sentence}");

        // And the same rule one tier up, in the cloud's words.
        let about = About {
            peer: "cluster",
            tier: "cloud",
        };
        let Holder::Nowhere(sentence) = holder(about, false, None, false) else {
            panic!("nobody can answer");
        };
        assert!(sentence.contains("no replica of this cloud"), "{sentence}");
        assert!(sentence.contains("cluster's session"), "{sentence}");
    }

    /// The endpoint decides when it names a scheme, and this replica's own
    /// configuration decides when it does not.
    #[test]
    fn an_endpoint_without_a_scheme_is_read_as_whatever_this_replica_serves() {
        assert_eq!(dial("https://a:3000/", false), ("a:3000", true));
        assert_eq!(dial("http://a:3000", true), ("a:3000", false));
        assert_eq!(dial("a:3000", true), ("a:3000", true));
        assert_eq!(dial("a:3000/", false), ("a:3000", false));
    }

    /// An accepted but silent connection must expire under the sibling deadline.
    /// This exercises response timeout without requiring a network DROP rule.
    #[tokio::test(start_paused = true)]
    async fn a_sibling_that_answers_nothing_is_given_up_on_rather_than_waited_for() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (accepted, was_accepted) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let held = listener.accept().await;
            let _ = accepted.send(());
            // Hold it open and write nothing. A close would be an answer.
            std::future::pending::<()>().await;
            drop(held);
        });

        let sibling = Sibling {
            serves_tls: false,
            tls: None,
        };
        let started = tokio::time::Instant::now();
        let refused = ask(&sibling, &endpoint, "/apis/meister.io/v1/vms/web-1/logs")
            .await
            .expect_err("silence is not an answer");

        assert!(
            was_accepted.await.is_ok(),
            "the connection was taken, so this is the read that timed out"
        );
        assert!(
            refused.to_string().contains("did not answer within 5s"),
            "the 503 has to say the wait was ours and bounded: {refused:#}"
        );
        assert_eq!(
            started.elapsed(),
            SIBLING_TIMEOUT,
            "and it waited exactly the budget, not the kernel's"
        );
    }

    /// What a replica's REST edge answers a refused forward with, read back
    /// the way both halves of a forward read it: the node's word stays a word.
    #[tokio::test]
    async fn a_sibling_refusal_keeps_its_reason_across_the_hop() {
        use axum::response::IntoResponse;
        let answered = crate::ApiError::new(
            hyper::StatusCode::CONFLICT,
            crate::CANNOT_SEND,
            "vm uid-1 has 1 device(s) (crosvm-gpu)",
        )
        .into_response();
        let body = answered.into_body().collect().await.unwrap().to_bytes();

        let refusal = refusal_in(&body);

        assert_eq!(refusal.reason, crate::CANNOT_SEND);
        assert_eq!(refusal.message, "vm uid-1 has 1 device(s) (crosvm-gpu)");
    }

    /// A body that is not this API's refusal (a proxy's page, a peer that
    /// predates the envelope) is the sentence as it stands, with no word
    /// invented for it.
    #[test]
    fn a_body_that_is_not_a_refusal_is_read_as_it_stands() {
        let refusal = refusal_in(&Bytes::from_static(b" 502 Bad Gateway\n"));

        assert_eq!(refusal.message, "502 Bad Gateway");
        assert_eq!(refusal.reason, "");
    }

    /// A needle is a string somebody typed, and it travels in a query.
    #[test]
    fn a_needle_that_contains_a_separator_survives_the_hop() {
        assert_eq!(urlencode("plain-word.1_2~3"), "plain-word.1_2~3");
        assert_eq!(urlencode("a&b=c"), "a%26b%3Dc");
        assert_eq!(urlencode("a b"), "a%20b");
        assert_eq!(urlencode("ä"), "%C3%A4");
    }
}
