// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! One replica asking its sibling, for both tiers.
//!
//! ## Why a replica forwards at all
//!
//! A peer dials ONE replica and only that one can ask it anything. A node
//! dials one cluster-controller; a cluster dials one cloud-controller. With
//! three replicas behind one address, two of every three requests for a
//! console or a log land somewhere that cannot answer — and the client cannot
//! know which, because which replica holds a peer is a fact about a gRPC
//! stream and not about anything a client can see.
//!
//! So the replica that was asked looks at the endpoint the holder published
//! (`Node.status.sessionEndpoint`, `Cluster.status.sessionEndpoint`) and asks
//! it. Once: the forward carries a header that says so, and a replica that
//! sees the header and does not hold the session answers rather than passing
//! it on again.
//!
//! ## Why it is here and not in a tier
//!
//! It was the cluster tier's, written for a node's console. The cloud grew
//! exactly the same need one scope up — a `vm logs` at the cloud answers only
//! on the replica holding the CLUSTER's session — and the two ends of the
//! same idea in two files is how a header name, a timeout and a loop rule
//! start disagreeing. What stayed in the tiers is what differs: which object
//! carries the endpoint, and what is being asked for.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;

/// The header a forwarded request carries, and the whole of the loop
/// prevention. One hop is the design: a tier's replicas all see the same
/// endpoint, so a second hop could only ever be a mistake — and a mistake
/// that costs a request bouncing between two processes until one of them
/// times out.
pub const FORWARDED: &str = "x-meister-forwarded";

/// How long a forward waits on a sibling, connect and answer together.
///
/// One budget for the whole hop rather than one per step, because a client
/// hanging on a read cannot tell the steps apart and neither can the operator
/// reading the 503. What it is really for is the address that is BLACKHOLED
/// rather than refusing: a replica behind a dropped route or a DROP rule
/// answers nothing at all, and a connect to one costs the TCP SYN retry
/// budget — minutes on Linux — with a handler and a client hanging off it the
/// whole time. A refused connection was always instant; this is the other
/// half.
///
/// Five seconds: a sibling is one hop away on the same control-plane network
/// and reads something it already has, so a healthy forward is milliseconds.
/// Anything past five seconds is not slow, it is gone.
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

/// What the tier is talking about, for the two sentences `holder` writes.
///
/// A pair of words rather than a format string at each call site: the
/// sentences are the operator's, they name a key in a config file, and there
/// are two tiers writing the same two of them.
#[derive(Clone, Copy, Debug)]
pub struct About {
    /// What holds the session — `"node"`, `"cluster"`.
    pub peer: &'static str,
    /// Whose replicas these are — `"cluster"`, `"cloud"`.
    pub tier: &'static str,
}

/// Who can answer, as a pure decision.
///
/// Three inputs and three outcomes, so that the rule can be read and tested
/// without a session, a store or a second process.
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
    /// Whether THIS replica serves TLS on its REST port — which is the only
    /// honest answer to "does my sibling?", because both run one
    /// configuration. See `dial`: the address a sibling publishes carries no
    /// scheme, so this is where the scheme comes from.
    pub serves_tls: bool,
}

/// The authority to connect to and whether to wrap it in TLS.
///
/// An endpoint that names a scheme decides for itself; one that does not —
/// which is what `advertise_api` usually holds — is read as whatever this
/// replica serves.
pub fn dial(endpoint: &str, serves_tls: bool) -> (&str, bool) {
    if let Some(authority) = endpoint.strip_prefix("https://") {
        return (authority.trim_end_matches('/'), true);
    }
    if let Some(authority) = endpoint.strip_prefix("http://") {
        return (authority.trim_end_matches('/'), false);
    }
    (endpoint.trim_end_matches('/'), serves_tls)
}

/// GET this path from the sibling at `endpoint`, once, within the budget.
///
/// The body comes back unopened. What a console printed is the node's answer
/// and what a cluster reported is the cluster's; a tier that reshaped it on
/// the way through would be a tier that could get it wrong, and there are two
/// of them above the node.
///
/// A status the sibling did not call a success becomes an error carrying its
/// SENTENCE. That is right for a read — the caller turns it into one 503 —
/// and wrong for a write, which is what `relay` is for.
pub async fn ask(sibling: &Sibling, endpoint: &str, path: &str) -> anyhow::Result<Bytes> {
    let answer = relay(sibling, endpoint, hyper::Method::GET, path, Bytes::new()).await?;
    if !answer.status.is_success() {
        // The sibling's own SENTENCE and not its whole body: it answers in
        // this API's error envelope, and quoting the json around the sentence
        // would put an escaped document in front of the operator instead of
        // what the peer said.
        bail!(
            "the replica at {endpoint} answered {}: {}",
            answer.status,
            said(&answer.body)
        );
    }
    Ok(answer.body)
}

/// What a sibling said, whole: the status and the body it came with.
///
/// `ask` throws the status away because a read either has its answer or does
/// not. A WRITE cannot: a node PATCH the sibling refused with 404 "cluster
/// reports no node manacor" is a 404 and not a 503, and collapsing it would
/// make a client retry a request that will never work.
pub struct Answer {
    pub status: hyper::StatusCode,
    pub body: Bytes,
}

/// One hop to the sibling with a method and a body, and its answer whole.
///
/// The single place the forward is actually made; `ask` is this with GET, an
/// empty body, and the read's own reading of a failure.
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

/// The `message` of this API's `Status` refusal, or the body as it stands
/// when it is not one.
fn said(body: &Bytes) -> String {
    #[derive(serde::Deserialize)]
    struct Refusal {
        message: String,
    }
    match serde_json::from_slice::<Refusal>(body) {
        Ok(r) => r.message,
        Err(_) => String::from_utf8_lossy(body).trim().to_string(),
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

/// Percent-encoding for a query VALUE, by hand and only as far as a needle
/// needs it.
///
/// A log filter is an arbitrary string a person typed and it travels in a
/// query string on this one hop. Everything that is not unreserved goes as
/// `%XX`, which is more than strictly necessary and is the right side to err
/// on: the alternative is a needle containing `&` splitting into two
/// parameters at the sibling.
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

    /// A blackholed sibling is the whole reason there is a clock here.
    ///
    /// The unreachable half of that — a SYN into a DROP rule — costs the
    /// kernel's retry budget and cannot be built in a test; the reachable
    /// half can: accepted, then silent. Both are inside the same budget, so
    /// this proves the clock.
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

    /// A needle is a string somebody typed, and it travels in a query.
    #[test]
    fn a_needle_that_contains_a_separator_survives_the_hop() {
        assert_eq!(urlencode("plain-word.1_2~3"), "plain-word.1_2~3");
        assert_eq!(urlencode("a&b=c"), "a%26b%3Dc");
        assert_eq!(urlencode("a b"), "a%20b");
        assert_eq!(urlencode("ä"), "%C3%A4");
    }
}
