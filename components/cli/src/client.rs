// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;

use crate::config::{Credential, Target};

/// What a JSON merge patch is called on the wire. RFC 7386, and the only
/// patch format this control plane serves — there is no strategic merge and
/// no RFC 6902 here.
pub const MERGE_PATCH: &str = "application/merge-patch+json";

pub enum Transport {
    Unix(PathBuf),
    /// Plain http — the lab-internal shape, and still the default.
    Http {
        authority: String,
    },
    /// TLS. `host` is the name the certificate is checked against, which is
    /// the host part of the endpoint and not the address it resolved to.
    Https {
        authority: String,
        host: String,
    },
}

pub fn transport_for(endpoint: &str) -> Result<Transport> {
    if let Some(path) = endpoint.strip_prefix("unix://") {
        if path.is_empty() {
            bail!("endpoint {endpoint:?} has no socket path");
        }
        return Ok(Transport::Unix(PathBuf::from(path)));
    }
    let trimmed = endpoint.trim_end_matches('/');
    if let Some(authority) = trimmed.strip_prefix("http://") {
        if authority.is_empty() {
            bail!("endpoint {endpoint:?} has no host");
        }
        return Ok(Transport::Http {
            authority: authority.to_string(),
        });
    }
    if let Some(authority) = trimmed.strip_prefix("https://") {
        // The name, not the address: a certificate is issued to a host, and
        // ":3000" is not part of it.
        //
        // A bracketed IPv6 literal is why this is not one rsplit: "[::1]" has
        // colons of its own, and cutting at the last one leaves ":" as the
        // server name. Only a colon AFTER the closing bracket is a port
        // separator; inside the brackets every colon belongs to the address.
        let port_sep = match authority.rfind(']') {
            Some(close) => authority[close + 1..].find(':').map(|i| close + 1 + i),
            None => authority.rfind(':'),
        };
        let host = match port_sep {
            Some(i) => &authority[..i],
            None => authority,
        };
        if host.is_empty() {
            bail!("endpoint {endpoint:?} has no host");
        }
        return Ok(Transport::Https {
            authority: authority.to_string(),
            host: host.trim_matches(|c| c == '[' || c == ']').to_string(),
        });
    }
    bail!("unsupported endpoint scheme in {endpoint:?}; expected unix://, http:// or https://")
}

pub struct Client {
    transport: Transport,
    /// The finished `Authorization` value, or `None`.
    auth: Option<String>,
    /// Set for https endpoints only; carries the client certificate when the
    /// profile named one.
    tls: Option<std::sync::Arc<tokio_rustls::rustls::ClientConfig>>,
    timeout: Duration,
    /// `--dry-run`: every write this client makes carries `?dryRun=All`.
    /// See `previewing`.
    dry_run: bool,
}

impl Client {
    /// The finished `Authorization` header value, if this profile has one.
    ///
    /// For the one caller that does not go through `request`: a console keeps
    /// its socket after the upgrade, so it writes its own request head and
    /// needs the same credential this client would have sent.
    pub fn authorization(&self) -> Option<&str> {
        self.auth.as_deref()
    }

    /// The TLS config this client would use, for the same caller.
    pub fn tls(&self) -> Option<std::sync::Arc<tokio_rustls::rustls::ClientConfig>> {
        self.tls.clone()
    }

    /// Build a client for one target.
    ///
    /// The two ways a credential and an endpoint can disagree are both errors
    /// here rather than surprises later. A client certificate over plain http
    /// would be silently unused — the profile says "authenticate me" and
    /// nothing would; and an https endpoint with no CA would fall back to the
    /// system trust store, which a lab CA is not in, turning a config mistake
    /// into an opaque handshake failure.
    pub fn new(target: &Target) -> Result<Self> {
        let transport = transport_for(&target.endpoint)?;
        let tls_endpoint = matches!(transport, Transport::Https { .. });

        let mut auth = None;
        let mut identity: Option<(&std::path::Path, &std::path::Path)> = None;
        match &target.credential {
            Credential::None => {}
            Credential::Bearer(token) => auth = Some(format!("Bearer {token}")),
            // Unreachable in practice and refused rather than assumed:
            // `main::target_for` renews an expired session before any
            // command runs. If this ever fires, a code path has started
            // building a client without going through it, and sending a
            // dead token would be a 401 nobody could explain.
            Credential::StaleOidc => bail!(
                "internal: profile {} has an expired oidc session that was never renewed",
                target.profile_name
            ),
            Credential::Mtls { cert, key } => {
                if !tls_endpoint {
                    bail!(
                        "profile {} names a client certificate ({}) but its endpoint {} is not \
                         https; the certificate would never be sent",
                        target.profile_name,
                        cert.display(),
                        target.endpoint
                    );
                }
                identity = Some((cert.as_path(), key.as_path()));
            }
        }

        let tls = if tls_endpoint {
            pki::install_crypto_provider();
            let Some(ca) = target.ca_cert.as_deref() else {
                bail!(
                    "endpoint {} is https but profile {} names no ca_cert; the CA that signed the \
                     controller is not in any system trust store",
                    target.endpoint,
                    target.profile_name
                );
            };
            Some(pki::tls::client_config(Some(ca), identity)?)
        } else {
            None
        };

        Ok(Self {
            transport,
            auth,
            tls,
            timeout: Duration::from_secs(target.timeout_secs),
            dry_run: false,
        })
    }

    /// Turn every write this client makes into `?dryRun=All` — `--dry-run`.
    ///
    /// On the client and not on each verb, because the alternative is a
    /// parameter on thirty-two call sites and one of them will be the one
    /// that forgets. A flag that is honoured by every write except one is
    /// worse than no flag: the request somebody meant to preview is the one
    /// that lands.
    ///
    /// GET and DELETE are untouched. A dry-run GET is a GET, and a dry-run
    /// DELETE is a thing this API does not offer — `?dryRun` is answered by
    /// the write handlers, and adding the parameter to a delete would get it
    /// ignored, which is the one answer a preview may never give.
    pub fn previewing(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    /// The path a WRITE goes to, with the preview parameter when one was
    /// asked for. Appended with the right separator: several routes here
    /// already carry a query of their own.
    fn write_path<'p>(&self, path: &'p str) -> std::borrow::Cow<'p, str> {
        if !self.dry_run {
            return std::borrow::Cow::Borrowed(path);
        }
        let separator = if path.contains('?') { '&' } else { '?' };
        std::borrow::Cow::Owned(format!("{path}{separator}dryRun=All"))
    }

    pub async fn get(&self, path: &str) -> Result<Bytes> {
        self.request(Method::GET, path, None).await
    }

    pub async fn post(&self, path: &str, body: Option<Vec<u8>>) -> Result<Bytes> {
        self.request(Method::POST, &self.write_path(path), body)
            .await
    }

    pub async fn put(&self, path: &str, body: Option<Vec<u8>>) -> Result<Bytes> {
        self.request(Method::PUT, &self.write_path(path), body)
            .await
    }

    /// A JSON merge patch (RFC 7386) — the way this CLI writes one field of
    /// one object.
    ///
    /// Every "set" verb here used to be a GET, an edit and a PUT, which is a
    /// read-modify-write in a client and therefore a race the operator got
    /// shown as a 409. A patch is one call with three lines of body, and the
    /// server does the compare-and-swap against the version IT just read.
    pub async fn patch(&self, path: &str, body: serde_json::Value) -> Result<Bytes> {
        self.request_with(
            Method::PATCH,
            &self.write_path(path),
            Some(serde_json::to_vec(&body)?),
            MERGE_PATCH,
        )
        .await
    }

    pub async fn delete(&self, path: &str) -> Result<Bytes> {
        self.request(Method::DELETE, path, None).await
    }
}

/// `set` (`k=v`) and `rm` (`k`) as the label half of a merge patch.
///
/// The edit half of `meister ... label`, written once because a node label and
/// a cluster label are the same act against two inventories. Set before
/// remove, so `--rm k k=v` is not an order-dependent riddle: naming a key in
/// both means it goes.
///
/// A removal is `null`, which is what RFC 7386 says removal is — and it is
/// why this is a patch and no longer a read-modify-write. The old shape had
/// to read the whole label map to put one key in it; this says only what
/// changes, so two operators labelling the same node with different keys both
/// win instead of one of them losing a compare-and-swap.
pub fn labels_patch(set: &[String], rm: &[String]) -> Result<serde_json::Value> {
    let mut labels = serde_json::Map::new();
    for pair in set {
        let (k, v) = pair
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("{pair:?} is not a label: write it as key=value"))?;
        if k.is_empty() {
            anyhow::bail!("{pair:?} has an empty key");
        }
        labels.insert(k.to_string(), serde_json::Value::String(v.to_string()));
    }
    for key in rm {
        labels.insert(key.clone(), serde_json::Value::Null);
    }
    if labels.is_empty() {
        anyhow::bail!("name at least one key=value to set, or --rm KEY to take one off");
    }
    Ok(serde_json::json!({ "spec": { "labels": labels } }))
}

impl Client {
    pub async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<Bytes> {
        self.request_with(method, path, body, "application/json")
            .await
    }

    async fn request_with(
        &self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
        content_type: &'static str,
    ) -> Result<Bytes> {
        enum Conn {
            Unix(PathBuf),
            Tcp { authority: String },
            Tls { authority: String, host: String },
        }
        let conn = match &self.transport {
            Transport::Unix(p) => Conn::Unix(p.clone()),
            Transport::Http { authority } => Conn::Tcp {
                authority: authority.clone(),
            },
            Transport::Https { authority, host } => Conn::Tls {
                authority: authority.clone(),
                host: host.clone(),
            },
        };
        let tls = self.tls.clone();

        let auth = self.auth.clone();
        let path = path.to_string();
        let label = path.clone();
        let traceparent = telemetry::TraceParent::root();
        tracing::debug!(%path, trace_id = %traceparent.trace_id_hex(), "request");

        tokio::time::timeout(self.timeout, async move {
            let (mut sender, host_header) = match conn {
                Conn::Unix(socket) => {
                    let stream = UnixStream::connect(&socket).await.with_context(|| {
                        format!(
                            "connecting to {} - is the agent running, and do you have \
                             permission on the socket?",
                            socket.display()
                        )
                    })?;
                    let (sender, conn) =
                        hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
                    tokio::spawn(async move {
                        let _ = conn.await;
                    });
                    (sender, "localhost".to_string())
                }
                Conn::Tcp { authority } => {
                    let stream = tokio::net::TcpStream::connect(&authority)
                        .await
                        .with_context(|| {
                            format!("connecting to {authority} - is the controller running?")
                        })?;
                    let (sender, conn) =
                        hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
                    tokio::spawn(async move {
                        let _ = conn.await;
                    });
                    (sender, authority)
                }
                Conn::Tls { authority, host } => {
                    let config = tls.expect("an https transport always carries a tls config");
                    let stream = tokio::net::TcpStream::connect(&authority)
                        .await
                        .with_context(|| {
                            format!("connecting to {authority} - is the controller running?")
                        })?;
                    // The other end of the same measurement: a handshake is
                    // several small writes and a request follows immediately,
                    // which is exactly the shape Nagle plus delayed ACK turns
                    // into a 40ms stall. See controller_api::rest::serve.
                    let _ = stream.set_nodelay(true);
                    let server_name =
                        tokio_rustls::rustls::pki_types::ServerName::try_from(host.clone())
                            .with_context(|| format!("{host} is not a usable server name"))?;
                    let stream = tokio_rustls::TlsConnector::from(config)
                        .connect(server_name, stream)
                        .await
                        .with_context(|| {
                            format!(
                                "tls handshake with {authority} failed - does the profile's \
                                 ca_cert match the controller's certificate?"
                            )
                        })?;
                    let (sender, conn) =
                        hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
                    tokio::spawn(async move {
                        let _ = conn.await;
                    });
                    (sender, authority)
                }
            };

            let payload = body.map(Bytes::from).unwrap_or_default();
            let has_body = !payload.is_empty();

            let mut req = Request::builder()
                .method(method)
                .uri(&path)
                .header("Host", host_header)
                // Every request carries a trace context, so the trace starts
                // where the operator did rather than at the API edge — and
                // `meister vm create` can print the id the whole
                // chain will be found under.
                .header("traceparent", traceparent.to_string())
                .header("Accept", "application/json");
            if has_body {
                req = req.header("Content-Type", content_type);
            }
            if let Some(a) = &auth {
                req = req.header("Authorization", a);
            }

            let res = sender.send_request(req.body(Full::new(payload))?).await?;
            let status = res.status();
            let bytes = res.into_body().collect().await?.to_bytes();

            if !status.is_success() {
                let (message, reason) = describe_error(status, &bytes, &path);
                if status == StatusCode::CONFLICT {
                    return Err(anyhow::Error::new(Conflict(reason)).context(message));
                }
                bail!("{message}");
            }
            Ok(bytes)
        })
        .await
        .with_context(|| format!("request to {label} timed out"))?
    }
}

/// A 409 from an API server, carrying the machine-readable `reason` the body
/// named: `AlreadyExists`, `Conflict`, `Terminating`.
///
/// The reason and not the sentence, because there is exactly one caller that
/// has to tell two 409s apart — `apply`, which turns `AlreadyExists` into a
/// replace and lets everything else through — and matching on a sentence
/// somebody may reword is not a contract. The status has to survive the trip
/// through anyhow for the same reason.
#[derive(Debug)]
pub struct Conflict(pub String);

impl std::fmt::Display for Conflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Conflict {}

/// Which 409 this was, if it was one.
pub fn conflict_reason(e: &anyhow::Error) -> Option<String> {
    e.chain()
        .find_map(|c| c.downcast_ref::<Conflict>())
        .map(|c| c.0.clone())
}

/// A refusal from this API: the `Status` object, in the two fields a client
/// has any use for.
///
/// Only the new shape is read. The old `{"error": ...}` body was this API's
/// own and nobody else ever wrote one, so a parser that accepted both would
/// be a parser carrying a shape that no longer exists anywhere — and the
/// fallback below already handles a body this does not understand, including
/// one from something that is not this API at all.
#[derive(Default, serde::Deserialize)]
struct ErrBody {
    #[serde(default)]
    message: String,
    #[serde(default)]
    reason: String,
}

fn describe_error(status: StatusCode, body: &Bytes, path: &str) -> (String, String) {
    match serde_json::from_slice::<ErrBody>(body) {
        Ok(e) if !e.message.is_empty() => (format!("{status}: {}", e.message), e.reason),
        _ if body.is_empty() => (format!("{status} for {path}"), String::new()),
        _ => (
            format!("{status}: {}", String::from_utf8_lossy(body).trim()),
            String::new(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The name a certificate is checked against is the host, not the
    /// address and not the port — getting that wrong makes every handshake
    /// fail with a name mismatch nobody can read.
    #[test]
    fn an_https_endpoint_yields_the_host_the_certificate_is_checked_against() {
        let Transport::Https { authority, host } =
            transport_for("https://cloud.lab:3000/").unwrap()
        else {
            panic!("https")
        };
        assert_eq!(authority, "cloud.lab:3000");
        assert_eq!(host, "cloud.lab");

        let Transport::Https { host, .. } = transport_for("https://10.128.1.103:3000").unwrap()
        else {
            panic!("https")
        };
        assert_eq!(host, "10.128.1.103");
    }

    /// A bracketed IPv6 literal has colons of its own. Cutting at the last one
    /// used to leave ":" as the server name, so `https://[::1]` failed at the
    /// handshake with a message about an unusable name instead of connecting.
    /// With a port it happened to work, which is why the lab never saw it.
    #[test]
    fn a_bracketed_ipv6_endpoint_keeps_its_address_with_and_without_a_port() {
        for (endpoint, expected_authority) in [
            ("https://[::1]", "[::1]"),
            ("https://[2001:db8::1]", "[2001:db8::1]"),
        ] {
            let Transport::Https { authority, host } = transport_for(endpoint).unwrap() else {
                panic!("https")
            };
            assert_eq!(authority, expected_authority);
            assert_eq!(
                host,
                expected_authority.trim_matches(|c| c == '[' || c == ']')
            );
        }

        let Transport::Https { authority, host } = transport_for("https://[::1]:3000").unwrap()
        else {
            panic!("https")
        };
        assert_eq!(authority, "[::1]:3000");
        assert_eq!(host, "::1");
    }

    #[test]
    fn the_other_two_schemes_are_unchanged() {
        assert!(matches!(
            transport_for("http://10.128.1.104:3001").unwrap(),
            Transport::Http { .. }
        ));
        assert!(matches!(
            transport_for("unix:///run/meisterstack/agent.sock").unwrap(),
            Transport::Unix(_)
        ));
        assert!(transport_for("ftp://nope").is_err());
        assert!(transport_for("unix://").is_err());
        assert!(transport_for("https://").is_err());
    }

    /// The edit half of `meister ... label`, now as the patch body it sends.
    /// Set wins over nothing, remove wins over set, and a removal is `null`
    /// — which is what makes this one call instead of a read-modify-write.
    #[test]
    fn labels_become_a_merge_patch_in_which_a_removal_is_null() {
        let patch = labels_patch(&["zone=a".into(), "disk=nvme".into()], &[]).unwrap();
        assert_eq!(patch["spec"]["labels"]["zone"], "a");
        assert_eq!(patch["spec"]["labels"]["disk"], "nvme");

        // Remove runs after set, so naming a key in both means it goes.
        let patch = labels_patch(&["zone=c".into()], &["zone".into()]).unwrap();
        assert!(patch["spec"]["labels"]["zone"].is_null());

        // A removal on its own says nothing about the keys it does not name,
        // which is the whole reason this is a patch.
        let patch = labels_patch(&[], &["disk".into()]).unwrap();
        assert!(patch["spec"]["labels"]["disk"].is_null());
        assert_eq!(patch["spec"]["labels"].as_object().unwrap().len(), 1);
    }

    /// The one line an operator sees when the server says no, out of the
    /// `Status` object the server now sends.
    #[test]
    fn a_refusal_is_read_out_of_the_status_object() {
        let status = |code: u16, reason: &str, message: &str| {
            Bytes::from(
                serde_json::json!({
                    "apiVersion": "meister.io/v1", "kind": "Status", "status": "Failure",
                    "code": code, "reason": reason, "message": message,
                    "details": {"field": "spec.vm"},
                })
                .to_string(),
            )
        };

        let (line, reason) = describe_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            &status(
                422,
                "Invalid",
                "spec.vm is immutable; delete the vm and create it again",
            ),
            "/apis/meister.io/v1/vms/web-1",
        );
        assert_eq!(
            line,
            "422 Unprocessable Entity: spec.vm is immutable; delete the vm and create it again"
        );
        assert_eq!(reason, "Invalid", "what `apply` branches on");

        // A 409 still carries the word that tells two 409s apart.
        let (_, reason) = describe_error(
            StatusCode::CONFLICT,
            &status(409, "AlreadyExists", "vms/web-1 exists"),
            "/apis/meister.io/v1/vms",
        );
        assert_eq!(reason, "AlreadyExists");

        // Something that is not this API at all: the body as it stands,
        // rather than a parse error about it.
        let (line, reason) = describe_error(
            StatusCode::BAD_GATEWAY,
            &Bytes::from_static(b"<html>upstream</html>"),
            "/apis/meister.io/v1/vms",
        );
        assert_eq!(line, "502 Bad Gateway: <html>upstream</html>");
        assert!(reason.is_empty());

        // And an empty body names the path, because nothing else does.
        let (line, _) = describe_error(
            StatusCode::NOT_FOUND,
            &Bytes::new(),
            "/apis/meister.io/v1/vms/web-1",
        );
        assert!(line.ends_with("/apis/meister.io/v1/vms/web-1"), "{line}");
    }

    /// A pair that is not one is refused with the shape it should have had,
    /// rather than silently becoming a label named after the whole argument.
    #[test]
    fn a_pair_without_an_equals_sign_is_refused_and_says_what_was_wanted() {
        let e = labels_patch(&["zone".into()], &[]).unwrap_err().to_string();
        assert!(e.contains("key=value"), "{e}");
        assert!(
            labels_patch(&["=a".into()], &[]).is_err(),
            "an empty key is not a label"
        );
        // A value may contain an equals sign; only the first one splits.
        let patch = labels_patch(&["expr=a=b".into()], &[]).unwrap();
        assert_eq!(patch["spec"]["labels"]["expr"], "a=b");
        // And a label command that names nothing is a mistake, not a no-op.
        assert!(labels_patch(&[], &[]).is_err());
    }
}
