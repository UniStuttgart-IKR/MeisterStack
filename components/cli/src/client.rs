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
use macros::generated;
use tokio::net::UnixStream;

use crate::config::{Credential, Target};

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

#[generated(model = ClaudeOpus, version = "5")]
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
}

impl Client {
    /// Build a client for one target.
    ///
    /// The two ways a credential and an endpoint can disagree are both errors
    /// here rather than surprises later. A client certificate over plain http
    /// would be silently unused — the profile says "authenticate me" and
    /// nothing would; and an https endpoint with no CA would fall back to the
    /// system trust store, which a lab CA is not in, turning a config mistake
    /// into an opaque handshake failure.
    #[generated(model = ClaudeOpus, version = "5")]
    pub fn new(target: &Target) -> Result<Self> {
        let transport = transport_for(&target.endpoint)?;
        let tls_endpoint = matches!(transport, Transport::Https { .. });

        let mut auth = None;
        let mut identity: Option<(&std::path::Path, &std::path::Path)> = None;
        match &target.credential {
            Credential::None => {}
            Credential::Bearer(token) => auth = Some(format!("Bearer {token}")),
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
        })
    }

    pub async fn get(&self, path: &str) -> Result<Bytes> {
        self.request(Method::GET, path, None).await
    }

    pub async fn post(&self, path: &str, body: Option<Vec<u8>>) -> Result<Bytes> {
        self.request(Method::POST, path, body).await
    }

    pub async fn put(&self, path: &str, body: Option<Vec<u8>>) -> Result<Bytes> {
        self.request(Method::PUT, path, body).await
    }

    pub async fn delete(&self, path: &str) -> Result<Bytes> {
        self.request(Method::DELETE, path, None).await
    }

    /// A read-modify-write of one object's spec: GET it, change the field,
    /// PUT it back.
    ///
    /// This is what every "set" verb in this CLI actually is. There is no
    /// second api for changing a role, a quota, an assignment or a run
    /// strategy — there is the object, and the server derives the work from
    /// the drift the edit causes.
    ///
    /// The PUT is a CAS on resourceVersion, so a caller that expects to race
    /// a controller retries on [`is_conflict`]; one that does not, does not.
    /// `subject` names the object the way an operator does, for the error
    /// when it turns out to have no spec at all.
    #[generated(model = ClaudeOpus, version = "5")]
    pub async fn patch_spec(
        &self,
        path: &str,
        parsing: &'static str,
        subject: &str,
        edit: &dyn Fn(&mut serde_json::Map<String, serde_json::Value>) -> Result<()>,
    ) -> Result<Bytes> {
        let current = self.get(path).await?;
        let mut object: serde_json::Value = serde_json::from_slice(&current).context(parsing)?;
        let spec = object
            .get_mut("spec")
            .and_then(|s| s.as_object_mut())
            .ok_or_else(|| anyhow::anyhow!("{subject} has no spec object"))?;
        edit(spec)?;
        self.put(path, Some(serde_json::to_vec(&object)?)).await
    }
}

/// Apply `set` (`k=v`) and `rm` (`k`) to an object's `spec.labels`.
///
/// The edit half of `meister ... label`, written once because a node label and
/// a cluster label are the same act against two inventories. Set before
/// remove, so `--rm k k=v` is not an order-dependent riddle: naming a key in
/// both means it goes.
///
/// The map is created if the object has none, and removed entirely when the
/// last pair goes — an empty map and no map mean the same thing to the
/// scheduler, and leaving `"labels": {}` behind makes a diff look like a
/// change that is not one.
#[generated(model = ClaudeOpus, version = "5")]
pub fn edit_labels(
    spec: &mut serde_json::Map<String, serde_json::Value>,
    set: &[String],
    rm: &[String],
) -> Result<()> {
    let mut labels = match spec.remove("labels") {
        Some(serde_json::Value::Object(m)) => m,
        None | Some(serde_json::Value::Null) => serde_json::Map::new(),
        Some(other) => anyhow::bail!("spec.labels is {other}, not an object"),
    };
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
        labels.remove(key.as_str());
    }
    if !labels.is_empty() {
        spec.insert("labels".to_string(), serde_json::Value::Object(labels));
    }
    Ok(())
}

impl Client {
    #[generated(model = ClaudeFable, version = "5")]
    pub async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<Vec<u8>>,
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
                // `meister cluster vm create` can print the id the whole
                // chain will be found under.
                .header("traceparent", traceparent.to_string())
                .header("Accept", "application/json");
            if has_body {
                req = req.header("Content-Type", "application/json");
            }
            if let Some(a) = &auth {
                req = req.header("Authorization", a);
            }

            let res = sender.send_request(req.body(Full::new(payload))?).await?;
            let status = res.status();
            let bytes = res.into_body().collect().await?.to_bytes();

            if !status.is_success() {
                let message = describe_error(status, &bytes, &path);
                if status == StatusCode::CONFLICT {
                    return Err(anyhow::Error::new(Conflict).context(message));
                }
                bail!("{message}");
            }
            Ok(bytes)
        })
        .await
        .with_context(|| format!("request to {label} timed out"))?
    }
}

/// A 409 from an API server: the object changed between our GET and our PUT.
/// Whether that deserves a retry or a complaint is the caller's business, so
/// the status has to survive the trip through anyhow — the message alone
/// would have to be matched on, which is not a contract.
#[derive(Debug)]
pub struct Conflict;

impl std::fmt::Display for Conflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("resource version conflict")
    }
}

impl std::error::Error for Conflict {}

pub fn is_conflict(e: &anyhow::Error) -> bool {
    e.chain().any(|c| c.is::<Conflict>())
}

#[generated(model = ClaudeOpus, version = "4.8")]
fn describe_error(status: StatusCode, body: &Bytes, path: &str) -> String {
    #[derive(serde::Deserialize)]
    struct ErrBody {
        error: String,
    }
    match serde_json::from_slice::<ErrBody>(body) {
        Ok(e) => format!("{status}: {}", e.error),
        Err(_) if body.is_empty() => format!("{status} for {path}"),
        Err(_) => format!("{status}: {}", String::from_utf8_lossy(body).trim()),
    }
}

#[cfg(test)]
#[generated(model = ClaudeOpus, version = "5")]
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

    /// The edit half of `meister ... label`. Set wins over nothing, remove
    /// wins over set, and an object that ends up with no labels loses the key
    /// entirely — `"labels": {}` and no labels mean the same thing to the
    /// scheduler, and one of them makes a diff look like a change.
    #[test]
    fn labels_are_set_then_removed_and_an_empty_map_leaves_no_key_behind() {
        let mut spec = serde_json::Map::new();
        edit_labels(&mut spec, &["zone=a".into(), "disk=nvme".into()], &[]).unwrap();
        assert_eq!(spec["labels"]["zone"], "a");
        assert_eq!(spec["labels"]["disk"], "nvme");

        // Setting an existing key replaces it.
        edit_labels(&mut spec, &["zone=b".into()], &[]).unwrap();
        assert_eq!(spec["labels"]["zone"], "b");

        // Remove runs after set, so naming a key in both means it goes.
        edit_labels(&mut spec, &["zone=c".into()], &["zone".into()]).unwrap();
        assert!(spec["labels"].get("zone").is_none());

        // And the last one takes the key with it.
        edit_labels(&mut spec, &[], &["disk".into()]).unwrap();
        assert!(spec.get("labels").is_none(), "no empty map left behind");

        // Removing what is not there is not an error: `label --rm x` twice is
        // an operator making sure, not a mistake.
        edit_labels(&mut spec, &[], &["gone".into()]).unwrap();
    }

    /// A pair that is not one is refused with the shape it should have had,
    /// rather than silently becoming a label named after the whole argument.
    #[test]
    fn a_pair_without_an_equals_sign_is_refused_and_says_what_was_wanted() {
        let mut spec = serde_json::Map::new();
        let e = edit_labels(&mut spec, &["zone".into()], &[])
            .unwrap_err()
            .to_string();
        assert!(e.contains("key=value"), "{e}");
        assert!(
            edit_labels(&mut spec, &["=a".into()], &[]).is_err(),
            "an empty key is not a label"
        );
        // A value may contain an equals sign; only the first one splits.
        edit_labels(&mut spec, &["expr=a=b".into()], &[]).unwrap();
        assert_eq!(spec["labels"]["expr"], "a=b");
    }

    /// An object whose labels are not an object at all is a refusal and not a
    /// silent overwrite: somebody hand-edited it, and throwing that away is
    /// how an operator loses something they meant.
    #[test]
    fn labels_that_are_not_an_object_are_refused_rather_than_replaced() {
        let mut spec = serde_json::Map::new();
        spec.insert("labels".into(), serde_json::json!("zone=a"));
        assert!(edit_labels(&mut spec, &["zone=b".into()], &[]).is_err());
    }
}
