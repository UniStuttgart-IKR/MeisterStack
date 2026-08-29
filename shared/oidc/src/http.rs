// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The smallest https client that can talk to an identity provider: one GET
//! for a document, one form POST for a token.
//!
//! Hand-rolled on hyper rather than pulled in as a client crate, and for the
//! reason the workspace manifest gives for `ring`: every client crate worth
//! having brings its own TLS backend, and a second crypto stack in a tree
//! that has gone to some trouble to have exactly one is a worse cost than
//! ninety lines. It is the same hyper, the same tokio-rustls and the same
//! ring the CLI already dials controllers with.
//!
//! https only. A provider reached over plain http hands out bearer tokens to
//! anyone on the path, and there is no configuration in which that is the
//! intended behaviour, so it is not a setting.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;

/// How long any one call to a provider may take. A person is waiting on the
/// CLI side and a request is holding a refresh task on the controller side;
/// neither is served by hanging.
pub const TIMEOUT: Duration = Duration::from_secs(15);

/// A response that came back, whatever it said. The device flow needs the
/// status as well as the body: `authorization_pending` arrives as a 400.
pub struct Response {
    pub status: StatusCode,
    pub body: Bytes,
}

impl Response {
    /// The body as JSON, with the status folded in — for the calls where a
    /// non-2xx is simply a failure.
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        if !self.status.is_success() {
            bail!(
                "the provider answered {}: {}",
                self.status,
                String::from_utf8_lossy(&self.body).trim()
            );
        }
        serde_json::from_slice(&self.body).context("the provider's answer is not the json expected")
    }
}

/// A url split into the three pieces a request needs.
#[derive(Debug)]
struct Url<'a> {
    host: &'a str,
    authority: String,
    path_and_query: &'a str,
}

fn parse(url: &str) -> Result<Url<'_>> {
    let Some(rest) = url.strip_prefix("https://") else {
        bail!("{url:?} is not an https url; an identity provider is not reachable over plain http");
    };
    let (authority, path_and_query) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        bail!("{url:?} has no host");
    }
    // The name the certificate is checked against is the host, and ":443" is
    // not part of it. Bracketed IPv6 for the same reason the CLI's transport
    // does it: only a colon after the closing bracket separates a port.
    let port_sep = match authority.rfind(']') {
        Some(close) => authority[close + 1..].find(':').map(|i| close + 1 + i),
        None => authority.rfind(':'),
    };
    let host = match port_sep {
        Some(i) => &authority[..i],
        None => authority,
    };
    let host = host.trim_matches(|c| c == '[' || c == ']');
    if host.is_empty() {
        bail!("{url:?} has no host");
    }
    let authority = match port_sep {
        Some(_) => authority.to_string(),
        None => format!("{authority}:443"),
    };
    Ok(Url {
        host,
        authority,
        path_and_query,
    })
}

/// Whom to trust for a provider.
///
/// `None` means the platform's roots, which is the opposite of what
/// `pki::tls::client_config` does with `None` and is right for the opposite
/// reason: a controller is a private name signed by a lab CA, a provider is
/// a public name signed by a public one. A lab provider with its own CA
/// names the bundle and gets that instead of, not as well as, the public
/// list.
fn tls_config(ca: Option<&Path>) -> Result<Arc<ClientConfig>> {
    let roots = match ca {
        Some(path) => pki::tls::roots(path)?,
        None => RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        },
    };
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .context("no usable TLS protocol versions")?
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

pub async fn get(url: &str, ca: Option<&Path>) -> Result<Response> {
    send(Method::GET, url, None, ca).await
}

/// `application/x-www-form-urlencoded`, which is what every OAuth endpoint
/// takes and the only body this client ever sends.
pub async fn post_form(url: &str, form: &[(&str, &str)], ca: Option<&Path>) -> Result<Response> {
    let body = form
        .iter()
        .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    send(Method::POST, url, Some(body), ca).await
}

/// Percent-encoding for a form field: everything but the unreserved set.
///
/// By hand because the alternative is a crate for eleven lines, and because
/// what goes through here is a client id, a scope and a device code — all of
/// them already restricted alphabets, none of them worth a dependency.
fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

async fn send(
    method: Method,
    url: &str,
    form_body: Option<String>,
    ca: Option<&Path>,
) -> Result<Response> {
    let parsed = parse(url)?;
    let tls = tls_config(ca)?;

    let mut req = Request::builder()
        .method(method)
        .uri(parsed.path_and_query)
        .header(hyper::header::HOST, &parsed.authority)
        .header(hyper::header::ACCEPT, "application/json");
    let body = match &form_body {
        Some(b) => {
            req = req.header(
                hyper::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            );
            Full::new(Bytes::from(b.clone()))
        }
        None => Full::new(Bytes::new()),
    };
    let req = req.body(body).context("building the request")?;

    let work = async {
        let tcp = TcpStream::connect(&parsed.authority)
            .await
            .with_context(|| format!("connecting to {}", parsed.authority))?;
        let server_name = rustls_pki_types::ServerName::try_from(parsed.host.to_string())
            .with_context(|| format!("{:?} is not a usable server name", parsed.host))?;
        let stream = tokio_rustls::TlsConnector::from(tls)
            .connect(server_name, tcp)
            .await
            .with_context(|| format!("tls handshake with {}", parsed.host))?;

        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .context("http handshake")?;
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!(error = %format!("{e:#}"), "provider connection ended");
            }
        });
        let res = sender.send_request(req).await.context("sending")?;
        let status = res.status();
        let body = res
            .into_body()
            .collect()
            .await
            .context("reading")?
            .to_bytes();
        Ok::<_, anyhow::Error>(Response { status, body })
    };

    tokio::time::timeout(TIMEOUT, work)
        .await
        .with_context(|| format!("{url} did not answer within {}s", TIMEOUT.as_secs()))?
        .with_context(|| format!("talking to {url}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_url_splits_into_host_authority_and_path() {
        let u = parse("https://idp.example.org/realms/x/.well-known/openid-configuration").unwrap();
        assert_eq!(u.host, "idp.example.org");
        assert_eq!(u.authority, "idp.example.org:443");
        assert_eq!(
            u.path_and_query,
            "/realms/x/.well-known/openid-configuration"
        );

        let u = parse("https://idp.example.org:8443/keys").unwrap();
        assert_eq!(u.host, "idp.example.org");
        assert_eq!(u.authority, "idp.example.org:8443");

        // The bracketed literal's own colons are not port separators.
        let u = parse("https://[fd00::1]:8443/keys").unwrap();
        assert_eq!(u.host, "fd00::1");
        assert_eq!(u.authority, "[fd00::1]:8443");

        let u = parse("https://idp.example.org").unwrap();
        assert_eq!(u.path_and_query, "/");
    }

    /// Plain http is not a configuration, it is a mistake — and one that
    /// would hand every token on the wire to whoever is listening.
    #[test]
    fn plain_http_is_refused_by_shape() {
        let err = parse("http://idp.example.org/keys").unwrap_err();
        assert!(err.to_string().contains("plain http"), "{err}");
        assert!(parse("idp.example.org").is_err());
        assert!(parse("https://").is_err());
    }

    #[test]
    fn form_fields_are_percent_encoded() {
        assert_eq!(encode("openid profile"), "openid%20profile");
        assert_eq!(encode("abc-123_x.y~z"), "abc-123_x.y~z");
        assert_eq!(encode("a&b=c"), "a%26b%3Dc");
    }
}
