// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Where this node may fetch a base image from: the egress policy, enforced here because
//! this is the tier that connects (R3-F10).
//!
//! * `[images] allowed_sources` lists host names, `*.domain` patterns, `*` (any host name)
//!   and CIDRs. **Empty, the default, allows nothing.**
//! * Every resolved address is classified (`common::fetch_url::classify`): loopback,
//!   link-local, multicast and metadata addresses are always refused; private ranges need a
//!   CIDR entry, a host name alone never opens them.
//! * The check runs before curl starts and the approved address is pinned with `--resolve`,
//!   so DNS rebinding cannot change where the connection goes.
//! * curl follows no redirect itself (`--max-redirs 0`); a 3xx target goes through the
//!   whole check again before a second request.
//!
//! The fetch still runs in the agent's network namespace; a separate network-restricted
//! fetch unit is still open (R3-F10).

use std::net::IpAddr;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use common::fetch_url::{AddrClass, Cidr, FetchUrl, Host, check_dns_name, classify};

/// How long a DNS lookup for an image host may take.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, PartialEq, Eq)]
enum HostPattern {
    /// `*`: any DNS name; never an address literal or a private address behind the name.
    Any,
    /// `*.example.org`: every name strictly below `example.org`.
    Below(String),
    /// `mirror.example.org`: that name.
    Exact(String),
}

impl HostPattern {
    fn matches(&self, name: &str) -> bool {
        match self {
            HostPattern::Any => true,
            HostPattern::Exact(n) => n == name,
            HostPattern::Below(suffix) => name
                .strip_suffix(suffix.as_str())
                .is_some_and(|head| !head.is_empty()),
        }
    }
}

/// The operator's list, parsed.
#[derive(Clone, Debug, Default)]
pub struct EgressPolicy {
    hosts: Vec<HostPattern>,
    cidrs: Vec<Cidr>,
    /// Test-only: loopback ports of a test's own listener; no node build can set it.
    #[cfg(test)]
    loopback_ports: Vec<u16>,
    /// Test-only: loopback on any port, for cache tests with throwaway origins.
    #[cfg(test)]
    any_loopback: bool,
}

/// A URL that passed, and the one address it may be fetched from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pinned {
    pub url: FetchUrl,
    pub addr: IpAddr,
}

impl Pinned {
    /// The curl arguments that fetch exactly this: the canonical URL, and a
    /// `--resolve` that pins a name to the approved address.
    pub fn curl_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        if let Host::Name(name) = &self.url.host {
            let addr = match self.addr {
                IpAddr::V4(a) => a.to_string(),
                IpAddr::V6(a) => format!("[{a}]"),
            };
            args.push("--resolve".to_string());
            args.push(format!("{name}:{}:{addr}", self.url.port));
        }
        args.push(self.url.canonical());
        args
    }
}

impl EgressPolicy {
    /// Nothing may be fetched. What a node with no `[images]` section gets.
    pub fn deny_all() -> Self {
        Self::default()
    }

    /// Parse `[images] allowed_sources`. A typo is a start-up error, not an
    /// image that silently never fetches.
    pub fn from_sources(entries: &[String]) -> Result<Self> {
        let mut policy = Self::default();
        for entry in entries {
            let e = entry.trim();
            if let Ok(cidr) = Cidr::parse(e) {
                policy.cidrs.push(cidr);
                continue;
            }
            let lower = e.to_ascii_lowercase();
            let pattern = if lower == "*" {
                HostPattern::Any
            } else if let Some(suffix) = lower.strip_prefix("*.") {
                check_dns_name(suffix).map_err(anyhow::Error::msg)?;
                HostPattern::Below(format!(".{suffix}"))
            } else {
                check_dns_name(&lower).map_err(|_| {
                    anyhow::anyhow!(
                        "{e:?} is neither a host name, a *.domain pattern, * nor a CIDR \
                         (no scheme, no port, no path)"
                    )
                })?;
                HostPattern::Exact(lower)
            };
            policy.hosts.push(pattern);
        }
        Ok(policy)
    }

    /// Test-only: loopback on these ports, for tests whose origin is a 127.0.0.1 listener.
    #[cfg(test)]
    pub fn loopback_for_tests(ports: &[u16]) -> Self {
        Self {
            loopback_ports: ports.to_vec(),
            ..Self::default()
        }
    }

    /// Test-only: loopback on any port.
    #[cfg(test)]
    pub fn any_loopback_for_tests() -> Self {
        Self {
            any_loopback: true,
            ..Self::default()
        }
    }

    #[cfg(test)]
    fn test_permits(&self, url: &FetchUrl, addr: IpAddr) -> bool {
        addr.is_loopback()
            && matches!(url.host, Host::Ip(_))
            && (self.any_loopback || self.loopback_ports.contains(&url.port))
    }

    #[cfg(not(test))]
    fn test_permits(&self, _url: &FetchUrl, _addr: IpAddr) -> bool {
        false
    }

    fn is_empty(&self) -> bool {
        #[cfg(test)]
        if self.any_loopback || !self.loopback_ports.is_empty() {
            return false;
        }
        self.hosts.is_empty() && self.cidrs.is_empty()
    }

    /// Whether this address may be connected to for this URL; the whole rule, no I/O.
    fn admits(&self, url: &FetchUrl, addr: IpAddr) -> Result<(), String> {
        if self.test_permits(url, addr) {
            return Ok(());
        }
        let in_cidr = self.cidrs.iter().any(|c| c.contains(addr));
        let name_listed = match &url.host {
            Host::Name(n) => self.hosts.iter().any(|p| p.matches(n)),
            Host::Ip(_) => false,
        };
        match classify(addr) {
            AddrClass::Never => Err(format!(
                "{addr} is a loopback, link-local, multicast or metadata address, which no \
                 image is ever fetched from"
            )),
            AddrClass::Private if !in_cidr => Err(format!(
                "{addr} is in a private range, and no CIDR in [images] allowed_sources \
                 contains it"
            )),
            AddrClass::Public if !(in_cidr || name_listed) => Err(format!(
                "neither the host {} nor the address {addr} is in [images] allowed_sources",
                url.host_text()
            )),
            _ => Ok(()),
        }
    }

    /// Decide for a URL whose host resolved to `resolved`: the first address
    /// the policy admits, or every reason there was none.
    pub fn decide(&self, url: &FetchUrl, resolved: &[IpAddr]) -> Result<Pinned, String> {
        if self.is_empty() {
            return Err(
                "this node has no [images] allowed_sources, so it fetches no image \
                        from any url; an operator lists the image hosts or CIDRs it may use"
                    .into(),
            );
        }
        let test_origin = resolved.iter().any(|&a| self.test_permits(url, a));
        if !url.port_allowed() && !test_origin {
            return Err(format!(
                "port {} is not one this node fetches images from (80 and 443 only)",
                url.port
            ));
        }
        let mut why = Vec::new();
        for &addr in resolved {
            match self.admits(url, addr) {
                Ok(()) => {
                    return Ok(Pinned {
                        url: url.clone(),
                        addr,
                    });
                }
                Err(e) => why.push(e),
            }
        }
        if why.is_empty() {
            why.push(format!("{} resolved to no address", url.host_text()));
        }
        Err(why.join("; "))
    }

    /// Parse, resolve and decide. Everything that can refuse a fetch does so
    /// here, before any connection to the target is made.
    pub async fn vet(&self, text: &str) -> Result<Pinned> {
        let url = FetchUrl::parse(text)
            .map_err(anyhow::Error::msg)
            .with_context(|| format!("the image url {text:?} is refused"))?;
        let resolved: Vec<IpAddr> = match &url.host {
            Host::Ip(a) => vec![*a],
            Host::Name(name) => {
                let lookup = tokio::net::lookup_host((name.as_str(), url.port));
                match tokio::time::timeout(RESOLVE_TIMEOUT, lookup).await {
                    Ok(Ok(addrs)) => addrs.map(|s| s.ip()).collect(),
                    Ok(Err(e)) => bail!("resolving {name} for the image url {text:?}: {e}"),
                    Err(_) => bail!(
                        "resolving {name} for the image url {text:?} took longer than {}s",
                        RESOLVE_TIMEOUT.as_secs()
                    ),
                }
            }
        };
        self.decide(&url, &resolved)
            .map_err(|why| anyhow::anyhow!("the image url {text:?} is refused: {why}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> FetchUrl {
        FetchUrl::parse(s).unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn policy(entries: &[&str]) -> EgressPolicy {
        EgressPolicy::from_sources(&entries.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .unwrap()
    }

    /// The default is no source at all (R3-F10).
    #[test]
    fn an_empty_list_fetches_nothing() {
        let err = EgressPolicy::deny_all()
            .decide(
                &url("https://cloud-images.ubuntu.com/x.img"),
                &[ip("185.125.190.37")],
            )
            .unwrap_err();
        assert!(err.contains("allowed_sources"), "{err}");
    }

    /// Loopback and the metadata address are refused however the list reads (R3-F10).
    #[test]
    fn loopback_and_metadata_are_never_fetched_from() {
        let p = policy(&["*", "0.0.0.0/0", "::/0"]);
        for (u, a) in [
            ("http://127.0.0.1/x", "127.0.0.1"),
            (
                "http://169.254.169.254/latest/meta-data/",
                "169.254.169.254",
            ),
            ("http://[::1]/x", "::1"),
            ("http://[::ffff:127.0.0.1]/x", "::ffff:127.0.0.1"),
            ("http://evil.example/x", "169.254.169.254"),
            ("http://evil.example/x", "127.0.0.1"),
        ] {
            assert!(p.decide(&url(u), &[ip(a)]).is_err(), "{u} via {a}");
        }
    }

    /// A private address needs a CIDR; a host-name entry is not enough (R3-F10).
    #[test]
    fn a_private_address_needs_a_cidr_entry() {
        let by_name = policy(&["mirror.lab.example"]);
        let err = by_name
            .decide(&url("http://mirror.lab.example/x.img"), &[ip("10.0.8.21")])
            .unwrap_err();
        assert!(err.contains("private"), "{err}");
        assert!(
            by_name
                .decide(&url("http://10.0.8.21/x.img"), &[ip("10.0.8.21")])
                .is_err()
        );

        let with_cidr = policy(&["mirror.lab.example", "10.0.8.0/24"]);
        assert_eq!(
            with_cidr
                .decide(&url("http://mirror.lab.example/x.img"), &[ip("10.0.8.21")])
                .unwrap()
                .addr,
            ip("10.0.8.21")
        );
        assert!(
            with_cidr
                .decide(&url("http://10.0.9.1/x.img"), &[ip("10.0.9.1")])
                .is_err()
        );
    }

    /// The allowed mirror is fetched, pinned to the address that passed (R3-F10).
    #[test]
    fn an_allowed_mirror_is_pinned_to_the_address_that_passed() {
        let p = policy(&["cloud-images.ubuntu.com", "*.example.org"]);
        let pinned = p
            .decide(
                &url("https://cloud-images.ubuntu.com/noble/x.img"),
                &[ip("10.1.1.1"), ip("185.125.190.37")],
            )
            .unwrap();
        assert_eq!(
            pinned.addr,
            ip("185.125.190.37"),
            "the private answer is skipped"
        );
        assert_eq!(
            pinned.curl_args(),
            vec![
                "--resolve".to_string(),
                "cloud-images.ubuntu.com:443:185.125.190.37".to_string(),
                "https://cloud-images.ubuntu.com:443/noble/x.img".to_string(),
            ]
        );
        assert!(
            p.decide(&url("https://a.example.org/x"), &[ip("93.184.215.14")])
                .is_ok()
        );
        assert!(
            p.decide(&url("https://example.org/x"), &[ip("93.184.215.14")])
                .is_err(),
            "*.example.org is below the domain, not the domain"
        );
        assert!(
            p.decide(&url("https://other.example/x"), &[ip("93.184.215.14")])
                .is_err()
        );
        assert!(
            p.decide(
                &url("https://cloud-images.ubuntu.com:8443/x"),
                &[ip("185.125.190.37")]
            )
            .is_err(),
            "80 and 443 only"
        );
    }

    /// A redirect goes through the same decision; one to a denied target is refused (R3-F10).
    #[test]
    fn a_redirect_to_a_denied_target_is_refused() {
        let p = policy(&["cloud-images.ubuntu.com"]);
        assert!(
            p.decide(
                &url("https://cloud-images.ubuntu.com/x"),
                &[ip("185.125.190.37")]
            )
            .is_ok()
        );
        for target in [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1/",
            "http://10.0.0.1/",
        ] {
            let u = url(target);
            let Host::Ip(a) = u.host else { unreachable!() };
            assert!(p.decide(&u, &[a]).is_err(), "{target}");
        }
    }

    #[test]
    fn a_bad_entry_is_a_start_up_error() {
        for bad in [
            "https://mirror.example",
            "mirror.example:8080",
            "*.",
            "10.0.0.0/40",
            "a b",
        ] {
            assert!(
                EgressPolicy::from_sources(&[bad.to_string()]).is_err(),
                "{bad}"
            );
        }
    }
}
