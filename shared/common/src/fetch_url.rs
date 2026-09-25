// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! What an image URL is allowed to look like, and what an address is.
//!
//! Astra finding R3-F10, 2026-09-25: an `Image`'s `spec.url` was any string
//! starting with `http://` or `https://`, a member may write images in its
//! tenant, and the node fetched it with `curl --location`. That is a
//! server-side request forgery from the agent's network: loopback, the
//! cloud's metadata address, the management network, and any of them again
//! behind a redirect. The checksum is only compared after the bytes arrived,
//! so it never stood in the way of the request itself.
//!
//! Two tiers need the same answer, which is why this is here and not in
//! either of them: the cloud refuses a URL whose shape is wrong when the
//! image is created, and the node, which is the tier that actually connects,
//! parses the same string with the same parser and then decides per address
//! (`meister-agent`'s `images::egress`).
//!
//! The parser is deliberately a strict SUBSET of what curl accepts, and that
//! is the point of having one: a check made on one reading of a URL and a
//! connection made on another is how SSRF filters are bypassed. So anything
//! two parsers might read differently is refused outright -- userinfo, percent
//! signs or backslashes in the authority, non-ASCII, numeric host spellings
//! other than a plain dotted quad (`127.1`, `0x7f.1`, `2130706433`), IPv6
//! zone ids -- and the node hands curl the [`FetchUrl::canonical`] spelling
//! rebuilt from the parsed parts, never the original text.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The two ports an image URL may name. Anything else is refused at both
/// tiers; a mirror on another port is an open item (R3-F10), not a default.
pub const ALLOWED_PORTS: [u16; 2] = [80, 443];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }

    fn default_port(self) -> u16 {
        match self {
            Scheme::Http => 80,
            Scheme::Https => 443,
        }
    }
}

/// Where the URL points: a DNS name, lowercased, or an address literal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Host {
    Name(String),
    Ip(IpAddr),
}

/// An http(s) URL in the one shape both tiers accept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchUrl {
    pub scheme: Scheme,
    pub host: Host,
    pub port: u16,
    /// Path and query, starting with `/`. The fragment is dropped: it is
    /// never sent, so it means nothing to a fetch.
    pub path: String,
}

impl FetchUrl {
    /// Parse `text` strictly. The error is a sentence for the person who
    /// wrote the URL.
    pub fn parse(text: &str) -> Result<Self, String> {
        if text
            .bytes()
            .any(|b| !b.is_ascii() || b.is_ascii_control() || b == b' ' || b == b'\\')
        {
            return Err(
                "the url may only contain printable ASCII, with no spaces or \
                        backslashes; an internationalised host name has to be written in \
                        its punycode form"
                    .into(),
            );
        }
        let (scheme, rest) = match text.split_once("://") {
            Some((s, rest)) if s.eq_ignore_ascii_case("http") => (Scheme::Http, rest),
            Some((s, rest)) if s.eq_ignore_ascii_case("https") => (Scheme::Https, rest),
            _ => return Err("the url must start with http:// or https://".into()),
        };
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(end);
        if authority.contains('@') {
            return Err(
                "the url may not carry a user name or password (the part before @); \
                        a node's fetch sends no credentials"
                    .into(),
            );
        }
        if authority.contains('%') {
            return Err(
                "the url's host may not be percent-encoded or carry an IPv6 zone id".into(),
            );
        }
        let (host, port) = split_host_port(authority)?;
        let port = match port {
            Some(p) => p,
            None => scheme.default_port(),
        };
        let tail = tail.split_once('#').map_or(tail, |(before, _)| before);
        let path = match tail {
            "" => "/".to_string(),
            t if t.starts_with('?') => format!("/{t}"),
            t => t.to_string(),
        };
        Ok(Self {
            scheme,
            host,
            port,
            path,
        })
    }

    /// The URL rebuilt from its parts, port always explicit. This is what a
    /// node hands curl, so that what was checked is what is fetched.
    pub fn canonical(&self) -> String {
        format!(
            "{}://{}:{}{}",
            self.scheme.as_str(),
            self.host_text(),
            self.port,
            self.path
        )
    }

    /// The host as it appears in a URL (IPv6 in brackets).
    pub fn host_text(&self) -> String {
        match &self.host {
            Host::Name(n) => n.clone(),
            Host::Ip(IpAddr::V4(a)) => a.to_string(),
            Host::Ip(IpAddr::V6(a)) => format!("[{a}]"),
        }
    }

    /// Whether the port is one of [`ALLOWED_PORTS`].
    pub fn port_allowed(&self) -> bool {
        ALLOWED_PORTS.contains(&self.port)
    }
}

fn split_host_port(authority: &str) -> Result<(Host, Option<u16>), String> {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (v6, after) = rest
            .split_once(']')
            .ok_or("the url's IPv6 address is missing its closing ]")?;
        let addr: Ipv6Addr = v6
            .parse()
            .map_err(|_| format!("{v6:?} is not an IPv6 address"))?;
        let port = match after {
            "" => None,
            p => Some(p.strip_prefix(':').ok_or("junk after the IPv6 address")?),
        };
        (Host::Ip(IpAddr::V6(addr)), port)
    } else {
        let (h, port) = match authority.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        };
        (parse_host(h)?, port)
    };
    let port = match port {
        None => None,
        Some(p) if !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()) => {
            match p.parse::<u16>() {
                Ok(0) | Err(_) => return Err(format!("{p:?} is not a port")),
                Ok(n) => Some(n),
            }
        }
        Some(p) => return Err(format!("{p:?} is not a port")),
    };
    Ok((host, port))
}

/// A host name or a dotted quad, and nothing a resolver might read as a
/// number in some other base.
fn parse_host(h: &str) -> Result<Host, String> {
    if h.is_empty() {
        return Err("the url has no host".into());
    }
    let labels: Vec<&str> = h.split('.').collect();
    if labels
        .iter()
        .all(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_digit()))
    {
        // All-numeric: a plain dotted quad or nothing. `127.1`, `0177.0.0.1`
        // and `2130706433` are all 127.0.0.1 to some resolver and a name to
        // none, so they are refused rather than guessed.
        let plain = labels.len() == 4 && labels.iter().all(|l| l.len() == 1 || !l.starts_with('0'));
        return match (plain, h.parse::<Ipv4Addr>()) {
            (true, Ok(a)) => Ok(Host::Ip(IpAddr::V4(a))),
            _ => Err(format!(
                "{h:?} is not a dotted-quad IPv4 address, and a numeric host in any other \
                 spelling is refused"
            )),
        };
    }
    let lower = h.to_ascii_lowercase();
    check_dns_name(&lower)?;
    Ok(Host::Name(lower))
}

/// A DNS name as the allowlist and the URL both spell one: labels of
/// `[a-z0-9-]`, no label starting or ending with `-`, and a last label that
/// starts with a letter, which is what rules out `0x7f.1` and friends.
pub fn check_dns_name(name: &str) -> Result<(), String> {
    let bad = || format!("{name:?} is not a host name");
    if name.is_empty() || name.len() > 253 {
        return Err(bad());
    }
    let labels: Vec<&str> = name.split('.').collect();
    for l in &labels {
        if l.is_empty()
            || l.len() > 63
            || l.starts_with('-')
            || l.ends_with('-')
            || !l
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(bad());
        }
    }
    if !labels
        .last()
        .is_some_and(|l| l.as_bytes()[0].is_ascii_lowercase())
    {
        return Err(bad());
    }
    Ok(())
}

/// What an address is, for the purpose of being fetched from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AddrClass {
    /// Routable on the internet.
    Public,
    /// A private or special-purpose range: RFC 1918, CGNAT, ULA,
    /// documentation and benchmarking ranges. Refused unless the node's
    /// allowlist names a CIDR that contains the address.
    Private,
    /// Never fetched from, whatever the allowlist says: loopback,
    /// unspecified, link-local (where the cloud metadata services live),
    /// multicast, broadcast, reserved, and the known metadata addresses.
    Never,
}

/// Classify an address. An IPv6 address that embeds an IPv4 one
/// (IPv4-mapped, the NAT64 well-known prefix, 6to4) is as strict as the
/// stricter of the two readings, so `::ffff:127.0.0.1` is loopback.
pub fn classify(addr: IpAddr) -> AddrClass {
    match addr {
        IpAddr::V4(a) => classify_v4(a),
        IpAddr::V6(a) => {
            let own = classify_v6(a);
            match embedded_v4(a) {
                Some(v4) => own.max(classify_v4(v4)),
                None => own,
            }
        }
    }
}

fn classify_v4(a: Ipv4Addr) -> AddrClass {
    let o = a.octets();
    let never = a.is_unspecified()
        || a.is_loopback()
        || a.is_link_local()
        || a.is_multicast()
        || a.is_broadcast()
        || o[0] == 0
        || o[0] >= 240
        // Alibaba's metadata service sits inside CGNAT, Oracle's in the IETF
        // protocol block; both are named so that allowing the range around
        // them does not allow them.
        || a == Ipv4Addr::new(100, 100, 100, 200)
        || a == Ipv4Addr::new(192, 0, 0, 192);
    if never {
        return AddrClass::Never;
    }
    let private = a.is_private()
        || (o[0] == 100 && (o[1] & 0xc0) == 64)
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || a.is_documentation()
        || (o[0] == 198 && (o[1] & 0xfe) == 18);
    match private {
        true => AddrClass::Private,
        false => AddrClass::Public,
    }
}

fn classify_v6(a: Ipv6Addr) -> AddrClass {
    let s = a.segments();
    let never = a.is_unspecified()
        || a.is_loopback()
        || a.is_multicast()
        || (s[0] & 0xffc0) == 0xfe80
        || (s[0] & 0xffc0) == 0xfec0
        // AWS's IPv6 metadata address, inside the ULA range.
        || a == Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254);
    if never {
        return AddrClass::Never;
    }
    let private = (s[0] & 0xfe00) == 0xfc00
        || (s[0] == 0x2001 && s[1] == 0x0db8)
        || (s[0] == 0x2001 && s[1] == 0)
        || (s[0] == 0x64 && s[1] == 0xff9b && s[2] == 1);
    match private {
        true => AddrClass::Private,
        false => AddrClass::Public,
    }
}

/// The IPv4 address an IPv6 one stands for, where it stands for one.
fn embedded_v4(a: Ipv6Addr) -> Option<Ipv4Addr> {
    let s = a.segments();
    let low =
        |hi: u16, lo: u16| Ipv4Addr::new((hi >> 8) as u8, hi as u8, (lo >> 8) as u8, lo as u8);
    if let Some(v4) = a.to_ipv4_mapped() {
        return Some(v4);
    }
    // IPv4-compatible (deprecated), NAT64 well-known prefix.
    if s[..6] == [0; 6] || (s[0] == 0x64 && s[1] == 0xff9b && s[2..6] == [0; 4]) {
        return Some(low(s[6], s[7]));
    }
    // 6to4.
    if s[0] == 0x2002 {
        return Some(low(s[1], s[2]));
    }
    None
}

/// An address range, IPv4 or IPv6, for the node's allowlist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// `10.0.8.0/24`, `2001:db8::/32`, or a bare address (a /32 or /128).
    pub fn parse(text: &str) -> Result<Self, String> {
        let (a, p) = match text.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (text, None),
        };
        let addr: IpAddr = a
            .parse()
            .map_err(|_| format!("{text:?} is not an address or a CIDR"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match p {
            None => max,
            Some(p) => match p.parse::<u8>() {
                Ok(n) if n <= max && p.bytes().all(|b| b.is_ascii_digit()) => n,
                _ => return Err(format!("{text:?} has a prefix length that is not one")),
            },
        };
        Ok(Self { addr, prefix })
    }

    pub fn contains(&self, other: IpAddr) -> bool {
        // An IPv4-mapped IPv6 address is the IPv4 address it maps.
        let other = match other {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(other, IpAddr::V4),
            v4 => v4,
        };
        match (self.addr, other) {
            (IpAddr::V4(net), IpAddr::V4(a)) => {
                let mask = u32::MAX.checked_shl(32 - self.prefix as u32).unwrap_or(0);
                (u32::from(net) & mask) == (u32::from(a) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(a)) => {
                let mask = u128::MAX.checked_shl(128 - self.prefix as u32).unwrap_or(0);
                (u128::from(net) & mask) == (u128::from(a) & mask)
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn a_plain_url_parses_and_is_rebuilt_with_its_port() {
        let u = FetchUrl::parse("HTTPS://Cloud-Images.Ubuntu.com/noble/x.img?a=1#frag").unwrap();
        assert_eq!(u.host, Host::Name("cloud-images.ubuntu.com".into()));
        assert_eq!(u.port, 443);
        assert_eq!(
            u.canonical(),
            "https://cloud-images.ubuntu.com:443/noble/x.img?a=1"
        );
        let v6 = FetchUrl::parse("http://[2001:db8::1]/x").unwrap();
        assert_eq!(v6.canonical(), "http://[2001:db8::1]:80/x");
        assert_eq!(FetchUrl::parse("http://a.example").unwrap().path, "/");
    }

    /// Everything two parsers could read differently is refused.
    #[test]
    fn ambiguous_urls_are_refused() {
        for bad in [
            "ftp://a.example/x",
            "file:///etc/passwd",
            "http://user:pw@a.example/x",
            "http://a.example@127.0.0.1/x",
            "http://127.1/x",
            "http://0177.0.0.1/x",
            "http://2130706433/x",
            "http://0x7f.0.0.1/x",
            "http://a.example%2f@b/x",
            "http://[fe80::1%25eth0]/x",
            "http://a.example:0/x",
            "http://a.example:99999/x",
            "http://a.example:/x",
            "http://a\\b.example/x",
            "http://a .example/x",
            "http:///x",
            "http://-a.example/x",
            "http://a.example./x",
        ] {
            assert!(FetchUrl::parse(bad).is_err(), "{bad} should be refused");
        }
        assert!(
            !FetchUrl::parse("http://a.example:8080/x")
                .unwrap()
                .port_allowed()
        );
        assert!(
            FetchUrl::parse("http://a.example/x")
                .unwrap()
                .port_allowed()
        );
    }

    #[test]
    fn addresses_are_classified_by_their_strictest_reading() {
        for never in [
            "127.0.0.1",
            "0.0.0.0",
            "169.254.169.254",
            "100.100.100.200",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "fe80::1",
            "fd00:ec2::254",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "64:ff9b::a9fe:a9fe",
            "2002:7f00:1::",
        ] {
            assert_eq!(classify(ip(never)), AddrClass::Never, "{never}");
        }
        for private in [
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "fd12::1",
        ] {
            assert_eq!(classify(ip(private)), AddrClass::Private, "{private}");
        }
        for public in ["185.125.190.37", "2620:2d:4000:1::17"] {
            assert_eq!(classify(ip(public)), AddrClass::Public, "{public}");
        }
    }

    #[test]
    fn a_cidr_contains_what_it_says() {
        let c = Cidr::parse("10.0.8.0/24").unwrap();
        assert!(c.contains(ip("10.0.8.21")));
        assert!(c.contains(ip("::ffff:10.0.8.21")));
        assert!(!c.contains(ip("10.0.9.1")));
        assert!(Cidr::parse("10.0.8.21").unwrap().contains(ip("10.0.8.21")));
        assert!(
            Cidr::parse("2001:db8::/32")
                .unwrap()
                .contains(ip("2001:db8::5"))
        );
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains(ip("1.2.3.4")));
        assert!(Cidr::parse("10.0.0.0/33").is_err());
        assert!(Cidr::parse("mirror.example").is_err());
    }
}
