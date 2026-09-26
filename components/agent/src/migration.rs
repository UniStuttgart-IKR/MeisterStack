// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Choose this node's advertised migration address and an available port.
//! The receive acknowledgement carries the resulting URL to the source.

use std::net::{IpAddr, TcpListener, UdpSocket};

use anyhow::{Result, anyhow};

/// Migration receiver settings resolved at startup. Both address and port
/// range are required to receive a migration.
#[derive(Debug, Clone)]
pub struct Endpoint {
    /// The address a peer on the cluster network can open a connection to
    /// this node on.
    advertise: Option<String>,
    /// The inclusive port range a receiving VMM may listen on.
    ports: Option<(u16, u16)>,
}

impl Endpoint {
    /// `advertise` as configured, or derived; `ports` as parsed.
    pub fn new(advertise: Option<String>, ports: Option<(u16, u16)>) -> Self {
        Self { advertise, ports }
    }

    /// Whether this node can receive at all — which is what a refusal has to
    /// be able to say before anything is built.
    pub fn can_receive(&self) -> bool {
        self.advertise.is_some() && self.ports.is_some()
    }

    /// Choose the first bindable port and render a Cloud Hypervisor TCP URL.
    /// The test listener is immediately dropped; another process can acquire the
    /// port before the VMM binds it.
    pub fn listen_url(&self) -> Result<String> {
        let advertise = self.advertise.as_deref().ok_or_else(|| {
            anyhow!(
                "this node has no address to receive a migration on; set \
                 `advertise_addr` in the agent's config"
            )
        })?;
        let (from, to) = self.ports.ok_or_else(|| {
            anyhow!(
                "this node does not receive live migrations; set \
                 `migration_ports` under [hypervisor.cloud-hypervisor] to a range \
                 that is open between the nodes"
            )
        })?;
        for port in from..=to {
            // Probe wildcard binding as the VMM will; the advertised address may
            // not currently be assigned locally.
            if TcpListener::bind(("0.0.0.0", port)).is_ok() {
                return Ok(agent_api::migration_url(advertise, port));
            }
        }
        Err(anyhow!(
            "every port from {from} to {to} is in use; this node cannot receive \
             another migration until one of them is free"
        ))
    }
}

/// Derive an advertised address from the route to a controller endpoint using
/// an IPv4 UDP socket. No packet is sent. Configure `advertise_addr` explicitly
/// when peers need a different interface or this derivation cannot reach them.
pub fn derive_advertise(endpoints: &[String]) -> Option<String> {
    for endpoint in endpoints {
        let Some(target) = socket_target(endpoint) else {
            continue;
        };
        let Ok(socket) = UdpSocket::bind(("0.0.0.0", 0)) else {
            continue;
        };
        if socket.connect(&target).is_err() {
            continue;
        }
        match socket.local_addr().map(|a| a.ip()) {
            // Allow loopback addresses for peers on this host.
            Ok(ip) => return Some(render(ip)),
            Err(_) => continue,
        }
    }
    None
}

/// Extract `host:port` from a controller endpoint, defaulting to port 443
/// when absent. The port is used only to select a route.
fn socket_target(endpoint: &str) -> Option<String> {
    let rest = endpoint
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(endpoint);
    let rest = rest.split('/').next()?;
    if rest.is_empty() {
        return None;
    }
    // For bracketed IPv6 literals, only a suffix after the closing bracket can be a port.
    let has_port = match rest.rsplit_once(']') {
        Some((_, after)) => after.starts_with(':'),
        None => rest.matches(':').count() == 1,
    };
    Some(match has_port {
        true => rest.to_string(),
        false => format!("{rest}:443"),
    })
}

/// An address as a migration URL wants it: an IPv6 literal in brackets,
/// everything else as it is.
fn render(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Missing receiver configuration names the relevant config key.
    #[test]
    fn a_node_that_cannot_receive_says_which_key_is_missing() {
        let no_addr = Endpoint::new(None, Some((49_000, 49_001)));
        assert!(!no_addr.can_receive());
        let said = format!("{:#}", no_addr.listen_url().expect_err("no address"));
        assert!(said.contains("advertise_addr"), "{said}");

        let no_ports = Endpoint::new(Some("10.0.0.5".into()), None);
        assert!(!no_ports.can_receive());
        let said = format!("{:#}", no_ports.listen_url().expect_err("no ports"));
        assert!(said.contains("migration_ports"), "{said}");
    }

    /// The url is the form v53 actually parses, and it comes out of the
    /// range's low end first.
    #[test]
    fn a_receiving_node_answers_with_an_address_in_its_range() {
        let endpoint = Endpoint::new(Some("10.0.0.5".into()), Some((49_000, 49_099)));
        assert!(endpoint.can_receive());
        let url = endpoint.listen_url().expect("a free port");
        assert!(url.starts_with("tcp:10.0.0.5:"), "{url}");
        let port: u16 = url
            .rsplit(':')
            .next()
            .expect("a port")
            .parse()
            .expect("u16");
        assert!((49_000..=49_099).contains(&port), "{url}");
    }

    /// An exhausted range is refused without selecting an outside port.
    #[test]
    fn a_full_range_refuses_rather_than_going_outside_it() {
        let held = TcpListener::bind(("0.0.0.0", 0)).expect("a port");
        let port = held.local_addr().expect("an address").port();
        let endpoint = Endpoint::new(Some("10.0.0.5".into()), Some((port, port)));
        let said = format!("{:#}", endpoint.listen_url().expect_err("nothing free"));
        assert!(said.contains(&port.to_string()), "{said}");
    }

    /// Controller endpoints retain explicit ports and IPv6 brackets.
    #[test]
    fn a_controller_endpoint_becomes_something_a_route_can_be_asked_about() {
        assert_eq!(
            socket_target("http://10.0.0.1:3501").as_deref(),
            Some("10.0.0.1:3501")
        );
        assert_eq!(
            socket_target("10.0.0.1:3501").as_deref(),
            Some("10.0.0.1:3501")
        );
        assert_eq!(
            socket_target("https://ctl.example").as_deref(),
            Some("ctl.example:443")
        );
        assert_eq!(
            socket_target("http://[2001:db8::1]:3501").as_deref(),
            Some("[2001:db8::1]:3501")
        );
        assert_eq!(
            socket_target("http://[2001:db8::1]").as_deref(),
            Some("[2001:db8::1]:443")
        );
        assert_eq!(socket_target(""), None);
    }

    /// A loopback controller selects the loopback source address.
    #[test]
    fn the_advertised_address_is_the_one_the_kernel_would_use() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("a port");
        let addr = listener.local_addr().expect("an address");
        let derived = derive_advertise(&[format!("http://{addr}")]).expect("an address");
        assert_eq!(derived, "127.0.0.1", "the route to loopback is loopback");
        assert!(derive_advertise(&[]).is_none(), "nothing to derive from");
    }
}
