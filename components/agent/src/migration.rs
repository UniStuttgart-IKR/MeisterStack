// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Where a migration stream lands on this node.
//!
//! One question, and it is the node's alone to answer: **which address and
//! which port should the source dial?** No tier above can answer it — the
//! controller does not know which of a node's interfaces carries cluster
//! traffic, and it must not know which ports are free — so the answer travels
//! back up in `Ack.payload` and then straight across to the other node,
//! unopened.

use std::net::{IpAddr, TcpListener, UdpSocket};

use anyhow::{Result, anyhow};

/// This node's end of a live migration, decided once at start-up.
///
/// Both halves may be absent, and absent means the same thing in both cases:
/// this node does not receive live migrations. That is a configuration, not a
/// fault — a node with no `migration_ports` has an operator who has not
/// opened the firewall, and receiving a stream into a port nobody can reach
/// would fail later and less clearly.
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

    /// An address to listen on, in cloud-hypervisor's own spelling.
    ///
    /// The port is found by BINDING it and letting the binding go, which is
    /// the same small race every port allocator in this position has: between
    /// the drop and the VMM's own bind, somebody else could take it. It is
    /// bounded rather than eliminated because the alternative — holding the
    /// listener and handing the fd over — is not something the VMM's API
    /// accepts. What makes it acceptable is the failure mode: a port that was
    /// taken in between fails the receive loudly, before the source has been
    /// told anything, and the migration is retried by the tier that asked for
    /// it.
    ///
    /// The range is walked in order rather than sampled, so that a node
    /// receiving two guests at once uses two adjacent ports and an operator
    /// reading `ss` sees a block rather than a scatter.
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
            // Bound to the wildcard and not to `advertise`: the VMM will bind
            // it the same way, and a node whose advertised address is a
            // floating one may not hold it at this instant.
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

/// The address of the socket this agent would use to reach its controller.
///
/// The honest derivation of "where can a peer reach me": the kernel is asked
/// which source address it would pick for a route to the controller, and
/// that address is by construction one that carries traffic on the cluster
/// network. No packet is sent — a connected UDP socket only fixes the route.
///
/// It is wrong on exactly one shape of node: one whose route to the
/// controller and whose route to its peers leave by different interfaces.
/// Such a node sets `advertise_addr` itself, which is what the key is for.
///
/// `None` when there is nothing to derive from, and then a node without an
/// explicit `advertise_addr` simply does not receive migrations.
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
            // A loopback source is not a lie — it is what a peer on this
            // machine would use, and the local end-to-end test is exactly
            // that. It is passed on rather than rejected; a node whose only
            // route to its controller is loopback has a controller on the
            // same machine, and its operator knows it.
            Ok(ip) => return Some(render(ip)),
            Err(_) => continue,
        }
    }
    None
}

/// `http://host:port` or `host:port` -> `host:port`, which is what a UDP
/// connect wants. A URL with no port gets the scheme's, because a route is
/// picked by address and any port will do.
fn socket_target(endpoint: &str) -> Option<String> {
    let rest = endpoint
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(endpoint);
    let rest = rest.split('/').next()?;
    if rest.is_empty() {
        return None;
    }
    // An IPv6 literal keeps its brackets, and the port is what follows the
    // closing one — the same rule `migration_url` states, and for the same
    // reason: the last colon is not the separator in an IPv6 address.
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

    /// A node that was not told where it is, or which ports are open, says so
    /// — with the key to set. Both sentences name a config key, because
    /// "cannot receive" is not something an operator can act on.
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

    /// A range with nothing free in it is a refusal with a sentence, and not
    /// a wrap-around to a port outside it.
    #[test]
    fn a_full_range_refuses_rather_than_going_outside_it() {
        let held = TcpListener::bind(("0.0.0.0", 0)).expect("a port");
        let port = held.local_addr().expect("an address").port();
        let endpoint = Endpoint::new(Some("10.0.0.5".into()), Some((port, port)));
        let said = format!("{:#}", endpoint.listen_url().expect_err("nothing free"));
        assert!(said.contains(&port.to_string()), "{said}");
    }

    /// The endpoint list is parsed the way a route lookup needs it, and an
    /// IPv6 literal keeps its brackets — the same rule the migration url
    /// obeys, because the last colon is not a separator there.
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

    /// And the derivation itself, against a listener on this machine: the
    /// answer is an address, and it is one this node really has.
    #[test]
    fn the_advertised_address_is_the_one_the_kernel_would_use() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("a port");
        let addr = listener.local_addr().expect("an address");
        let derived = derive_advertise(&[format!("http://{addr}")]).expect("an address");
        assert_eq!(derived, "127.0.0.1", "the route to loopback is loopback");
        assert!(derive_advertise(&[]).is_none(), "nothing to derive from");
    }
}
