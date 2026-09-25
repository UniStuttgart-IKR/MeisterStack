// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Fetch guest output for REST, cloud commands and sibling requests.
//!
//! Return the agent document unchanged. If the node session is elsewhere, use
//! its advertised endpoint for one authenticated sibling hop. The forwarded
//! header prevents a stale endpoint from causing a forwarding loop.

use anyhow::bail;
use controller_api::{EtcdStore, Node, StoreError, Vm, VmPhaseKind};
use proto::command;
use tracing::{debug, info};

use crate::session::SessionRegistry;

/// The header, the budget, the loop rule and the hop itself all live in
/// `controller_api::forward` since the cloud grew the same need one scope up.
/// Re-exported under the names this tier already used.
pub use controller_api::forward::{FORWARDED, Holder, holder as decide_holder};

/// What `holder` says this tier is talking about.
const ABOUT: controller_api::forward::About = controller_api::forward::About {
    peer: "node",
    tier: "cluster",
};

/// Filters carried to the node, where filtering precedes truncation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Keep {
    pub hide: Vec<String>,
    pub only: Vec<String>,
    /// Which streams, empty = the node's default (the guest's own). `vmm` is
    /// the driver's diagnostics and comes only when named.
    pub streams: Vec<String>,
}

impl Keep {
    /// What a REST edge of this API read off the query string. Empty values
    /// are dropped rather than sent as an empty needle, which would match
    /// every line and make `only=` mean its own opposite.
    pub fn from_pairs(pairs: &[(String, String)]) -> Self {
        let mut keep = Self::default();
        for (key, value) in pairs {
            match key.as_str() {
                "hide" if !value.is_empty() => keep.hide.push(value.clone()),
                "only" if !value.is_empty() => keep.only.push(value.clone()),
                "streams" if !value.is_empty() => keep.streams.extend(
                    value
                        .split(',')
                        .filter(|s| !s.is_empty())
                        .map(str::to_string),
                ),
                _ => {}
            }
        }
        keep
    }

    /// The same thing as a query string, for the one hop that is HTTP rather
    /// than a session: a forward to the replica holding the node.
    pub fn query(&self) -> String {
        let mut out = String::new();
        for (key, values) in [
            ("hide", &self.hide),
            ("only", &self.only),
            ("streams", &self.streams),
        ] {
            for value in values {
                out.push_str(&format!(
                    "&{key}={}",
                    controller_api::forward::urlencode(value)
                ));
            }
        }
        out
    }
}

/// Guest output or an explanation that the VM has not been dispatched.
pub enum Logs {
    /// The node's JSON document, verbatim.
    From(Vec<u8>),
    /// The VM is not on a node. The sentence says which of the two reasons.
    NotYet(String),
}

/// The empty document, which is what `NotYet` renders as at a REST edge: an
/// empty list of streams, in the same shape a node would have sent.
pub const NO_STREAMS: &[u8] = b"[]";

/// Cluster identity and transport credentials for a sibling request.
pub struct Forward {
    /// This cluster's own name — what the sibling's permission table lets
    /// read, and what the log line says.
    pub cluster: String,
    /// How to speak to a sibling and with what credential. See
    /// `controller_api::forward::Sibling`.
    pub sibling: controller_api::forward::Sibling,
}

/// Fetch this VM's output locally or through one sibling.
/// Transport failures and agent refusals propagate to the caller.
#[allow(clippy::too_many_arguments)]
pub async fn fetch(
    registry: &SessionRegistry,
    store: &EtcdStore,
    forward: &Forward,
    vm: &Vm,
    lines: u32,
    keep: &Keep,
    traceparent: &str,
    forwarded: bool,
) -> anyhow::Result<Logs> {
    let Some(node) = vm.spec.node_name.as_deref() else {
        return Ok(Logs::NotYet(format!(
            "vm {} is not placed on a node yet, so nothing has printed anything",
            vm.metadata.name
        )));
    };

    if never_reached_the_node(vm) {
        return Ok(Logs::NotYet(format!(
            "vm {} has not been handed to node {node} yet, so nothing has printed anything",
            vm.metadata.name
        )));
    }

    let here = registry.connected().contains(node);
    // Only asked for when it is needed, which is the uncommon half: a
    // single-replica cluster never reads this object at all.
    let endpoint = if here {
        None
    } else {
        match store.get::<Node>(node).await {
            Ok(n) => n.status.session_endpoint,
            // The node object is gone but the VM still names it. Not a reason
            // to fail differently: nobody is holding a session for it.
            Err(StoreError::NotFound(_)) => None,
            Err(e) => return Err(e.into()),
        }
    };

    match decide_holder(ABOUT, here, endpoint.as_deref(), forwarded) {
        Holder::Here => {
            let payload = registry
                .send_command(
                    node,
                    traceparent,
                    command::Op::Logs(proto::FetchLogs {
                        // The uid and not the name: the node has never heard
                        // of the name, and the uid is the identity that
                        // survives the hop.
                        id: vm.metadata.uid.clone(),
                        lines,
                        hide: keep.hide.clone(),
                        only: keep.only.clone(),
                        streams: keep.streams.clone(),
                    }),
                )
                .await?;
            Ok(Logs::From(payload))
        }
        Holder::Sibling(endpoint) => {
            info!(cluster = %forward.cluster, vm = %vm.metadata.name, node, %endpoint,
                  "forwarding a console read to the replica that holds the session");
            // The forward carries what was asked for, filter included: a
            // sibling that answered the unfiltered console would make the
            // answer depend on which replica a client happened to reach.
            let path = format!(
                "/apis/meister.io/v1/vms/{}/logs?lines={lines}{}",
                vm.metadata.name,
                keep.query()
            );
            let payload = controller_api::forward::ask(&forward.sibling, &endpoint, &path).await?;
            Ok(Logs::From(payload.to_vec()))
        }
        // An error and not an empty document, because it is the same fact
        // the "this node has no session" refusal has always been: the party
        // that holds the answer is out of reach. The caller turns it into a
        // 503, and a caller that retries is right.
        Holder::Nowhere(why) => {
            debug!(vm = %vm.metadata.name, node, reason = %why, "nobody to ask");
            bail!("{why}")
        }
    }
}

/// Avoid asking an agent for a VM that has no dispatch evidence.
/// Pending is treated as undispatched; Failed also requires observedGeneration zero.
fn never_reached_the_node(vm: &Vm) -> bool {
    match vm.status.phase().kind() {
        VmPhaseKind::Pending => true,
        VmPhaseKind::Failed => vm.status.observed_generation == 0,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use controller_api::object::Resource as _;

    /// This tier carries the needles and never reads them — but it does have
    /// to put them on the wire correctly for the one hop that is HTTP.
    #[test]
    fn a_forward_carries_what_was_asked_for() {
        assert_eq!(Keep::default().query(), "", "nothing asked, nothing added");

        let keep = Keep {
            hide: vec!["alive t=".into()],
            only: vec!["disk:".into()],
            streams: vec!["vmm".into()],
        };
        // Leading `&` because it is appended after `?lines=`.
        assert_eq!(keep.query(), "&hide=alive%20t%3D&only=disk%3A&streams=vmm");

        // A needle that would otherwise end the value or start another
        // parameter — the reason this is encoded at all.
        let nasty = Keep {
            hide: vec!["a&b=c".into()],
            only: Vec::new(),
            streams: Vec::new(),
        };
        assert_eq!(nasty.query(), "&hide=a%26b%3Dc");
    }

    /// An empty needle is dropped rather than sent: an empty `only` matches
    /// every line, so passing one on would make the flag mean its opposite.
    #[test]
    fn an_empty_needle_is_not_a_needle() {
        let pairs = |v: Vec<(&str, &str)>| -> Vec<(String, String)> {
            v.into_iter()
                .map(|(k, x)| (k.to_string(), x.to_string()))
                .collect()
        };
        let none = Keep::from_pairs(&pairs(vec![("hide", ""), ("only", "")]));
        assert!(none.hide.is_empty() && none.only.is_empty());

        // Streams are comma-separated as well as repeatable, because both
        // spellings are what people try.
        assert_eq!(
            Keep::from_pairs(&pairs(vec![("streams", "console,vmm")])).streams,
            ["console", "vmm"]
        );
        assert_eq!(
            Keep::from_pairs(&pairs(vec![("hide", "a"), ("hide", "b"), ("lines", "5")])).hide,
            ["a", "b"],
            "repeatable, and lines is somebody else's parameter"
        );
    }

    /// A VM the node was never told about has printed nothing, and saying so
    /// is not the same as failing to reach somebody.
    #[test]
    fn a_vm_that_was_never_dispatched_has_no_console_rather_than_a_conflict() {
        let vm = |phase: VmPhaseKind, observed: u64| {
            let mut vm: Vm = serde_json::from_value(serde_json::json!({
                "apiVersion": "meister.io/v1", "kind": "Vm",
                "metadata": {"name": "web-1"}, "spec": {"vm": {}},
            }))
            .expect("a vm");
            // The holder has to be named for the derivation to keep a word at
            // all — a VM nobody claims is `Pending` whatever anybody said
            // about it (see `settle_vm`), and a VM whose console is being
            // read is on a machine.
            vm.status.node_name = Some("agent-1".into());
            vm.status.reported = Some(controller_api::VmReported::by(
                "agent-1",
                phase,
                controller_api::VmReason::Unrecorded,
                None,
                chrono::Utc::now(),
            ));
            vm.settle(chrono::Utc::now());
            vm.status.observed_generation = observed;
            vm
        };

        // Never dispatched: the phase says so on its own.
        assert!(never_reached_the_node(&vm(VmPhaseKind::Pending, 0)));
        // Failed before the create ever left this process.
        assert!(never_reached_the_node(&vm(VmPhaseKind::Failed, 0)));

        // Failed AFTER a dispatch: the node had it. If it has lost the record
        // now, two truths really do disagree and 409 is the right word.
        assert!(!never_reached_the_node(&vm(VmPhaseKind::Failed, 1)));
        for phase in [
            VmPhaseKind::Provisioning,
            VmPhaseKind::Running,
            VmPhaseKind::Stopped,
            VmPhaseKind::Paused,
            VmPhaseKind::Quarantined,
        ] {
            assert!(
                !never_reached_the_node(&vm(phase, 0)),
                "{phase:?} is a phase only a node can have reported"
            );
        }
    }
}
