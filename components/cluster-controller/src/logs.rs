// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Asking the node a VM is bound to for what its guest printed.
//!
//! One function, three callers: this tier's own REST route, the cloud's
//! FetchVmLogs command, and a sibling replica forwarding. All of them want
//! the same thing — the node's document, unopened — and having them ask
//! through one place is what keeps the answers from drifting apart.
//!
//! Nothing here reads or reshapes the document. What a console printed is the
//! node's answer; a tier that reformatted it on the way through would be a
//! tier that could get it wrong, and there are two of them above the node.
//!
//! ## Why a replica forwards
//!
//! A node dials ONE cluster-controller replica and only that one can ask it
//! anything. With three replicas behind one address, two of every three
//! requests for a console land somewhere that cannot answer — and the client
//! cannot know which, because which replica holds a node is a fact about a
//! gRPC stream and not about anything a client can see. So the replica that
//! was asked looks at `Node.status.session_endpoint`, which the holder wrote
//! at Hello, and asks it. Once: the forward carries a header that says so,
//! and a replica that sees the header and does not hold the session answers
//! 503 rather than passing it on again.

use anyhow::bail;
use controller_api::{EtcdStore, Node, StoreError, Vm, VmPhase};
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

/// Which lines a caller wants, as it travels this tier.
///
/// A pair of substring lists and nothing more: this tier neither reads them
/// nor applies them. It carries them to the node, which is the only party
/// holding the whole ring and therefore the only one that can filter BEFORE
/// shortening — see the agent's `LogFilter` for why that order is the point.
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

/// What the fetch found. Not being placed yet is an ANSWER and not a failure:
/// a Pending VM has printed nothing because nothing has started, which is the
/// commonest true thing to say about one.
pub enum Logs {
    /// The node's JSON document, verbatim.
    From(Vec<u8>),
    /// The VM is not on a node. The sentence says which of the two reasons.
    NotYet(String),
}

/// The empty document, which is what `NotYet` renders as at a REST edge: an
/// empty list of streams, in the same shape a node would have sent.
pub const NO_STREAMS: &[u8] = b"[]";

/// Everything a forward needs: who we are to the sibling, and how to trust
/// it.
///
/// `None` for both is the plain-http lab, which is how every cluster in this
/// stack has run so far and still runs by default.
pub struct Forward {
    /// This cluster's own name — what the sibling's permission table lets
    /// read, and what the log line says.
    pub cluster: String,
    /// How to speak to a sibling and with what credential. See
    /// `controller_api::forward::Sibling`.
    pub sibling: controller_api::forward::Sibling,
}

/// Ask this VM's node for the end of its output.
///
/// An error here is always about reaching the node — no session, a session
/// that would not take the command, a node that did not answer — and never
/// about the VM. The caller turns that into a 503, because "I could not reach
/// the thing that has the answer" is a different sentence from "there is no
/// answer".
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

/// Has this VM's spec never left this process?
///
/// The honest detour around a wrong word. A node answers "Rejected" when it
/// is asked for the console of a VM it has no record of, and that travelled
/// up as a 409 — a word from the agent API, which is not a client contract
/// and is not being changed. But 409 says "two truths disagree", and about a
/// VM that was never dispatched nothing disagrees at all: it has printed
/// nothing because nothing was started, and the empty document says exactly
/// that in the same shape a node would have sent.
///
/// The signal is `observedGeneration`, which is the reconciler's own record
/// of having dispatched (see `dispatch_create`). `Pending` needs no such
/// record — the phase IS "not dispatched". A VM that ran and then failed has
/// a dispatch behind it, so it keeps the 409 with the node's own sentence,
/// and there the word is right: the node had this VM and lost its record.
fn never_reached_the_node(vm: &Vm) -> bool {
    match vm.status.phase {
        VmPhase::Pending => true,
        VmPhase::Failed => vm.status.observed_generation == 0,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let vm = |phase: VmPhase, observed: u64| {
            let mut vm: Vm = serde_json::from_value(serde_json::json!({
                "apiVersion": "meister.io/v1", "kind": "Vm",
                "metadata": {"name": "web-1"}, "spec": {"vm": {}},
            }))
            .expect("a vm");
            vm.status.phase = phase;
            vm.status.observed_generation = observed;
            vm
        };

        // Never dispatched: the phase says so on its own.
        assert!(never_reached_the_node(&vm(VmPhase::Pending, 0)));
        // Failed before the create ever left this process.
        assert!(never_reached_the_node(&vm(VmPhase::Failed, 0)));

        // Failed AFTER a dispatch: the node had it. If it has lost the record
        // now, two truths really do disagree and 409 is the right word.
        assert!(!never_reached_the_node(&vm(VmPhase::Failed, 1)));
        for phase in [
            VmPhase::Provisioning,
            VmPhase::Running,
            VmPhase::Stopped,
            VmPhase::Paused,
            VmPhase::Quarantined,
        ] {
            assert!(
                !never_reached_the_node(&vm(phase, 0)),
                "{phase:?} is a phase only a node can have reported"
            );
        }
    }
}
