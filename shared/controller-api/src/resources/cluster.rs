// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The `Cluster` kind: one cluster tier as the cloud sees it.
//! Moved out of `resources.rs` unchanged.

use super::*;

/// A cluster is a cluster-controller the cloud knows about — the same story as
/// a Node one tier down. The object appears on the first Hello and outlives
/// the session, because a cluster that is down has to stay listed as not
/// connected, with the capacity it last had.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClusterSpec {
    /// False CORDONS the cluster — nothing new is placed on it while its VMs
    /// and its session carry on untouched.
    #[serde(default = "schedulable_default")]
    pub schedulable: bool,
    /// True empties the cluster: the same table one scope up that
    /// `Node.spec.drain` runs one scope down, over clusters instead of
    /// machines.
    ///
    /// One difference, and it is a hard one: **there is no live migration
    /// across clusters**, so the `Live` row of the table never fires here. A
    /// running VM leaves a cluster only if its owner said
    /// `evacuation: restart`, and it leaves through a stop and a start.
    #[serde(default, skip_serializing_if = "is_false")]
    pub drain: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

impl Default for ClusterSpec {
    fn default() -> Self {
        Self {
            schedulable: true,
            drain: false,
            labels: BTreeMap::new(),
        }
    }
}

/// What the cluster last reported about itself, summed over its ready nodes.
/// Deliberately coarse: the cloud places a VM on a *cluster*, and which node
/// inside it ends up carrying the VM is the cluster's decision — an aggregate
/// this far away is not something to second-guess a scheduler with.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClusterCapacity {
    #[serde(default)]
    pub vcpus: u32,
    #[serde(default)]
    pub mem_mib: u64,
    /// The union of the ready nodes' device catalogues: what this cluster can
    /// host at all, in the `<driver>/<profile>` spelling NodeCapacity uses.
    /// `gpuProfiles` was the name until 2026-08-28, and it was wrong from the
    /// day the list stopped being about GPUs: `volume/filesystem` and
    /// `network/vxlan` stand in it beside `nvrm/4q`. The alias keeps objects
    /// written under the old name readable — the fleet's etcd is full of them
    /// until the next rollout.
    #[serde(default, alias = "gpuProfiles", skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClusterStatus {
    /// A session exists AND the cluster's heartbeat has not expired.
    #[serde(default)]
    pub connected: bool,
    /// Where the cloud replica holding this cluster's session can be reached
    /// over REST.
    ///
    /// The same field a Node carries one tier down, for the same reason: a
    /// cluster dials ONE cloud replica and only that one can ask it anything,
    /// so a console read landing anywhere else has to be forwarded rather
    /// than refused. Written at Hello by whichever replica took the session;
    /// `None` when that replica has no `advertise_api` and would otherwise
    /// publish an address pointing at the asker's own loopback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_heartbeat: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default)]
    pub nodes_ready: u32,
    #[serde(default)]
    pub nodes_total: u32,
    #[serde(default)]
    pub capacity: ClusterCapacity,
    /// Cloud-managed VMs the cluster named in its last status.
    #[serde(default)]
    pub vms: u32,
    /// The cluster's nodes, as it last reported them.
    ///
    /// A field on this object and deliberately NOT a Node resource of its
    /// own at this tier. A cloud that kept Node objects would have a second
    /// inventory of machines it does not own, with its own lifecycle, its own
    /// staleness and its own way of disagreeing with the cluster's — and the
    /// cloud places on a CLUSTER, so nothing up here has a use for a node
    /// except an operator reading and draining one.
    ///
    /// Evidence, like the rest of this status: the cloud writes nothing into
    /// it, and a drain sent from here shows up when the cluster next reports.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nodes: Vec<NodeSummary>,
    /// What the drain of this cluster has done — the same evidence a node
    /// carries, one scope up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draining: Option<Draining>,
}

/// One node of a cluster, as the cloud has it: spec and status flattened,
/// because at this tier it is a report and not an object.
///
/// It wears the same field names the `Node` object does one tier down, so
/// that one `meister node ls` renders both and `-o json` reads the same at
/// either endpoint.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodeSummary {
    pub name: String,
    #[serde(default)]
    pub ready: bool,
    #[serde(default = "schedulable_default")]
    pub schedulable: bool,
    /// `spec.drain` of the node down there. It travels for the same reason
    /// `schedulable` does: an operator draining a machine should be able to
    /// see from the cloud that it is being drained.
    #[serde(default, skip_serializing_if = "is_false")]
    pub drain: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    #[serde(default)]
    pub vcpus: u32,
    #[serde(default)]
    pub mem_mib: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub vms: u32,
    /// `status.conditions` of the node down there, relayed unchanged.
    ///
    /// It travels for the reason `drain` does: what makes a machine unusable
    /// has to be visible from the chair an operator is actually sitting in,
    /// and the cloud is that chair. The cloud's own scheduler reads it too —
    /// see `Candidate::unhealthy`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<NodeCondition>,
    /// `status.draining` of the node down there — what its drain has actually
    /// done so far, relayed unchanged.
    ///
    /// `drain` above is the ASK and this is the evidence, which is what
    /// somebody watching a drain is waiting for. Without it an operator who
    /// started the drain from the cloud could see that they had started it and
    /// nothing else, and had to open a second profile against a second tier to
    /// find out whether it was moving.
    ///
    /// `None` on a machine nobody is emptying, which is nearly all of them,
    /// and on a cluster that predates the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draining: Option<Draining>,
    /// `spec.accepts` of the node down there — the workload classes it takes,
    /// empty for a machine that takes everything.
    ///
    /// It travels for the reason `conditions` does: the cloud's own scheduler
    /// reads it, through [`crate::cluster_accepts`], so that a class no
    /// machine of a fleet takes is a refusal made BEFORE the binding rather
    /// than a Pending sentence a tier below writes about a machine this tier
    /// never knew was fussy.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepts: Vec<String>,
}

pub type Cluster = Object<ClusterSpec, ClusterStatus>;
