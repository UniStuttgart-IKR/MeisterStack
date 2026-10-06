// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Cluster configuration and the capacity and health reported to the cloud.

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
    /// Request evacuation of the cluster using the drain policy shared with node drains.
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
    /// Union of ready nodes' device capabilities in driver/profile form.
    #[serde(default, alias = "gpuProfiles", skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
}

/// How many unplaced demands one cluster status carries, and the cloud keeps:
/// it copies the list onto its Cluster object, every write of which is all of
/// it. A cluster with more cloud VMs than this waiting for a node offers no
/// room anyway, and says how many more there are (`unplaced_omitted`). The
/// sender keeps to it and the receiver holds it to it. (IKR-B78)
pub const UNPLACED_CARRIED_MAX: usize = 128;

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClusterStatus {
    /// A session exists AND the cluster's heartbeat has not expired.
    #[serde(default)]
    pub connected: bool,
    /// REST address of the cloud replica holding this cluster session, written at Hello for
    /// one-hop request forwarding. Absent when that replica cannot advertise a reachable
    /// address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_endpoint: Option<String>,
    /// When this cluster last reported, as the API answers it. The same
    /// field one tier up, moved for the same reason and joined in the same
    /// way — see `NodeStatus::last_heartbeat` and `EtcdStore::beat`.
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
    /// Latest node inventory reported by the cluster. These entries remain status evidence
    /// rather than independent cloud Node resources; commands take effect when the cluster
    /// reports them back.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nodes: Vec<NodeSummary>,
    /// What each cloud VM the cluster holds without a node asks for: room no
    /// node's bound sum carries yet. At most [`UNPLACED_CARRIED_MAX`]; see
    /// `unplaced_omitted`. Empty from a cluster that predates the field.
    /// (IKR-B78)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unplaced: Vec<crate::Capacity>,
    /// How many more cloud VMs wait there for a node than `unplaced` carries.
    /// Nonzero: the room left on its nodes is not known here, and placement
    /// counts none. (IKR-B78)
    #[serde(default, skip_serializing_if = "is_zero")]
    pub unplaced_omitted: u32,
    /// What the drain of this cluster has done — the same evidence a node
    /// carries, one scope up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draining: Option<Draining>,
}

/// Flattened cluster-reported node entry for cloud inspection and drain requests.
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
    /// What the VMs bound to this node ask for, as its cluster counts them
    /// (cluster-local VMs included). Zero from a cluster that predates the
    /// field, which leaves the whole capacity as the room. (IKR-B78)
    #[serde(default)]
    pub bound_vcpus: u32,
    #[serde(default)]
    pub bound_mem_mib: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub vms: u32,
    /// Agent conditions relayed through the cluster without reinterpretation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<NodeCondition>,
    /// Cluster-reported drain progress for this node. Absent when no drain is active or the
    /// reporting cluster predates the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draining: Option<Draining>,
    /// Workload classes accepted by the node, relayed for cloud inspection.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepts: Vec<String>,
}

pub type Cluster = Object<ClusterSpec, ClusterStatus>;
