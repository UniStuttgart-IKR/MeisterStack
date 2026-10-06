// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Node scheduling policy, capacity, health and machine compatibility.

use super::*;

/// Operator policy for a node registered by an agent Hello.
/// The object outlives its session; status records the latest observations.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NodeSpec {
    /// Allow new placements. Clearing this cordons the node without moving VMs.
    #[serde(default = "schedulable_default")]
    pub schedulable: bool,
    /// Request evacuation according to [`crate::drain::verdict`].
    ///
    /// Drain prevents new placements without changing `schedulable`, so clearing
    /// it restores the existing cordon policy. Status records progress and
    /// blockers. Node-local persistent disks prevent movement; devices prevent
    /// live migration. Running guests require an allowed evacuation strategy.
    #[serde(default, skip_serializing_if = "is_false")]
    pub drain: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    /// Accepted workload classes. Empty accepts every class; a nonempty list
    /// accepts only those named. This is operator policy, independent of driver
    /// capabilities. See [`crate::resources::accepts_class`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepts: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodeCapacity {
    #[serde(default)]
    pub vcpus: u32,
    #[serde(default)]
    pub mem_mib: u64,
    /// Driver capabilities as `<driver>/<profile>` or a bare driver name.
    /// The `gpuProfiles` alias accepts older stored objects.
    #[serde(default, alias = "gpuProfiles", skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    /// Reported volume locality by backend, such as `nfs: shared`.
    /// An absent entry means unknown, not node-local; placement then uses the
    /// legacy soft preference. Locality is separate from capability matching.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub volume_localities: BTreeMap<String, Locality>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodeStatus {
    /// The agent has a session AND its heartbeat has not expired.
    #[serde(default)]
    pub ready: bool,
    /// Latest heartbeat, joined by REST from `<prefix>/leases/nodes/<name>`.
    /// It is stored separately to avoid rewriting the node inventory per beat.
    /// `None` is treated as expired by [`crate::heartbeat::expired`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_heartbeat: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_version: Option<String>,
    #[serde(default)]
    pub capacity: NodeCapacity,
    /// VMs the agent reported in its last status report.
    #[serde(default)]
    pub vms: u32,
    /// REST address of the replica holding the node session. Other replicas
    /// forward session-bound requests here once. Set at Hello and cleared on
    /// disconnect; absent when the holder cannot advertise a usable address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_endpoint: Option<String>,
    /// What the drain of this node has done, and what it could not do.
    ///
    /// `None` on a node nobody asked to empty, which is nearly all of them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draining: Option<Draining>,
    /// Current agent-reported conditions, replaced by each StatusReport. They complement
    /// session readiness and veto placement. An empty list is compatible with older agents and
    /// does not prove that every condition was checked.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<NodeCondition>,
    /// Machine state compatibility reported at Hello and used before migration setup. Absent on
    /// older agents; missing evidence alone does not establish an incompatibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine: Option<MachineProfile>,
}

/// Machine properties used to check whether saved guest state can be restored
/// on another node. See [`live_migration_refusal`]. Empty fields provide no
/// compatibility evidence. Nested hosts require special handling because their
/// saved virtualization state can depend on the physical host.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MachineProfile {
    /// `GenuineIntel`, `AuthenticAMD`. The coarsest difference there is.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cpu_vendor: String,
    /// `/proc/cpuinfo` `model name`, verbatim — what an operator reads in a
    /// refusal, and what tells two generations of one vendor apart.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cpu_model: String,
    /// The CPU flags this machine offers, sorted and space-separated. Whole
    /// and not a digest, because a difference is only useful if the sentence
    /// can name which flag.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cpu_flags: String,
    /// This node is itself a guest. The field D-X1 turns on.
    #[serde(default, skip_serializing_if = "is_false")]
    pub nested: bool,
    /// Which hypervisor it runs under, when it is nested. Empty on metal.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hypervisor: String,
    /// The CPUID profile the VMM gives a guest — `Host` in v53, that enum's
    /// only variant. Here for the day it has a second one.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cpu_profile: String,
    /// What the hypervisor binary calls itself, e.g. `cloud-hypervisor v53.0`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hypervisor_version: String,
    /// `uname -r`. Named in a sentence, never a refusal on its own.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kernel: String,
    /// The physical machine this node is on, when anybody can say so:
    /// `[node] physical_host` in the agent's config, or a DMI serial. Empty
    /// is the ordinary answer for a nested guest, and that emptiness is why
    /// the nested rule is written the way it is.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host: String,
}

impl MachineProfile {
    /// Has this node said anything at all?
    ///
    /// A profile with nothing in it is what an agent from before the field
    /// sends and what a node that could read none of it sends, and the two
    /// are the same answer: "did not say". Nothing is refused on one.
    pub fn said_anything(&self) -> bool {
        *self != Self::default()
    }

    /// Short description used when explaining a migration refusal.
    pub fn describe(&self) -> String {
        let cpu = match (self.cpu_model.as_str(), self.cpu_vendor.as_str()) {
            ("", "") => "an unnamed cpu".to_string(),
            ("", vendor) => vendor.to_string(),
            (model, _) => model.to_string(),
        };
        let mut out = cpu;
        if self.nested {
            out.push_str(" on nested ");
            out.push_str(match self.hypervisor.as_str() {
                "" => "virtualisation",
                hypervisor => hypervisor,
            });
        }
        if !self.host.is_empty() {
            out.push_str(&format!(" (host {})", self.host));
        }
        out
    }
}

/// Explain a known incompatibility between migration endpoints.
///
/// Compare CPU vendor, model and profile when both endpoints report them.
/// Nested nodes must identify the same physical host when that check applies.
/// Missing CPU information alone is not a refusal, for older agents. Kernel
/// and hypervisor versions are diagnostic fields, not compatibility rules.
/// `None` permits an attempt; it does not guarantee restoration.
pub fn live_migration_refusal(
    source_node: &str,
    source: &MachineProfile,
    target_node: &str,
    target: &MachineProfile,
) -> Option<String> {
    if !source.said_anything() || !target.said_anything() {
        return None;
    }
    let refuse = |what: &str, fix: &str| {
        Some(format!(
            "live migration refused: {what}. {source_node} is {}, {target_node} is {} — {fix}",
            source.describe(),
            target.describe()
        ))
    };
    let differs = |a: &str, b: &str| !a.is_empty() && !b.is_empty() && a != b;

    if differs(&source.cpu_vendor, &target.cpu_vendor) {
        return refuse(
            "the two machines are not the same make of cpu",
            "a saved vcpu state does not cross vendors; move it with `vm reschedule`, \
             or set spec.evacuation = restart so a drain reboots it",
        );
    }
    if differs(&source.cpu_model, &target.cpu_model) {
        return refuse(
            "the two machines are different cpu models",
            "cloud-hypervisor gives a guest this machine's own cpuid (profile Host), \
             so the saved state names registers the destination does not have; move \
             it with `vm reschedule`, or set spec.evacuation = restart",
        );
    }
    if differs(&source.cpu_profile, &target.cpu_profile) {
        return refuse(
            "the two nodes give their guests different cpu profiles",
            "live migration needs the same profile at both ends; set the same one in \
             [hypervisor.cloud-hypervisor] on both nodes, or move it with \
             `vm reschedule`",
        );
    }
    if source.nested && target.nested && !same_physical_host(source, target) {
        return refuse(
            "both machines are themselves guests, and this cannot be shown to be one \
             physical host",
            "nested state does not cross a physical host — measured, twice, on this \
             lab's own hardware (D-X1). Put the two nodes on one host and set \
             `physical_host` on both so this can be seen, or move the guest with \
             `vm reschedule`",
        );
    }
    None
}

/// Are these two nested nodes provably on one physical machine?
///
/// Both have to NAME a host and name the same one. An empty `host` is "nobody
/// can say", which a nested guest usually cannot — and the rule above turns
/// on this being a proof rather than an absence of evidence.
fn same_physical_host(a: &MachineProfile, b: &MachineProfile) -> bool {
    !a.host.is_empty() && a.host == b.host
}

/// An agent-reported condition with a bounded category and explanatory message.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodeCondition {
    /// One of [`NodeConditionType::as_str`], a closed set — but read as an
    /// OPEN one on purpose. See `NodeConditionType::parse`.
    #[serde(rename = "type")]
    pub type_: String,
    /// The same thing in words, naming what would have to change.
    #[serde(default)]
    pub message: String,
}

impl NodeCondition {
    /// Whether this condition takes the whole node out of placement. A word
    /// this build does not know vetoes, as every condition used to; one that
    /// only withdraws a capability does not, because the capability is
    /// already missing from the node's catalogue and that alone keeps the vms
    /// needing it away, while the node still serves every other vm.
    pub fn vetoes_placement(&self) -> bool {
        NodeConditionType::parse(&self.type_).is_none_or(NodeConditionType::vetoes_placement)
    }

    /// The types among `conditions` that veto placement: what a scheduling
    /// candidate is unhealthy with, and what its diagnostics name.
    pub fn vetoing(conditions: &[NodeCondition]) -> Vec<String> {
        conditions
            .iter()
            .filter(|c| c.vetoes_placement())
            .map(|c| c.type_.clone())
            .collect()
    }
}

/// Known agent condition categories. Preserve the protocol spelling when ingesting reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeConditionType {
    /// The disk the node stores on has no room left.
    DiskPressure,
    /// The node's own database refuses reads or writes.
    StoreUnhealthy,
    /// `cgroup_root` is not a cgroup2 filesystem, so no teardown finishes.
    CgroupUnusable,
    /// A configured device driver could not be built, so the node does not
    /// offer its capability. Everything else on the node works.
    DriverUnavailable,
}

impl NodeConditionType {
    pub const ALL: [NodeConditionType; 4] = [
        NodeConditionType::DiskPressure,
        NodeConditionType::StoreUnhealthy,
        NodeConditionType::CgroupUnusable,
        NodeConditionType::DriverUnavailable,
    ];

    /// The spelling on the wire and in the object. `parse` is its inverse.
    pub fn as_str(self) -> &'static str {
        match self {
            NodeConditionType::DiskPressure => "DiskPressure",
            NodeConditionType::StoreUnhealthy => "StoreUnhealthy",
            NodeConditionType::CgroupUnusable => "CgroupUnusable",
            NodeConditionType::DriverUnavailable => "DriverUnavailable",
        }
    }

    /// See [`NodeCondition::vetoes_placement`].
    pub fn vetoes_placement(self) -> bool {
        !matches!(self, NodeConditionType::DriverUnavailable)
    }

    /// `None` for a word this tier does not know — which is a real answer and
    /// not an error. An agent newer than its controller may raise a condition
    /// this build has never heard of; the node still stops being a candidate
    /// (an unknown word vetoes, see [`NodeCondition::vetoes_placement`]), and
    /// the word travels through to the operator unshortened. Rejecting it
    /// would be the one reading that turns a newer agent's honesty into a
    /// controller that ignores it.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.as_str() == s)
    }
}

/// Current drain progress: VMs leaving, VMs staying, and their reasons.
// `Eq` because `NodeSummary` is: a cluster's report of a node is compared
// whole against the one the cloud stored, and every field of this one is a
// number, a string or a bool.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Draining {
    /// Snapshot count of VMs still on this node and currently leaving. Successfully moved VMs
    /// leave this count; it is not a cumulative drain total.
    #[serde(default)]
    pub leaving: u32,
    /// One entry per leaving VM, by name — the same pairing `staying` and
    /// `reasons` have. A number that goes to zero says a drain is done; the
    /// names say what it is waiting for.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub leaving_vms: Vec<String>,
    /// VMs moved during this drain, accumulated from the previous leaving list.
    /// A VM counts when it leaves this node and still exists elsewhere. Clearing
    /// `spec.drain` clears this count along with the rest of the drain status.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub moved_total: u32,
    /// VMs that are still here and are not going.
    #[serde(default)]
    pub staying: u32,
    /// One reason per VM that remains on the drained node.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<StayingVm>,
    /// Nothing is on its way any more. What is left is left.
    ///
    /// Derived at write time rather than by the reader, so that a dashboard
    /// and a script cannot disagree about when a drain finished.
    #[serde(default)]
    pub complete: bool,
}

/// One VM a drain did not move, and why.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct StayingVm {
    pub vm: String,
    /// One of [`StayReason::as_str`], a closed set.
    pub reason: String,
    /// The same thing in words, and it names what would have to change.
    pub message: String,
}

/// Why a VM did not leave a machine that is being emptied.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum StayReason {
    /// Its owner said `evacuation: never`, which is the default. The
    /// commonest answer by far, and not a fault.
    EvacuationNever,
    /// A persistent disk whose bytes are on this machine. Nothing moves it,
    /// whatever the owner said — the alternative would be a VM booted
    /// somewhere its data is not.
    NodeLocalDisk,
    /// It would go, and there is nowhere for it to go: no other machine has
    /// the room, the device profile, or a way to reach its disks. The one
    /// reason on this list that a change of hardware fixes.
    NoTarget,
}

impl StayReason {
    pub const ALL: [StayReason; 3] = [
        StayReason::EvacuationNever,
        StayReason::NodeLocalDisk,
        StayReason::NoTarget,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            StayReason::EvacuationNever => "evacuation-never",
            StayReason::NodeLocalDisk => "node-local-disk",
            StayReason::NoTarget => "no-target",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.as_str() == s)
    }

    /// Whether a drain that is left with only this kind of VM is FINISHED.
    ///
    /// The two structural refusals are: a VM whose owner said no, and a VM
    /// whose data is here. Neither becomes possible by waiting, so a drain
    /// holding only those is done — which is the brief's "a drain is finished /// when `staying` names only `never` and `node-local`". `NoTarget` is the
    /// odd one out and deliberately does NOT finish a drain: another machine
    /// coming back changes the answer.
    pub fn settles_a_drain(self) -> bool {
        match self {
            StayReason::EvacuationNever | StayReason::NodeLocalDisk => true,
            StayReason::NoTarget => false,
        }
    }
}

pub type Node = Object<NodeSpec, NodeStatus>;
