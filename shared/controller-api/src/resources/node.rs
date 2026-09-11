// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The `Node` kind: one machine, what it may be asked to carry,
//! and what it reports back. Moved out of `resources.rs`
//! unchanged.

use super::*;

/// A node is an agent the cluster knows about. The object is created on the
/// first Hello and outlives the session: spec is what an operator decided,
/// status is what the agent last reported (§2 of the design).
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NodeSpec {
    /// False CORDONS the node — the scheduler places nothing new on it while
    /// the running VMs and the session stay untouched.
    ///
    /// Deliberately still its own field beside `drain`, and the pair is the
    /// distinction Kubernetes draws with the same two words: cordon is a
    /// statement about the FUTURE and drain is an instruction about the
    /// present. An operator who wants nothing new here and nothing moved has
    /// exactly one way to say so, and it is this one.
    #[serde(default = "schedulable_default")]
    pub schedulable: bool,
    /// True empties the node: every VM on it that CAN go, goes, and
    /// `status.draining` says what happened to each one that could not.
    ///
    /// Additive and false by default, which is every node ever written — a
    /// drain is something somebody asks for, and a field that defaulted the
    /// other way would empty a fleet on upgrade.
    ///
    /// It implies the cordon (a node being emptied is not a placement
    /// target) without SETTING `schedulable`, because the two are the
    /// operator's two separate statements and a controller writing into one
    /// of them would be a controller editing intent. `undrain` therefore
    /// gives back exactly the schedulability the operator had asked for.
    ///
    /// What "can go" means is the table in [`crate::drain::verdict`], and its
    /// short form is: a stopped VM is rescheduled, a running one is rebooted
    /// into place only if its owner said `evacuation = restart`, a VM with a
    /// persistent node-local disk never moves, and nothing with a device
    /// moves live.
    #[serde(default, skip_serializing_if = "is_false")]
    pub drain: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    /// The workload classes this machine takes, and nothing else.
    ///
    /// Decision 6 of 6k, and Kubernetes' taint and toleration said in one
    /// word from the side an operator actually thinks about it: "this machine
    /// is for routers". A workload names its class (`VmSpec.class`,
    /// `RouterSpec.class`), a node names what it accepts, and the scheduler
    /// asks [`crate::resources::accepts_class`].
    ///
    /// **Empty is everything**, which is what makes the field additive: every
    /// node ever written carries no list, and reading an empty list as
    /// "nothing" would empty a fleet on upgrade. A node that names classes is
    /// EXCLUSIVE — it stops taking the ordinary `vm` class the moment it says
    /// `["router"]`, and that is the whole point of it. An operator who wants
    /// a machine to do both writes both.
    ///
    /// It is the operator's statement and not the machine's, which is why it
    /// is spec and not status: a gateway-capable node is capable of running
    /// VMs too, and whether it SHOULD is a decision nobody but an operator
    /// can make.
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
    /// The node's device catalogue, flattened to `<driver>/<profile>` (and the
    /// bare driver name where a driver resolves no profiles, e.g. vfio). One
    /// flat list, because matching a VM's device request against it is what a
    /// DevicePolicy will do.
    /// `gpuProfiles` was the name until 2026-08-28, and it was wrong from the
    /// day the list stopped being about GPUs: `volume/filesystem` and
    /// `network/vxlan` stand in it beside `nvrm/4q`. The alias keeps objects
    /// written under the old name readable — the fleet's etcd is full of them
    /// until the next rollout.
    #[serde(default, alias = "gpuProfiles", skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    /// What each VOLUME backend in `capabilities` said about where its bytes
    /// are, by backend name: `{"lvm-thin": "node-local", "nfs": "shared"}`.
    ///
    /// Beside the flat catalogue rather than inside it, because it is a
    /// different KIND of statement. The catalogue answers "can this node serve /// the request", which is a yes or no and belongs in a list of strings; a
    /// locality answers "and if it does, who else can see the result", which
    /// is what a pool's status is derived from and what decides whether a VM
    /// is pinned to this machine.
    ///
    /// Empty is the ordinary reading of an agent that predates the field, and
    /// it means "did not say" rather than "node-local": a pool whose nodes all
    /// say nothing keeps no locality at all, and placement falls back to the
    /// soft preference it has always had.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub volume_localities: BTreeMap<String, Locality>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodeStatus {
    /// The agent has a session AND its heartbeat has not expired.
    #[serde(default)]
    pub ready: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_heartbeat: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_version: Option<String>,
    #[serde(default)]
    pub capacity: NodeCapacity,
    /// VMs the agent reported in its last status report.
    #[serde(default)]
    pub vms: u32,
    /// The REST address of the cluster-controller replica that holds this
    /// node's session, while one does.
    ///
    /// A node dials ONE replica and only that one can ask it anything — the
    /// console among it. With three replicas behind one address a client
    /// cannot know which, and should not have to: the replica that was asked
    /// reads this and forwards once. Written at Hello, cleared when the
    /// stream ends, and empty at a cluster whose `advertise_api` is unset and
    /// whose `listen_api` is a wildcard, because a replica that cannot name
    /// itself must not name something wrong.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_endpoint: Option<String>,
    /// What the drain of this node has done, and what it could not do.
    ///
    /// `None` on a node nobody asked to empty, which is nearly all of them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draining: Option<Draining>,
    /// What the NODE says is wrong with itself — the half of "is this machine /// usable" that a heartbeat cannot carry.
    ///
    /// `ready` answers "is the agent there", and the mini-chaos run showed
    /// what that leaves out: a node whose store had taken one I/O error said
    /// `ready`, held its session, passed check.sh and refused every command
    /// for three hours, and the scheduler kept placing on it. So this is the
    /// second question, asked of the only party that can answer it: the node
    /// itself. It arrives on the status road (control.proto,
    /// `StatusReport.conditions`) and is replaced wholesale by every report,
    /// because it is a statement about NOW and not a log.
    ///
    /// Empty is the ordinary answer and it says "nothing is wrong". It is also
    /// what an agent that predates the field says, so an empty list is never
    /// evidence that a condition was ruled out — which is why the scheduler
    /// reads it as a veto and never as a permission.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<NodeCondition>,
    /// What a guest's machine state would be restored INTO on this node.
    ///
    /// Said once at Hello, because none of it changes while an agent runs, and
    /// held here so that the party choosing a destination can compare BEFORE
    /// it opens a stream. See [`MachineProfile`].
    ///
    /// `None` on every node whose agent predates the field, and `None` is
    /// never evidence: a comparison that refused on a silence would turn a
    /// rolling upgrade into a fleet that cannot migrate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine: Option<MachineProfile>,
}

/// The machine a guest runs ON, as far as its saved state is concerned.
///
/// **Why this exists.** A live migration does not move a program, it moves a
/// MACHINE STATE — vCPU registers, MSRs, the nested-virtualisation state —
/// and that state is only restorable into a machine that can hold it.
/// cloud-hypervisor v53 checks the CPUID before the transfer and does not
/// check the rest, so the failure arrives two milliseconds after the vCPUs
/// are made, in one line the control plane never sees:
///
/// ```text
/// Request to create new vCPUs: desired = 1 …
/// WARN Migration aborted as migration command State failed:
///      Failed to receive migratable component snapshot
/// ```
///
/// The lab spent two nights on that (D-X1), and the answer was measured with
/// two bare v53 processes and no MeisterStack at all: the same guest moved
/// between two processes on ONE physical host and failed between two agent
/// VMs on TWO physical hosts, every time, with or without a NIC and with or
/// without the fabric disk. Nested KVM state does not cross a physical host.
///
/// So the node says what it is, and [`live_migration_refusal`] compares two
/// of these before a stream is opened rather than after. A refusal costs
/// nothing: the guest keeps running and a drain moves it by reboot.
///
/// Every field may be empty, and an empty field is never evidence.
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

    /// A one-line description for the sentence beside a refusal.
    ///
    /// The three things that decide, in the order they decide: what the CPU
    /// is, whether the machine is itself a guest, and which host it is on
    /// when that is knowable. Not the flags — a refusal names the flag that
    /// differs, and a hundred that do not would bury it.
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

/// Why a running guest's machine state cannot be restored from `source` into
/// `target` — or `None`, meaning it may be tried.
///
/// **The pre-flight check D-X1 asked for**, and the whole of it is here so
/// that it can be argued and enumerated without a fleet. Four rules, in the
/// order of how coarse the difference is:
///
///   * **the vendor.** No profile papers over Intel against AMD.
///   * **the cpu model.** Two generations of one vendor differ in what a
///     saved vCPU state names, and v53 pins `profile: Host`, which means "give
///     the guest exactly this machine's cpuid". The day `CpuProfile` has a
///     second variant, a fleet that sets the same one everywhere is a fleet
///     whose guests move between different models — which is what the third
///     rule is for.
///   * **the cpu profile.** Two ends that would give the guest different
///     cpuid are two ends between which nothing restores, whatever the
///     silicon is.
///   * **nested, across hosts.** The one the lab measured. A nested machine's
///     saved state carries its own host's nested-virtualisation state, and
///     that does not cross a physical host. Two nested nodes are refused
///     unless BOTH name a physical host and both name the same one — because
///     "we cannot tell" is not "it is fine", and the lab's answer to "we
///     cannot tell" was two nights.
///
/// **Silence is never a refusal.** A profile that says nothing is what an
/// agent from before this field sends, and a comparison that refused on one
/// would turn a rolling upgrade into a fleet that cannot migrate. Each rule
/// needs both sides to have spoken.
///
/// The kernel and the hypervisor version are deliberately NOT rules. Both are
/// worth naming beside a refusal somebody else caused, and neither is on its
/// own a reason a guest cannot move — a fleet mid-upgrade differs in both and
/// migrates perfectly well.
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

/// One thing a node says is wrong with itself, in a word and a sentence.
///
/// The pairing every other reason in this tree carries — see `StayingVm` —
/// and for the same reason: an operator reads the sentence, a program
/// branches on the word.
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

/// The conditions an agent can raise, as this tier spells them.
///
/// A closed set with an open door: the controller half branches on the LIST
/// being non-empty, never on the individual variant, so a word from a newer
/// agent still takes its node out of the running. What the enum is for is the
/// short spelling in a table and the fact that the three names exist in one
/// place rather than as literals in five.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeConditionType {
    /// The disk the node stores on has no room left.
    DiskPressure,
    /// The node's own database refuses reads or writes.
    StoreUnhealthy,
    /// `cgroup_root` is not a cgroup2 filesystem, so no teardown finishes.
    CgroupUnusable,
}

impl NodeConditionType {
    pub const ALL: [NodeConditionType; 3] = [
        NodeConditionType::DiskPressure,
        NodeConditionType::StoreUnhealthy,
        NodeConditionType::CgroupUnusable,
    ];

    /// The spelling on the wire and in the object. `parse` is its inverse.
    pub fn as_str(self) -> &'static str {
        match self {
            NodeConditionType::DiskPressure => "DiskPressure",
            NodeConditionType::StoreUnhealthy => "StoreUnhealthy",
            NodeConditionType::CgroupUnusable => "CgroupUnusable",
        }
    }

    /// The one word a `node ls` READY column has room for.
    ///
    /// Lower case and short, because it stands where `yes` stands and the
    /// column is what an operator scans down.
    pub fn short(self) -> &'static str {
        match self {
            NodeConditionType::DiskPressure => "pressure",
            NodeConditionType::StoreUnhealthy => "store",
            NodeConditionType::CgroupUnusable => "cgroup",
        }
    }

    /// `None` for a word this tier does not know — which is a real answer and
    /// not an error. An agent newer than its controller may raise a condition
    /// this build has never heard of; the node still stops being a candidate
    /// (the list is non-empty), and the word travels through to the operator
    /// unshortened. Rejecting it would be the one reading that turns a newer
    /// agent's honesty into a controller that ignores it.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.as_str() == s)
    }
}

/// The evidence a drain leaves: how much moved, what stayed, and one sentence
/// per thing that stayed.
///
/// A drain is not a request that returns — it is a level condition a
/// reconciler works at — so "is it done" has to be readable off the object
/// rather than waited for on a connection. That is what `complete` is: no VM
/// on this machine is still on its way anywhere, and everything left is left
/// for a reason no amount of waiting changes.
// `Eq` because `NodeSummary` is: a cluster's report of a node is compared
// whole against the one the cloud stored, and every field of this one is a
// number, a string or a bool.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Draining {
    /// VMs that are still on this machine and on their way off it.
    ///
    /// A SNAPSHOT, and named for it. It was called `moved`, which read like a
    /// total and was not one: a VM that has arrived somewhere else is neither
    /// here nor leaving, so it left the count — and a finished drain reported
    /// `0 moved, 1 staying (done)` after moving two machines' worth of VMs
    /// (migration D4, seen in the E2E). A cumulative counter would be the
    /// other honest answer and it would need a lifecycle: something has to
    /// reset it on `undrain`, and then it is a counter with a lifetime rather
    /// than a fact about now. This is the fact about now, and it is the same
    /// thing `staying` beside it already is.
    #[serde(default)]
    pub leaving: u32,
    /// One entry per leaving VM, by name — the same pairing `staying` and
    /// `reasons` have. A number that goes to zero says a drain is done; the
    /// names say what it is waiting for.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub leaving_vms: Vec<String>,
    /// How many VMs this drain has actually got off the machine, since it
    /// started.
    ///
    /// The other honest answer the doc above asks for, and the one a person
    /// means by "how did the drain go": `leaving` is a fact about now and
    /// goes to zero exactly when the work is done, so a finished drain that
    /// moved two machines' worth of guests reported `0 leaving, 1 staying
    /// (done)` and looked like a drain that had done nothing. Measured:
    /// `{"seconds":39.1,"report.moved":0,"really_moved":1}`.
    ///
    /// It is a counter and it has the lifetime the doc above worried about,
    /// stated rather than avoided: the whole `Draining` block is cleared when
    /// `spec.drain` goes false, so a counter never outlives the drain it
    /// counted and an `undrain` + `drain` starts at zero. Derived by
    /// comparing this pass's list against the last one — a name that was
    /// leaving, is not here any more, and still exists somewhere else has
    /// left — so nothing has to be remembered between passes except this
    /// number.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub moved_total: u32,
    /// VMs that are still here and are not going.
    #[serde(default)]
    pub staying: u32,
    /// One entry per staying VM, naming it and why.
    ///
    /// The sentence and the category both, for the reason every other pair
    /// like it in this tree carries both: the sentence is what an operator
    /// reads and the category is what a client branches on, and asking a
    /// program to match on prose is asking it to break.
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
