// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Scheduling as a plugin trait: v1 ships best-effort First-Fit; smarter
//! strategies (distributed best effort, bin packing, GPU-topology aware)
//! replace the implementation, not the reconciler.
//!
//! One trait serves both tiers. A cluster picks a node for a VM, the cloud
//! picks a cluster for a VM, and the decision is the same shape both times —
//! so the candidate is named for what it is to the scheduler, not for which
//! tier it happens to live on.

use common::capability::{self, Locality, offers};
use tracing::debug;

use std::collections::BTreeMap;

use crate::resources::{AntiAffinity, NodeSummary, StoragePool, Vm};

/// What a machine has, and what a VM wants of it. Two numbers, because those
/// are the two a node can run out of.
///
/// Disk is deliberately not here. A volume is provisioned by a driver that
/// knows its own backend — thin pool, NFS export, a file on a filesystem —
/// and the honest answer to "how much room is left" is a different question
/// per backend. A number this control plane invented for it would be wrong on
/// most nodes and would refuse VMs for a reason that is not true.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Capacity {
    pub vcpus: u32,
    pub mem_mib: u64,
}

impl Capacity {
    /// What one VM asks for, out of the agent's own spec.
    ///
    /// Absent fields are zero, and that is the conservative direction: a spec
    /// this controller cannot read the size of asks for nothing and is
    /// therefore never REFUSED for a reason nobody can check. The agent's
    /// serde is the validating authority for the rest of the document, and a
    /// spec that names no vcpus does not get past it.
    pub fn wanted_by(vm: &Vm) -> Self {
        Self::wanted_by_spec(&vm.spec.vm)
    }

    /// The same reading, of a spec that is not on an object yet. What an
    /// admission or a quota check at a create edge has in hand is a POST
    /// body, and it has to be measured by the same function that measures the
    /// object afterwards — two readings of "how big is this VM" are two
    /// readings that start disagreeing.
    pub fn wanted_by_spec(spec: &serde_json::Value) -> Self {
        let number = |field: &str| spec.get(field).and_then(serde_json::Value::as_u64);
        Self {
            vcpus: number("vcpus").unwrap_or(0).min(u32::MAX as u64) as u32,
            mem_mib: number("memory_mib").unwrap_or(0),
        }
    }

    /// Saturating, because a node whose reported capacity shrank under the
    /// VMs already on it is a real state — an operator lowering
    /// `capacity_vcpus` on a running node does exactly that — and the answer
    /// to it is "nothing is free", not an overflow.
    pub fn minus(self, other: Self) -> Self {
        Self {
            vcpus: self.vcpus.saturating_sub(other.vcpus),
            mem_mib: self.mem_mib.saturating_sub(other.mem_mib),
        }
    }

    pub fn plus(self, other: Self) -> Self {
        Self {
            vcpus: self.vcpus.saturating_add(other.vcpus),
            mem_mib: self.mem_mib.saturating_add(other.mem_mib),
        }
    }

    /// Does this fit in `room`? Both dimensions, and neither is optional.
    pub fn fits_in(self, room: Self) -> bool {
        self.vcpus <= room.vcpus && self.mem_mib <= room.mem_mib
    }
}

/// How much more than it has a machine may be asked to carry.
///
/// The asymmetry is the whole point and it is not a preference: overcommitting
/// MEMORY means the OOM killer picks a VM and ends it, and overcommitting
/// vCPU means the guests wait for each other. One is a lost VM, the other is
/// a slow one, and a control plane that cannot tell those apart will
/// eventually do the first while believing it did the second.
#[derive(Clone, Copy, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Overcommit {
    /// Guests wait for each other. Four is the usual starting point and the
    /// only number here that is a judgement rather than a derivation; a fleet
    /// that was relying on the unlimited placement this stack had before
    /// admission existed raises it.
    #[serde(default = "Overcommit::default_vcpu")]
    pub vcpu: f64,
    /// One, and it may not become more than one by accident. See the type's
    /// own doc: the failure mode on this axis is an OOM kill, which is a VM
    /// somebody loses rather than a VM that is slow.
    #[serde(default = "Overcommit::default_memory")]
    pub memory: f64,
}

impl Overcommit {
    pub const VCPU_DEFAULT: f64 = 4.0;
    pub const MEMORY_DEFAULT: f64 = 1.0;

    fn default_vcpu() -> f64 {
        Self::VCPU_DEFAULT
    }
    fn default_memory() -> f64 {
        Self::MEMORY_DEFAULT
    }

    /// Refuse a configuration that would let the OOM killer decide which VM
    /// survives, and one that would make a factor meaningless.
    ///
    /// Loud at start-up rather than quietly clamped: an operator who wrote
    /// `memory = 1.5` believes something about their fleet that this control
    /// plane will not do, and finding that out from a VM that died at three in
    /// the morning is the worst possible way to learn it.
    pub fn check(&self) -> anyhow::Result<()> {
        if !(self.memory.is_finite() && self.memory > 0.0) {
            anyhow::bail!("admission.memory must be a positive number");
        }
        if self.memory > Self::MEMORY_DEFAULT {
            anyhow::bail!(
                "admission.memory = {} would overcommit memory; this control plane does not, \
                 because the failure mode is the OOM killer choosing which vm survives",
                self.memory
            );
        }
        if !(self.vcpu.is_finite() && self.vcpu > 0.0) {
            anyhow::bail!("admission.vcpu must be a positive number");
        }
        Ok(())
    }

    /// What a machine of this capacity may be asked to carry.
    pub fn allowance(&self, capacity: Capacity) -> Capacity {
        // Truncating, not rounding: half a vCPU of allowance is not a vCPU,
        // and the direction to be wrong in is downwards.
        Capacity {
            vcpus: (capacity.vcpus as f64 * self.vcpu) as u32,
            mem_mib: (capacity.mem_mib as f64 * self.memory) as u64,
        }
    }
}

impl Default for Overcommit {
    fn default() -> Self {
        Self {
            vcpu: Self::VCPU_DEFAULT,
            memory: Self::MEMORY_DEFAULT,
        }
    }
}

/// Which inventory a candidate came out of: a node under a cluster, or a
/// cluster under the cloud.
///
/// It sits on the candidate because the selector to enforce depends on it —
/// see `VmSpec::node_selector`. A list never mixes the two, so this is
/// redundant in the sense that a caller always knows; it is here so that the
/// functions reading it are total and cannot be called with the wrong tier's
/// question.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateKind {
    Node,
    Cluster,
}

/// What the scheduler knows about a placement candidate, assembled from the
/// Node (or Cluster) objects in etcd rather than from the session map alone.
#[derive(Clone, Debug)]
pub struct Candidate {
    pub name: String,
    /// A session exists ON THIS REPLICA and the candidate's heartbeat has not
    /// expired.
    ///
    /// Replica-local on purpose: it is what says whether this process can
    /// send this machine a command, and a VM belongs to the replica holding
    /// its node's session (`may_reconcile`). See `alive` for the other
    /// question, which is not the same one.
    pub connected: bool,
    /// The machine is up, as the STORE says — `Node.status.ready`, written by
    /// whichever replica holds its session, read by all of them.
    ///
    /// The fleet-wide fact, and it exists because one thing this control
    /// plane places is deliberately placed on SEVERAL machines at once. A
    /// router's priority list has to be the same list at every replica, or a
    /// three-replica cluster whose two gateway nodes hang off two different
    /// replicas can never plan a router onto both — each replica sees the
    /// other's machine as "not connected" and plans around it. Seen exactly
    /// that way in the lab: a router that came up on two nodes lost one of
    /// them the moment that node's session moved, and never got it back.
    ///
    /// The sending half is answered elsewhere and already: a router's
    /// commands go through `Dispatch`, which forwards to the replica that
    /// holds the session. So the planner may name a machine this process
    /// cannot itself reach.
    ///
    /// Equal to `connected` at the cloud tier, where there is one view.
    pub alive: bool,
    /// `spec.schedulable` — an operator draining it without stopping it.
    pub schedulable: bool,
    /// What the machine itself says is wrong with it — `status.conditions`,
    /// by type, in the order it reported them. Empty is a healthy machine and
    /// is what every candidate built before this field carries.
    ///
    /// The third half of "usable", beside connected and schedulable, and the
    /// one neither of those can express: `connected` is a fact about a socket
    /// and `schedulable` is a fact about an operator, and the machine that
    /// wedged in the mini-chaos run was both. A node that cannot act on a
    /// command is not a candidate for one, whatever its heartbeat says.
    ///
    /// Read as a VETO and never as a permission: an empty list is also what an
    /// agent too old to have the field reports, so it can only ever mean
    /// "said nothing", which is exactly how the scheduler treated every node
    /// before this existed.
    pub unhealthy: Vec<String>,
    /// What is still free here: the allowance this candidate's capacity gives
    /// under the configured overcommit, minus everything already bound to it.
    ///
    /// On the Candidate and not behind a `Scheduler` parameter, so that the
    /// rule reaches every strategy that will ever be written. Whether a VM
    /// FITS is not a matter of strategy — a bin-packer and a first-fit may
    /// disagree about where to put it and must not disagree about whether the
    /// machine can hold it.
    ///
    /// Derived per pass and never stored: it is capacity minus a sum over the
    /// VM objects, both of which the controller already has in hand, and a
    /// second copy in etcd would be a number that can be wrong.
    pub free: Capacity,
    /// The candidate's device catalogue, spelled by `common::capability`
    /// — the same function the node's own capacity is built with, so the two
    /// halves of the sentence cannot drift apart. Empty = no devices offered.
    ///
    /// Named for what it holds rather than for the field it is read from:
    /// `NodeCapacity.capabilities` is a wire name (design §2, control.proto)
    /// and stays, but nothing in the scheduler is about GPUs.
    pub catalogue: Vec<String>,
    /// Which tier's inventory this came from, and therefore which of the VM's
    /// two selectors applies.
    pub kind: CandidateKind,
    /// `spec.labels` off the Node or Cluster object — what an operator wrote
    /// on this machine, and the half of a selector that lives on the
    /// inventory.
    pub labels: BTreeMap<String, String>,
    /// The workload classes this candidate takes, `NodeSpec.accepts`. Empty
    /// is everything, which is every machine that was never told otherwise —
    /// see `resources::accepts_class`.
    ///
    /// The mirror image of a selector and beside it on purpose: a selector is
    /// the WORKLOAD choosing machines, this is the MACHINE choosing
    /// workloads, and a scheduler has to honour both or an operator who said
    /// "this one is for routers" gets VMs on it anyway.
    ///
    /// **Always empty at the cloud tier**, and that is a gap rather than a
    /// decision: `proto::NodeReport` carries a node's labels, conditions,
    /// capabilities and drain, and nothing that says what it accepts. So the
    /// cloud cannot see the refusal and the cluster is what makes it — a VM
    /// of a class nobody there takes comes back Pending with the cluster's
    /// own sentence. Filling this in at the cloud needs a field on that
    /// message.
    pub accepts: Vec<String>,
    /// The `metadata.labels` of every VM already bound here.
    ///
    /// What anti-affinity is measured against, and derived per pass from the
    /// same VM listing `free` is: two VMs are "together" exactly when one is
    /// bound to the candidate the other is being placed on. Not stored, for
    /// the same reason `free` is not — a second copy in etcd is a number that
    /// can be wrong.
    pub hosted: Vec<BTreeMap<String, String>>,
    /// What a guest's machine state would be restored INTO here, when this
    /// candidate is a machine and has said.
    ///
    /// **Not a scheduling input.** Nothing in `feasible` reads it and nothing
    /// should: where to put a NEW guest is a question about room, devices and
    /// selectors, and a machine profile answers none of them. It is here
    /// because the one caller that needs it — choosing a live migration's
    /// DESTINATION — chooses from this very list, and a second list built
    /// from Node objects beside it would be a second answer to "which
    /// machines are there".
    ///
    /// `None` at the cloud tier, where a candidate is a cluster and not a
    /// machine, and `None` from a node whose agent predates the field.
    /// Neither is evidence: see [`crate::live_migration_refusal`].
    pub machine: Option<crate::MachineProfile>,
}

/// Does every pair of `selector` appear in `labels`?
///
/// An empty selector matches everything, which is what makes "no selector"
/// and "a selector nobody wrote" the same thing and keeps every VM written
/// before this feature placed exactly where it was.
pub fn selects(selector: &BTreeMap<String, String>, labels: &BTreeMap<String, String>) -> bool {
    selector.iter().all(|(k, v)| labels.get(k) == Some(v))
}

/// The selector this candidate is measured against — the node one for a node,
/// the cluster one for a cluster.
pub fn selector_for(vm: &Vm, kind: CandidateKind) -> &BTreeMap<String, String> {
    match kind {
        CandidateKind::Node => &vm.spec.node_selector,
        CandidateKind::Cluster => &vm.spec.cluster_selector,
    }
}

/// Does this candidate already hold a VM that `term` says to stay away from?
fn collides(term: &AntiAffinity, candidate: &Candidate) -> bool {
    candidate
        .hosted
        .iter()
        .any(|labels| selects(&term.selector, labels))
}

/// Every candidate this VM may be placed on at all.
///
/// The conjunction of every rule that is NOT a matter of strategy: up,
/// willing, roomy, offers what is asked for, carries the labels selected, and
/// holds nothing a required anti-affinity term forbids. A bin-packer and a
/// first-fit may disagree about which of these to take and must not disagree
/// about which of them are allowed — the same argument `Candidate::free`
/// makes, extended to the rest of the question.
///
/// Order is preserved, so a strategy that wants "the first" gets the first in
/// inventory order and stays deterministic.
pub fn feasible<'a>(vm: &Vm, candidates: &'a [Candidate]) -> Vec<&'a Candidate> {
    let wanted = DevicePolicy::of(vm);
    let size = Capacity::wanted_by(vm);
    usable(candidates)
        .filter(|c| crate::resources::accepts_class(&c.accepts, vm.spec.class()))
        .filter(|c| size.fits_in(c.free))
        .filter(|c| selects(selector_for(vm, c.kind), &c.labels))
        .filter(|c| wanted.met_by(&c.catalogue))
        .filter(|c| {
            !vm.spec
                .anti_affinity
                .iter()
                .filter(|t| t.required)
                .any(|t| collides(t, c))
        })
        .collect()
}

/// Up, willing and able — the three cuts that are about the MACHINE and about
/// nothing that is being placed on it.
///
/// Its own function because there is a second thing being placed now. A
/// volume asks for no vCPUs, carries no anti-affinity and matches no VM
/// selector, but a node that is down, drained or wedged is no more a
/// candidate to provision on than it is to run on. Sharing the predicate is
/// what keeps "unusable" from meaning three different things depending on
/// what is being scheduled — and the wedged case is exactly the one the
/// mini-chaos run reached through the volume path, not the VM path.
pub fn is_usable(c: &Candidate) -> bool {
    c.connected && c.schedulable && c.unhealthy.is_empty()
}

/// The same three cuts, asked about the FLEET rather than about this process:
/// the machine is up, willing and able, whoever happens to be holding its
/// session.
///
/// For what is placed on several machines at once, which is routers and
/// nothing else. Every replica has to derive the same priority list out of
/// the same store — that is what makes two replicas planning one router in
/// the same pass harmless — and `connected` cannot do it, because it is a
/// fact about THIS process's socket. See `Candidate::alive`.
pub fn is_alive(c: &Candidate) -> bool {
    c.alive && c.schedulable && c.unhealthy.is_empty()
}

fn usable(candidates: &[Candidate]) -> impl Iterator<Item = &Candidate> {
    candidates.iter().filter(|c| is_usable(c))
}

/// The candidates that are up and willing but have said something is wrong
/// with them — the set the `NodeUnhealthy` sentence is about.
fn wedged(candidates: &[Candidate]) -> Vec<&Candidate> {
    candidates
        .iter()
        .filter(|c| c.connected && c.schedulable && !c.unhealthy.is_empty())
        .collect()
}

/// "agent-1a (StoreUnhealthy), agent-2b (DiskPressure)" — who is wedged and
/// with what, for the one sentence that has to send an operator to a machine.
fn wedged_sentence(field: &[Candidate]) -> String {
    wedged(field)
        .iter()
        .map(|c| format!("{} ({})", c.name, c.unhealthy.join(", ")))
        .collect::<Vec<_>>()
        .join(", ")
}

/// What a volume demands of the machine that would PROVISION it.
///
/// The storage mirror of `DevicePolicy`, and deliberately the same shape: a
/// policy derived once from the objects, then asked as often as a scheduler
/// likes. Two conjuncts, and they are different KINDS of fact, which is why
/// neither can stand in for the other:
///
///   * the backend — `volume/lvm-thin` in the node's own catalogue, the same
///     entry a VM asking for that driver already matches. A node without the
///     driver cannot make the volume whatever an object says.
///   * reachability — `StoragePoolSpec.nodes`, which is an operator's
///     statement about wiring. A volume group is on ONE machine and an export
///     is mounted by a handful; no catalogue entry can say which, because the
///     agent does not know what a pool is.
///
/// An empty node list is every node — see the field. That is the
/// single-machine lab, and there the policy degenerates to the catalogue
/// check the VM half already does.
pub struct StoragePolicy {
    driver: String,
    nodes: Vec<String>,
}

impl StoragePolicy {
    /// From the pool a volume was reserved out of. The VOLUME contributes
    /// nothing to the demand today — size is the pool's own admission
    /// question and mode is the driver's — so this takes the pool alone and
    /// says so, rather than taking a volume it would not read.
    pub fn of(pool: &StoragePool) -> Self {
        Self {
            driver: pool.spec.driver.clone(),
            nodes: pool.spec.nodes.clone(),
        }
    }

    /// The catalogue entry a candidate has to carry, spelled the one way
    /// `common::capability` spells everything.
    pub fn wanted(&self) -> String {
        capability::entry(capability::VOLUME, Some(&self.driver))
    }

    /// Can this candidate provision out of the pool?
    pub fn met_by(&self, candidate: &Candidate) -> bool {
        self.reaches(&candidate.name)
            && offers(&candidate.catalogue, capability::VOLUME, Some(&self.driver))
    }

    fn reaches(&self, name: &str) -> bool {
        self.nodes.is_empty() || self.nodes.iter().any(|n| n == name)
    }
}

/// Every candidate this volume may be provisioned on at all.
///
/// The second application of the same idea `feasible` is, and it shares the
/// half that is about the machine (`usable`) rather than restating it. What
/// it does NOT share is everything that is about a VM: a volume asks for no
/// vCPUs and no memory, so `Capacity` does not appear here — how much room is
/// left on a thin pool is the backend's own admission question, asked at
/// `provision` time by the driver that owns the pool, and a controller
/// second-guessing it would be a second answer that goes stale.
///
/// Order is preserved, so a strategy that wants "the first" stays
/// deterministic — the same promise `feasible` makes.
pub fn feasible_for_storage<'a>(
    policy: &StoragePolicy,
    candidates: &'a [Candidate],
) -> Vec<&'a Candidate> {
    usable(candidates).filter(|c| policy.met_by(c)).collect()
}

/// Narrow a feasible set to the candidates that already hold the data — or
/// leave it alone, if honouring that would mean placing nothing.
///
/// SOFT, and never anything else. A VM whose volume lives on node A runs best
/// on node A, and the day the storage is rebalanced — a node drained, a
/// replica moved, a pool re-cut — a hard rule would strand every VM that had
/// been placed by it. The fallback is the whole difference, and it is the
/// same one `preferred` makes for anti-affinity: a preference that can strand
/// a VM is a requirement whose author did not know they were writing one.
///
/// `holders` is where the data actually is, by candidate name. Empty — which
/// is every VM whose disks are declared in its own spec rather than reserved
/// as objects — leaves the set exactly as it was.
pub fn prefer_local<'a>(feasible: Vec<&'a Candidate>, holders: &[String]) -> Vec<&'a Candidate> {
    if holders.is_empty() {
        return feasible;
    }
    let local: Vec<&Candidate> = feasible
        .iter()
        .copied()
        .filter(|c| holders.iter().any(|h| h == &c.name))
        .collect();
    if local.is_empty() { feasible } else { local }
}

/// Why this volume found no candidate, in a sentence and a category.
///
/// The same two-part answer `pending_reason_of` gives a VM and for the same
/// two reasons: an operator reads the sentence off the object, and the
/// category is what may become a metric label. The order of the cuts is the
/// order that sends an operator to the right machine — nobody is here, nobody
/// is willing, nobody has the backend, nobody the pool named is here.
pub fn storage_pending_reason(
    policy: &StoragePolicy,
    pool: &str,
    candidates: &[Candidate],
) -> (PendingReason, String) {
    if candidates.is_empty() {
        return (
            PendingReason::NoCandidates,
            "no candidates are known here yet".to_string(),
        );
    }
    let usable: Vec<&Candidate> = usable(candidates).collect();
    if usable.is_empty() {
        // The specific answer before the general one, exactly as the VM
        // half's first cut orders them: a wedged node is not a drained one.
        let wedged = wedged_sentence(candidates);
        if !wedged.is_empty() {
            return (
                PendingReason::NodeUnhealthy,
                format!(
                    "every candidate that is up and willing says something is wrong with \
                     itself: {wedged}"
                ),
            );
        }
        return (
            PendingReason::NoneUsable,
            format!(
                "none of the {} known candidates is both connected and schedulable",
                candidates.len()
            ),
        );
    }
    // Backend before wiring. "Nobody has this driver" is a different operator
    // problem from "the machines that do are not the ones the pool names",
    // and only the second is about something written in the pool object.
    let with_driver: Vec<&&Candidate> = usable
        .iter()
        .filter(|c| offers(&c.catalogue, capability::VOLUME, Some(&policy.driver)))
        .collect();
    if with_driver.is_empty() {
        return (
            PendingReason::Unserved,
            format!(
                "no connected candidate offers [{}], which storage pool {pool} is made of",
                policy.wanted()
            ),
        );
    }
    (
        PendingReason::Unserved,
        format!(
            "storage pool {pool} names [{}], and none of them is a connected candidate that \
             offers {}",
            policy.nodes.join(", "),
            policy.wanted()
        ),
    )
}

/// One volume a VM names, and what it therefore demands of the node.
///
/// Assembled by the tier that has the objects — the volume for its node, the
/// pool for its locality and its wiring — so that this module goes on knowing
/// nothing about etcd. The same shape `StoragePolicy` has, one question later:
/// that one asks where a volume may be MADE, this one asks where the VM that
/// uses it may RUN.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VolumeBinding {
    /// What the VM's spec called it, for the sentence.
    pub volume: String,
    /// `Volume.status.node` — where the bytes were made. `None` while the
    /// volume has not been placed.
    pub node: Option<String>,
    /// `StoragePool.status.locality`. `None` = nobody has said (an agent that
    /// predates the field, a pool nothing has reported on), and then this
    /// binding constrains nothing hard — see `required`.
    pub locality: Option<Locality>,
    /// `StoragePoolSpec.nodes`. Empty = every node.
    pub pool_nodes: Vec<String>,
    /// `StoragePoolSpec.driver` — the backend this volume came out of.
    ///
    /// Read for ONE locality: `networked`. A node-local or shared volume is
    /// pinned to machines by name, and the name is the whole constraint; a
    /// networked one is pinned to nothing by name, and what a candidate then
    /// has to have is the DRIVER that can reach the bytes. Without this the
    /// scheduler would place such a VM anywhere and find out at the attach —
    /// which works, because that refusal is structural and the VM moves, but
    /// it is placement by trial and it shows in the events.
    ///
    /// `None` on a binding built without one, which reads as "no claim to
    /// insist on" and is exactly the old behaviour.
    pub driver: Option<String>,
}

impl VolumeBinding {
    /// The nodes that can serve this volume, or `None` for "no hard rule".
    ///
    /// The one place the locality axis is actually spent, and each arm is a
    /// different sentence:
    ///
    ///   * `node-local` — the bytes are on ONE machine, so the VM runs there
    ///     or nowhere. HARD, and it is the reason the axis exists: the same
    ///     rule as a soft preference would place the VM next to an empty
    ///     directory and boot it.
    ///   * `shared` — every node in the pool sees the same bytes, so the pool
    ///     is the rule and the volume's own node means nothing. Still soft in
    ///     effect where the pool names no nodes, because then the pool is
    ///     every node.
    ///   * `networked` — the bytes are elsewhere and the DRIVER says which
    ///     nodes can reach them. No driver claims it yet (position 18 of the
    ///     catalogue brings NVMe-oF); the arm is here so the axis is complete
    ///     and the day a driver arrives this is the line that changes.
    ///   * `None` — nobody has said. Falls back to the soft preference this
    ///     scheduler has always had, which is what keeps a mixed-version
    ///     cluster placing VMs at all.
    pub fn required(&self) -> Option<Vec<String>> {
        match self.locality {
            Some(Locality::NodeLocal) => self.node.clone().map(|n| vec![n]),
            Some(Locality::Shared) => {
                (!self.pool_nodes.is_empty()).then(|| self.pool_nodes.clone())
            }
            Some(Locality::Networked) | None => None,
        }
    }

    /// The catalogue entry a candidate needs to reach this volume, where
    /// reaching it is a capability rather than a place.
    ///
    /// Only `networked`, and only because that is the one locality whose
    /// answer to "where are the bytes" is "not here, and it does not matter
    /// where here is". A `node-local` volume names its machine and a
    /// `shared` one names its pool's; both are answered by `required` and
    /// neither needs this. For a networked one the driver IS the constraint:
    /// a node that cannot speak NVMe-oF cannot reach an NVMe-oF namespace,
    /// however much room it has.
    ///
    /// The day `StoragePool.spec.attacher` exists this returns the ATTACHER's
    /// claim rather than the provider's — the two are separate roles and the
    /// catalogue says so. Today they are one driver on one machine, which is
    /// the shape the lab proves, and this is the line that changes.
    pub fn claim(&self) -> Option<String> {
        matches!(self.locality, Some(Locality::Networked))
            .then(|| self.driver.clone())
            .flatten()
            .filter(|d| !d.is_empty())
    }

    /// Whether this volume is nailed to some machine OTHER than `node`.
    ///
    /// `required()` asked of a VM that is already placed, which is a
    /// different question from the one the scheduler asks: the scheduler is
    /// choosing and this is checking. It is what refuses an attach of a
    /// node-local disk to a VM that runs somewhere else — a move is not an
    /// attach, and the two would be told apart far too late otherwise (the
    /// node would be handed a path that is not on it).
    ///
    /// `false` where nothing is known: an unplaced volume, a pool nobody has
    /// reported a locality for, a `shared` pool that names no nodes. Same
    /// direction as `required` — silence never pins.
    pub fn pins_elsewhere(&self, node: &str) -> bool {
        self.required()
            .is_some_and(|allowed| !allowed.iter().any(|n| n == node))
    }
}

/// Narrow a candidate set to those every binding REQUIRES — the hard half.
///
/// The `feasible` of the volume question, and split from the soft half for
/// exactly the reason those two are split one function apart: a requirement
/// and a preference must be applied in that order and never mixed. A
/// preference applied first can leave the requirement nothing to choose from,
/// and its fallback would then hand back a node the requirement forbids.
///
/// An empty binding list — every VM whose disks are all inline — leaves the
/// set exactly as it was.
pub fn feasible_for_volumes<'a>(
    bindings: &[VolumeBinding],
    candidates: Vec<&'a Candidate>,
) -> Vec<&'a Candidate> {
    let mut allowed = candidates;
    for binding in bindings {
        // The claim, for a volume whose bytes are on neither this node nor
        // any named one. See `VolumeBinding::claim`.
        if let Some(claim) = binding.claim() {
            allowed.retain(|c| offers(&c.catalogue, capability::VOLUME, Some(&claim)));
        }
        let Some(nodes) = binding.required() else {
            continue;
        };
        allowed.retain(|c| nodes.iter().any(|n| n == &c.name));
    }
    allowed
}

/// Narrow to the candidates that already hold the data — or leave the set
/// alone, if honouring that would mean placing nothing.
///
/// The soft half, over the bindings that have NO hard rule: a `shared` pool
/// with no node list, and a pool whose locality nobody has reported. Both are
/// "any node will do, and this one will do best", which is a preference and
/// must behave like one.
///
/// Applied AFTER capacity, which is what makes the fallback real: a node that
/// holds the data and has no room left has to lose to a node that has room,
/// or the preference would be a requirement whose author did not know they
/// were writing one. `prefer_local` is the mechanism; this is the half of the
/// binding list it may be given.
pub fn preferred_for_volumes<'a>(
    bindings: &[VolumeBinding],
    feasible: Vec<&'a Candidate>,
) -> Vec<&'a Candidate> {
    let holders: Vec<String> = bindings
        .iter()
        .filter(|b| b.required().is_none())
        .filter_map(|b| b.node.clone())
        .collect();
    prefer_local(feasible, &holders)
}

/// Why this VM's volumes left it nowhere to go.
///
/// Only reached when `feasible` found candidates and `feasible_for_volumes`
/// left none, so the sentence is always about a volume and never about the
/// cluster being empty — that case has its own reasons one function up.
pub fn volume_pending_reason(
    bindings: &[VolumeBinding],
    candidates: &[&Candidate],
) -> (PendingReason, String) {
    for binding in bindings {
        let Some(nodes) = binding.required() else {
            continue;
        };
        if candidates
            .iter()
            .any(|c| nodes.iter().any(|n| n == &c.name))
        {
            continue;
        }
        let locality = binding
            .locality
            .map(Locality::as_str)
            .unwrap_or("of unknown locality");
        return (
            PendingReason::NoNodeForVolume,
            format!(
                "volume {} is {locality} and lives on [{}]; none of them is a candidate that \
                 can also run this vm",
                binding.volume,
                nodes.join(", ")
            ),
        );
    }
    // Every hard rule is satisfiable on its own and together they are not:
    // two node-local volumes on two different machines is the shape, and it
    // is a split request in exactly the sense the existing reason means.
    (
        PendingReason::Split,
        format!(
            "no single candidate can reach all {} of this vm's volumes at once",
            bindings.len()
        ),
    )
}

/// Why the machines this VM's volumes pinned it to cannot take it — the
/// sentence for a narrowing that left nodes standing and a scheduler that
/// then threw every one of them out.
///
/// `volume_pending_reason` above answers the case where the narrowing emptied
/// the candidate list. This answers the OTHER one, and until it existed that
/// case fell through to `pending_reason_of` against the FULL node list: a VM
/// whose `node-local` disks are on a drained `agent-1` was told *"no single
/// candidate offers all of [hypervisor] at once"* while both nodes offered
/// `hypervisor` and the truth was that the only node it could use was
/// drained. An operator read a sentence about hypervisors and went looking at
/// the wrong end of the cluster.
///
/// `None` means the volumes are not the reason and the ordinary sentence is
/// the true one: nothing was pinned, or a usable node survived the narrowing
/// and something else defeated it (room, a selector, a device).
///
/// Asked AFTER `assign` and not before, which is the whole correction. Before
/// it, "is this node usable" has not been decided by the party that decides
/// it.
pub fn volume_nodes_unusable(
    bindings: &[VolumeBinding],
    allowed: &[&Candidate],
) -> Option<(PendingReason, String)> {
    // Nothing is nailed down, so nothing here explains anything.
    if bindings.iter().all(|b| b.required().is_none()) {
        return None;
    }
    // An empty list is the other function's sentence, and a list with a
    // usable node in it is not a list the volumes defeated.
    if allowed.is_empty() || allowed.iter().any(|c| is_usable(c)) {
        return None;
    }
    // Not connected before drained before wedged: each is more fundamental
    // than the next, and an operator who un-drains a node that is also gone
    // has fixed nothing. The third is what the data disk case needed — the
    // machine holding the bytes is up and willing and cannot write them.
    let state = |c: &Candidate| {
        if !c.connected {
            "not connected".to_string()
        } else if !c.schedulable {
            "drained".to_string()
        } else {
            format!("reporting {}", c.unhealthy.join(", "))
        }
    };
    let names: Vec<&str> = allowed.iter().map(|c| c.name.as_str()).collect();
    let first = state(allowed[0]);
    let sentence = if allowed.iter().all(|c| state(c) == first) {
        // One state, so it can be said once — and the singular case is the
        // common one and reads like a person wrote it.
        match names.as_slice() {
            [only] => format!("the node holding this vm's volumes ({only}) is {first}"),
            _ => format!(
                "the nodes holding this vm's volumes ({}) are {first}",
                names.join(", ")
            ),
        }
    } else {
        format!(
            "no node holding this vm's volumes can take it: {}",
            allowed
                .iter()
                .map(|c| format!("{} is {}", c.name, state(c)))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    Some((PendingReason::NoNodeForVolume, sentence))
}

/// What a VM demands of the NODES inside a cluster.
///
/// The question the cloud tier could not ask until `ClusterStatus.nodes`
/// existed, and the reason two findings were open at once. A cluster's
/// capacity is a SUM and its catalogue a UNION, so a cluster could look able
/// to serve a VM that no single node of it can: the `nodeSelector` was
/// checked one tier down, after the binding, so a VM that no node matched
/// went Pending on a cluster it should never have been sent to. And a VM
/// naming a `node-local` volume had the same problem one step worse — the
/// bytes are on one machine of one cluster, and nothing up here knew it.
///
/// Both are the same question and this is it, asked once, before the binding.
#[derive(Debug)]
pub struct NodeDemand<'a> {
    /// `spec.nodeSelector` — matched against each node's own labels, which
    /// the cluster reports and the cloud mirrors.
    pub selector: &'a BTreeMap<String, String>,
    /// The nodes that may serve this VM's volumes, or `None` for "any".
    ///
    /// The INTERSECTION of what every referenced volume allows: one
    /// `node-local` volume allows exactly the node holding it, a `shared` one
    /// allows its pool's nodes, and an unknown locality allows everything —
    /// so an empty vector here means the volumes contradict each other and no
    /// node anywhere can serve them.
    pub allowed: Option<Vec<String>>,
}

impl NodeDemand<'_> {
    /// Whether at least one node of this cluster could actually run the VM.
    ///
    /// A node has to be usable — up and not drained — before its labels are
    /// worth reading: a cluster whose only matching node is being drained is
    /// a cluster the VM should not be sent to, which is the whole point of
    /// asking before the binding rather than after it.
    pub fn met_by_a_node(&self, nodes: &[NodeSummary]) -> bool {
        nodes.iter().any(|n| {
            n.ready
                && n.schedulable
                // The same veto `is_usable` applies one tier down. A cloud
                // that binds a VM to a cluster whose only matching machine
                // has a full disk has sent the VM somewhere it will sit
                // Pending, which is exactly what asking before the binding
                // exists to prevent.
                && n.conditions.is_empty()
                && selects(self.selector, &n.labels)
                && self
                    .allowed
                    .as_ref()
                    .is_none_or(|allowed| allowed.iter().any(|a| a == &n.name))
        })
    }
}

/// Narrow the allowed-node set by one more volume.
///
/// `None` narrows nothing — an unknown locality, or a `shared` pool that
/// names no nodes, is "any node will do". Two `Some`s intersect, and an empty
/// result is the honest answer that no node serves both.
pub fn narrow_allowed(
    current: Option<Vec<String>>,
    next: Option<Vec<String>>,
) -> Option<Vec<String>> {
    match (current, next) {
        (None, next) => next,
        (current, None) => current,
        (Some(current), Some(next)) => {
            Some(current.into_iter().filter(|c| next.contains(c)).collect())
        }
    }
}

/// Narrow a feasible set to those that also honour the PREFERRED terms — or/// Narrow a feasible set to those that also honour the PREFERRED terms — or
/// leave it alone, if honouring them would mean placing nothing./// Narrow a feasible set to those that also honour the PREFERRED terms — or
/// leave it alone, if honouring them would mean placing nothing.
///
/// That fallback is the whole difference between a preference and a
/// requirement, and it is why the two are separate flags rather than one
/// knob: a preference that can strand a VM is a requirement whose author did
/// not know they were writing one.
pub fn preferred<'a>(vm: &Vm, feasible: Vec<&'a Candidate>) -> Vec<&'a Candidate> {
    let soft: Vec<&AntiAffinity> = vm
        .spec
        .anti_affinity
        .iter()
        .filter(|t| !t.required)
        .collect();
    if soft.is_empty() {
        return feasible;
    }
    let clean: Vec<&Candidate> = feasible
        .iter()
        .copied()
        .filter(|c| !soft.iter().any(|t| collides(t, c)))
        .collect();
    if clean.is_empty() { feasible } else { clean }
}

pub trait Scheduler: Send + Sync {
    /// Pick a placement for an unbound VM; None = leave it Pending.
    fn assign(&self, vm: &Vm, candidates: &[Candidate]) -> Option<String>;
}

/// The TOML spelling: `scheduler = "first-fit"`.
///
/// The same shape `retry` has for the requeue policy, and for the same
/// reason: a plugin trait with exactly one implementation wired in by hand is
/// not a seam, it is a comment about one. Both controllers resolve their
/// scheduler through here, so a second strategy is a new arm and a new line in
/// a config file rather than an edit in two `main`s.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct SchedulerConfig(pub String);

impl SchedulerConfig {
    /// Default when the config says nothing: First-Fit — what both tiers were
    /// wired to outright before this was a choice, so a config that does not
    /// mention a scheduler still gets exactly the placement it had.
    pub fn into_scheduler(this: Option<Self>) -> anyhow::Result<std::sync::Arc<dyn Scheduler>> {
        Ok(match this.as_ref().map(|s| s.0.as_str()) {
            None | Some("first-fit") => std::sync::Arc::new(FirstFit),
            Some("spread") => std::sync::Arc::new(Spread),
            Some(other) => {
                anyhow::bail!("scheduler = {other:?}, expected \"first-fit\" or \"spread\"")
            }
        })
    }
}

/// What the VM's opaque spec demands of a candidate's catalogue.
///
/// The controller deliberately does not parse the whole NewVmSpec — the
/// agent's serde stays the validator — but the driver names in it are the one
/// part scheduling cannot be correct without. Two lists now, one shape:
/// `devices[].driver`/`.profile` as they always were, and `volumes[].driver`
/// as a profile of the `volume` capability, because that is how a node claims
/// a storage backend (see `common::capability::VOLUME`). Without the second
/// half, an lvm-thin VM lands wherever there is room and fails at the first
/// `lvcreate`.
///
/// A volume that names no driver — or names the default one — produces no
/// request at all. It genuinely constrains nothing: every node registers that
/// backend whether or not it is configured. And asking for it anyway would
/// strand such a VM on any node whose agent predates the volume catalogue,
/// which claims no `volume/*` entries and would then never take a plain disk
/// again. A mixed-version cluster is the normal state during a rollout, and
/// that is the case this rule is for.
///
/// Three lists now: `nics[].vxlan_id` is the third, as a profile of the
/// `network` capability. The same argument one more time and a sharper one —
/// an overlay VM on a node with no `[network.vxlan]` section does not merely
/// fail late; the agent there refuses it outright, and the only alternative to
/// refusing would be a tenant's VM on the shared default bridge. A NIC that
/// names no overlay asks for nothing, so a plain VM still lands on any node,
/// including one whose agent predates all of this.
fn resource_requests(vm: &Vm) -> Vec<(String, Option<String>)> {
    let array = |field: &str| -> &[serde_json::Value] {
        vm.spec
            .vm
            .get(field)
            .and_then(|d| d.as_array())
            .map(Vec::as_slice)
            .unwrap_or(&[])
    };

    let mut requests: Vec<(String, Option<String>)> = array("devices")
        .iter()
        .filter_map(|d| {
            let driver = d.get("driver")?.as_str()?.to_string();
            let profile = d
                .get("profile")
                .and_then(|p| p.as_str())
                .map(str::to_string);
            Some((driver, profile))
        })
        .collect();

    requests.extend(array("volumes").iter().filter_map(|v| {
        let driver = v.get("driver").and_then(|d| d.as_str())?;
        (driver != capability::DEFAULT_VOLUME_DRIVER)
            .then(|| (capability::VOLUME.to_string(), Some(driver.to_string())))
    }));

    // One request however many NICs are on the overlay: what is being asked
    // for is a node that can join overlays at all, and asking for it twice
    // would only make the debug line longer.
    if array("nics")
        .iter()
        .any(|n| n.get("vxlan_id").is_some_and(|v| !v.is_null()))
    {
        requests.push((
            capability::NETWORK.to_string(),
            Some(capability::VXLAN.to_string()),
        ));
    }

    // And the other side of the same field: a NIC that names a provider
    // network needs a node that really holds an interface for THAT physnet,
    // which is exactly what a gateway claim says. One request per distinct
    // physnet, because two of them are two different wires and a node holding
    // one is not a node holding the other — this is the one place where
    // asking twice is not noise.
    let mut physnets: Vec<&str> = array("nics")
        .iter()
        .filter_map(|n| crate::vni::physnet_of(n.as_object()?))
        .collect();
    physnets.dedup();
    for physnet in physnets {
        requests.push((
            capability::NETWORK.to_string(),
            Some(capability::gateway_claim(physnet)),
        ));
    }

    // Every VM asks for a hypervisor, whatever else it asks for.
    //
    // A BARE request — any hypervisor will do, and which one is the node's
    // business. Matching the name would be sizing knowledge this tier does
    // not have and should not learn: a VM does not care whether it is served
    // by cloud-hypervisor or by whatever comes next, only that something
    // serves it.
    //
    // Shipping this was deliberately held back until no node in the fleet ran
    // an agent that predates the claim: such a node claims no `hypervisor/*`,
    // and a VM requiring one would go Pending there for ever. Claiming is
    // additive and safe during a rollout; requiring is not. The condition is
    // met now — `manacor` was the last node still on a hand-started binary
    // from before the claim, and the image round replaced it.
    //
    // What it buys: a storage-only node has room, is connected, is
    // schedulable, and carries no hypervisor at all, so without this the
    // first ordinary VM lands there, the agent refuses correctly, and the VM
    // ends Failed on a machine that could never have run it. A volume may
    // still be placed there, which is the whole point of having such a node.
    requests.push((capability::HYPERVISOR.to_string(), None));

    requests
}

/// What one VM asks of the machine it lands on, derived from its spec once
/// and then asked as often as a scheduler likes.
///
/// A seam, not a new rule — the derivation below is `resource_requests`
/// unchanged. It exists so that the next scheduler can ASK what a VM needs
/// instead of re-reading `spec.vm` to find out: the placement contract of a
/// volume driver or a vxlan nic is a property of the spec, not of whichever
/// strategy is looking at it, and two strategies deriving it separately is how
/// they start disagreeing about where an lvm-thin VM may run.
pub struct DevicePolicy(Vec<(String, Option<String>)>);

impl DevicePolicy {
    pub fn of(vm: &Vm) -> Self {
        Self(resource_requests(vm))
    }

    /// A VM that constrains nothing places anywhere.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Does this candidate's catalogue offer everything the VM asked for?
    /// Every request on ONE candidate: a combo VM cannot be split across two.
    pub fn met_by(&self, catalogue: &[String]) -> bool {
        self.0
            .iter()
            .all(|(driver, profile)| offers(catalogue, driver, profile.as_deref()))
    }

    /// The requests themselves, for a scheduler that wants to say what it
    /// could not place.
    pub fn requests(&self) -> &[(String, Option<String>)] {
        &self.0
    }

    /// The requests no usable candidate offers, spelled the way a catalogue
    /// spells them (`nvrm/4q`, `volume/lvm-thin`, `network/vxlan`).
    ///
    /// Not "which candidate fell short" but "what nobody has": a VM needs ALL
    /// of its requests on ONE candidate, so the useful answer to an operator
    /// is the part of the ask that no single machine can serve.
    pub fn unmet(&self, candidates: &[Candidate]) -> Vec<String> {
        let usable: Vec<&Candidate> = candidates
            .iter()
            .filter(|c| c.connected && c.schedulable)
            .collect();
        self.0
            .iter()
            .filter(|(driver, profile)| {
                !usable
                    .iter()
                    .any(|c| offers(&c.catalogue, driver, profile.as_deref()))
            })
            .map(|(driver, profile)| capability::entry(driver, profile.as_deref()))
            .collect()
    }
}

/// The CATEGORY of why a VM found no placement — the same question
/// `pending_reason` answers in a sentence, in a form that can be a label.
///
/// The two exist together and neither replaces the other. The sentence names
/// the capabilities nobody offers and counts the candidates it looked at, and
/// that is what an operator reads off the object; it is also, for exactly
/// those reasons, unbounded, and a metric label with an unbounded value range
/// is what takes a Prometheus down. This is the closed set behind it, so that
/// "how many VMs are pending, and why" is a time series rather than a string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingReason {
    /// Nothing has ever dialled in here.
    NoCandidates,
    /// Some are known; none is both connected and schedulable — everything is
    /// down, or everything is drained.
    NoneUsable,
    /// Everything that is up and willing has said something is wrong with
    /// itself: a full disk, a store that refuses writes, a cgroup root that
    /// is not one.
    ///
    /// Its own reason and not `NoneUsable`, because the operator fix is a
    /// different one and lives on a different machine. "Everything is
    /// drained" sends somebody to `node uncordon`; this sends them to the
    /// node named in the sentence, which is where the mini-chaos run's three
    /// wasted hours went.
    NodeUnhealthy,
    /// Everything is up and willing and none of it has room. The fourth
    /// case, and without it a full cluster looks from the API exactly like a
    /// cluster where nothing is happening.
    NoCapacity,
    /// Every machine that is up and willing takes only classes this workload
    /// is not one of — `NodeSpec.accepts` on one side, `spec.class` on the
    /// other.
    ///
    /// Its own reason, and it is asked before room, because the operator fix
    /// is a different one and "no candidate has room" would send somebody to
    /// buy memory for a fleet whose machines are all reserved for routers.
    /// It is also not `SelectorUnmatched`: a selector is what the WORKLOAD
    /// asked for and is fixed by editing the workload; this is what the
    /// MACHINES accept and is fixed by editing a node.
    ClassRefused,
    /// Room enough, and nothing carries the labels the VM selects.
    SelectorUnmatched,
    /// Something the VM asks for is offered by nobody at all.
    Unserved,
    /// Every part of the ask is served somewhere, and no single candidate
    /// serves all of it at once.
    Split,
    /// Everything that would otherwise do already holds a VM this one is
    /// required to stay away from.
    AntiAffinity,
    /// A volume this VM names is not `Ready` yet. Its own reason and not
    /// `Unserved`, because nothing is missing: the disk is being made, and
    /// the answer is to wait rather than to change anything.
    VolumeNotReady,
    /// The volume is Ready, and no candidate can reach it. Where a
    /// `node-local` volume is IS where the VM has to run, so this is a hard
    /// wall rather than a preference that was not met — the node holding the
    /// data is down, drained, or out of room.
    NoNodeForVolume,
    /// A `Secret` this VM's cloud-init reads from cannot be opened here yet:
    /// it has not been mirrored down, it holds no such key, or this tier has
    /// no `secrets_key`.
    ///
    /// Its own word rather than `VolumeNotReady`, which is what it borrowed
    /// while there was nothing else to say. A reason is a METRIC LABEL —
    /// `pending_reason{reason="volume-not-ready"}` counting VMs waiting for a
    /// secret would send whoever is reading the dashboard to the storage.
    SecretNotReady,
}

impl PendingReason {
    /// Every variant, in declaration order — see `RunStrategy::ALL`. What a
    /// pass walks to publish a zero for the reasons nothing is pending for,
    /// so that a reason with no VMs stays a flat line in a dashboard rather
    /// than a series that vanishes.
    pub const ALL: [PendingReason; 12] = [
        PendingReason::NoCandidates,
        PendingReason::NoneUsable,
        PendingReason::NodeUnhealthy,
        PendingReason::ClassRefused,
        PendingReason::NoCapacity,
        PendingReason::SelectorUnmatched,
        PendingReason::Unserved,
        PendingReason::Split,
        PendingReason::AntiAffinity,
        PendingReason::VolumeNotReady,
        PendingReason::NoNodeForVolume,
        PendingReason::SecretNotReady,
    ];

    /// Where this variant sits in `ALL` — the slot a `PendingTally` counts
    /// into. Derived from the table rather than written twice, so the two
    /// cannot drift.
    pub fn index(self) -> usize {
        Self::ALL
            .iter()
            .position(|r| *r == self)
            .expect("ALL names every variant")
    }

    /// The label value. Kebab-case and stable: a dashboard is written against
    /// these words, and renaming one silently breaks every query that names
    /// it.
    pub fn as_str(self) -> &'static str {
        match self {
            PendingReason::NoCandidates => "no-candidates",
            PendingReason::NoneUsable => "none-usable",
            PendingReason::NodeUnhealthy => "node-unhealthy",
            PendingReason::ClassRefused => "class-refused",
            PendingReason::NoCapacity => "no-capacity",
            PendingReason::SelectorUnmatched => "selector-unmatched",
            PendingReason::Unserved => "unserved-request",
            PendingReason::Split => "split-request",
            PendingReason::AntiAffinity => "anti-affinity",
            PendingReason::VolumeNotReady => "volume-not-ready",
            PendingReason::SecretNotReady => "secret-not-ready",
            PendingReason::NoNodeForVolume => "no-node-for-volume",
        }
    }
}

/// How many VMs are pending for each reason, over one reconcile pass.
///
/// A gauge cannot be incremented from inside the per-VM step and be right:
/// what a dashboard needs is "how many are pending for this reason NOW", so
/// the pass counts and publishes once at the end — including the zeros, so
/// that a reason nothing is pending for stays a flat line rather than a
/// series that disappears while the panel is being read.
///
/// Atomics rather than a `Cell`, because the pass holds this behind a shared
/// reference across an await and the future has to stay `Send`. There is no
/// contention: one pass, one task.
#[derive(Debug, Default)]
pub struct PendingTally([std::sync::atomic::AtomicI64; PendingReason::ALL.len()]);

impl PendingTally {
    pub fn new() -> Self {
        Self(std::array::from_fn(|_| {
            std::sync::atomic::AtomicI64::new(0)
        }))
    }

    pub fn note(&self, reason: PendingReason) {
        self.0[reason.index()].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Publish every reason for this tier, zero included.
    pub fn publish(&self, tier: &str) {
        for reason in PendingReason::ALL {
            let n = self.0[reason.index()].load(std::sync::atomic::Ordering::Relaxed);
            telemetry::metrics::scheduling().set_pending(tier, reason.as_str(), n);
        }
    }
}

/// One cut the scheduler makes at the field, and what it means that nothing
/// survived it.
///
/// A candidate that is not usable at all is carried past every cut untouched:
/// the cuts are about the VM's demands, and whether anybody is usable is the
/// first row's question and nobody else's.
struct Cut {
    /// Which candidates get past this cut.
    keep: fn(&Vm, &Capacity, &DevicePolicy, &Candidate) -> bool,
    /// What to say when no usable candidate got past. Reads the field as it
    /// stood BEFORE the cut, which is what these sentences have to name: the
    /// roomiest machine, the tier the labels are about, the part of the ask
    /// nobody serves.
    verdict: fn(&Vm, &Capacity, &DevicePolicy, &[Candidate]) -> (PendingReason, String),
}

/// The reasons a VM can be Pending, in the order they are asked.
///
/// The order IS the answer and that is why it is a table: "nobody is here" and
/// "nobody is willing" are different operator problems from "nobody can", and
/// only the last is about the VM's own demands. Room before capability, the
/// same order FirstFit filters in — a VM that fits nowhere is not a VM whose
/// device request went unserved, and telling an operator to add a GPU when
/// what is missing is memory sends them to the wrong machine. Selector before
/// catalogue, because an unmatched selector is something the operator wrote
/// down a moment ago and can fix by reading it again; saying "nobody offers
/// nvrm/4q" to somebody whose typo was `zone=stutgart` sends them to the wrong
/// problem. Anti-affinity last, because it is the subtlest of the cuts and
/// blaming it while a GPU is also missing would be true and useless.
///
/// A new reason is a new row, and where it goes in the list is the whole of
/// the decision.
const CUTS: [Cut; 6] = [
    // Is anybody here at all, is anybody willing, and is anybody able?
    Cut {
        keep: |_, _, _, _| true,
        verdict: |_, _, _, field| {
            if field.is_empty() {
                return (
                    PendingReason::NoCandidates,
                    "no candidates are known here yet".to_string(),
                );
            }
            // Before the drained/down sentence, because it is the more
            // specific answer: a machine that is up, willing and wedged would
            // otherwise be counted into "none is connected and schedulable",
            // which is a sentence that sends an operator to look at a cordon
            // that is not there.
            let wedged = wedged_sentence(field);
            if !wedged.is_empty() {
                return (
                    PendingReason::NodeUnhealthy,
                    format!(
                        "every candidate that is up and willing says something is wrong with \
                         itself: {wedged}"
                    ),
                );
            }
            (
                PendingReason::NoneUsable,
                format!(
                    "none of the {} known candidates is both connected and schedulable",
                    field.len()
                ),
            )
        },
    },
    // What the machines accept. Before room, because a fleet whose machines
    // are all reserved for routers has plenty of room and no place for this
    // vm, and "no candidate has room" would send somebody to buy memory.
    Cut {
        keep: |vm, _, _, c| crate::resources::accepts_class(&c.accepts, vm.spec.class()),
        verdict: |vm, _, _, field| {
            let takers: Vec<String> = field
                .iter()
                .filter(|c| is_usable(c))
                .map(|c| format!("{} ({})", c.name, c.accepts.join(", ")))
                .collect();
            (
                PendingReason::ClassRefused,
                format!(
                    "no candidate accepts the class {:?}: {}",
                    vm.spec.class(),
                    takers.join(", ")
                ),
            )
        },
    },
    // Room.
    Cut {
        keep: |_, size, _, c| size.fits_in(c.free),
        verdict: |_, size, _, field| {
            let biggest = field
                .iter()
                .filter(|c| is_usable(c))
                .map(|c| c.free)
                .max_by_key(|f| (f.mem_mib, f.vcpus))
                .unwrap_or_default();
            (
                PendingReason::NoCapacity,
                format!(
                    "no candidate has room for {} vcpu and {} MiB; the roomiest has {} vcpu and \
                     {} MiB free",
                    size.vcpus, size.mem_mib, biggest.vcpus, biggest.mem_mib
                ),
            )
        },
    },
    // The labels the VM selects.
    Cut {
        keep: |vm, _, _, c| selects(selector_for(vm, c.kind), &c.labels),
        verdict: |vm, _, _, field| {
            // The kind is the same for every candidate of one list, so the
            // first usable one names the tier this sentence is about.
            let kind = field
                .iter()
                .find(|c| is_usable(c))
                .map(|c| c.kind)
                .unwrap_or(CandidateKind::Node);
            let asked = selector_for(vm, kind)
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(", ");
            (
                PendingReason::SelectorUnmatched,
                format!("no candidate carries the labels this vm selects [{asked}]"),
            )
        },
    },
    // The catalogue: every request on ONE candidate.
    Cut {
        keep: |_, _, wanted, c| wanted.met_by(&c.catalogue),
        verdict: |_, _, wanted, field| match wanted.unmet(field) {
            // Every request IS served somewhere, so the ask is servable in
            // principle and the split is what defeated it: no single candidate
            // holds the whole set. Worth its own sentence, because the
            // operator fix is different (put the capabilities on one machine,
            // or ask for less on one vm).
            unmet if unmet.is_empty() => split(wanted),
            unmet => (
                PendingReason::Unserved,
                format!("no connected candidate offers [{}]", unmet.join(", ")),
            ),
        },
    },
    // Anti-affinity, and by here everything else fits — so if a required term
    // is what empties the set, it really is the reason.
    Cut {
        keep: |vm, _, _, c| {
            !vm.spec
                .anti_affinity
                .iter()
                .filter(|t| t.required)
                .any(|t| collides(t, c))
        },
        verdict: |_, _, _, _| {
            (
                PendingReason::AntiAffinity,
                "every candidate that would otherwise do already holds a vm this one must stay away from"
                    .to_string(),
            )
        },
    },
];

/// Everything is served somewhere and no one candidate serves it all.
fn split(wanted: &DevicePolicy) -> (PendingReason, String) {
    (
        PendingReason::Split,
        format!(
            "no single candidate offers all of [{}] at once, though each part is served \
             somewhere",
            wanted
                .requests()
                .iter()
                .map(|(d, p)| capability::entry(d, p.as_deref()))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    )
}

/// Why a VM found no placement: the category, and one sentence an operator
/// can act on.
///
/// The scheduler's `None` is the whole of what the reconciler learns, and
/// until this existed the explanation lived only as a `debug!` line inside a
/// controller — so a Pending VM was a dead end for anybody holding only the
/// API. This turns the same cases into a sentence that can be stored on the
/// object and read back with `vm inspect`, and into a category that can be a
/// metric label.
///
/// One walk down `CUTS`: narrow, and the first cut that leaves nothing usable
/// is the answer. A field that survives every cut is the `Split` case — every
/// part of the ask is served, no one machine serves all of it.
pub fn pending_reason_of(vm: &Vm, candidates: &[Candidate]) -> (PendingReason, String) {
    let size = Capacity::wanted_by(vm);
    let wanted = DevicePolicy::of(vm);
    let mut field: Vec<Candidate> = candidates.to_vec();
    for cut in CUTS {
        let next: Vec<Candidate> = field
            .iter()
            .filter(|c| !is_usable(c) || (cut.keep)(vm, &size, &wanted, c))
            .cloned()
            .collect();
        if !next.iter().any(is_usable) {
            return (cut.verdict)(vm, &size, &wanted, &field);
        }
        field = next;
    }
    split(&wanted)
}

/// Just the sentence, for the callers that only put it on the object.
pub fn pending_reason(vm: &Vm, candidates: &[Candidate]) -> String {
    pending_reason_of(vm, candidates).1
}

/// Put a VM onto a candidate, in the pass's own picture of the world.
///
/// Called by a pass the moment it decides, and that timing is the whole
/// point: a pass places VMs one after another out of one listing, so without
/// this the second VM of a pass would be measured against a machine that
/// still looks empty. An API-edge check cannot do this at all — the objects
/// it would have to count do not exist yet when it runs.
///
/// **Both halves, in one call, on purpose.** A placement changes two things
/// about a candidate — it has less room, and it now holds something. The
/// first was booked here from the beginning and the second was not, and the
/// consequence was measured in the lab: a burst of creates that one pass sees
/// together stacked five VMs with a `required` anti-affinity term onto one
/// node while free nodes stood beside it, because `collides()` was asking an
/// inventory from before the pass. Two functions to call in the right order
/// is an invitation to call one; there is one.
///
/// A binding whose write then loses its compare-and-swap leaves this pass
/// with one candidate too poor and one label too many, which costs at most
/// one VM one tick: the next pass derives both from the store again.
pub fn spend(candidates: &mut [Candidate], name: &str, vm: &Vm) {
    if let Some(c) = candidates.iter_mut().find(|c| c.name == name) {
        c.free = c.free.minus(Capacity::wanted_by(vm));
        c.hosted.push(vm.metadata.labels.clone());
    }
}

pub struct FirstFit;

impl Scheduler for FirstFit {
    fn assign(&self, vm: &Vm, candidates: &[Candidate]) -> Option<String> {
        let placed = preferred(vm, feasible(vm, candidates))
            .first()
            .map(|c| c.name.clone());
        if placed.is_none() {
            let wanted = DevicePolicy::of(vm);
            if !wanted.is_empty() && candidates.iter().any(|c| c.connected && c.schedulable) {
                debug!(vm = %vm.metadata.name, requests = ?wanted.requests(),
                       "no candidate offers everything this vm asks for");
            }
        }
        placed
    }
}

/// The other strategy: of everything that fits, the one carrying the least.
///
/// The counterpart to First-Fit rather than a replacement for it. First-Fit
/// fills a machine before it touches the next, which is what one wants when
/// the machines cost money; this spreads, which is what one wants when the
/// VMs are meant to survive one of them going away. Anti-affinity states that
/// intent per VM and exactly; this is the blunt version for a whole cluster,
/// and the two compose — `feasible` has already cut what must not be, and
/// this only chooses among what may.
///
/// Ties break on the name, so two passes over the same inventory place the
/// same way and a test can say which.
pub struct Spread;

impl Scheduler for Spread {
    fn assign(&self, vm: &Vm, candidates: &[Candidate]) -> Option<String> {
        preferred(vm, feasible(vm, candidates))
            .into_iter()
            .min_by(|a, b| {
                a.hosted
                    .len()
                    .cmp(&b.hosted.len())
                    .then_with(|| a.name.cmp(&b.name))
            })
            .map(|c| c.name.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resources::{VmSpec, new_vm};

    /// Room enough that these tests are about what they say they are about.
    /// Admission has tests of its own; everywhere else a candidate is assumed
    /// to have space, exactly as every one of these tests did before it
    /// existed.
    const ROOMY: Capacity = Capacity {
        vcpus: 64,
        mem_mib: 65536,
    };

    /// What every compute node claims, and what every VM now requires. In
    /// the helpers rather than in each test, because a candidate WITHOUT it
    /// is a storage-only node — a real and different thing, and the tests
    /// that mean one say so.
    const RUNS_VMS: &str = "hypervisor/cloud-hypervisor";

    fn candidate(name: &str, connected: bool, schedulable: bool) -> Candidate {
        Candidate {
            accepts: Vec::new(),
            machine: None,
            kind: CandidateKind::Node,
            labels: Default::default(),
            hosted: Vec::new(),
            free: ROOMY,
            unhealthy: Vec::new(),
            name: name.into(),
            connected,
            alive: connected,
            schedulable,
            catalogue: vec![RUNS_VMS.to_string()],
        }
    }

    fn gpu_candidate(name: &str, profiles: &[&str]) -> Candidate {
        Candidate {
            accepts: Vec::new(),
            machine: None,
            kind: CandidateKind::Node,
            labels: Default::default(),
            hosted: Vec::new(),
            free: ROOMY,
            unhealthy: Vec::new(),
            name: name.into(),
            connected: true,
            alive: true,
            schedulable: true,
            catalogue: std::iter::once(RUNS_VMS.to_string())
                .chain(profiles.iter().map(|p| p.to_string()))
                .collect(),
        }
    }

    fn vm() -> Vm {
        vm_asking(serde_json::json!({}))
    }

    /// A VM that asks for room and nothing else.
    fn sized(vcpus: u32, mem_mib: u64) -> Vm {
        vm_asking(serde_json::json!({"vcpus": vcpus, "memory_mib": mem_mib}))
    }
    fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }
    /// A usable, roomy candidate carrying `on` and already holding VMs
    /// labelled `holding`.
    fn labelled(name: &str, on: &[(&str, &str)], holding: &[&[(&str, &str)]]) -> Candidate {
        Candidate {
            machine: None,
            labels: labels(on),
            hosted: holding.iter().map(|h| labels(h)).collect(),
            ..candidate(name, true, true)
        }
    }
    fn selecting(pairs: &[(&str, &str)]) -> Vm {
        let mut v = vm();
        v.spec.node_selector = labels(pairs);
        v
    }
    fn avoiding(pairs: &[(&str, &str)], required: bool) -> Vm {
        let mut v = vm();
        v.spec.anti_affinity = vec![AntiAffinity {
            selector: labels(pairs),
            required,
        }];
        v
    }

    fn vm_asking(spec: serde_json::Value) -> Vm {
        new_vm(
            "t",
            VmSpec {
                class: Default::default(),
                cluster_selector: Default::default(),
                node_selector: Default::default(),
                anti_affinity: Vec::new(),
                node_name: None,
                cluster_name: None,
                run_strategy: Default::default(),
                evacuation: Default::default(),
                tenant: None,
                vm: spec,
            },
        )
    }

    /// The machine's half of the pairing, and the whole point of it: a node
    /// an operator reserved for routers stops being a candidate for the
    /// ordinary class, and the sentence names the node and what it takes —
    /// so somebody reading `vm get` is sent to the machine rather than to
    /// the shop for more memory.
    #[test]
    fn a_node_that_accepts_only_routers_takes_no_ordinary_vm() {
        let mut gateway = candidate("gw-1", true, true);
        gateway.accepts = vec![crate::resources::CLASS_ROUTER.to_string()];
        let plain = candidate("agent-1", true, true);

        assert_eq!(FirstFit.assign(&vm(), &[gateway.clone()]), None);
        assert_eq!(
            FirstFit.assign(&vm(), &[gateway.clone(), plain]).as_deref(),
            Some("agent-1")
        );

        // ... and a workload OF that class goes exactly there.
        let mut router_class = vm();
        router_class.spec.class = crate::resources::CLASS_ROUTER.to_string();
        assert_eq!(
            FirstFit
                .assign(&router_class, &[gateway.clone()])
                .as_deref(),
            Some("gw-1")
        );

        let (reason, sentence) = pending_reason_of(&vm(), &[gateway]);
        assert_eq!(reason, PendingReason::ClassRefused);
        assert!(sentence.contains("gw-1 (router)"), "{sentence}");
        assert!(sentence.contains("\"vm\""), "{sentence}");
    }

    /// A machine that was never told otherwise takes everything, which is
    /// every machine in every fleet that predates the field. Read the other
    /// way round this would empty a cluster on upgrade.
    #[test]
    fn a_node_that_accepts_nothing_in_particular_takes_everything() {
        let plain = candidate("agent-1", true, true);
        for class in ["", "router", "gpu"] {
            let mut asking = vm();
            asking.spec.class = class.to_string();
            assert_eq!(
                FirstFit
                    .assign(&asking, std::slice::from_ref(&plain))
                    .as_deref(),
                Some("agent-1"),
                "class {class:?}"
            );
        }
    }

    /// The other half of 6k's third decision: a NIC that names a provider
    /// network is a demand for a node that really holds an interface for
    /// THAT wire, and one physnet is not another. Without it a VM with a
    /// `physnet` NIC lands wherever there is room and the agent refuses it.
    #[test]
    fn a_nic_on_a_provider_network_asks_for_the_node_that_holds_that_wire() {
        let outside = vm_asking(serde_json::json!({
            "nics": [{ "physnet": "ext" }],
        }));
        let mut holds_ext = candidate("gw-1", true, true);
        holds_ext.catalogue.push("network/gateway:ext".into());
        let mut holds_dmz = candidate("gw-2", true, true);
        holds_dmz.catalogue.push("network/gateway:dmz".into());

        assert_eq!(
            FirstFit
                .assign(&outside, &[holds_dmz.clone(), holds_ext.clone()])
                .as_deref(),
            Some("gw-1"),
            "the wrong wire is not a fit"
        );
        assert_eq!(FirstFit.assign(&outside, &[holds_dmz]), None);
        // A plain NIC asks for none of this and still lands anywhere.
        assert!(
            FirstFit
                .assign(
                    &vm_asking(serde_json::json!({ "nics": [{}] })),
                    &[holds_ext]
                )
                .is_some()
        );
    }

    #[test]
    fn first_fit_skips_candidates_that_are_down_or_drained() {
        let candidates = [
            candidate("gone", false, true),
            candidate("draining", true, false),
            candidate("ok", true, true),
        ];
        assert_eq!(FirstFit.assign(&vm(), &candidates).as_deref(), Some("ok"));
    }

    #[test]
    fn no_usable_candidate_leaves_the_vm_pending() {
        assert_eq!(
            FirstFit.assign(&vm(), &[candidate("gone", false, true)]),
            None
        );
    }

    /// The same FirstFit decides both tiers; nothing in it knows whether the
    /// names it is choosing between are nodes or whole clusters.
    #[test]
    fn the_same_scheduler_places_on_clusters() {
        let clusters = [
            candidate("cluster-1", false, true),
            candidate("cluster-2", true, true),
        ];
        assert_eq!(
            FirstFit.assign(&vm(), &clusters).as_deref(),
            Some("cluster-2")
        );
    }

    fn nvrm_4q() -> serde_json::Value {
        serde_json::json!({"devices": [{"driver": "nvrm", "partition": "mediated", "profile": "4q"}]})
    }

    /// The testenv matrix's GPU pinning: a profiled device request must land
    /// on the one candidate whose catalogue carries it, however early a
    /// device-less candidate sits in the list.
    #[test]
    fn a_device_request_skips_candidates_that_do_not_offer_it() {
        let candidates = [
            gpu_candidate("agent-1a", &[]),
            gpu_candidate(
                "manacor",
                &["nvrm/2q", "nvrm/4q", "crosvm-gpu/venus", "vfio"],
            ),
        ];
        assert_eq!(
            FirstFit
                .assign(&vm_asking(nvrm_4q()), &candidates)
                .as_deref(),
            Some("manacor")
        );
        // and a VM without device requests still takes the first fit
        assert_eq!(
            FirstFit.assign(&vm(), &candidates).as_deref(),
            Some("agent-1a")
        );
    }

    /// The negative half of the matrix: a cluster with no GPU node leaves the
    /// VM Pending rather than binding it somewhere it cannot start.
    #[test]
    fn an_unserved_device_request_stays_pending() {
        let candidates = [
            gpu_candidate("agent-2a", &[]),
            gpu_candidate("agent-2b", &[]),
        ];
        assert_eq!(FirstFit.assign(&vm_asking(nvrm_4q()), &candidates), None);
    }

    /// vfio resolves no profiles, so its capacity entry is the bare driver
    /// name — and a bare request is content with any profile of its driver.
    /// The rule itself lives in `common::capability` and is tested there;
    /// what this holds is that FirstFit asks it the right question.
    #[test]
    fn bare_and_profiled_requests_match_the_catalogue_spellings() {
        let bare_vfio = serde_json::json!({"devices": [{"driver": "vfio"}]});
        let bare_nvrm = serde_json::json!({"devices": [{"driver": "nvrm"}]});
        let candidates = [gpu_candidate("manacor", &["nvrm/4q", "vfio"])];
        assert_eq!(
            FirstFit
                .assign(&vm_asking(bare_vfio), &candidates)
                .as_deref(),
            Some("manacor")
        );
        assert_eq!(
            FirstFit
                .assign(&vm_asking(bare_nvrm), &candidates)
                .as_deref(),
            Some("manacor")
        );
        // profiled request, wrong profile: no fit
        let nvrm_8q = serde_json::json!({"devices": [{"driver": "nvrm", "profile": "8q"}]});
        assert_eq!(FirstFit.assign(&vm_asking(nvrm_8q), &candidates), None);
    }

    fn volume_candidate(name: &str, backends: &[&str]) -> Candidate {
        Candidate {
            accepts: Vec::new(),
            machine: None,
            kind: CandidateKind::Node,
            labels: Default::default(),
            hosted: Vec::new(),
            free: ROOMY,
            unhealthy: Vec::new(),
            name: name.into(),
            connected: true,
            alive: true,
            schedulable: true,
            catalogue: std::iter::once(RUNS_VMS.to_string())
                .chain(
                    backends
                        .iter()
                        .map(|b| capability::entry(capability::VOLUME, Some(b))),
                )
                .collect(),
        }
    }

    fn vm_with_volumes(volumes: serde_json::Value) -> Vm {
        vm_asking(serde_json::json!({ "volumes": volumes }))
    }

    /// The half this pass added, as a table. A spec's `volumes[].driver` is a
    /// placement constraint exactly as `devices[].driver` is: an lvm-thin VM
    /// on a node without the backend would fail at the first `lvcreate`,
    /// after being bound and started.
    #[test]
    fn a_volume_driver_places_the_vm_the_same_way_a_device_driver_does() {
        let plain = volume_candidate("agent-1a", &["filesystem"]);
        let thin = volume_candidate("manacor", &["filesystem", "lvm-thin", "nfs"]);

        for (name, volumes, expected) in [
            // no driver named: the default, which every node has
            (
                "default",
                serde_json::json!([{"size_bytes": 1}]),
                Some("agent-1a"),
            ),
            // named explicitly: still the default, still everywhere
            (
                "default by name",
                serde_json::json!([{"size_bytes": 1, "driver": "filesystem"}]),
                Some("agent-1a"),
            ),
            // a real backend: only where it is configured
            (
                "lvm-thin",
                serde_json::json!([{"size_bytes": 1, "driver": "lvm-thin"}]),
                Some("manacor"),
            ),
            (
                "nfs",
                serde_json::json!([{"size_bytes": 1, "driver": "nfs"}]),
                Some("manacor"),
            ),
            // nobody serves it: Pending, rather than bound where it dies
            (
                "ceph",
                serde_json::json!([{"size_bytes": 1, "driver": "ceph"}]),
                None,
            ),
            // a boot disk anywhere plus a share only manacor can serve
            (
                "mixed",
                serde_json::json!([
                    {"size_bytes": 1},
                    {"size_bytes": 0, "driver": "nfs", "params": {"kind": "share"}},
                ]),
                Some("manacor"),
            ),
        ] {
            let candidates = [plain.clone(), thin.clone()];
            assert_eq!(
                FirstFit
                    .assign(&vm_with_volumes(volumes), &candidates)
                    .as_deref(),
                expected,
                "{name}"
            );
        }
    }

    /// The rollout case, and the reason the default driver produces no
    /// request: a node running an agent from before the volume catalogue
    /// claims no `volume/*` entries at all. A VM with a plain disk still
    /// belongs there — it always did.
    #[test]
    fn a_plain_disk_still_places_on_a_node_that_claims_no_storage_at_all() {
        let old = [gpu_candidate("agent-1a", &[])];
        let plain = serde_json::json!([{"size_bytes": 1}]);
        assert_eq!(
            FirstFit.assign(&vm_with_volumes(plain), &old).as_deref(),
            Some("agent-1a")
        );
        // but a backend it never claimed is still refused
        let thin = serde_json::json!([{"size_bytes": 1, "driver": "lvm-thin"}]);
        assert_eq!(FirstFit.assign(&vm_with_volumes(thin), &old), None);
    }

    fn overlay_candidate(name: &str, vxlan: bool) -> Candidate {
        let mut catalogue = vec![RUNS_VMS.to_string()];
        if vxlan {
            catalogue.push(capability::entry(
                capability::NETWORK,
                Some(capability::VXLAN),
            ));
        }
        Candidate {
            accepts: Vec::new(),
            machine: None,
            kind: CandidateKind::Node,
            labels: Default::default(),
            hosted: Vec::new(),
            free: ROOMY,
            unhealthy: Vec::new(),
            name: name.into(),
            connected: true,
            alive: true,
            schedulable: true,
            catalogue,
        }
    }

    fn vm_with_nics(nics: serde_json::Value) -> Vm {
        vm_asking(serde_json::json!({ "nics": nics }))
    }

    /// The third list, as a table. A tenant VM must never land on a node
    /// without an overlay: there the agent refuses it, and the only
    /// alternative to refusing would be the VM on the shared default bridge —
    /// which is the one outcome tenancy exists to prevent.
    #[test]
    fn a_vxlan_nic_places_the_vm_only_where_overlays_are_served() {
        let plain = overlay_candidate("agent-1a", false);
        let overlay = overlay_candidate("agent-1b", true);

        for (name, nics, expected) in [
            // no overlay named: any node, including one that serves none
            ("plain nic", serde_json::json!([{}]), Some("agent-1a")),
            ("no nics at all", serde_json::json!([]), Some("agent-1a")),
            // an explicit null is "none named", not "named nothing"
            (
                "null vxlan_id",
                serde_json::json!([{"vxlan_id": null}]),
                Some("agent-1a"),
            ),
            // a tenant nic: only where the section is configured
            (
                "tenant nic",
                serde_json::json!([{"vxlan_id": 10000}]),
                Some("agent-1b"),
            ),
            // one plain, one on the overlay: the node has to serve both
            (
                "mixed",
                serde_json::json!([{}, {"vxlan_id": 10000}]),
                Some("agent-1b"),
            ),
        ] {
            let candidates = [plain.clone(), overlay.clone()];
            assert_eq!(
                FirstFit.assign(&vm_with_nics(nics), &candidates).as_deref(),
                expected,
                "{name}"
            );
        }
    }

    /// The negative half: a cluster where nobody serves overlays leaves the
    /// tenant VM Pending rather than binding it where it cannot start.
    #[test]
    fn an_overlay_vm_with_nowhere_to_go_stays_pending() {
        let none = [overlay_candidate("a", false), overlay_candidate("b", false)];
        let tenant = serde_json::json!([{"vxlan_id": 10000}]);
        assert_eq!(FirstFit.assign(&vm_with_nics(tenant), &none), None);
        // while a plain VM is placed on exactly the same cluster
        assert_eq!(
            FirstFit
                .assign(&vm_with_nics(serde_json::json!([{}])), &none)
                .as_deref(),
            Some("a")
        );
    }

    /// Two NICs on the overlay ask for one thing, not two. Nothing depends on
    /// the count, and a duplicate would only make the "nobody serves this"
    /// debug line say it twice.
    #[test]
    fn several_overlay_nics_are_still_one_request() {
        let both = [overlay_candidate("agent-1b", true)];
        let two = serde_json::json!([{"vxlan_id": 10000}, {"vxlan_id": 10000}]);
        assert_eq!(
            FirstFit.assign(&vm_with_nics(two), &both).as_deref(),
            Some("agent-1b")
        );
    }

    /// Devices and volumes are one requirement list: a GPU VM on thin
    /// provisioning needs a node with both, and there is no splitting it.
    #[test]
    fn a_device_and_a_volume_request_must_meet_on_the_same_candidate() {
        let spec = serde_json::json!({
            "devices": [{"driver": "nvrm", "profile": "4q"}],
            "volumes": [{"size_bytes": 1, "driver": "lvm-thin"}],
        });
        let gpu_only = [gpu_candidate("gpu", &["nvrm/4q"])];
        let storage_only = [gpu_candidate("thin", &["volume/lvm-thin"])];
        let both = [gpu_candidate("manacor", &["nvrm/4q", "volume/lvm-thin"])];
        assert_eq!(FirstFit.assign(&vm_asking(spec.clone()), &gpu_only), None);
        assert_eq!(
            FirstFit.assign(&vm_asking(spec.clone()), &storage_only),
            None
        );
        assert_eq!(
            FirstFit.assign(&vm_asking(spec), &both).as_deref(),
            Some("manacor")
        );
    }

    /// All three kinds on one candidate: the overlay is not a special case,
    /// it is a third entry in the same list, matched by the same rule.
    #[test]
    fn a_device_a_volume_and_an_overlay_must_all_meet_on_one_candidate() {
        let spec = serde_json::json!({
            "devices": [{"driver": "nvrm", "profile": "4q"}],
            "volumes": [{"size_bytes": 1, "driver": "lvm-thin"}],
            "nics": [{"vxlan_id": 10000}],
        });
        let no_overlay = [gpu_candidate("half", &["nvrm/4q", "volume/lvm-thin"])];
        assert_eq!(FirstFit.assign(&vm_asking(spec.clone()), &no_overlay), None);
        let all = [gpu_candidate(
            "manacor",
            &["nvrm/4q", "volume/lvm-thin", "network/vxlan"],
        )];
        assert_eq!(
            FirstFit.assign(&vm_asking(spec), &all).as_deref(),
            Some("manacor")
        );
    }

    /// The seam itself: what a scheduler asks a spec for is a list of
    /// (driver, profile) pairs, and asking is all a second strategy has to do
    /// to place a VM the way this one would.
    #[test]
    fn a_spec_states_its_requirements_once_for_every_scheduler_to_read() {
        let spec = serde_json::json!({
            "devices": [{"driver": "nvrm", "profile": "4q"}],
            "volumes": [{"size_bytes": 1, "driver": "lvm-thin"}],
            "nics": [{"vxlan_id": 10000}],
        });
        let wanted = DevicePolicy::of(&vm_asking(spec));
        assert_eq!(
            wanted.requests(),
            [
                ("nvrm".to_string(), Some("4q".to_string())),
                ("volume".to_string(), Some("lvm-thin".to_string())),
                ("network".to_string(), Some("vxlan".to_string())),
                // Last and always: every VM needs a machine that runs VMs.
                ("hypervisor".to_string(), None),
            ]
        );
        assert!(wanted.met_by(&[
            "nvrm/4q".into(),
            "volume/lvm-thin".into(),
            "network/vxlan".into(),
            RUNS_VMS.into()
        ]));
        assert!(
            !wanted.met_by(&[
                "nvrm/4q".into(),
                "volume/lvm-thin".into(),
                "network/vxlan".into()
            ]),
            "everything it asked for, on a node that runs no vms"
        );
        assert!(!wanted.met_by(&["nvrm/4q".into()]));
        // A spec that constrains nothing still asks for the one thing every
        // VM asks for, so a candidate claiming nothing at all no longer
        // answers it. See the test below.
        assert!(!DevicePolicy::of(&vm()).is_empty());
        assert!(!DevicePolicy::of(&vm()).met_by(&[]));
        assert!(DevicePolicy::of(&vm()).met_by(&[RUNS_VMS.to_string()]));
    }

    /// The other half of the sentence, and this test is the one that changed
    /// when it shipped.
    ///
    /// A node has claimed `hypervisor/<name>` since the storage split, and
    /// requiring one was held back for exactly as long as any node ran an
    /// agent that predates the claim — such a node claims nothing, and a VM
    /// requiring `hypervisor/*` would go Pending there for ever. Claiming is
    /// additive and safe during a rollout; requiring is not. The last node on
    /// an older binary was replaced by the image round, so it ships here.
    #[test]
    fn every_vm_asks_for_a_hypervisor_and_does_not_care_which() {
        let plain = DevicePolicy::of(&vm());
        assert_eq!(
            plain.requests(),
            [("hypervisor".to_string(), None)],
            "a plain vm asks for a hypervisor and nothing else"
        );
        // Bare: any hypervisor answers it, because which one is the node's
        // business and matching the name would be sizing knowledge this tier
        // does not have.
        assert!(plain.met_by(&["hypervisor/cloud-hypervisor".to_string()]));
        assert!(plain.met_by(&["hypervisor/whatever-comes-next".to_string()]));
        // A storage-only node claims none and is no longer a candidate — the
        // whole point.
        assert!(!plain.met_by(&["volume/lvm-thin".to_string()]));
        assert!(!plain.met_by(&[]));
        // The loaded spec asks for its three AND for a hypervisor, and all
        // four have to meet on ONE node — a VM cannot be split across two.
        let loaded = DevicePolicy::of(&vm_asking(serde_json::json!({
            "devices": [{"driver": "nvrm", "profile": "4q"}],
            "volumes": [{"size_bytes": 1, "driver": "lvm-thin"}],
            "nics": [{"vxlan_id": 10000}],
        })));
        assert!(
            loaded
                .requests()
                .iter()
                .any(|(driver, profile)| driver == capability::HYPERVISOR && profile.is_none())
        );

        // And the other half of the point: a storage-only node is still a
        // candidate for a VOLUME. The requirement cuts VMs and nothing else,
        // which is what makes such a node worth having.
        let pool = storage_pool("lvm-thin", &[]);
        let storage_only = storage_candidate("shelf-1", &["lvm-thin"]);
        assert_eq!(
            feasible_for_storage(&StoragePolicy::of(&pool), &[storage_only]).len(),
            1,
            "a node that runs no vms may still hold disks"
        );
    }

    fn storage_candidate(name: &str, drivers: &[&str]) -> Candidate {
        Candidate {
            accepts: Vec::new(),
            machine: None,
            kind: CandidateKind::Node,
            labels: Default::default(),
            hosted: Vec::new(),
            free: ROOMY,
            unhealthy: Vec::new(),
            name: name.into(),
            connected: true,
            alive: true,
            schedulable: true,
            catalogue: drivers
                .iter()
                .map(|d| capability::entry(capability::VOLUME, Some(d)))
                .collect(),
        }
    }

    fn storage_pool(driver: &str, nodes: &[&str]) -> StoragePool {
        StoragePool::declare(
            "fast",
            crate::resources::StoragePoolSpec {
                driver: driver.into(),
                nodes: nodes.iter().map(|n| n.to_string()).collect(),
                ..Default::default()
            },
        )
    }

    /// The second application of `feasible`, and the point of building it as
    /// one: a node that is down or drained is no more a candidate to
    /// provision on than it is to run on, and that predicate is shared rather
    /// than restated. If "drained" ever means two different things depending
    /// on what is being placed, this test is what notices.
    #[test]
    fn a_volume_is_placed_by_the_same_rules_about_the_machine() {
        let policy = StoragePolicy::of(&storage_pool("lvm-thin", &[]));
        let mut fleet = vec![
            storage_candidate("a", &["lvm-thin"]),
            storage_candidate("b", &["lvm-thin"]),
        ];
        assert_eq!(feasible_for_storage(&policy, &fleet).len(), 2);

        fleet[0].connected = false;
        fleet[1].schedulable = false;
        assert!(
            feasible_for_storage(&policy, &fleet).is_empty(),
            "down and drained are not candidates for a volume either"
        );

        // ... and the VM half agrees about the very same fleet.
        assert!(feasible(&vm(), &fleet).is_empty());
    }

    /// Two conjuncts and neither stands in for the other. A node with the
    /// driver that the pool does not name cannot reach the volume group; a
    /// node the pool names without the driver cannot make the LV.
    #[test]
    fn a_candidate_needs_both_the_backend_and_the_wiring() {
        let policy = StoragePolicy::of(&storage_pool("lvm-thin", &["a"]));
        let fleet = vec![
            storage_candidate("a", &["lvm-thin"]),
            // has the driver, is not named by the pool
            storage_candidate("b", &["lvm-thin"]),
            // is named by the pool in another world, has no driver
            storage_candidate("c", &["filesystem"]),
        ];
        let fits = feasible_for_storage(&policy, &fleet);
        assert_eq!(fits.len(), 1);
        assert_eq!(fits[0].name, "a");
        assert_eq!(policy.wanted(), "volume/lvm-thin");
    }

    /// An empty node list is every node, which is the single-machine lab and
    /// the compatibility direction: a pool nobody restricted narrows nothing,
    /// and the policy degenerates to the catalogue check the VM half already
    /// does.
    #[test]
    fn a_pool_that_names_no_nodes_is_reachable_from_all_of_them() {
        let policy = StoragePolicy::of(&storage_pool("filesystem", &[]));
        let fleet = vec![
            storage_candidate("a", &["filesystem"]),
            storage_candidate("b", &["filesystem", "lvm-thin"]),
        ];
        assert_eq!(feasible_for_storage(&policy, &fleet).len(), 2);
    }

    /// Locality is SOFT and never anything else.
    ///
    /// Among the candidates that can serve, the ones already holding the data
    /// win. When none of them can serve — the node was drained, the pool
    /// re-cut, the replica moved — the set is left exactly as it was, because
    /// a hard rule would strand every VM that a previous placement had put
    /// next to its disk. That fallback is the whole difference between a
    /// preference and a requirement.
    #[test]
    fn locality_prefers_the_holder_and_never_strands_anything() {
        let fleet = vec![
            storage_candidate("a", &["lvm-thin"]),
            storage_candidate("b", &["lvm-thin"]),
            storage_candidate("c", &["lvm-thin"]),
        ];
        let all: Vec<&Candidate> = fleet.iter().collect();

        let local = prefer_local(all.clone(), &["b".to_string()]);
        assert_eq!(local.len(), 1);
        assert_eq!(local[0].name, "b");

        // Nobody holds it: every VM whose disks are declared in its own spec.
        assert_eq!(prefer_local(all.clone(), &[]).len(), 3);

        // The holder cannot serve any more — storage moved, or the node was
        // drained out from under it. Everything still fits.
        let holder_gone = prefer_local(all.clone(), &["elsewhere".to_string()]);
        assert_eq!(
            holder_gone.len(),
            3,
            "a soft rule that can empty the set is a hard rule nobody meant to write"
        );

        // Several holders, and the order of the feasible list survives.
        let two = prefer_local(all, &["c".to_string(), "a".to_string()]);
        assert_eq!(
            two.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
            vec!["a", "c"]
        );
    }

    /// Why a volume is stuck, in the order that sends an operator to the
    /// right machine: nobody is here, nobody is willing, nobody has the
    /// backend, and only then "the ones the pool names are not among them".
    #[test]
    fn an_unplaceable_volume_says_which_of_the_four_things_is_wrong() {
        let policy = StoragePolicy::of(&storage_pool("lvm-thin", &["a"]));

        let (why, msg) = storage_pending_reason(&policy, "fast", &[]);
        assert_eq!(why, PendingReason::NoCandidates);
        assert!(msg.contains("no candidates"), "{msg}");

        let mut down = vec![storage_candidate("a", &["lvm-thin"])];
        down[0].connected = false;
        let (why, msg) = storage_pending_reason(&policy, "fast", &down);
        assert_eq!(why, PendingReason::NoneUsable);
        assert!(msg.contains("1 known candidates"), "{msg}");

        // Up and willing, wrong backend everywhere.
        let no_driver = vec![storage_candidate("a", &["filesystem"])];
        let (why, msg) = storage_pending_reason(&policy, "fast", &no_driver);
        assert_eq!(why, PendingReason::Unserved);
        assert!(msg.contains("volume/lvm-thin"), "{msg}");
        assert!(msg.contains("storage pool fast"), "{msg}");

        // The backend is out there, just not on a machine the pool names.
        let elsewhere = vec![storage_candidate("b", &["lvm-thin"])];
        let (why, msg) = storage_pending_reason(&policy, "fast", &elsewhere);
        assert_eq!(why, PendingReason::Unserved);
        assert!(msg.contains("storage pool fast names [a]"), "{msg}");
    }

    /// No `Capacity` anywhere in the storage half, and that is a decision
    /// rather than an omission: how much room is left on a thin pool is the
    /// backend's own admission question, asked by the driver that owns the
    /// pool at the moment it provisions. A controller carrying a second
    /// answer would be carrying one that goes stale between passes.
    #[test]
    fn a_volume_asks_for_no_vcpus_and_no_memory() {
        let policy = StoragePolicy::of(&storage_pool("lvm-thin", &[]));
        let mut broke = storage_candidate("a", &["lvm-thin"]);
        broke.free = Capacity {
            vcpus: 0,
            mem_mib: 0,
        };
        assert_eq!(feasible_for_storage(&policy, &[broke.clone()]).len(), 1);
        // ... and the same candidate holds no VM at all.
        assert!(feasible(&sized(1, 1), &[broke]).is_empty());
    }

    /// The config seam: nothing configured is the FirstFit both controllers
    /// were wired to by hand, and a name nobody serves is an error at
    /// start-up rather than a silently different placement.
    #[test]
    fn the_scheduler_spelling_resolves() {
        #[derive(serde::Deserialize)]
        struct F {
            scheduler: Option<SchedulerConfig>,
        }
        let parse = |s: &str| toml::from_str::<F>(s).unwrap().scheduler;
        assert!(SchedulerConfig::into_scheduler(parse("")).is_ok());
        assert!(SchedulerConfig::into_scheduler(parse(r#"scheduler = "first-fit""#)).is_ok());
        assert!(SchedulerConfig::into_scheduler(parse(r#"scheduler = "bin-packing""#)).is_err());
    }

    /// The three shapes of "why is it Pending", as an operator reads them.
    /// Until this existed, the answer lived only in a debug line inside
    /// whichever replica happened to run the pass.
    #[test]
    fn a_pending_vm_can_say_which_of_the_three_reasons_it_is() {
        let nothing: [Candidate; 0] = [];
        assert!(pending_reason(&vm(), &nothing).contains("no candidates are known"));

        let asleep = [
            candidate("gone", false, true),
            candidate("draining", true, false),
        ];
        let msg = pending_reason(&vm(), &asleep);
        assert!(msg.contains("connected and schedulable"), "{msg}");
        assert!(msg.contains('2'), "it says how many it looked at: {msg}");

        // Asked for something nobody has: the message names exactly that.
        let plain = [gpu_candidate("agent-1a", &[])];
        let msg = pending_reason(&vm_asking(nvrm_4q()), &plain);
        assert!(msg.contains("nvrm/4q"), "{msg}");
    }

    // --- admission ----------------------------------------------------------

    fn room(name: &str, vcpus: u32, mem_mib: u64) -> Candidate {
        Candidate {
            machine: None,
            free: Capacity { vcpus, mem_mib },
            ..candidate(name, true, true)
        }
    }

    /// The measured lab behaviour this position exists to end: three nodes
    /// with the same catalogue took EVERY overlay VM onto whichever sorted
    /// first, because the scheduler never asked whether it could carry them.
    /// Now the first one fills up and the next VM goes to the second.
    #[test]
    fn a_full_candidate_is_passed_over_for_one_that_has_room() {
        let nodes = [room("agent-1a", 0, 0), room("agent-1b", 8, 8192)];
        assert_eq!(
            FirstFit.assign(&sized(2, 2048), &nodes).as_deref(),
            Some("agent-1b")
        );
        // and with nowhere to go it waits, with the reason on the object
        let full = [room("agent-1a", 0, 0)];
        assert_eq!(FirstFit.assign(&sized(2, 2048), &full), None);
        let (why, sentence) = pending_reason_of(&sized(2, 2048), &full);
        assert_eq!(why, PendingReason::NoCapacity);
        assert!(sentence.contains("2 vcpu and 2048 MiB"), "{sentence}");
        assert!(sentence.contains("roomiest"), "{sentence}");
    }

    /// Both dimensions, and neither is optional: a machine with cores and no
    /// memory is as full as one with memory and no cores.
    #[test]
    fn a_vm_has_to_fit_in_both_dimensions() {
        let want = Capacity {
            vcpus: 4,
            mem_mib: 4096,
        };
        assert!(want.fits_in(Capacity {
            vcpus: 4,
            mem_mib: 4096
        }));
        assert!(!want.fits_in(Capacity {
            vcpus: 3,
            mem_mib: 4096
        }));
        assert!(!want.fits_in(Capacity {
            vcpus: 4,
            mem_mib: 4095
        }));

        // What a spec asks for, and what a spec that says nothing asks for.
        assert_eq!(Capacity::wanted_by(&sized(2, 512)).vcpus, 2);
        assert_eq!(Capacity::wanted_by(&sized(2, 512)).mem_mib, 512);
        assert_eq!(Capacity::wanted_by(&vm()), Capacity::default());
    }

    /// The DoD case, and the one an API-edge check cannot answer: two VMs
    /// created in the same breath, each of which fits and which together do
    /// not.
    ///
    /// This is what makes the binding and not the edge the authority. The
    /// pass places them one after another and DEDUCTS as it goes, so the
    /// second one asks a candidate that has already been spent. Both being
    /// bound is not a race that is unlikely here — it is arithmetic that
    /// cannot happen.
    #[test]
    fn two_vms_that_together_do_not_fit_cannot_both_be_bound() {
        let mut nodes = vec![room("agent-1a", 4, 4096)];
        let first = sized(2, 3072);
        let second = sized(2, 3072);

        let placed_first = FirstFit.assign(&first, &nodes).expect("the first one fits");
        assert_eq!(placed_first, "agent-1a");
        // What the pass does the moment it decides, before it looks at the
        // next VM: see `spend` in both reconcilers.
        spend(&mut nodes, &placed_first, &first);

        assert_eq!(
            FirstFit.assign(&second, &nodes),
            None,
            "the room the first one took is gone"
        );
        assert_eq!(
            pending_reason_of(&second, &nodes).0,
            PendingReason::NoCapacity
        );
    }

    /// Memory is never overcommitted, and a config that says otherwise is an
    /// error at start-up rather than a fleet that finds out at three in the
    /// morning which VM the OOM killer picked.
    #[test]
    fn the_memory_factor_may_not_be_raised() {
        let parse = |s: &str| toml::from_str::<Overcommit>(s).expect("parses");
        assert_eq!(parse("").memory, 1.0);
        assert_eq!(parse("").vcpu, Overcommit::VCPU_DEFAULT);
        assert!(parse("").check().is_ok());

        let err = parse("memory = 1.5").check().unwrap_err();
        assert!(err.to_string().contains("OOM"), "{err}");
        assert!(parse("memory = 0.9").check().is_ok(), "lower is allowed");
        assert!(parse("memory = 0").check().is_err());
        assert!(parse("vcpu = 0").check().is_err());
        assert!(parse("vcpu = 16").check().is_ok());
    }

    /// What the factors do to a machine's allowance. vCPU is stretched, RAM
    /// is not, and the stretch truncates rather than rounds — half a vCPU of
    /// allowance is not a vCPU.
    #[test]
    fn the_allowance_stretches_vcpu_and_leaves_memory_alone() {
        let host = Capacity {
            vcpus: 8,
            mem_mib: 16384,
        };
        let default = Overcommit::default().allowance(host);
        assert_eq!(default.vcpus, 32);
        assert_eq!(default.mem_mib, 16384);

        let tight = Overcommit {
            vcpu: 1.0,
            memory: 1.0,
        }
        .allowance(host);
        assert_eq!(tight, host);

        let odd = Overcommit {
            vcpu: 1.5,
            memory: 1.0,
        }
        .allowance(Capacity {
            vcpus: 3,
            mem_mib: 1,
        });
        assert_eq!(odd.vcpus, 4, "4.5 truncates down");

        // And a node whose reported capacity shrank under what is on it has
        // nothing free rather than an overflow.
        assert_eq!(
            Capacity {
                vcpus: 2,
                mem_mib: 1024
            }
            .minus(Capacity {
                vcpus: 8,
                mem_mib: 8192
            }),
            Capacity::default()
        );
    }

    /// Draining, as the whole round trip: a cordoned candidate takes nothing
    /// new, the sentence and the category say why, and uncordoning makes it
    /// take the VM again. Nothing here is about the VMs already on it — the
    /// scheduler is only ever asked about UNBOUND ones, which is the whole of
    /// why draining cannot evict anything.
    #[test]
    fn a_drained_candidate_takes_nothing_new_until_it_is_undrained() {
        let drained = [candidate("manacor", true, false)];
        assert_eq!(FirstFit.assign(&vm(), &drained), None);
        let (why, sentence) = pending_reason_of(&vm(), &drained);
        assert_eq!(why, PendingReason::NoneUsable);
        assert!(sentence.contains("connected and schedulable"), "{sentence}");

        // The one field, flipped back.
        let mut back = drained;
        back[0].schedulable = true;
        assert_eq!(FirstFit.assign(&vm(), &back).as_deref(), Some("manacor"));

        // And with somewhere else to go, the drained one is simply passed
        // over rather than being the reason for anything.
        let mixed = [
            candidate("manacor", true, false),
            candidate("ibiza", true, true),
        ];
        assert_eq!(FirstFit.assign(&vm(), &mixed).as_deref(), Some("ibiza"));
    }

    /// A selector is an AND over pairs, and an empty one is not a constraint.
    /// The second half is the compatibility promise: every VM written before
    /// this feature existed carries no selector and must place exactly where
    /// it always did.
    #[test]
    fn a_selector_narrows_to_the_machines_that_carry_it_and_an_empty_one_narrows_nothing() {
        let inventory = [
            labelled("agent-1a", &[("zone", "a"), ("disk", "nvme")], &[]),
            labelled("agent-1b", &[("zone", "b"), ("disk", "nvme")], &[]),
        ];
        assert_eq!(
            FirstFit.assign(&selecting(&[("zone", "b")]), &inventory),
            Some("agent-1b".into())
        );
        // Both pairs must match, not either.
        assert_eq!(
            FirstFit.assign(&selecting(&[("zone", "b"), ("disk", "sata")]), &inventory),
            None
        );
        assert_eq!(
            FirstFit.assign(&vm(), &inventory),
            Some("agent-1a".into()),
            "no selector is no constraint"
        );
    }

    /// The two selectors are answered by different tiers, and that is the
    /// whole point of there being two: a node label is not something the
    /// cloud tier should have to know about.
    #[test]
    fn each_tier_answers_only_its_own_selector() {
        let node = labelled("agent-1a", &[("zone", "a")], &[]);
        let cluster = Candidate {
            kind: CandidateKind::Cluster,
            ..labelled("cluster-1", &[("region", "stuttgart")], &[])
        };

        let mut wants_node = vm();
        wants_node.spec.node_selector = labels(&[("zone", "a")]);
        assert_eq!(
            FirstFit.assign(&wants_node, std::slice::from_ref(&node)),
            Some("agent-1a".into())
        );
        assert_eq!(
            FirstFit.assign(&wants_node, std::slice::from_ref(&cluster)),
            Some("cluster-1".into()),
            "a node selector says nothing about a cluster"
        );

        let mut wants_region = vm();
        wants_region.spec.cluster_selector = labels(&[("region", "muenchen")]);
        assert_eq!(FirstFit.assign(&wants_region, &[cluster]), None);
        assert_eq!(
            FirstFit.assign(&wants_region, &[node]),
            Some("agent-1a".into()),
            "a cluster selector says nothing about a node"
        );
    }

    /// The case the feature exists for: two replicas of one service must not
    /// share a machine, so the second goes elsewhere even though the first
    /// machine still has room.
    #[test]
    fn a_required_term_moves_the_second_replica_off_the_machine_holding_the_first() {
        let inventory = [
            labelled("agent-1a", &[], &[&[("app", "web")]]),
            labelled("agent-1b", &[], &[]),
        ];
        assert_eq!(
            FirstFit.assign(&avoiding(&[("app", "web")], true), &inventory),
            Some("agent-1b".into())
        );
        // And when the only machine left is the one it must avoid, it waits
        // rather than sitting down beside it.
        let only = [labelled("agent-1a", &[], &[&[("app", "web")]])];
        assert_eq!(
            FirstFit.assign(&avoiding(&[("app", "web")], true), &only),
            None
        );
        // A term whose selector matches nothing there is not a constraint.
        assert_eq!(
            FirstFit.assign(&avoiding(&[("app", "db")], true), &only),
            Some("agent-1a".into())
        );
    }

    /// The difference between a preference and a requirement, in one test: it
    /// is honoured when it can be, and it is dropped rather than stranding
    /// the VM. A preference that can leave a VM Pending is a requirement
    /// whose author did not know they were writing one.
    #[test]
    fn a_preferred_term_gives_way_rather_than_leaving_the_vm_pending() {
        let roomier = [
            labelled("agent-1a", &[], &[&[("app", "web")]]),
            labelled("agent-1b", &[], &[]),
        ];
        assert_eq!(
            FirstFit.assign(&avoiding(&[("app", "web")], false), &roomier),
            Some("agent-1b".into()),
            "honoured when it can be"
        );
        let only = [labelled("agent-1a", &[], &[&[("app", "web")]])];
        assert_eq!(
            FirstFit.assign(&avoiding(&[("app", "web")], false), &only),
            Some("agent-1a".into()),
            "and dropped rather than refusing to place"
        );
    }

    /// First-Fit fills a machine before it touches the next; Spread does the
    /// opposite. Both are legitimate and the choice is the operator's, which
    /// is what the `scheduler = ...` line is for.
    #[test]
    fn spread_takes_the_least_loaded_and_first_fit_takes_the_first() {
        let inventory = [
            labelled("agent-1a", &[], &[&[("app", "web")], &[("app", "db")]]),
            labelled("agent-1b", &[], &[&[("app", "web")]]),
            labelled("agent-1c", &[], &[]),
        ];
        assert_eq!(FirstFit.assign(&vm(), &inventory), Some("agent-1a".into()));
        assert_eq!(Spread.assign(&vm(), &inventory), Some("agent-1c".into()));

        // Ties break on the name, so two passes over one inventory place the
        // same way and this test can say which.
        let tied = [
            labelled("agent-2b", &[], &[]),
            labelled("agent-2a", &[], &[]),
        ];
        assert_eq!(Spread.assign(&vm(), &tied), Some("agent-2a".into()));
    }

    /// The invariant `Candidate::free` states, extended to every rule that is
    /// not a matter of strategy: two strategies may disagree about WHERE and
    /// must never disagree about WHETHER.
    #[test]
    fn the_strategies_disagree_about_where_and_never_about_whether() {
        let cases: [(&str, Vm, Vec<Candidate>); 5] = [
            ("empty", vm(), vec![]),
            ("all down", vm(), vec![candidate("gone", false, true)]),
            (
                "selector unmatched",
                selecting(&[("zone", "a")]),
                vec![labelled("agent-1a", &[("zone", "b")], &[])],
            ),
            (
                "anti-affinity",
                avoiding(&[("app", "web")], true),
                vec![labelled("agent-1a", &[], &[&[("app", "web")]])],
            ),
            (
                "placeable",
                vm(),
                vec![
                    labelled("agent-1a", &[], &[]),
                    labelled("agent-1b", &[], &[]),
                ],
            ),
        ];
        for (what, vm, inventory) in cases {
            let a = FirstFit.assign(&vm, &inventory).is_some();
            let b = Spread.assign(&vm, &inventory).is_some();
            assert_eq!(a, b, "{what}: the strategies disagreed about whether");
            // And the third narrowing, the one that writes the sentence, has
            // to agree with both — three filter chains that can drift apart
            // are three chances to tell an operator something untrue.
            let feasible_here = !feasible(&vm, &inventory).is_empty();
            assert_eq!(a, feasible_here, "{what}: feasible disagreed with assign");
        }
    }

    /// A second strategy is a config line and not an edit in two `main`s —
    /// which was the claim `SchedulerConfig` was written to make, and this is
    /// the first time there is a second strategy to make it with.
    #[test]
    fn the_scheduler_is_chosen_by_name_and_an_unknown_name_is_refused() {
        let named = |s: &str| SchedulerConfig::into_scheduler(Some(SchedulerConfig(s.into())));
        let inventory = [
            labelled("agent-1a", &[], &[&[("app", "web")]]),
            labelled("agent-1b", &[], &[]),
        ];
        assert_eq!(
            named("first-fit").unwrap().assign(&vm(), &inventory),
            Some("agent-1a".into())
        );
        assert_eq!(
            named("spread").unwrap().assign(&vm(), &inventory),
            Some("agent-1b".into())
        );
        // Absent still means first-fit, so a config that never mentioned a
        // scheduler places exactly where it always did.
        assert_eq!(
            SchedulerConfig::into_scheduler(None)
                .unwrap()
                .assign(&vm(), &inventory),
            Some("agent-1a".into())
        );
        let e = match named("bin-packing") {
            Ok(_) => panic!("an unknown scheduler name must not resolve"),
            Err(e) => e.to_string(),
        };
        assert!(e.contains("first-fit") && e.contains("spread"), "{e}");
    }

    /// Every sentence an operator reads, checked for the artefact that has
    /// bitten this repository before: a string literal broken over two source
    /// lines whose continuation keeps the indentation. It compiles, it passes
    /// every test that greps for a word, and it puts a run of spaces in the
    /// middle of a sentence on somebody's terminal.
    #[test]
    fn no_sentence_carries_a_run_of_spaces_from_the_source_that_wrote_it() {
        let occupied = [labelled("agent-1a", &[], &[&[("app", "web")]])];
        let unlabelled = [labelled("agent-1a", &[("zone", "b")], &[])];
        let full = [Candidate {
            free: Capacity::default(),
            ..candidate("agent-1a", true, true)
        }];
        let sentences = [
            pending_reason(&vm(), &[]),
            pending_reason(&vm(), &[candidate("gone", false, true)]),
            pending_reason(&sized(2, 2048), &full),
            pending_reason(&selecting(&[("zone", "a")]), &unlabelled),
            pending_reason(&avoiding(&[("app", "web")], true), &occupied),
            pending_reason(&vm_asking(nvrm_4q()), &[gpu_candidate("agent-1a", &[])]),
        ];
        for s in sentences {
            assert!(!s.contains("  "), "run of spaces in: {s:?}");
            assert!(!s.contains('\n'), "newline in: {s:?}");
            assert!(s.is_ascii(), "non-ascii in: {s:?}");
        }
    }

    /// The bug the lab found, as a test: a burst of creates that ONE pass
    /// sees together used to stack onto one node while free nodes stood
    /// beside it. `spend` booked the room and not the occupancy, so
    /// `collides` asked an inventory from before the pass — and five VMs that
    /// were required to stay apart landed on one machine.
    ///
    /// Written against `spend` and not against a reconciler on purpose: this
    /// is the contract a pass relies on, and both tiers rely on it the same
    /// way.
    #[test]
    fn a_burst_of_creates_in_one_pass_does_not_stack_what_must_stay_apart() {
        let mut inv = vec![
            labelled("agent-1a", &[], &[]),
            labelled("agent-1b", &[], &[]),
            labelled("agent-1c", &[], &[]),
        ];
        let replica = |n: u32| {
            let mut v = avoiding(&[("app", "web")], true);
            v.metadata.name = format!("web-{n}");
            v.metadata.labels = labels(&[("app", "web")]);
            v
        };

        let mut placed = Vec::new();
        for n in 1..=3 {
            let vm = replica(n);
            let node = FirstFit
                .assign(&vm, &inv)
                .unwrap_or_else(|| panic!("web-{n} found no node"));
            spend(&mut inv, &node, &vm);
            placed.push(node);
        }
        placed.sort();
        placed.dedup();
        assert_eq!(placed.len(), 3, "three replicas, three nodes");

        // And the fourth waits rather than joining one of them.
        assert_eq!(FirstFit.assign(&replica(4), &inv), None);

        // The other half of what `spend` books is still booked: room.
        let sized_vm = sized(2, 1024);
        let mut room = vec![labelled("agent-1a", &[], &[])];
        let before = room[0].free;
        spend(&mut room, "agent-1a", &sized_vm);
        assert!(room[0].free.mem_mib < before.mem_mib, "room is spent too");
    }

    /// The category behind the sentence: a closed set, because the sentence
    /// itself counts candidates and names capabilities and is therefore
    /// exactly the kind of string that must never become a metric label.
    #[test]
    fn every_sentence_carries_the_category_it_belongs_to() {
        let nothing: [Candidate; 0] = [];
        assert_eq!(
            pending_reason_of(&vm(), &nothing).0,
            PendingReason::NoCandidates
        );
        let asleep = [
            candidate("gone", false, true),
            candidate("draining", true, false),
        ];
        assert_eq!(
            pending_reason_of(&vm(), &asleep).0,
            PendingReason::NoneUsable
        );
        let plain = [gpu_candidate("agent-1a", &[])];
        assert_eq!(
            pending_reason_of(&vm_asking(nvrm_4q()), &plain).0,
            PendingReason::Unserved
        );
        let full = [Candidate {
            free: Capacity::default(),
            ..candidate("agent-1a", true, true)
        }];
        assert_eq!(
            pending_reason_of(&sized(2, 2048), &full).0,
            PendingReason::NoCapacity
        );
        let union = [gpu_candidate("cluster-1", &["nvrm/4q", "network/vxlan"])];
        let split = serde_json::json!({
            "devices": [{"driver": "nvrm", "profile": "4q"}],
            "nics": [{"vxlan_id": 10000}],
        });
        assert_eq!(
            pending_reason_of(&vm_asking(split), &union).0,
            PendingReason::Split
        );
        // Room and catalogue are fine and the labels are not.
        let unlabelled = [labelled("agent-1a", &[("zone", "b")], &[])];
        let (why, sentence) = pending_reason_of(&selecting(&[("zone", "a")]), &unlabelled);
        assert_eq!(why, PendingReason::SelectorUnmatched);
        assert!(sentence.contains("zone=a"), "{sentence}");
        // Everything fits and the neighbour is the problem.
        let occupied = [labelled("agent-1a", &[], &[&[("app", "web")]])];
        assert_eq!(
            pending_reason_of(&avoiding(&[("app", "web")], true), &occupied).0,
            PendingReason::AntiAffinity
        );

        // The label spellings are what a dashboard is written against, so
        // they are asserted rather than left to the Debug impl. Distinct,
        // and every variant is in ALL.
        let words: Vec<&str> = PendingReason::ALL.iter().map(|r| r.as_str()).collect();
        assert_eq!(
            words,
            [
                "no-candidates",
                "none-usable",
                "node-unhealthy",
                "class-refused",
                "no-capacity",
                "selector-unmatched",
                "unserved-request",
                "split-request",
                "anti-affinity",
                "volume-not-ready",
                "no-node-for-volume",
                "secret-not-ready"
            ]
        );
        // and the sentence is still the sentence
        assert_eq!(
            pending_reason(&vm(), &nothing),
            pending_reason_of(&vm(), &nothing).1
        );
    }

    /// The trap the lab walked into, and the reason this function has a third
    /// case: a cloud sees a CLUSTER catalogue, which is the UNION of its
    /// nodes'. Every part of the ask is served somewhere in that cluster and
    /// no single machine serves all of it — so the VM binds and then sits
    /// Pending forever, one tier down, with nothing to read.
    #[test]
    fn a_request_served_only_in_pieces_says_so_instead_of_naming_a_gap() {
        let union = [gpu_candidate("cluster-1", &["nvrm/4q", "network/vxlan"])];
        let spec = serde_json::json!({
            "devices": [{"driver": "nvrm", "profile": "4q"}],
            "nics": [{"vxlan_id": 10000}],
        });
        // Nothing is unmet — the union offers both — so the assign still
        // fails only one tier down. The sentence has to say that.
        let asked = DevicePolicy::of(&vm_asking(spec.clone()));
        assert!(asked.unmet(&union).is_empty(), "the union does offer both");
        let msg = pending_reason(&vm_asking(spec), &union);
        assert!(msg.contains("no single candidate"), "{msg}");
        assert!(msg.contains("each part is served somewhere"), "{msg}");
        assert!(
            msg.contains("nvrm/4q") && msg.contains("network/vxlan"),
            "{msg}"
        );
    }

    /// Every request must be served by ONE candidate — a combo VM (nvrm +
    /// crosvm) cannot be split across nodes.
    #[test]
    fn all_requests_must_fit_on_the_same_candidate() {
        let combo = serde_json::json!({"devices": [
            {"driver": "nvrm", "profile": "4q"},
            {"driver": "crosvm-gpu", "profile": "venus"},
        ]});
        let only_nvrm = [gpu_candidate("half", &["nvrm/4q"])];
        assert_eq!(FirstFit.assign(&vm_asking(combo.clone()), &only_nvrm), None);
        let both = [gpu_candidate("manacor", &["nvrm/4q", "crosvm-gpu/venus"])];
        assert_eq!(
            FirstFit.assign(&vm_asking(combo), &both).as_deref(),
            Some("manacor")
        );
    }

    fn binding(
        volume: &str,
        node: Option<&str>,
        locality: Option<Locality>,
        pool: &[&str],
    ) -> VolumeBinding {
        VolumeBinding {
            volume: volume.into(),
            node: node.map(str::to_string),
            locality,
            // The claim half is exercised by `served_by` below; every test
            // that is about the NAME half wants no claim in the way.
            driver: None,
            pool_nodes: pool.iter().map(|n| n.to_string()).collect(),
        }
    }

    /// A networked binding: the bytes are nowhere in particular and the
    /// DRIVER is the constraint.
    fn served_by(volume: &str, driver: &str) -> VolumeBinding {
        VolumeBinding {
            volume: volume.into(),
            node: None,
            locality: Some(Locality::Networked),
            driver: Some(driver.into()),
            pool_nodes: Vec::new(),
        }
    }

    /// The `networked` axis, spent. Until this position nothing claimed it:
    /// `required` answered `None` and every node was a candidate, so a VM
    /// whose disk is on a fabric could be placed on a machine that cannot
    /// speak to it — which worked, because the attach refusal is structural
    /// and the VM moves, but it is placement by trial.
    #[test]
    fn a_networked_volume_is_reachable_by_whoever_carries_the_driver() {
        let initiator = volume_candidate("manacor", &["nvmeof-import"]);
        let plain = volume_candidate("agent-1", &["filesystem"]);
        let binding = [served_by("imp-1", "nvmeof-import")];

        assert_eq!(binding[0].claim(), Some("nvmeof-import".to_string()));
        let allowed = feasible_for_volumes(&binding, vec![&initiator, &plain]);
        assert_eq!(
            allowed.iter().map(|c| &c.name).collect::<Vec<_>>(),
            ["manacor"],
            "a node without the driver cannot reach the fabric"
        );

        // It pins nothing by NAME, which is the whole difference from
        // node-local: any machine with the driver will do, and that is what
        // makes such a volume survive a node going away.
        assert_eq!(binding[0].required(), None);

        // Every other locality answers no claim at all: they pin by name and
        // the name is the constraint.
        for locality in [Locality::NodeLocal, Locality::Shared] {
            let mut named = served_by("data-1", "lvm-thin");
            named.locality = Some(locality);
            assert_eq!(named.claim(), None, "{locality:?}");
        }
        // And a networked binding whose pool has gone missing insists on
        // nothing rather than on the empty string.
        let mut poolless = served_by("imp-1", "");
        assert_eq!(poolless.claim(), None);
        poolless.driver = None;
        assert_eq!(poolless.claim(), None);
    }

    /// The axis spent, in one test. A node-local volume pins the VM to
    /// exactly the machine that holds it; a shared one opens the pool; a pool
    /// nobody has reported on constrains nothing hard, which is what keeps a
    /// mixed-version cluster placing VMs at all.
    #[test]
    fn locality_decides_whether_a_volume_pins_a_vm_or_merely_prefers_a_node() {
        let local = binding("data-1", Some("manacor"), Some(Locality::NodeLocal), &[]);
        assert_eq!(local.required(), Some(vec!["manacor".to_string()]));

        let shared = binding(
            "data-2",
            Some("manacor"),
            Some(Locality::Shared),
            &["manacor", "soller"],
        );
        assert_eq!(
            shared.required(),
            Some(vec!["manacor".to_string(), "soller".to_string()]),
            "the pool is the rule, and the volume's own node means nothing"
        );

        // A shared pool that names no nodes is every node, so nothing is cut.
        assert_eq!(
            binding("data-3", Some("manacor"), Some(Locality::Shared), &[]).required(),
            None
        );
        // Nobody has said: fall back to the preference this scheduler has
        // always had.
        assert_eq!(
            binding("data-4", Some("manacor"), None, &[]).required(),
            None
        );
        // The arm position 18 will change, and it constrains nothing today.
        assert_eq!(
            binding("data-5", Some("manacor"), Some(Locality::Networked), &[]).required(),
            None
        );
    }

    /// A node-local volume leaves exactly one candidate, and it is the one
    /// that holds the data. This is the whole difference from the soft
    /// preference: the same rule as a preference would place the VM next to
    /// an empty directory and boot it.
    #[test]
    fn a_node_local_volume_leaves_exactly_the_node_that_holds_it() {
        let nodes = [gpu_candidate("manacor", &[]), gpu_candidate("soller", &[])];
        let bindings = [binding(
            "data-1",
            Some("soller"),
            Some(Locality::NodeLocal),
            &[],
        )];
        let left = feasible_for_volumes(&bindings, nodes.iter().collect());
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].name, "soller");
    }

    /// A shared volume opens the pool, and a node outside it is still not a
    /// candidate — an export is only the same bytes for the machines that
    /// mount it.
    #[test]
    fn a_shared_volume_opens_the_pool_and_nothing_beyond_it() {
        let nodes = [
            gpu_candidate("manacor", &[]),
            gpu_candidate("soller", &[]),
            gpu_candidate("inca", &[]),
        ];
        let bindings = [binding(
            "data-1",
            Some("manacor"),
            Some(Locality::Shared),
            &["manacor", "soller"],
        )];
        let mut left: Vec<String> = feasible_for_volumes(&bindings, nodes.iter().collect())
            .into_iter()
            .map(|c| c.name.clone())
            .collect();
        left.sort();
        assert_eq!(left, vec!["manacor".to_string(), "soller".into()]);
    }

    /// Two node-local volumes on two machines is a request no single node can
    /// serve, and it is a split in exactly the sense the existing reason
    /// means. The sentence for a single unreachable volume names the volume,
    /// its locality and the nodes that hold it.
    #[test]
    fn a_volume_that_cuts_everything_away_says_which_one_and_why() {
        let nodes = [gpu_candidate("manacor", &[]), gpu_candidate("soller", &[])];
        let refs: Vec<&Candidate> = nodes.iter().collect();

        // The node holding it is not a candidate at all.
        let away = [binding(
            "data-1",
            Some("inca"),
            Some(Locality::NodeLocal),
            &[],
        )];
        assert!(feasible_for_volumes(&away, refs.clone()).is_empty());
        let (why, sentence) = volume_pending_reason(&away, &refs);
        assert_eq!(why, PendingReason::NoNodeForVolume);
        assert!(sentence.contains("data-1"), "{sentence}");
        assert!(sentence.contains("node-local"), "{sentence}");
        assert!(sentence.contains("inca"), "{sentence}");

        // Two volumes, each reachable, never together.
        let split = [
            binding("data-1", Some("manacor"), Some(Locality::NodeLocal), &[]),
            binding("data-2", Some("soller"), Some(Locality::NodeLocal), &[]),
        ];
        assert!(feasible_for_volumes(&split, refs.clone()).is_empty());
        let (why, sentence) = volume_pending_reason(&split, &refs);
        assert_eq!(why, PendingReason::Split);
        assert!(sentence.contains("all 2"), "{sentence}");
    }

    /// D8, the controller half: a node that is up, uncordoned and has said
    /// something is wrong with itself is not a candidate.
    ///
    /// The mini-chaos run put a machine in exactly this state — redb wedged
    /// after one I/O error, `ready` true, session held, `check.sh` green —
    /// and a reschedule placed a VM onto it, which then failed on the node
    /// with the store's error. Everything the scheduler had to go on said the
    /// machine was fine, because everything it had to go on measured the
    /// heartbeat.
    #[test]
    fn a_node_that_says_it_is_wedged_is_not_a_candidate() {
        let wedged = Candidate {
            unhealthy: vec![
                crate::NodeConditionType::StoreUnhealthy
                    .as_str()
                    .to_string(),
            ],
            ..gpu_candidate("agent-1a", &[])
        };
        let fine = gpu_candidate("agent-1b", &[]);
        let vm = vm();

        assert!(
            feasible(&vm, std::slice::from_ref(&wedged)).is_empty(),
            "a wedged machine is not feasible"
        );
        // And the healthy one beside it still is, which is the whole point:
        // the fleet keeps working around the machine that cannot.
        assert_eq!(
            FirstFit
                .assign(&vm, &[wedged.clone(), fine.clone()])
                .as_deref(),
            Some("agent-1b")
        );
        assert_eq!(FirstFit.assign(&vm, std::slice::from_ref(&wedged)), None);
    }

    /// And the sentence, which is the half an operator acts on. It has to
    /// name the machine and the word, because the fix is on that machine.
    #[test]
    fn the_wedged_node_is_named_in_the_pending_reason() {
        let wedged = Candidate {
            unhealthy: vec![
                crate::NodeConditionType::StoreUnhealthy
                    .as_str()
                    .to_string(),
            ],
            ..gpu_candidate("agent-1a", &[])
        };
        let vm = vm();

        let (why, sentence) = pending_reason_of(&vm, std::slice::from_ref(&wedged));
        assert_eq!(why, PendingReason::NodeUnhealthy);
        assert!(sentence.contains("agent-1a"), "{sentence}");
        assert!(sentence.contains("StoreUnhealthy"), "{sentence}");

        // NOT the drained sentence. That one sends an operator to look for a
        // cordon that is not there, which is the wrong machine and the wrong
        // command.
        assert!(
            !sentence.contains("connected and schedulable"),
            "{sentence}"
        );

        // A drained machine beside it is still reported as drained: the
        // wedged sentence is the more specific one and only claims the
        // machines it is about.
        let drained = Candidate {
            schedulable: false,
            ..gpu_candidate("agent-1b", &[])
        };
        let (why, sentence) = pending_reason_of(&vm, &[wedged, drained]);
        assert_eq!(why, PendingReason::NodeUnhealthy);
        assert!(sentence.contains("agent-1a"), "{sentence}");
        assert!(!sentence.contains("agent-1b"), "{sentence}");
    }

    /// The volume half of the same veto, and it is the half the run actually
    /// reached: the wedged node's disk was what the next provision was sent
    /// to.
    #[test]
    fn a_wedged_node_provisions_nothing_and_the_sentence_says_why() {
        let policy = StoragePolicy::of(&storage_pool("filesystem", &[]));
        let wedged = Candidate {
            unhealthy: vec![crate::NodeConditionType::DiskPressure.as_str().to_string()],
            ..storage_candidate("agent-1a", &["filesystem"])
        };
        assert!(
            feasible_for_storage(&policy, std::slice::from_ref(&wedged)).is_empty(),
            "no volume is provisioned on a machine that says its disk is full"
        );
        let (why, sentence) = storage_pending_reason(&policy, "mc-fs", &[wedged]);
        assert_eq!(why, PendingReason::NodeUnhealthy);
        assert!(sentence.contains("agent-1a"), "{sentence}");
        assert!(sentence.contains("DiskPressure"), "{sentence}");
    }

    /// A word this build has never heard of still takes the machine out of
    /// the running, and travels into the sentence as it came.
    ///
    /// The controller half branches on the LIST and never on the variant,
    /// exactly so that an agent newer than its controller is believed rather
    /// than ignored.
    #[test]
    fn an_unknown_condition_still_vetoes_the_node() {
        let odd = Candidate {
            unhealthy: vec!["FanFailure".to_string()],
            ..gpu_candidate("agent-1a", &[])
        };
        let vm = vm();
        assert!(feasible(&vm, std::slice::from_ref(&odd)).is_empty());
        let (why, sentence) = pending_reason_of(&vm, &[odd]);
        assert_eq!(why, PendingReason::NodeUnhealthy);
        assert!(sentence.contains("FanFailure"), "{sentence}");
    }

    /// And the direction that must NOT change: an empty list is what every
    /// agent from before this field reports, so it can only ever mean "said
    /// nothing". A veto, never a permission.
    #[test]
    fn a_node_that_says_nothing_is_placed_exactly_as_before() {
        let quiet = gpu_candidate("agent-1a", &[]);
        assert!(quiet.unhealthy.is_empty());
        let vm = vm();
        assert_eq!(
            FirstFit
                .assign(&vm, std::slice::from_ref(&quiet))
                .as_deref(),
            Some("agent-1a")
        );
    }

    /// The other half of the same question, and the one that was answered
    /// about the wrong machines: the narrowing leaves a node standing, the
    /// scheduler refuses it anyway, and the sentence has to be about THAT
    /// node.
    ///
    /// Straight out of the drain scenario. `agent-1` holds the disks and is
    /// drained; `agent-2` is fine and irrelevant, because the VM cannot go
    /// there. Before this, the fall-through counted both and reported a
    /// hypervisor split.
    #[test]
    fn a_drained_node_holding_the_disks_is_named_as_the_reason() {
        let drained = Candidate {
            schedulable: false,
            ..gpu_candidate("agent-1", &[])
        };
        let fine = gpu_candidate("agent-2", &[]);
        let bindings = [binding(
            "data-1",
            Some("agent-1"),
            Some(Locality::NodeLocal),
            &[],
        )];

        // What `place` computes: the volumes narrow the list to the machine
        // that holds them, and the machine that holds them is drained.
        let allowed = feasible_for_volumes(&bindings, vec![&drained, &fine]);
        assert_eq!(
            allowed.iter().map(|c| &c.name).collect::<Vec<_>>(),
            ["agent-1"]
        );

        let (why, sentence) =
            volume_nodes_unusable(&bindings, &allowed).expect("the volumes are the reason");
        assert_eq!(why, PendingReason::NoNodeForVolume);
        assert_eq!(
            sentence,
            "the node holding this vm's volumes (agent-1) is drained"
        );

        // Not connected outranks drained: un-draining a machine that is gone
        // fixes nothing.
        let gone = Candidate {
            connected: false,
            alive: false,
            ..drained.clone()
        };
        let (_, sentence) = volume_nodes_unusable(&bindings, &[&gone]).expect("still the reason");
        assert!(sentence.ends_with("is not connected"), "{sentence}");

        // Two machines, two states, and each one is named.
        let both = [binding(
            "data-1",
            Some("agent-1"),
            Some(Locality::Shared),
            &["agent-1", "agent-3"],
        )];
        let third = Candidate {
            connected: false,
            alive: false,
            ..gpu_candidate("agent-3", &[])
        };
        let (_, sentence) =
            volume_nodes_unusable(&both, &[&drained, &third]).expect("still the reason");
        assert_eq!(
            sentence,
            "no node holding this vm's volumes can take it: agent-1 is drained, \
             agent-3 is not connected"
        );
    }

    /// And the three ways this sentence is NOT the true one. Each would be a
    /// sharper answer replaced by a vaguer one, which is the same defect in
    /// the other direction.
    #[test]
    fn the_volumes_are_not_blamed_when_they_are_not_the_reason() {
        let drained = Candidate {
            schedulable: false,
            ..gpu_candidate("agent-1", &[])
        };
        let fine = gpu_candidate("agent-2", &[]);

        // Nothing pinned: an unknown locality is a preference, and a VM that
        // could have gone anywhere was not defeated by its disk.
        let soft = [binding("data-1", Some("agent-1"), None, &[])];
        assert!(volume_nodes_unusable(&soft, &[&drained]).is_none());

        let hard = [binding(
            "data-1",
            Some("agent-1"),
            Some(Locality::NodeLocal),
            &[],
        )];
        // The narrowing emptied the list: that is `volume_pending_reason`'s
        // sentence, and it names the volume.
        assert!(volume_nodes_unusable(&hard, &[]).is_none());
        // A usable node survived, so something else — room, a label, a device
        // — is what defeated the placement.
        assert!(volume_nodes_unusable(&hard, &[&drained, &fine]).is_none());
    }

    /// The soft half keeps its fallback, which is the whole difference
    /// between a preference and a requirement.
    #[test]
    fn an_unknown_locality_prefers_the_volumes_node_and_gives_way() {
        let nodes = [gpu_candidate("manacor", &[]), gpu_candidate("soller", &[])];
        let bindings = [binding("data-1", Some("soller"), None, &[])];
        let preferred = preferred_for_volumes(&bindings, nodes.iter().collect());
        assert_eq!(preferred.len(), 1);
        assert_eq!(preferred[0].name, "soller");

        // ... and where the holder is not among them, everything stands.
        let elsewhere = [binding("data-1", Some("inca"), None, &[])];
        assert_eq!(
            preferred_for_volumes(&elsewhere, nodes.iter().collect()).len(),
            2,
            "a preference that can strand a vm is a requirement"
        );
    }

    /// A VM whose disks are all inline asks nothing of either half — which is
    /// every VM written before this milestone.
    #[test]
    fn a_vm_with_no_references_is_left_exactly_as_it_was() {
        let nodes = [gpu_candidate("manacor", &[]), gpu_candidate("soller", &[])];
        assert_eq!(feasible_for_volumes(&[], nodes.iter().collect()).len(), 2);
        assert_eq!(preferred_for_volumes(&[], nodes.iter().collect()).len(), 2);
    }

    fn summary(name: &str, ready: bool, schedulable: bool, labels: &[(&str, &str)]) -> NodeSummary {
        NodeSummary {
            name: name.into(),
            ready,
            schedulable,
            drain: false,
            labels: labels
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            vcpus: 8,
            mem_mib: 8192,
            capabilities: Vec::new(),
            accepts: Vec::new(),
            vms: 0,
            conditions: Vec::new(),
            draining: None,
        }
    }

    /// The same summary with one condition on it — a machine that is up,
    /// willing, and has just said it cannot act.
    fn wedged_summary(name: &str, labels: &[(&str, &str)]) -> NodeSummary {
        let mut n = summary(name, true, true, labels);
        n.conditions = vec![crate::NodeCondition {
            type_: crate::NodeConditionType::StoreUnhealthy.as_str().into(),
            message: "the store refuses writes".into(),
        }];
        n
    }

    /// The finding from the image report, closed: a `nodeSelector` now cuts
    /// CLUSTERS. Before this it was checked one tier down, after the binding,
    /// so a VM no node matched went Pending on a cluster it should never have
    /// been sent to.
    #[test]
    fn a_cluster_with_no_matching_node_cannot_serve_the_vm() {
        let want: BTreeMap<String, String> = [("disk".to_string(), "nvme".to_string())]
            .into_iter()
            .collect();
        let demand = NodeDemand {
            selector: &want,
            allowed: None,
        };
        assert!(demand.met_by_a_node(&[summary("a", true, true, &[("disk", "nvme")])]));
        assert!(!demand.met_by_a_node(&[summary("a", true, true, &[("disk", "sata")])]));
        assert!(!demand.met_by_a_node(&[]));

        // A node that is down or drained does not count, which is the whole
        // reason to ask before the binding rather than after it.
        assert!(!demand.met_by_a_node(&[summary("a", false, true, &[("disk", "nvme")])]));
        assert!(!demand.met_by_a_node(&[summary("a", true, false, &[("disk", "nvme")])]));
        // And neither does one that is up, uncordoned and has said it cannot
        // act. That is D8's half at THIS tier: a cloud that binds a VM to a
        // cluster whose only matching machine is wedged has sent it somewhere
        // it can only sit Pending.
        assert!(!demand.met_by_a_node(&[wedged_summary("a", &[("disk", "nvme")])]));
        // One healthy machine beside it is enough, as it always was.
        assert!(demand.met_by_a_node(&[
            wedged_summary("a", &[("disk", "nvme")]),
            summary("b", true, true, &[("disk", "nvme")]),
        ]));
    }

    /// And the volume half: a node-local disk pins the VM to one machine, so
    /// only the cluster holding that machine is a candidate at all.
    #[test]
    fn a_node_local_volume_cuts_every_cluster_but_the_one_holding_it() {
        let none = BTreeMap::new();
        let demand = NodeDemand {
            selector: &none,
            allowed: Some(vec!["manacor".to_string()]),
        };
        assert!(demand.met_by_a_node(&[
            summary("soller", true, true, &[]),
            summary("manacor", true, true, &[])
        ]));
        assert!(!demand.met_by_a_node(&[summary("soller", true, true, &[])]));
    }

    /// Both halves at once, which is the case that made them one question:
    /// the node that holds the disk also has to carry the labels.
    #[test]
    fn the_node_holding_the_disk_must_also_match_the_selector() {
        let want: BTreeMap<String, String> = [("zone".to_string(), "a".to_string())]
            .into_iter()
            .collect();
        let demand = NodeDemand {
            selector: &want,
            allowed: Some(vec!["manacor".to_string()]),
        };
        assert!(demand.met_by_a_node(&[summary("manacor", true, true, &[("zone", "a")])]));
        assert!(
            !demand.met_by_a_node(&[
                summary("manacor", true, true, &[("zone", "b")]),
                summary("soller", true, true, &[("zone", "a")])
            ]),
            "one node has the labels and the other has the disk: neither can run it"
        );
    }

    /// Narrowing: unknown constrains nothing, two sets intersect, and an
    /// empty intersection is the honest answer that no node serves both.
    #[test]
    fn two_volumes_narrow_to_the_nodes_that_serve_both() {
        let a = || Some(vec!["manacor".to_string(), "soller".into()]);
        assert_eq!(narrow_allowed(None, None), None);
        assert_eq!(narrow_allowed(None, a()), a());
        assert_eq!(narrow_allowed(a(), None), a());
        assert_eq!(
            narrow_allowed(a(), Some(vec!["soller".to_string(), "inca".into()])),
            Some(vec!["soller".to_string()])
        );
        assert_eq!(
            narrow_allowed(a(), Some(vec!["inca".to_string()])),
            Some(Vec::new()),
            "two node-local disks on two machines: no node serves both"
        );
    }

    /// A VM that refers to nothing and selects nothing demands nothing —
    /// every VM before this milestone, and the case that must not regress.
    #[test]
    fn a_vm_that_asks_for_nothing_is_served_by_any_node_that_is_up() {
        let none = BTreeMap::new();
        let demand = NodeDemand {
            selector: &none,
            allowed: None,
        };
        assert!(demand.met_by_a_node(&[summary("a", true, true, &[])]));
        assert!(
            !demand.met_by_a_node(&[]),
            "but a cluster with no nodes serves nothing"
        );
    }

    /// The whole of what position 6 buys, in one place: the same node, the
    /// two questions, two answers.
    ///
    /// A storage-only node has room, is connected and is schedulable. Before
    /// the requirement it was indistinguishable from a compute node, so the
    /// first ordinary VM landed there, the agent refused correctly, and the
    /// VM ended Failed on a machine that could never have run it. Now it is
    /// not a candidate for a VM — and still is one for a disk, which is the
    /// reason to have such a node at all.
    #[test]
    fn a_storage_only_node_serves_disks_and_no_longer_serves_vms() {
        let shelf = storage_candidate("shelf-1", &["lvm-thin"]);
        let compute = gpu_candidate("manacor", &[]);

        // The VM half: only the compute node.
        let placed = FirstFit.assign(&vm(), &[shelf.clone(), compute.clone()]);
        assert_eq!(placed.as_deref(), Some("manacor"));
        assert_eq!(
            FirstFit.assign(&vm(), std::slice::from_ref(&shelf)),
            None,
            "a node that runs no vms is not a candidate for one"
        );

        // And the sentence an operator reads says what is missing rather
        // than something about room.
        let (why, sentence) = pending_reason_of(&vm(), std::slice::from_ref(&shelf));
        assert_eq!(why, PendingReason::Unserved);
        assert!(sentence.contains("hypervisor"), "{sentence}");

        // The volume half: the shelf serves the pool it was built for, and
        // the requirement did not touch that question.
        let pool = storage_pool("lvm-thin", &[]);
        let policy = StoragePolicy::of(&pool);
        let both = [shelf, compute];
        let served: Vec<&str> = feasible_for_storage(&policy, &both)
            .into_iter()
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(served, vec!["shelf-1"], "a disk may still go there");
    }
}
