// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Shared placement interface for choosing nodes or clusters.
//!
//! FirstFit filters candidates by selectors, capabilities, capacity and storage
//! constraints. Both tiers provide the same candidate shape and own the commit
//! of the selected binding.

use common::capability::{self, Locality, offers};
use tracing::debug;

use std::collections::BTreeMap;

use crate::resources::{AntiAffinity, CapacityReservation, NodeSummary, StoragePool, Vm};

/// CPU and memory supply or demand. Storage capacity is excluded because
/// drivers and pools own backend-specific space admission.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "camelCase")]
pub struct Capacity {
    pub vcpus: u32,
    pub mem_mib: u64,
}

impl Capacity {
    /// Read CPU and memory demand from the agent spec.
    /// Missing or unreadable numbers count as zero; callers rely on prior validation.
    pub fn wanted_by(vm: &Vm) -> Self {
        Self::wanted_by_spec(&vm.spec.vm)
    }

    /// Read demand before object creation, using the same sizing rules as placement
    /// and quota checks on stored VMs.
    pub fn wanted_by_spec(spec: &serde_json::Value) -> Self {
        let number = |field: &str| spec.get(field).and_then(serde_json::Value::as_u64);
        Self {
            vcpus: number("vcpus").unwrap_or(0).min(u32::MAX as u64) as u32,
            mem_mib: number("memory_mib").unwrap_or(0),
        }
    }

    /// Subtract saturating at zero when usage exceeds newly reported capacity.
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

/// Capacity multipliers for admission. CPU overcommit permits contention;
/// memory overcommit is disallowed to avoid admitting deliberate memory excess.
#[derive(Clone, Copy, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Overcommit {
    /// CPU admission multiplier, defaulting to four.
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

    /// Reject nonfinite or nonpositive factors and memory overcommit instead of
    /// silently clamping an unsupported configuration.
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

/// Candidate tier selecting which VM selector applies: node or cluster.
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
    /// Unexpired peer session held by this replica, permitting direct dispatch.
    /// Use alive for fleet-wide readiness independent of local ownership.
    pub connected: bool,
    /// Fleet-wide readiness from stored node status, independent of which replica
    /// holds its session. Router planning uses this view; Dispatch forwards commands
    /// to the session holder. At the cloud tier this equals `connected`.
    pub alive: bool,
    /// `spec.schedulable` — an operator draining it without stopping it.
    pub schedulable: bool,
    /// The node's vetoing conditions (see `NodeCondition::vetoes_placement`).
    /// Empty means none was reported, including by legacy agents; it is not
    /// independent proof of health.
    pub unhealthy: Vec<String>,
    /// Per-pass capacity after bound VMs and incoming migration reservations.
    /// All strategies consume this same budget; it is derived, not persisted.
    pub free: Capacity,
    /// Offered capabilities encoded through `common::capability` to match VM
    /// requests consistently. Empty means no advertised capabilities.
    pub catalogue: Vec<String>,
    /// Which tier's inventory this came from, and therefore which of the VM's
    /// two selectors applies.
    pub kind: CandidateKind,
    /// `spec.labels` off the Node or Cluster object — what an operator wrote
    /// on this machine, and the half of a selector that lives on the
    /// inventory.
    pub labels: BTreeMap<String, String>,
    /// Node workload classes; empty accepts all classes. Cloud candidates
    /// currently have no node acceptance list on the wire, so the cluster
    /// performs the final class check.
    pub accepts: Vec<String>,
    /// The VMs bound here as anti-affinity sees them, derived with capacity
    /// usage from each pass's VM inventory.
    pub hosted: Vec<Hosted>,
    /// Machine profile for live-migration compatibility, not ordinary VM
    /// placement. None at the cloud tier or for older nodes means unavailable
    /// evidence, not compatibility.
    pub machine: Option<crate::MachineProfile>,
}

/// One VM a candidate already holds, as anti-affinity measures it: whose it
/// is and what it is labelled.
///
/// The tenant travels with the labels because a term only ever means the
/// owner's own VMs. Labels are the tenant's to choose, so measured across
/// tenants one tenant's labels would push another's VMs off a machine, and a
/// term's refusals would tell its owner what somebody else runs where.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Hosted {
    pub tenant: Option<String>,
    pub labels: BTreeMap<String, String>,
}

impl Hosted {
    pub fn of(vm: &Vm) -> Self {
        Self {
            tenant: vm.spec.tenant.clone(),
            labels: vm.metadata.labels.clone(),
        }
    }
}

/// The VMs bound to `on` by `bound`, every phase counted, exactly as
/// [`free_on`] counts them: what anti-affinity is measured against.
pub fn hosted_on(on: &str, vms: &[Vm], bound: fn(&Vm) -> Option<&str>) -> Vec<Hosted> {
    vms.iter()
        .filter(|v| bound(v) == Some(on))
        .map(Hosted::of)
        .collect()
}

/// Require every selector pair to match; an empty selector matches all labels.
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

/// Does this candidate already hold a VM of `vm`'s own tenant that `term`
/// says to stay away from? Another tenant's VMs are never meant; see
/// [`Hosted`].
fn collides(term: &AntiAffinity, vm: &Vm, candidate: &Candidate) -> bool {
    candidate
        .hosted
        .iter()
        .filter(|h| h.tenant == vm.spec.tenant)
        .any(|h| selects(&term.selector, &h.labels))
}

/// Apply hard VM constraints while preserving inventory order: health,
/// connectivity, schedulability, capacity, capabilities, selectors and
/// required anti-affinity. Strategies choose only within this set.
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
                .any(|t| collides(t, vm, c))
        })
        .collect()
}

/// Local-session usability shared by VM and storage placement: connected,
/// schedulable and without reported health vetoes.
pub fn is_usable(c: &Candidate) -> bool {
    c.connected && c.schedulable && c.unhealthy.is_empty()
}

/// Fleet-wide usability independent of which replica holds the session.
/// Router planners need this shared view to derive consistent placements.
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

/// Requirements for provisioning a volume: the requested backend capability
/// and the pool's allowed nodes. These are independent; having a driver does
/// not establish access to a particular pool. An empty node list allows all.
pub struct StoragePolicy {
    driver: String,
    nodes: Vec<String>,
}

impl StoragePolicy {
    /// Build placement demand from pool driver and node constraints.
    /// Volume size and access semantics are admitted separately.
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

/// Filter storage provisioning candidates by node usability and driver
/// capability. Storage operations consume no VM CPU/memory budget; backend
/// space admission remains the provider's responsibility. Preserve order.
pub fn feasible_for_storage<'a>(
    policy: &StoragePolicy,
    candidates: &'a [Candidate],
) -> Vec<&'a Candidate> {
    usable(candidates).filter(|c| policy.met_by(c)).collect()
}

/// Prefer existing data holders only when at least one remains feasible.
/// An empty holder set or no feasible holder leaves the full set available.
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

/// Explain failed storage placement with a bounded category for metrics and
/// a detailed message for the object.
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

/// Referenced-volume locality constraints on VM placement, resolved by the caller
/// so the scheduler needs no store access.
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
    /// Provider driver used to constrain networked-volume access. NodeLocal
    /// and Shared use location rules instead. None keeps the legacy behavior
    /// of requiring no explicit driver claim.
    pub driver: Option<String>,
}

impl VolumeBinding {
    /// Allowed nodes from volume locality, or None when no hard restriction applies.
    ///
    /// Node-local pins to the volume holder. Shared uses the pool's node list.
    /// Networked uses the backend capability. Unknown locality retains only a
    /// soft preference for the previous holder.
    pub fn required(&self) -> Option<Vec<String>> {
        match self.locality {
            Some(Locality::NodeLocal) => self.node.clone().map(|n| vec![n]),
            Some(Locality::Shared) => {
                (!self.pool_nodes.is_empty()).then(|| self.pool_nodes.clone())
            }
            Some(Locality::Networked) | None => None,
        }
    }

    /// Required driver capability for Networked storage. Current provider
    /// and attacher names are combined; NodeLocal and Shared use location
    /// constraints rather than this claim.
    pub fn claim(&self) -> Option<String> {
        matches!(self.locality, Some(Locality::Networked))
            .then(|| self.driver.clone())
            .flatten()
            .filter(|d| !d.is_empty())
    }

    /// Check whether a volume's hard locality excludes an already placed
    /// node. Unknown locality or an unplaced volume does not establish a pin.
    pub fn pins_elsewhere(&self, node: &str) -> bool {
        self.required()
            .is_some_and(|allowed| !allowed.iter().any(|n| n == node))
    }
}

/// Apply all hard volume bindings before soft preferences. No bindings
/// leaves the candidate set unchanged.
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

/// Apply soft locality preferences after capacity and hard constraints.
/// Only bindings without a hard location rule participate; fall back to
/// all feasible nodes when no preferred holder fits.
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

/// Explain volume constraints that eliminated otherwise feasible candidates.
/// Empty-fleet and ordinary capability failures are diagnosed separately.
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

/// Explain when volume locality left candidates but all were unusable.
/// Run after assignment fails so the message reflects actual eligibility.
/// Return None when locality did not cause the failure; ordinary capacity,
/// selector and capability diagnostics then apply.
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
    // Prioritize disconnection, then scheduling exclusion, then health conditions
    // so the message names the first obstacle to using the volume's node.
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

/// Node-level requirements checked before cloud cluster binding.
/// Aggregate cluster capacity/capability alone does not establish that
/// one node can satisfy the combined request or hold node-local data.
#[derive(Debug)]
pub struct NodeDemand<'a> {
    /// `spec.nodeSelector` — matched against each node's own labels, which
    /// the cluster reports and the cloud mirrors.
    pub selector: &'a BTreeMap<String, String>,
    /// Intersection of nodes permitted by all referenced volumes.
    /// None means unrestricted; an empty set means no common placement exists.
    pub allowed: Option<Vec<String>>,
    /// What the VM asks of ONE machine. A cluster's capacity is a sum, and
    /// a sum can hold a VM no node of it can (IKR-B78).
    pub size: Capacity,
    /// The workload class one node must accept, as `VmSpec::class` reads it.
    pub class: &'a str,
}

impl NodeDemand<'_> {
    /// Require ONE usable node satisfying the selector, the volume constraints,
    /// the class and the room before binding a VM to this cluster.
    pub fn met_by_a_node(&self, rooms: &[NodeRoom]) -> bool {
        self.node_for(rooms).is_some()
    }

    /// Take this VM's size off the node it is assumed to land on, so the next
    /// VM measured against `rooms` in the same pass sees it. False when no
    /// node takes it.
    pub fn debit(&self, rooms: &mut [NodeRoom]) -> bool {
        let Some(at) = self.node_for(rooms) else {
            return false;
        };
        rooms[at].room = rooms[at].room.minus(self.size);
        true
    }

    /// Take this VM's size off EVERY node that takes it: for a VM whose node
    /// is not known, so that none of the nodes it may be on counts its room
    /// as free. No node keeps more room than [`debit`](Self::debit) would
    /// have left it, whichever node the VM is really on.
    pub fn debit_each(&self, rooms: &mut [NodeRoom]) {
        for room in rooms
            .iter_mut()
            .filter(|r| r.takes(self.size) && self.wants(&r.node))
        {
            room.room = room.room.minus(self.size);
        }
    }

    /// Of the nodes that take this VM, the one with the most room.
    fn node_for(&self, rooms: &[NodeRoom]) -> Option<usize> {
        roomiest(rooms, self.size, |r| self.wants(&r.node))
    }

    /// Whether this VM may run on `node`, room aside: its selector, the
    /// locality of its volumes and its class.
    fn wants(&self, node: &NodeSummary) -> bool {
        selects(self.selector, &node.labels)
            && self
                .allowed
                .as_ref()
                .is_none_or(|allowed| allowed.iter().any(|a| a == &node.name))
            && crate::resources::accepts_class(&node.accepts, self.class)
    }
}

/// One reported node as the cloud measures it within a pass: what its
/// cluster said, and the room left on it once the VMs counted against it are
/// taken off. (IKR-B78)
#[derive(Clone, Debug)]
pub struct NodeRoom {
    pub node: NodeSummary,
    pub room: Capacity,
}

impl NodeRoom {
    /// What `node` has left, as its cluster reported the VMs bound to it.
    pub fn reported(node: &NodeSummary, overcommit: Overcommit) -> Self {
        let capacity = Capacity {
            vcpus: node.vcpus,
            mem_mib: node.mem_mib,
        };
        let bound = Capacity {
            vcpus: node.bound_vcpus,
            mem_mib: node.bound_mem_mib,
        };
        Self {
            node: node.clone(),
            room: overcommit.allowance(capacity).minus(bound),
        }
    }

    /// Usable, and with room for `size` left. The health veto applies before
    /// cloud placement, as it does to node scheduling.
    fn takes(&self, size: Capacity) -> bool {
        self.node.usable() && size.fits_in(self.room)
    }
}

/// The rooms of one cluster's nodes, less `unplaced`: what VMs ask for that
/// the cluster holds without a node yet, or that are bound to it and not
/// reported by it yet. Neither is in any node's bound sum, and both will
/// land on one. Each comes off the node with the most room it fits, which is
/// the assumption that never overstates what the next VM finds; the next
/// report says where they really went. One no node takes takes no room: it
/// waits down there.
pub fn node_rooms(
    nodes: &[NodeSummary],
    overcommit: Overcommit,
    unplaced: &[Capacity],
) -> Vec<NodeRoom> {
    let mut rooms: Vec<NodeRoom> = nodes
        .iter()
        .map(|n| NodeRoom::reported(n, overcommit))
        .collect();
    for size in unplaced {
        if let Some(at) = roomiest(&rooms, *size, |_| true) {
            rooms[at].room = rooms[at].room.minus(*size);
        }
    }
    rooms
}

/// Of the rooms that take `size` and that `wants` accepts, the one with the
/// most room — memory first, then vCPUs, then the name, so two passes over
/// one report assume the same.
fn roomiest(
    rooms: &[NodeRoom],
    size: Capacity,
    wants: impl Fn(&NodeRoom) -> bool,
) -> Option<usize> {
    rooms
        .iter()
        .enumerate()
        .filter(|(_, r)| r.takes(size) && wants(r))
        .max_by(|(_, a), (_, b)| {
            (a.room.mem_mib, a.room.vcpus)
                .cmp(&(b.room.mem_mib, b.room.vcpus))
                .then_with(|| b.node.name.cmp(&a.node.name))
        })
        .map(|(at, _)| at)
}

/// Intersect another volume's allowed nodes. None imposes no restriction;
/// an empty intersection means no node can serve all volumes.
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

/// Prefer candidates satisfying soft anti-affinity terms, but retain the feasible
/// set when none satisfy them. Preferences must not prevent placement.
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
        .filter(|c| !soft.iter().any(|t| collides(t, vm, c)))
        .collect();
    if clean.is_empty() { feasible } else { clean }
}

pub trait Scheduler: Send + Sync {
    /// Pick a placement for an unbound VM; None = leave it Pending.
    fn assign(&self, vm: &Vm, candidates: &[Candidate]) -> Option<String>;
}

/// Shared scheduler configuration, such as `scheduler = "first-fit"`, resolved
/// by both controller tiers.
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

/// Extract capability requests from VM fields: hypervisor, devices, nondefault
/// volume backends, overlays and provider networks. Shape validation is done at
/// the API edge. The default volume backend adds no requirement; every VM still
/// requires a hypervisor capability.
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

    // Require the gateway capability for every distinct provider physnet named
    // by NICs; access to one provider wire does not imply access to another.
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

    // Require a hypervisor capability for every VM, keeping storage-only
    // nodes out of compute placement. Agents predating this claim cannot
    // satisfy the requirement; additive advertisement must precede rollout.
    requests.push((capability::HYPERVISOR.to_string(), None));

    requests
}

/// Capability requests derived once from the VM spec and reused by
/// scheduling strategies.
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

    /// Requests individually absent from all connected, schedulable candidates.
    /// An empty result does not prove all requests coexist on one candidate.
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

/// Bounded pending-reason categories for metrics. Detailed object
/// messages separately carry names, counts and requested capabilities.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingReason {
    /// Nothing has ever dialled in here.
    NoCandidates,
    /// Some are known; none is both connected and schedulable — everything is
    /// down, or everything is drained.
    NoneUsable,
    /// All otherwise usable candidates report health problems.
    NodeUnhealthy,
    /// Everything is up and willing and none of it has room. The fourth
    /// case, and without it a full cluster looks from the API exactly like a
    /// cluster where nothing is happening.
    NoCapacity,
    /// Eligible machines reject this workload class. Checked before capacity
    /// to distinguish node acceptance policy from insufficient resources.
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
    /// No usable placement can reach a Ready volume under its locality constraints.
    NoNodeForVolume,
    /// A cloud-init secret cannot yet be resolved, such as an absent mirror,
    /// missing key or unavailable sealing key. Separate from storage readiness.
    SecretNotReady,
    /// The room left on the nodes of a cluster that could otherwise take the
    /// VM is not known: more VMs wait there for a node than its status lists.
    /// Only where a node of it reports room for the VM before those are
    /// counted: then nothing says the room is gone, so not `NoCapacity`, and
    /// none of the VM's asks is what is missing, so not a node-level ask. A VM
    /// no node's reported room holds is `NoCapacity` whatever the list left
    /// out (NL4-2).
    RoomUnknown,
}

impl PendingReason {
    /// All reasons in declaration order, used to publish zero-valued metric series
    /// for categories with no pending VMs.
    pub const ALL: [PendingReason; 13] = [
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
        PendingReason::RoomUnknown,
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
            PendingReason::RoomUnknown => "room-unknown",
        }
    }

    /// Map detailed pending categories to the VM phase reason: a scheduling
    /// blocker or a dependency still being prepared. Detailed metric labels
    /// and object messages retain the specific cause.
    pub fn category(self) -> crate::resources::VmReason {
        use crate::resources::VmReason;
        match self {
            PendingReason::VolumeNotReady | PendingReason::SecretNotReady => VmReason::NotReady,
            PendingReason::NoCandidates
            | PendingReason::NoneUsable
            | PendingReason::NodeUnhealthy
            | PendingReason::ClassRefused
            | PendingReason::NoCapacity
            | PendingReason::SelectorUnmatched
            | PendingReason::Unserved
            | PendingReason::Split
            | PendingReason::AntiAffinity
            | PendingReason::NoNodeForVolume
            | PendingReason::RoomUnknown => VmReason::Unplaced,
        }
    }
}

/// Per-pass counts by pending reason, published once with explicit zeros.
/// Atomics keep the shared reference Send across await points.
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

/// One ordered diagnostic constraint and its failure explanation.
/// Unusable candidates pass later demand cuts because the initial cut diagnoses
/// usability separately.
struct Cut {
    /// Which candidates get past this cut.
    keep: fn(&Vm, &Capacity, &DevicePolicy, &Candidate) -> bool,
    /// Explain an exhausted constraint using candidates from before the cut,
    /// such as available capacity or missing capabilities.
    verdict: fn(&Vm, &Capacity, &DevicePolicy, &[Candidate]) -> (PendingReason, String),
}

/// Ordered diagnostic cuts. The first exhausted constraint determines
/// the pending explanation; apply basic availability and capacity checks
/// before more specific selector, capability and anti-affinity diagnostics.
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
            // Prefer a specific health veto over a generic disconnected/unschedulable
            // message when a candidate is reachable but unhealthy.
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
            // Every request exists somewhere, but no candidate offers the complete set.
            // Report split capabilities separately from a missing capability.
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
                .any(|t| collides(t, vm, c))
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

/// Return a bounded category and readable placement explanation. Walk
/// the diagnostic cuts; Split means individual requirements are available
/// but no single candidate satisfies their combination.
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

/// Book a placement in this pass's candidate view: subtract capacity and add
/// the hosted labels used by anti-affinity. Later choices must see both changes.
/// If the binding loses CAS, this pass conservatively retains the booking; the
/// next pass rebuilds its view from the store.
pub fn spend(candidates: &mut [Candidate], name: &str, vm: &Vm) {
    if let Some(c) = candidates.iter_mut().find(|c| c.name == name) {
        c.free = c.free.minus(Capacity::wanted_by(vm));
        c.hosted.push(Hosted::of(vm));
    }
}

/// CPU and memory allowance after every bound VM (Pending included); no GPU accounting.
/// Reservations for not-yet-bound guests are subtracted by [`hold`] / [`reservation_holds`].
/// Shared so the candidate list and claim confirmation compute the same number.
pub fn free_on(
    node: &str,
    capacity: &crate::resources::NodeCapacity,
    vms: &[Vm],
    overcommit: Overcommit,
) -> Capacity {
    overcommit
        .allowance(Capacity {
            vcpus: capacity.vcpus,
            mem_mib: capacity.mem_mib,
        })
        .minus(bound_on(node, vms))
}

/// What each of `vms` held without a node asks for: the half of its demand no
/// node's bound sum carries yet. One entry per VM, because each lands on one
/// machine. A VM on its way out will land nowhere. (IKR-B78)
pub fn unplaced_demand<'a>(vms: impl IntoIterator<Item = &'a Vm>) -> Vec<Capacity> {
    vms.into_iter()
        .filter(|v| v.spec.node_name.is_none() && !v.is_deleting())
        .map(Capacity::wanted_by)
        .collect()
}

/// What the VMs bound to `node` ask for, Pending included. The used half of
/// [`free_on`], and what a cluster reports up per node so the cloud measures
/// one node's room the same way.
pub fn bound_on(node: &str, vms: &[Vm]) -> Capacity {
    vms.iter()
        .filter(|v| v.spec.node_name.as_deref() == Some(node))
        .fold(Capacity::default(), |sum, vm| {
            sum.plus(Capacity::wanted_by(vm))
        })
}

/// Sum reservations independently of bound VM usage: migrating guests stay bound to their
/// source until settlement and placements are claimed before binding, yet destination
/// capacity must already count.
pub fn reserved_on(node: &str, held: &[CapacityReservation]) -> Capacity {
    held.iter()
        .filter(|r| r.spec.node == node)
        .fold(Capacity::default(), |sum, r| sum.plus(r.spec.size()))
}

/// Subtract outstanding reservations from candidate capacity, saturating at
/// zero. Apply once when building the candidate view, so ordinary placement
/// and migration account for the same promised room. Saturation makes a
/// double subtraction impossible to undo by simply adding capacity back.
pub fn hold(candidates: &mut [Candidate], held: &[CapacityReservation]) {
    for candidate in candidates.iter_mut() {
        candidate.free = candidate.free.minus(reserved_on(&candidate.name, held));
    }
}

/// Check a created reservation against room before reservations. Count earlier
/// reservations by etcd revision; malformed versions sort last. This gives
/// replicas a consistent winner when separate create-only keys overbook a
/// node. The losing caller must release its own reservation.
pub fn reservation_holds(
    room: Capacity,
    mine: &CapacityReservation,
    held: &[CapacityReservation],
) -> bool {
    fn made_at(r: &CapacityReservation) -> (i64, &str) {
        (
            r.metadata.resource_version.parse().unwrap_or(i64::MAX),
            r.metadata.name.as_str(),
        )
    }
    let ahead = held
        .iter()
        .filter(|r| r.spec.node == mine.spec.node && r.metadata.name != mine.metadata.name)
        .filter(|r| made_at(r) < made_at(mine))
        .fold(Capacity::default(), |sum, r| sum.plus(r.spec.size()));
    mine.spec.size().fits_in(room.minus(ahead))
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

/// Choose the feasible candidate hosting the fewest VMs, breaking ties
/// by name. Hard constraints and anti-affinity filtering run first.
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

    /// Capacity fixture large enough to isolate tests of other placement constraints.
    const ROOMY: Capacity = Capacity {
        vcpus: 64,
        mem_mib: 65536,
    };

    /// Hypervisor capability included by compute-node fixtures.
    /// Tests of storage-only nodes explicitly omit it.
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
            hosted: holding
                .iter()
                .map(|h| Hosted {
                    tenant: None,
                    labels: labels(h),
                })
                .collect(),
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

    /// A node restricted to router workloads excludes ordinary VM classes.
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

    /// A provider NIC requires the gateway capability for its exact physnet.
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

    /// Scheduler capability matching supports bare and profiled driver requests.
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

    /// Nondefault volume drivers constrain placement through the capability catalogue.
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

    /// The default volume backend adds no catalogue requirement, preserving placement
    /// on older agents that do not advertise storage capabilities.
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

    /// VXLAN NICs require overlay capability rather than falling back to a shared
    /// default bridge.
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

    /// Every VM requires an advertised hypervisor capability; storage-only
    /// nodes remain eligible for storage provisioning.
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

    /// Storage placement shares node usability checks with VM placement.
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

    /// An unrestricted pool node list imposes no placement narrowing.
    #[test]
    fn a_pool_that_names_no_nodes_is_reachable_from_all_of_them() {
        let policy = StoragePolicy::of(&storage_pool("filesystem", &[]));
        let fleet = vec![
            storage_candidate("a", &["filesystem"]),
            storage_candidate("b", &["filesystem", "lvm-thin"]),
        ];
        assert_eq!(feasible_for_storage(&policy, &fleet).len(), 2);
    }

    /// Holder preference falls back when no preferred candidate is feasible.
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

    /// Volume placement does not consume CPU or memory. Drivers admit backend
    /// space at provisioning time.
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

    /// Skip full candidates in favor of nodes with enough remaining capacity.
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

    /// In-pass capacity booking prevents two individually fitting VMs from
    /// spending the same remaining capacity.
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

    /// Cordon excludes new placement until reenabled; scheduling eligibility alone
    /// does not evict bound VMs.
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

    /// Selectors AND their pairs; an empty selector adds no constraint.
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

    /// A candidate holding one VM labelled `app=web` of `tenant`.
    fn holding_web_of(name: &str, tenant: Option<&str>) -> Candidate {
        Candidate {
            hosted: vec![Hosted {
                tenant: tenant.map(str::to_string),
                labels: labels(&[("app", "web")]),
            }],
            ..candidate(name, true, true)
        }
    }

    /// `avoiding`, asked by a VM of `tenant`.
    fn avoiding_as(tenant: &str, pairs: &[(&str, &str)], required: bool) -> Vm {
        let mut v = avoiding(pairs, required);
        v.spec.tenant = Some(tenant.into());
        v
    }

    /// A term means its owner's own VMs: another tenant's VM wearing the
    /// label does not push this one off the machine. (IKR-B71)
    #[test]
    fn a_term_does_not_see_another_tenants_vm() {
        let only = [holding_web_of("agent-1a", Some("umbrella"))];
        assert_eq!(
            FirstFit.assign(&avoiding_as("acme", &[("app", "web")], true), &only),
            Some("agent-1a".into())
        );
    }

    /// The same machine, holding the tenant's own `web`, is avoided.
    #[test]
    fn a_term_still_sees_its_own_tenants_vm() {
        let only = [holding_web_of("agent-1a", Some("acme"))];
        assert_eq!(
            FirstFit.assign(&avoiding_as("acme", &[("app", "web")], true), &only),
            None
        );
    }

    /// An unscoped VM's term means unscoped VMs only, and no tenant's VM.
    #[test]
    fn an_unscoped_term_does_not_see_a_tenants_vm() {
        let only = [holding_web_of("agent-1a", Some("acme"))];
        assert_eq!(
            FirstFit.assign(&avoiding(&[("app", "web")], true), &only),
            Some("agent-1a".into())
        );
    }

    /// What a pass spends carries the tenant, so the next VM of the same
    /// tenant in that pass sees it and one of another tenant does not.
    #[test]
    fn a_spent_placement_is_hosted_under_its_tenant() {
        let mut room = vec![candidate("agent-1a", true, true)];
        let mut first = avoiding_as("acme", &[("app", "web")], true);
        first.metadata.labels = labels(&[("app", "web")]);
        spend(&mut room, "agent-1a", &first);
        assert_eq!(FirstFit.assign(&first, &room), None);
        assert_eq!(
            FirstFit.assign(&avoiding_as("umbrella", &[("app", "web")], true), &room),
            Some("agent-1a".into())
        );
    }

    /// Soft anti-affinity yields when enforcing it would prevent placement.
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

    /// Diagnostic messages must not contain indentation accidentally retained by
    /// multiline string continuation.
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

    /// In-pass booking updates anti-affinity occupancy as well as capacity,
    /// so later placements see earlier decisions from the same pass.
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

    /// A reservation, as the arithmetic sees one: a node, a size and the
    /// revision etcd stamped on it.
    fn reservation(
        name: &str,
        node: &str,
        vcpus: u32,
        mem_mib: u64,
        at: i64,
    ) -> CapacityReservation {
        let mut r = CapacityReservation::declare(
            name,
            crate::resources::CapacityReservationSpec {
                node: node.to_string(),
                vm: format!("{name}-vm"),
                vm_uid: format!("vm-uid-{name}"),
                claimant: crate::resources::Claimant::Migration,
                migration: name.to_string(),
                migration_uid: format!("migration-uid-{name}"),
                vcpus,
                mem_mib,
            },
        );
        r.metadata.resource_version = at.to_string();
        r
    }

    /// Incoming migration reservations reduce the common feasible budget,
    /// even while the VM remains bound to its source.
    #[test]
    fn room_promised_to_a_guest_in_flight_is_not_room_a_scheduler_may_offer() {
        let guest = sized(4, 4096);
        let mut nodes = [room("agent-1a", 4, 4096)];
        assert_eq!(
            feasible(&guest, &nodes).len(),
            1,
            "the room is there to start with"
        );

        hold(&mut nodes, &[reservation("m-1", "agent-1a", 4, 4096, 10)]);
        assert!(
            feasible(&guest, &nodes).is_empty(),
            "and it is spoken for by a guest that has not landed yet"
        );
        // The sentence an operator reads is the ordinary one: there is no
        // room. Which is true — what is left is promised.
        assert_eq!(
            pending_reason_of(&guest, &nodes).0,
            PendingReason::NoCapacity
        );

        // Half of it, and half is left: the subtraction is a size and not a
        // veto.
        let mut half = [room("agent-1a", 4, 4096)];
        hold(&mut half, &[reservation("m-1", "agent-1a", 2, 2048, 10)]);
        assert_eq!(feasible(&sized(2, 2048), &half).len(), 1);
        assert!(feasible(&sized(3, 2048), &half).is_empty());

        // And a promise made on another machine takes nothing off this one.
        let mut elsewhere = [room("agent-1a", 4, 4096)];
        hold(
            &mut elsewhere,
            &[reservation("m-1", "agent-1b", 4, 4096, 10)],
        );
        assert_eq!(feasible(&guest, &elsewhere).len(), 1);
    }

    /// Distinct reservation keys can oversubscribe an aggregate budget.
    /// Post-write arbitration uses etcd revision order to select winners.
    #[test]
    fn of_two_reservations_against_one_slot_the_earlier_one_keeps_it() {
        let slot = Capacity {
            vcpus: 4,
            mem_mib: 4096,
        };
        let first = reservation("m-1", "agent-1a", 4, 4096, 10);
        let second = reservation("m-2", "agent-1a", 4, 4096, 11);
        let both = [first.clone(), second.clone()];
        assert!(reservation_holds(slot, &first, &both), "the earlier write");
        assert!(
            !reservation_holds(slot, &second, &both),
            "and the later one yields, on both replicas"
        );

        // A promise on another machine is not in this queue at all.
        let far = reservation("m-3", "agent-1b", 4, 4096, 9);
        assert!(reservation_holds(slot, &second, &[far, second.clone()]));

        // A revision nobody can read sorts last, so it is the one that gives
        // way — the conservative direction, and the only one that cannot turn
        // an unreadable field into an overcommitted machine.
        let mut unreadable = reservation("m-0", "agent-1a", 4, 4096, 1);
        unreadable.metadata.resource_version = String::new();
        assert!(reservation_holds(
            slot,
            &first,
            &[unreadable.clone(), first.clone()]
        ));
        assert!(!reservation_holds(
            slot,
            &unreadable,
            &[unreadable.clone(), first]
        ));
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
                "secret-not-ready",
                "room-unknown"
            ]
        );
        // and the sentence is still the sentence
        assert_eq!(
            pending_reason(&vm(), &nothing),
            pending_reason_of(&vm(), &nothing).1
        );
    }

    /// Distinguish split capabilities from an entirely missing request.
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

    /// Networked volumes require candidates advertising their volume driver.
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

    /// Locality distinguishes hard node-local binding, shared pool reachability
    /// and unrestricted unknown-locality fallback.
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

    /// Node-local storage is a hard holder constraint, not a locality preference.
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

    /// Explain incompatible volume locations and identify unreachable volumes.
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

    /// Reported health conditions veto a connected, uncordoned node.
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

    /// IKR-B43: a node whose device driver could not be built still takes
    /// vms that need no device. Only the missing capability keeps a vm away,
    /// through the catalogue the node no longer lists it in.
    #[test]
    fn a_node_with_an_unavailable_driver_still_takes_vms_without_devices() {
        let reported = [crate::NodeCondition {
            type_: crate::NodeConditionType::DriverUnavailable.as_str().into(),
            message: "device driver \"nvrm\" could not be built".into(),
        }];
        let degraded = Candidate {
            unhealthy: crate::NodeCondition::vetoing(&reported),
            ..gpu_candidate("agent-1a", &[])
        };
        let only = std::slice::from_ref(&degraded);
        assert_eq!(FirstFit.assign(&vm(), only).as_deref(), Some("agent-1a"));
        assert_eq!(FirstFit.assign(&vm_asking(nvrm_4q()), only), None);

        // The cloud's question about the cluster agrees.
        let mut node = summary("agent-1a", true, true, &[]);
        node.conditions = reported.to_vec();
        let anywhere = NodeDemand {
            selector: &BTreeMap::new(),
            allowed: None,
            size: Capacity::default(),
            class: crate::resources::CLASS_VM,
        };
        assert!(anywhere.met_by_a_node(&rooms(&[node])));
    }

    /// Unknown reported health conditions still veto placement and remain visible
    /// in the explanation, preserving conservative behavior across version skew.
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

    /// Pending diagnostics describe the candidates remaining after hard
    /// volume locality, excluding healthy nodes that cannot hold the VM.
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
            bound_vcpus: 0,
            bound_mem_mib: 0,
            capabilities: Vec::new(),
            accepts: Vec::new(),
            vms: 0,
            conditions: Vec::new(),
            draining: None,
        }
    }

    /// The nodes as their cluster reported them, nothing unplaced.
    fn rooms(nodes: &[NodeSummary]) -> Vec<NodeRoom> {
        node_rooms(nodes, Overcommit::default(), &[])
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

    /// Cloud placement requires a node satisfying the VM's node selector.
    #[test]
    fn a_cluster_with_no_matching_node_cannot_serve_the_vm() {
        let want: BTreeMap<String, String> = [("disk".to_string(), "nvme".to_string())]
            .into_iter()
            .collect();
        let demand = NodeDemand {
            selector: &want,
            allowed: None,
            size: Capacity::default(),
            class: crate::resources::CLASS_VM,
        };
        assert!(demand.met_by_a_node(&rooms(&[summary("a", true, true, &[("disk", "nvme")])])));
        assert!(!demand.met_by_a_node(&rooms(&[summary("a", true, true, &[("disk", "sata")])])));
        assert!(!demand.met_by_a_node(&rooms(&[])));

        // A node that is down or drained does not count, which is the whole
        // reason to ask before the binding rather than after it.
        assert!(!demand.met_by_a_node(&rooms(&[summary("a", false, true, &[("disk", "nvme")])])));
        assert!(!demand.met_by_a_node(&rooms(&[summary("a", true, false, &[("disk", "nvme")])])));
        // A reachable but unhealthy matching node cannot satisfy cloud placement.
        assert!(!demand.met_by_a_node(&rooms(&[wedged_summary("a", &[("disk", "nvme")])])));
        // One healthy machine beside it is enough, as it always was.
        assert!(demand.met_by_a_node(&rooms(&[
            wedged_summary("a", &[("disk", "nvme")]),
            summary("b", true, true, &[("disk", "nvme")]),
        ])));
    }

    /// And the volume half: a node-local disk pins the VM to one machine, so
    /// only the cluster holding that machine is a candidate at all.
    #[test]
    fn a_node_local_volume_cuts_every_cluster_but_the_one_holding_it() {
        let none = BTreeMap::new();
        let demand = NodeDemand {
            selector: &none,
            allowed: Some(vec!["manacor".to_string()]),
            size: Capacity::default(),
            class: crate::resources::CLASS_VM,
        };
        assert!(demand.met_by_a_node(&rooms(&[
            summary("soller", true, true, &[]),
            summary("manacor", true, true, &[])
        ])));
        assert!(!demand.met_by_a_node(&rooms(&[summary("soller", true, true, &[])])));
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
            size: Capacity::default(),
            class: crate::resources::CLASS_VM,
        };
        assert!(demand.met_by_a_node(&rooms(&[summary("manacor", true, true, &[("zone", "a")])])));
        assert!(
            !demand.met_by_a_node(&rooms(&[
                summary("manacor", true, true, &[("zone", "b")]),
                summary("soller", true, true, &[("zone", "a")])
            ])),
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
            size: Capacity::default(),
            class: crate::resources::CLASS_VM,
        };
        assert!(demand.met_by_a_node(&rooms(&[summary("a", true, true, &[])])));
        assert!(
            !demand.met_by_a_node(&rooms(&[])),
            "but a cluster with no nodes serves nothing"
        );
    }

    /// IKR-B78: a cluster of two 8 GiB nodes holds 16 GiB, and a 12 GiB VM fits
    /// that sum and neither node. One node has to have the room, after what is
    /// bound to it, and take the class.
    #[test]
    fn one_node_has_to_have_the_room_and_not_the_sum_of_them() {
        let none = BTreeMap::new();
        let asking = |mem_mib: u64, class: &'static str| NodeDemand {
            selector: &none,
            allowed: None,
            size: Capacity { vcpus: 1, mem_mib },
            class,
        };
        let two = [summary("a", true, true, &[]), summary("b", true, true, &[])];
        assert!(asking(4096, crate::resources::CLASS_VM).met_by_a_node(&rooms(&two)));
        assert!(!asking(12_288, crate::resources::CLASS_VM).met_by_a_node(&rooms(&two)));

        let mut busy = two.clone();
        for node in &mut busy {
            node.bound_mem_mib = 6144;
        }
        assert!(
            !asking(4096, crate::resources::CLASS_VM).met_by_a_node(&rooms(&busy)),
            "4 GiB free in all and 2 GiB on each"
        );

        let mut routers_only = two.clone();
        for node in &mut routers_only {
            node.accepts = vec!["router".to_string()];
        }
        assert!(!asking(1024, crate::resources::CLASS_VM).met_by_a_node(&rooms(&routers_only)));
    }

    /// IKR-B78 within one pass: two 4 GiB VMs bound in the same pass do not
    /// both fit a node with 6 GiB of room, so the second sees the first.
    #[test]
    fn a_vm_bound_in_the_same_pass_takes_its_room_off_a_node() {
        let none = BTreeMap::new();
        let four_gib = NodeDemand {
            selector: &none,
            allowed: None,
            size: Capacity {
                vcpus: 1,
                mem_mib: 4096,
            },
            class: crate::resources::CLASS_VM,
        };
        let mut one = summary("a", true, true, &[]);
        one.bound_mem_mib = 2048;
        let mut ledger = rooms(&[one]);
        assert!(four_gib.debit(&mut ledger));
        assert!(!four_gib.met_by_a_node(&ledger));
        assert!(!four_gib.debit(&mut ledger), "no node takes the second");
    }

    /// A VM whose node is not known takes its room off every node it may be
    /// on, and off none it may not: not one its selector misses, and not one
    /// it does not fit.
    #[test]
    fn a_vm_whose_node_is_not_known_takes_its_room_off_every_node_it_may_be_on() {
        let ssd: BTreeMap<String, String> = [("disk".to_string(), "ssd".to_string())]
            .into_iter()
            .collect();
        let four_gib = NodeDemand {
            selector: &ssd,
            allowed: None,
            size: Capacity {
                vcpus: 1,
                mem_mib: 4096,
            },
            class: crate::resources::CLASS_VM,
        };
        let mut full = summary("c", true, true, &[("disk", "ssd")]);
        full.bound_mem_mib = 6144;
        let mut ledger = rooms(&[
            summary("a", true, true, &[("disk", "ssd")]),
            summary("b", true, true, &[("disk", "sata")]),
            full,
        ]);

        four_gib.debit_each(&mut ledger);

        let left: Vec<u64> = ledger.iter().map(|r| r.room.mem_mib).collect();
        assert_eq!(left, [4096, 8192, 2048]);
    }

    /// What a cluster holds unplaced, and what is bound there unreported, comes
    /// off the node with the most room; one no node takes takes nothing.
    #[test]
    fn unplaced_demand_comes_off_the_roomiest_node_it_fits() {
        let mut small = summary("a", true, true, &[]);
        small.mem_mib = 4096;
        let big = summary("b", true, true, &[]);
        let unplaced = [
            Capacity {
                vcpus: 1,
                mem_mib: 2048,
            },
            Capacity {
                vcpus: 1,
                mem_mib: 65_536,
            },
        ];
        let ledger = node_rooms(&[small, big], Overcommit::default(), &unplaced);
        assert_eq!(
            ledger[0].room.mem_mib, 4096,
            "the smaller node keeps its room"
        );
        assert_eq!(
            ledger[1].room.mem_mib, 6144,
            "the 2 GiB came off the bigger one"
        );
    }

    /// An unplaced VM lands only on a node it can land on: not a drained one.
    #[test]
    fn unplaced_demand_does_not_come_off_a_node_that_takes_nothing() {
        let drained = summary("a", true, false, &[]);
        let ledger = node_rooms(
            &[drained],
            Overcommit::default(),
            &[Capacity {
                vcpus: 1,
                mem_mib: 1024,
            }],
        );
        assert_eq!(ledger[0].room.mem_mib, 8192);
    }

    /// What a cluster reports as unplaced: each VM without a node, one entry
    /// each, and not one on its way out.
    #[test]
    fn unplaced_demand_is_each_vm_without_a_node_that_stays() {
        let waiting = sized(2, 2048);
        let mut placed = sized(1, 1024);
        placed.spec.node_name = Some("agent-1a".into());
        let mut leaving = sized(4, 4096);
        leaving.metadata.deletion_timestamp = Some(chrono::Utc::now());
        assert_eq!(
            unplaced_demand(&[waiting, placed, leaving]),
            [Capacity {
                vcpus: 2,
                mem_mib: 2048
            }]
        );
    }

    /// A storage-only node can provision disks but cannot host VMs.
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
