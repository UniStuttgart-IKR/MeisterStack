// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The typed resources. The embedded VM definition stays the agent's
//! NewVmSpec JSON verbatim — one spec format everywhere, the agent is the
//! validating authority.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use macros::generated;
use serde::{Deserialize, Serialize};

use crate::object::{Metadata, Object, Resource};

pub const API_VERSION: &str = "meister.io/v1";

/// The resource table: every kind this control plane stores, with the
/// directory it lives in and the `kind` its envelope wears. One place, so that
/// adding a resource is adding a row rather than remembering to add a pair of
/// constants, a constructor and an entry in whatever else went by the name.
///
/// The store reads both off the type (`crate::object::Resource`), which is why
/// nothing outside this table ever spells a resource name again.
macro_rules! resources {
    ($( $(#[$about:meta])* $ty:ty => $resource:literal, $kind:literal; )*) => {
        $(
            $(#[$about])*
            #[generated(model = ClaudeOpus, version = "5")]
            impl Resource for $ty {
                const RESOURCE: &'static str = $resource;
                const KIND: &'static str = $kind;
            }
        )*

        /// The table itself, for the checks that have to walk every row of it.
        #[cfg(test)]
        const ALL_RESOURCES: &[(&str, &str)] = &[
            $( (<$ty as Resource>::RESOURCE, <$ty as Resource>::KIND) ),*
        ];
    };
}

resources! {
    Vm => "vms", "Vm";
    Node => "nodes", "Node";
    Cluster => "clusters", "Cluster";
    Image => "images", "Image";
    Tenant => "tenants", "Tenant";
    User => "users", "User";
    CertificateSigningRequest => "certificatesigningrequests", "CertificateSigningRequest";
    /// Server-owned counters — the one object kind here that is not something
    /// an operator creates, lists or names. See `vni`.
    Counter => "counters", "Counter";
    /// The address side of the network, MetalLB's shape: a pool is an OBJECT
    /// and not a config key, so an operator adds public addresses with the
    /// same verb they add anything else with, and a second cloud replica reads
    /// the same pools out of the same store.
    FloatingPool => "floatingpools", "FloatingPool";
    FloatingIp => "floatingips", "FloatingIp";
    /// A real subnet a tenant owns — the NAT-free half of the story. See
    /// `RoutedSubnetSpec`.
    RoutedSubnet => "routedsubnets", "RoutedSubnet";
    /// The only resource here that expires by itself. See `EventSpec`.
    Event => "events", "Event";
}

/// The cloud's ownership marker on a cluster-local object (the ownerRef
/// analogon of the design). Only the cloud session may change or delete an
/// object that carries it; a VM created straight at the cluster does not, and
/// local operation stays as free as it was.
pub const LABEL_MANAGED_BY: &str = "meister.io/managed-by";
pub const MANAGED_BY_CLOUD: &str = "cloud";
/// The uid of the cloud object this cluster-local object stands for. Names are
/// what people call VMs and people reuse names; this is which VM it is.
pub const LABEL_CLOUD_UID: &str = "meister.io/cloud-uid";

/// The agent's Desired vocabulary, 1:1. Absent happens through DELETE.
#[generated(model = ClaudeFable, version = "5")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum RunStrategy {
    #[default]
    Running,
    Stopped,
    Paused,
}

impl RunStrategy {
    /// Every variant, in declaration order. The tables that enumerate the
    /// controller's decisions walk this instead of each keeping a list of its
    /// own — one list, and `the_variant_lists_name_every_variant` is what
    /// makes adding a variant a compile error rather than a silent gap.
    pub const ALL: [RunStrategy; 3] = [
        RunStrategy::Running,
        RunStrategy::Stopped,
        RunStrategy::Paused,
    ];
}

#[generated(model = ClaudeFable, version = "5")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum VmPhase {
    #[default]
    Pending,
    Provisioning,
    Running,
    Stopped,
    Paused,
    Failed,
    Quarantined,
}

#[generated(model = ClaudeOpus, version = "5")]
impl VmPhase {
    /// Every variant, in declaration order — see `RunStrategy::ALL`.
    pub const ALL: [VmPhase; 7] = [
        VmPhase::Pending,
        VmPhase::Provisioning,
        VmPhase::Running,
        VmPhase::Stopped,
        VmPhase::Paused,
        VmPhase::Failed,
        VmPhase::Quarantined,
    ];

    /// The three phases that have come to rest. Everything else means a pass
    /// is in flight (Pending, Provisioning), the agent's own backoff is
    /// working (Failed), or the VM is deliberately nobody's to touch
    /// (Quarantined) — and nothing automatic argues with any of those.
    pub fn is_stable(self) -> bool {
        matches!(self, VmPhase::Running | VmPhase::Stopped | VmPhase::Paused)
    }

    /// The spelling that goes on the wire, in both directions and at both
    /// tiers. `parse` is its inverse and the tests hold them to it.
    pub fn as_str(self) -> &'static str {
        match self {
            VmPhase::Pending => "Pending",
            VmPhase::Provisioning => "Provisioning",
            VmPhase::Running => "Running",
            VmPhase::Stopped => "Stopped",
            VmPhase::Paused => "Paused",
            VmPhase::Failed => "Failed",
            VmPhase::Quarantined => "Quarantined",
        }
    }

    /// The spelling the agent puts on the wire (control.proto:
    /// VmStatusReport.phase). Unknown input is rejected rather than defaulted
    /// — a drifting agent should be visible, not silently "Pending".
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "Pending" => VmPhase::Pending,
            "Provisioning" => VmPhase::Provisioning,
            "Running" => VmPhase::Running,
            "Stopped" => VmPhase::Stopped,
            "Paused" => VmPhase::Paused,
            "Failed" => VmPhase::Failed,
            "Quarantined" => VmPhase::Quarantined,
            _ => return None,
        })
    }
}

#[generated(model = ClaudeFable, version = "5")]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VmSpec {
    /// Scheduling binding; empty until the scheduler assigns a node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
    /// The same binding one tier up: the cluster the cloud placed this VM on,
    /// empty until it did. One Vm type serves both tiers because the API form
    /// is deliberately the same on both — each tier writes its own binding and
    /// ignores the other's, and neither field is ever set at both ends at once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster_name: Option<String>,
    #[serde(default)]
    pub run_strategy: RunStrategy,
    /// Whose VM this is. Absent = unscoped, which is every VM written before
    /// this milestone and every VM an admin creates without naming one: it
    /// belongs to nobody, only an admin can see it, and it gets no overlay.
    ///
    /// The field lives on both tiers' Vm because the tier below has to know
    /// it too — not to authorize (there is one directory and it is the
    /// cloud's) but to say whose a VM is in `cluster vm ls`, and because the
    /// cluster is where the tenant's VNI is injected into the NIC specs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// The agent's NewVmSpec as raw JSON (same serde as the agent API).
    pub vm: serde_json::Value,
}

#[generated(model = ClaudeFable, version = "5")]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VmStatus {
    #[serde(default)]
    pub phase: VmPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
    /// Which cluster observed this phase — the cloud tier's counterpart to
    /// nodeName, and the only thing the cloud can honestly say about where a
    /// VM is: the node underneath it belongs to the cluster's own picture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<DateTime<Utc>>,
    /// Requeue bookkeeping (see `requeue`): how often the reconciler has
    /// kicked this Failed VM, and when it last did (or first saw the phase).
    /// Reset the moment the phase leaves Failed.
    #[serde(default, skip_serializing_if = "u32_is_zero")]
    pub requeue_attempts: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_requeue: Option<DateTime<Utc>>,
}

fn u32_is_zero(n: &u32) -> bool {
    *n == 0
}

pub type Vm = Object<VmSpec, VmStatus>;

/// The cloud's ownership marks on a cluster-local object. They are server-owned
/// the way uid and status are: a client that could write them could make its
/// own VM unremovable, or take the mark off one that really does belong to the
/// cloud.
#[generated(model = ClaudeOpus, version = "5")]
impl Metadata {
    pub fn managed_by_cloud(&self) -> bool {
        self.labels.get(LABEL_MANAGED_BY).map(String::as_str) == Some(MANAGED_BY_CLOUD)
    }

    /// Which cloud object this one stands for. A name is what people call a VM
    /// and people reuse names; this is which VM it is.
    pub fn cloud_uid(&self) -> Option<&str> {
        self.labels.get(LABEL_CLOUD_UID).map(String::as_str)
    }

    pub fn mark_managed_by_cloud(&mut self, uid: &str) {
        self.labels
            .insert(LABEL_MANAGED_BY.to_string(), MANAGED_BY_CLOUD.to_string());
        self.labels
            .insert(LABEL_CLOUD_UID.to_string(), uid.to_string());
    }

    /// Whatever the client's body said about ownership, what stands is what
    /// the stored object says.
    pub fn take_ownership_labels_from(&mut self, current: &Self) {
        for key in [LABEL_MANAGED_BY, LABEL_CLOUD_UID] {
            match current.labels.get(key) {
                Some(v) => self.labels.insert(key.to_string(), v.clone()),
                None => self.labels.remove(key),
            };
        }
    }
}

/// A new object of this resource, wearing the envelope its own type carries.
///
/// This replaced nine `new_*` helpers that were the same line each, and every
/// one of them was a place where a resource could be created wearing another
/// resource's kind. A VM keeps a constructor of its own because it is more
/// than an envelope — see `new_vm`.
#[generated(model = ClaudeOpus, version = "5")]
impl<S, St: Default> Object<S, St>
where
    Self: Resource,
{
    pub fn declare(name: &str, spec: S) -> Self {
        Self::new(API_VERSION, Self::KIND, name, spec)
    }
}

/// A VM, with the finalizer that makes teardown the one path out.
pub fn new_vm(name: &str, spec: VmSpec) -> Vm {
    let mut vm = Vm::declare(name, spec);
    vm.metadata
        .finalizers
        .push("meister.io/teardown".to_string());
    vm
}

/// A node is an agent the cluster knows about. The object is created on the
/// first Hello and outlives the session: spec is what an operator decided,
/// status is what the agent last reported (§2 of the design).
#[generated(model = ClaudeOpus, version = "5")]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeSpec {
    /// False drains the node — the scheduler places nothing new on it while
    /// the running VMs and the session stay untouched.
    #[serde(default = "schedulable_default")]
    pub schedulable: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

fn schedulable_default() -> bool {
    true
}

impl Default for NodeSpec {
    fn default() -> Self {
        Self {
            schedulable: true,
            labels: BTreeMap::new(),
        }
    }
}

#[generated(model = ClaudeOpus, version = "5")]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
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
}

#[generated(model = ClaudeOpus, version = "5")]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
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
}

pub type Node = Object<NodeSpec, NodeStatus>;

/// A cluster is a cluster-controller the cloud knows about — the same story as
/// a Node one tier down. The object appears on the first Hello and outlives
/// the session, because a cluster that is down has to stay listed as not
/// connected, with the capacity it last had.
#[generated(model = ClaudeOpus, version = "5")]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClusterSpec {
    /// False drains the cluster — nothing new is placed on it while its VMs
    /// and its session carry on untouched.
    #[serde(default = "schedulable_default")]
    pub schedulable: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

impl Default for ClusterSpec {
    fn default() -> Self {
        Self {
            schedulable: true,
            labels: BTreeMap::new(),
        }
    }
}

/// What the cluster last reported about itself, summed over its ready nodes.
/// Deliberately coarse: the cloud places a VM on a *cluster*, and which node
/// inside it ends up carrying the VM is the cluster's decision — an aggregate
/// this far away is not something to second-guess a scheduler with.
#[generated(model = ClaudeOpus, version = "5")]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
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

#[generated(model = ClaudeOpus, version = "5")]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClusterStatus {
    /// A session exists AND the cluster's heartbeat has not expired.
    #[serde(default)]
    pub connected: bool,
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
}

pub type Cluster = Object<ClusterSpec, ClusterStatus>;

/// How the bytes are laid out where `source` points. The agent's block driver
/// already tells raw from qcow2 by itself; carrying it here is for the operator
/// reading `image ls` and for the storage backends that will need it to decide
/// between a copy and a clone.
#[generated(model = ClaudeOpus, version = "5")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ImageFormat {
    #[default]
    Raw,
    Qcow2,
}

/// The image catalogue — a cloud resource from the start, because an image is
/// the one thing every tier below has to agree on by name.
///
/// v1 is a catalogue and a reference check, nothing else. `source` says where
/// the bytes already are (a path on shared storage, later a URL); no blob ever
/// travels through the control plane, and `status.availableOn` stays empty
/// until the shared-storage track has something true to write there.
#[generated(model = ClaudeOpus, version = "5")]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageSpec {
    /// The file name a node looks up under its own image_dir, and what a VM's
    /// `base_image` says. For a URL image this is the name the fetched bytes
    /// land under; for a path image it is where they already are.
    pub source: String,
    /// Where the bytes can be fetched from, if nobody has put them there by
    /// hand. Absent = the catalogue entry over existing shared storage this
    /// resource has always been, unchanged in every respect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// What those bytes must hash to, lowercase hex. Mandatory with `url` and
    /// meaningless without one — checked at the create edge, because an image
    /// fetched over a network and not checked is an image somebody else can
    /// choose the contents of.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default)]
    pub format: ImageFormat,
    #[serde(default)]
    pub size_bytes: u64,
    /// Whose image this is. Absent = unscoped, the shape every image in the
    /// catalogue had before this milestone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// Readable by every tenant, writable by none but its owner. The base
    /// images a lab shares — one nixos.raw everybody boots from — are exactly
    /// this, and without it every tenant would need its own copy of the
    /// catalogue entry pointing at the same file.
    #[serde(default, skip_serializing_if = "is_false")]
    pub public: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// Whether the bytes are there and are the right bytes.
///
/// A path image is `Ready` the moment it is registered: it is a catalogue
/// entry over storage somebody else already filled, and this control plane
/// has never claimed to check it. A URL image starts `Pending` — nobody has
/// fetched it yet — and moves when a node says what happened.
#[generated(model = ClaudeOpus, version = "5")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImagePhase {
    #[default]
    Pending,
    Ready,
    Failed,
}

#[generated(model = ClaudeOpus, version = "5")]
impl ImagePhase {
    pub const ALL: [ImagePhase; 3] = [ImagePhase::Pending, ImagePhase::Ready, ImagePhase::Failed];

    /// The spelling that goes on the wire (control.proto: ImageStateReport).
    /// `parse` is its inverse and the tests hold them to it.
    pub fn as_str(self) -> &'static str {
        match self {
            ImagePhase::Pending => "Pending",
            ImagePhase::Ready => "Ready",
            ImagePhase::Failed => "Failed",
        }
    }

    /// Unknown input is rejected rather than defaulted — a drifting node
    /// should be visible, not silently "Pending". The rule VmPhase follows.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.as_str() == s)
    }
}

#[generated(model = ClaudeOpus, version = "5")]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageStatus {
    /// Clusters that hold a local copy. Empty for as long as v1 distributes by
    /// reference only — an empty list here means "not tracked", and saying so
    /// is better than writing a number nobody computed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub available_on: Vec<String>,
    #[serde(default)]
    pub phase: ImagePhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// No finalizer: an image object owns no resource anywhere, so there is
/// nothing for a teardown to do and DELETE can mean delete.
pub type Image = Object<ImageSpec, ImageStatus>;

/// Normal or Warning, and Kubernetes' own two words for it.
///
/// The distinction earns its place: a dashboard and a person both want "show
/// me what went wrong" to be one filter rather than a list of reasons somebody
/// has to keep up to date.
#[generated(model = ClaudeOpus, version = "5")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    #[default]
    Normal,
    Warning,
}

impl EventType {
    pub fn as_str(self) -> &'static str {
        match self {
            EventType::Normal => "Normal",
            EventType::Warning => "Warning",
        }
    }
}

/// Something that happened to an object, kept for a while.
///
/// `VmStatus.message` holds exactly one sentence, so why a VM failed three
/// times and came up on the fourth was written down nowhere. This is the
/// record of the transitions themselves, cut to what is actually useful:
/// Kubernetes' shape without the fields nobody reads.
///
/// Three properties decide whether this is worth having at all, and all three
/// are enforced elsewhere rather than described here:
///
/// * **They expire.** Written through `EtcdStore::create_with_ttl`, so etcd
///   reaps them and nothing has to be alive for that to happen. Events
///   without an expiry fill a store and nobody ever tidies them.
/// * **They are aggregated.** The object's NAME is derived from what it is
///   about and why (see `events::name_of`), so the same thing happening
///   twenty times finds the object it made the first time and raises `count`.
/// * **They are made on CHANGE, never per pass.** That one is a property of
///   every call site: the reconcilers are level-triggered and re-derive
///   everything every few seconds, so an event per pass would be a store
///   filling at one write per VM per tick.
#[generated(model = ClaudeOpus, version = "5")]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventSpec {
    /// What this is about: the kind, the name a person calls it, and the uid
    /// that says WHICH one. The uid is in the name of the event object too —
    /// names get reused, and two VMs' histories must not merge because
    /// somebody recreated one under the same name.
    pub involved_kind: String,
    pub involved_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub involved_uid: String,
    /// A short CamelCase word, from a closed set (`events::reason`). What a
    /// filter matches on and what an aggregation groups by — so it may never
    /// carry a number, a name or a sentence, for the reason a metric label
    /// may not.
    pub reason: String,
    /// The sentence. This is where the numbers and the names go.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub message: String,
    #[serde(default)]
    pub event_type: EventType,
    /// Whose object this was about. Absent = unscoped, and then only an admin
    /// sees it — the same rule, and the same conservative direction, that an
    /// unscoped VM has.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    #[serde(default)]
    pub count: u32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// No finalizer, and no status: an event owns nothing, and there is nothing
/// about one that a controller observes afterwards.
pub type Event = Object<EventSpec, ()>;

// --- who may call, and on whose behalf --------------------------------------
//
// These three live at the cloud tier only, and that is the design decision
// rather than an omission: one directory, one truth. A cluster authenticates
// against the same CA and reads the role out of the certificate; it does not
// keep a second copy of the people.

/// A tenant is the unit a user belongs to and, from M5, the unit a VM and an
/// image belong to. It is also the unit a NETWORK belongs to: every tenant
/// carries a VXLAN network identifier, and that number is what makes the
/// isolation real rather than a label on an object.
#[generated(model = ClaudeOpus, version = "5")]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantSpec {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    /// How much this tenant may hold. Every field absent = unlimited, which
    /// is what every tenant written before this milestone says and therefore
    /// exactly what every one of them keeps doing.
    #[serde(default, skip_serializing_if = "TenantQuota::is_unset")]
    pub quota: TenantQuota,
    /// The tenant's overlay network, allocated by the cloud at create time
    /// and never afterwards. Server-owned and immutable, for the reason every
    /// identifier that names a wire is: two tenants sharing a VNI is not a
    /// conflict anybody would notice from an object, it is two tenants on one
    /// broadcast domain. `None` is a tenant created before this milestone, or
    /// one on a cloud that allocates none — it gets no overlay and its VMs
    /// land on the default bridge, exactly as they did yesterday.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vni: Option<u32>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
}

/// The ceiling on what a tenant may hold, one number per thing that runs out.
///
/// Every field optional, and absent means unlimited rather than zero. That is
/// the whole compatibility story: `floatingpool quota` was the only quota in
/// this system, so nothing else here was ever bounded, and a default of
/// anything but "unlimited" would stop a running fleet the moment this
/// milestone rolled out.
///
/// Set by an admin and by nobody else. Not a rule written here — the
/// middleware already says it, because `tenants` is not among the resources a
/// member may write (`auth::TENANT_SCOPED`), so a member raising their own
/// ceiling never reaches a handler at all.
#[generated(model = ClaudeOpus, version = "5")]
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantQuota {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_vms: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_vcpus: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_mem_mib: Option<u64>,
}

#[generated(model = ClaudeOpus, version = "5")]
impl TenantQuota {
    /// No ceiling of any kind — the shape every tenant had before this
    /// existed, and the one that is not serialised at all.
    pub fn is_unset(&self) -> bool {
        self.max_vms.is_none() && self.max_vcpus.is_none() && self.max_mem_mib.is_none()
    }
}

/// What a tenant is holding right now.
///
/// Computed where it is read and never stored, for the reason a candidate's
/// free capacity is: both halves are objects the server already has, and a
/// second copy in etcd would be a number that can be wrong — here in the
/// direction that lets a tenant past its own ceiling.
#[generated(model = ClaudeOpus, version = "5")]
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantUsage {
    #[serde(default)]
    pub vms: u32,
    #[serde(default)]
    pub vcpus: u32,
    #[serde(default)]
    pub mem_mib: u64,
}

/// What the tenant is using, filled in by the read that hands the object out.
///
/// The design gave a tenant `clusters` and `vmCount` and neither was
/// computable while VMs were not tenant-bound; they are now. Nothing writes
/// this to the store — a `Tenant` read back out of etcd carries zeros, and
/// the API is what puts the truth in it.
#[generated(model = ClaudeOpus, version = "5")]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantStatus {
    #[serde(default)]
    pub used: TenantUsage,
}

/// No finalizer: a tenant owns no resource anywhere yet, so DELETE can mean
/// delete — the same reason an Image has none.
pub type Tenant = Object<TenantSpec, TenantStatus>;

// --- the addresses a tenant may claim ---------------------------------------
//
// Two objects and a rule. The pool says which addresses exist and who may take
// how many of them; the reservation says who holds one and which VM it is for.
// Nothing here routes a packet or answers an ARP — that is the tenant's own
// appliance, or the environment's static route, or Part C's announcement. What
// this pair produces is OWNERSHIP, and ownership is what the node's nftables
// rules turn into an answer to "may this tap send from this address".

/// How many addresses a tenant may hold out of a PRIVATE pool without anybody
/// being asked. Four is a lab's worth: a gateway, a load balancer and two
/// spare — enough to build the appliance pattern without a ticket.
pub const DEFAULT_QUOTA_PRIVATE: u32 = 4;

/// And out of a PUBLIC one: none. A routable address is the scarce thing an
/// operator was actually given by somebody else, and the design rule is that
/// an admin hands those out one tenant at a time by raising this pool's quota
/// for them. A default of anything but zero would be this control plane
/// giving away addresses it does not own.
pub const DEFAULT_QUOTA_PUBLIC: u32 = 0;

/// A range of addresses an operator has, and who may take from it.
///
/// `cidrs` is a list of strings and not one CIDR because that is the shape a
/// real allocation has: four scattered public addresses are four entries, and
/// a lab's private range is one. Each entry is a CIDR, a single address or an
/// `a-b` range — `common::net::Ipv4Ranges` is the parser, shared with the node
/// that has to guard the same addresses.
#[generated(model = ClaudeOpus, version = "5")]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FloatingPoolSpec {
    pub cidrs: Vec<String>,
    /// These addresses are reachable from outside. It changes exactly one
    /// thing in this control plane — the default quota, which is zero — and
    /// that is the whole point: the stack cannot tell a routable address from
    /// a private one by looking at it, so an operator says so, and saying so
    /// closes the door rather than opening it.
    #[serde(default, skip_serializing_if = "is_false")]
    pub public: bool,
    /// The pool a reservation lands in when it names none. At most one pool
    /// may say true, checked at write time: two defaults would make "which
    /// pool did I just take an address from" a question about ordering.
    #[serde(default, skip_serializing_if = "is_false")]
    pub default: bool,
    /// Per-tenant ceiling on reservations out of THIS pool. A tenant that is
    /// not named here gets `DEFAULT_QUOTA_PRIVATE` or `DEFAULT_QUOTA_PUBLIC`
    /// depending on `public` — so raising a tenant's public quota is the one
    /// explicit act that hands out a routable address.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub quota: BTreeMap<String, u32>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
}

#[generated(model = ClaudeOpus, version = "5")]
impl FloatingPoolSpec {
    /// What this tenant may hold here: the named ceiling, or the default the
    /// pool's kind implies.
    pub fn quota_for(&self, tenant: &str) -> u32 {
        self.quota.get(tenant).copied().unwrap_or(if self.public {
            DEFAULT_QUOTA_PUBLIC
        } else {
            DEFAULT_QUOTA_PRIVATE
        })
    }
}

/// Empty, and honestly so: how many addresses are left is a question about
/// the reservations, which are their own objects and are counted when asked.
/// A number cached here would be a number that is wrong after every create.
#[generated(model = ClaudeOpus, version = "5")]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FloatingPoolStatus {}

/// No finalizer: a pool owns nothing. What keeps it from vanishing under a
/// reservation is the delete handler's refusal, exactly as a tenant with users
/// in it cannot be deleted.
pub type FloatingPool = Object<FloatingPoolSpec, FloatingPoolStatus>;

/// One address, held by one tenant, optionally pointed at one VM.
///
/// The object's `metadata.name` IS the address, and that is deliberate: the
/// address is the identity here, it is what an operator types (`floatingip
/// assign 10.255.0.7 --vm web`), and it is the only name under which two
/// racing allocators can collide — which turns the store's own create into
/// the compare-and-swap the allocation needs. See `floating::allocate`.
#[generated(model = ClaudeOpus, version = "5")]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FloatingIpSpec {
    /// Whose reservation this is. Never empty on a STORED object — a floating
    /// address belongs to somebody or it is not reserved — but defaulted on
    /// the way in, because the request a member sends names no tenant at all:
    /// the server fills in their own, exactly as it does for a VM. A required
    /// field here would make the self-service path a deserialization error.
    #[serde(default)]
    pub tenant: String,
    /// Which pool it came out of. Server-set at create (the named pool, or
    /// the default one) and immutable afterwards — the pool is where the
    /// address came from, and an object that could be re-pointed at another
    /// pool would move an address into a range that does not contain it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pool: String,
    /// The address itself, server-set and equal to `metadata.name`. Written
    /// twice on purpose: the name is how the store finds it, and the spec is
    /// what everything downstream reads, so a caller reading the object never
    /// has to know that the two are the same string.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub address: String,
    /// The VM this address is for, by name, inside the same tenant. `None` =
    /// reserved and unassigned, which is a perfectly good state: the address
    /// is the tenant's from the moment they take it, and pointing it at a VM
    /// is a second, reversible decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vm: Option<String>,
}

#[generated(model = ClaudeOpus, version = "5")]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FloatingIpStatus {}

pub type FloatingIp = Object<FloatingIpSpec, FloatingIpStatus>;

/// A real subnet a tenant owns, routed rather than translated.
///
/// The other half of the network story and the one the lab wants: a tenant
/// with a routed subnet needs no NAT and no gateway appliance to be reachable
/// — the addresses inside its overlay ARE the addresses outside it. The
/// hoster's mode is the same stack without this object: a tenant with no
/// routed subnet gets whatever private space it likes behind its own NAT
/// appliance, and this control plane never learns those addresses.
///
/// It also completes the anti-spoofing. A tenant whose address space is
/// UNKNOWN can only be told "not out of the floating pool"; a tenant whose
/// address space is written down here can be told "these and nothing else".
#[generated(model = ClaudeOpus, version = "5")]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoutedSubnetSpec {
    pub tenant: String,
    /// The subnet, CIDR. Either cut from the cloud's `routed_pools` at create
    /// time or named outright by the admin; either way it may not overlap any
    /// other routed subnet or any floating pool.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cidr: String,
    /// How big a block to cut when `cidr` was left empty. Kept on the object
    /// afterwards although `cidr` makes it redundant, for the reason
    /// `NicSpec.bridge` is kept next to `vxlan_id`: the record goes on saying
    /// what was ASKED for, and an admin reading it can see whether a /24 was
    /// a request or a coincidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix_len: Option<u32>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
}

/// The block size a routed subnet gets when nobody names one. A /24 is what
/// an operator draws on a whiteboard, and it is small enough that a /16 super
/// pool holds 256 tenants' worth of them.
pub const DEFAULT_ROUTED_PREFIX_LEN: u32 = 24;

#[generated(model = ClaudeOpus, version = "5")]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RoutedSubnetStatus {}

pub type RoutedSubnet = Object<RoutedSubnetSpec, RoutedSubnetStatus>;

/// A person. The object is the authorization side of an identity: the
/// certificate says who somebody is, this says what they may do and whose
/// tenant they are in, and the two are kept apart so that a role change is an
/// edit rather than a re-issue.
#[generated(model = ClaudeOpus, version = "5")]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserSpec {
    pub tenant: String,
    #[serde(default)]
    pub role: crate::auth::Role,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
}

/// One certificate this user has been issued.
///
/// A fingerprint and two dates — never the certificate, and above all never
/// the key. The point of recording them is that an operator can see how many
/// credentials are out there for a name and when they die, which is exactly
/// what a fingerprint answers and exactly what storing the PEM would add
/// nothing to.
#[generated(model = ClaudeOpus, version = "5")]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuedCertificate {
    /// `sha256:<hex>` over the DER.
    pub fingerprint: String,
    pub issued_at: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub serial: String,
    /// The CertificateSigningRequest this came out of, so the trail from a
    /// live credential back to the request and its approver is one hop.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub request: String,
}

#[generated(model = ClaudeOpus, version = "5")]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserStatus {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub certificates: Vec<IssuedCertificate>,
}

impl UserStatus {
    /// Certificates that have not expired at `now`. What `user ls` counts,
    /// because an expired fingerprint is history rather than a credential.
    pub fn live(&self, now: DateTime<Utc>) -> impl Iterator<Item = &IssuedCertificate> {
        self.certificates.iter().filter(move |c| c.not_after > now)
    }
}

pub type User = Object<UserSpec, UserStatus>;

/// The only signer this control plane has. Named anyway, exactly as K8s names
/// its own: a CSR that asks for a signer nobody runs must be refused rather
/// than quietly signed by whoever happens to be listening.
pub const SIGNER_USER_CLIENT: &str = "meister.io/user-client";

// --- server-owned counters ---------------------------------------------------

/// A number the server hands out, kept in the store so that handing it out is
/// a compare-and-swap rather than a hope.
///
/// It is an ordinary object with an ordinary `resourceVersion`, which is the
/// entire point: the store's CAS on that field is the allocator. Nothing else
/// had to be built, and nothing about it is specific to VNIs — the next
/// counter this stack needs takes another name under the same resource.
///
/// No REST route serves it. It is not something anybody creates, lists or
/// edits, and a counter an operator could PUT is a counter two tenants can be
/// given the same value from.
#[generated(model = ClaudeOpus, version = "5")]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CounterSpec {
    /// The value the next allocation hands out, before the floor is applied.
    pub next: u32,
}

#[generated(model = ClaudeOpus, version = "5")]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CounterStatus {}

pub type Counter = Object<CounterSpec, CounterStatus>;

/// A request for a client certificate. K8s' shape, because the flow is K8s'
/// flow: the client keeps its key and sends a CSR, somebody with the right to
/// approve says yes, and the signer turns the approved request into a
/// certificate the client then collects.
#[generated(model = ClaudeOpus, version = "5")]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CsrSpec {
    /// The PKCS#10 request, PEM. A public key and a name; the private half
    /// never existed on this machine.
    pub request: String,
    /// Who the certificate is for. The signer writes THIS into the subject,
    /// not whatever the request said about itself.
    pub username: String,
    #[serde(default = "default_signer")]
    pub signer_name: String,
}

fn default_signer() -> String {
    SIGNER_USER_CLIENT.to_string()
}

#[generated(model = ClaudeOpus, version = "5")]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CsrConditionType {
    Approved,
    Denied,
    Failed,
}

#[generated(model = ClaudeOpus, version = "5")]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CsrCondition {
    #[serde(rename = "type")]
    pub kind: CsrConditionType,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub message: String,
    pub last_update_time: DateTime<Utc>,
    /// The identity that set this condition. K8s does not record it on the
    /// object; here it is the whole audit trail there is, and a credential
    /// handed out by nobody in particular is worse than no record at all.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub by: String,
}

#[generated(model = ClaudeOpus, version = "5")]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CsrStatus {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<CsrCondition>,
    /// The signed certificate, PEM, once there is one. Public by nature —
    /// this is the half of the pair that is meant to be handed around.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
}

#[generated(model = ClaudeOpus, version = "5")]
impl CsrStatus {
    pub fn has(&self, kind: CsrConditionType) -> bool {
        self.conditions.iter().any(|c| c.kind == kind)
    }

    pub fn approved(&self) -> bool {
        self.has(CsrConditionType::Approved)
    }

    pub fn denied(&self) -> bool {
        self.has(CsrConditionType::Denied)
    }

    /// One word for `csr ls`, and the order matters: a denial outranks an
    /// approval that never produced anything, and a certificate outranks the
    /// approval that caused it.
    pub fn phase(&self) -> &'static str {
        if self.denied() {
            "Denied"
        } else if self.has(CsrConditionType::Failed) {
            "Failed"
        } else if self.certificate.is_some() {
            "Issued"
        } else if self.approved() {
            "Approved"
        } else {
            "Pending"
        }
    }

    /// Record a condition. Setting the same one twice is setting it, not
    /// appending: a request is approved once, and a list that grew every time
    /// somebody retried would turn the audit trail into noise.
    pub fn set(&mut self, condition: CsrCondition) {
        match self
            .conditions
            .iter_mut()
            .find(|c| c.kind == condition.kind)
        {
            Some(existing) => *existing = condition,
            None => self.conditions.push(condition),
        }
    }
}

pub type CertificateSigningRequest = Object<CsrSpec, CsrStatus>;

#[cfg(test)]
#[generated(model = ClaudeOpus, version = "5")]
mod tests {
    use super::*;

    /// The registration table read back through the trait: no two resources
    /// share a directory, and none shares a kind. A duplicated row would file
    /// one resource's objects under another's name — and since the store now
    /// derives that name from the type, nothing at a call site could ever
    /// catch it.
    #[test]
    fn every_resource_has_its_own_directory_and_its_own_kind() {
        let directories: std::collections::BTreeSet<&str> =
            ALL_RESOURCES.iter().map(|(r, _)| *r).collect();
        let kinds: std::collections::BTreeSet<&str> =
            ALL_RESOURCES.iter().map(|(_, k)| *k).collect();
        assert_eq!(directories.len(), ALL_RESOURCES.len(), "{directories:?}");
        assert_eq!(kinds.len(), ALL_RESOURCES.len(), "{kinds:?}");
        // A directory is a single path segment, because it is one: the key is
        // `<prefix>/registry/<resource>/<name>` and the REST route below it
        // matches one segment.
        assert!(
            ALL_RESOURCES
                .iter()
                .all(|(r, _)| !r.is_empty() && !r.contains('/')),
            "a resource directory is one path segment"
        );
    }

    /// The agent spells phases by hand (it must not depend on this crate), so
    /// guard the contract from both ends: every variant parses from the name
    /// serde and Debug use, and nothing else parses at all.
    /// The lists are only worth walking if they are complete. The `match`
    /// arms are the guard: an eighth phase or a fourth run strategy stops
    /// this file compiling, and the length check catches an entry dropped
    /// from the list without the enum changing.
    #[test]
    fn the_variant_lists_name_every_variant() {
        for phase in VmPhase::ALL {
            match phase {
                VmPhase::Pending
                | VmPhase::Provisioning
                | VmPhase::Running
                | VmPhase::Stopped
                | VmPhase::Paused
                | VmPhase::Failed
                | VmPhase::Quarantined => {}
            }
        }
        for strategy in RunStrategy::ALL {
            match strategy {
                RunStrategy::Running | RunStrategy::Stopped | RunStrategy::Paused => {}
            }
        }
        // No duplicates hiding a missing one.
        let spellings: std::collections::BTreeSet<_> =
            VmPhase::ALL.iter().map(|p| p.as_str()).collect();
        assert_eq!(spellings.len(), VmPhase::ALL.len());
        assert_eq!(VmPhase::ALL.iter().filter(|p| p.is_stable()).count(), 3);
    }

    #[test]
    fn every_phase_parses_from_its_own_spelling() {
        for phase in [
            VmPhase::Pending,
            VmPhase::Provisioning,
            VmPhase::Running,
            VmPhase::Stopped,
            VmPhase::Paused,
            VmPhase::Failed,
            VmPhase::Quarantined,
        ] {
            assert_eq!(VmPhase::parse(&format!("{phase:?}")), Some(phase));
            assert_eq!(VmPhase::parse(phase.as_str()), Some(phase));
        }
        assert_eq!(VmPhase::parse("running"), None);
        assert_eq!(VmPhase::parse(""), None);
    }

    /// Ownership is a fact about the stored object, never about the request.
    #[test]
    fn the_cloud_ownership_labels_are_server_owned() {
        let mut cloud_owned = Metadata::default();
        cloud_owned.mark_managed_by_cloud("uid-1");
        assert!(cloud_owned.managed_by_cloud());
        assert_eq!(cloud_owned.cloud_uid(), Some("uid-1"));

        // A client cannot label its own VM as the cloud's ...
        let mut forged = Metadata::default();
        forged.mark_managed_by_cloud("uid-forged");
        forged.labels.insert("mine".into(), "kept".into());
        forged.take_ownership_labels_from(&Metadata::default());
        assert!(!forged.managed_by_cloud());
        assert_eq!(forged.cloud_uid(), None);
        assert_eq!(forged.labels.get("mine").map(String::as_str), Some("kept"));

        // ... nor strip the labels off one that is.
        let mut stripped = Metadata::default();
        stripped.take_ownership_labels_from(&cloud_owned);
        assert!(stripped.managed_by_cloud());
        assert_eq!(stripped.cloud_uid(), Some("uid-1"));
    }

    /// One word for `csr ls`, and the order it comes out in. A denial
    /// outranks an approval that never produced anything; a certificate
    /// outranks the approval that caused it.
    #[test]
    fn a_request_has_exactly_one_phase_and_the_precedence_is_fixed() {
        let at = Utc::now();
        let cond = |kind| CsrCondition {
            kind,
            reason: String::new(),
            message: String::new(),
            last_update_time: at,
            by: "ops".into(),
        };

        let mut status = CsrStatus::default();
        assert_eq!(status.phase(), "Pending");
        status.set(cond(CsrConditionType::Approved));
        assert_eq!(status.phase(), "Approved");
        status.certificate = Some("-----BEGIN CERTIFICATE-----".into());
        assert_eq!(status.phase(), "Issued");
        status.set(cond(CsrConditionType::Denied));
        assert_eq!(
            status.phase(),
            "Denied",
            "a denial outranks the certificate"
        );

        // Approving twice is approving, not appending: a request is approved
        // once, and a list that grew on every retry would be noise where an
        // audit trail should be.
        let mut twice = CsrStatus::default();
        twice.set(cond(CsrConditionType::Approved));
        twice.set(cond(CsrConditionType::Approved));
        assert_eq!(twice.conditions.len(), 1);
    }

    /// The list on a user is what credentials EXIST, and one that has died is
    /// history rather than a credential.
    #[test]
    fn a_user_counts_only_the_certificates_that_are_still_alive() {
        let now = Utc::now();
        let cert = |offset_days: i64| IssuedCertificate {
            fingerprint: format!("sha256:{offset_days}"),
            issued_at: now,
            not_after: now + chrono::Duration::days(offset_days),
            serial: String::new(),
            request: String::new(),
        };
        let status = UserStatus {
            certificates: vec![cert(-1), cert(30)],
        };
        assert_eq!(status.live(now).count(), 1);
    }

    /// Defaults matter here: a user object written with a bare spec must not
    /// come back as an administrator.
    #[test]
    fn a_user_without_a_role_is_a_member() {
        let user: User = serde_json::from_value(serde_json::json!({
            "apiVersion": API_VERSION, "kind": User::KIND,
            "metadata": { "name": "alice" }, "spec": { "tenant": "acme" }
        }))
        .unwrap();
        assert_eq!(user.spec.role, crate::auth::Role::Member);
        assert_eq!(user.spec.role.group(), crate::auth::GROUP_MEMBERS);
        assert!(user.status.certificates.is_empty());
    }

    /// The signer is named on the request, exactly as K8s names its own: a
    /// request for a signer nobody runs must be refusable rather than
    /// quietly signed by whoever is listening.
    #[test]
    fn a_request_without_a_signer_gets_the_only_one_there_is() {
        let csr: CertificateSigningRequest = serde_json::from_value(serde_json::json!({
            "apiVersion": API_VERSION, "kind": CertificateSigningRequest::KIND,
            "metadata": { "name": "alice-1" },
            "spec": { "request": "-----BEGIN CERTIFICATE REQUEST-----", "username": "alice" }
        }))
        .unwrap();
        assert_eq!(csr.spec.signer_name, SIGNER_USER_CLIENT);
        assert_eq!(csr.status.phase(), "Pending");
    }

    #[test]
    fn a_node_without_a_spec_is_schedulable() {
        let node: Node = serde_json::from_value(serde_json::json!({
            "apiVersion": API_VERSION, "kind": Node::KIND,
            "metadata": { "name": "manacor" }, "spec": {}
        }))
        .unwrap();
        assert!(node.spec.schedulable);
        assert!(!node.status.ready);
    }
}
