// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The `StoragePool` kind: where volumes may be cut from. Moved
//! out of `resources.rs` unchanged.

use super::*;

/// Where volumes come from: a backend, the nodes that can reach it, and how
/// much of it each tenant may hold.
///
/// `nodes` is a list and not a label selector, and that is the honest shape
/// for what it describes: an LVM volume group is on ONE machine and an NFS
/// export is reachable from the handful that mount it. Which nodes reach a
/// pool is a fact an operator knows and writes down; deriving it from labels
/// would be inferring a physical connection from a piece of metadata.
///
/// Empty `nodes` means every node — the compatibility direction, and the one a
/// single-machine lab wants: a pool nobody restricted is a pool the scheduler
/// does not use to narrow anything.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StoragePoolSpec {
    /// The agent-side backend name — `lvm-thin`, `filesystem`, `nfs`. The
    /// same string a node claims as `volume/<driver>` in its catalogue, which
    /// is what lets the scheduler ask whether a candidate can serve this pool
    /// without learning anything new.
    pub driver: String,
    /// Which nodes can reach it. Empty = all of them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nodes: Vec<String>,
    /// Backend options, handed to the driver untouched — `{"pool":
    /// "vg0/thin"}` for lvm-thin, and whatever the next backend wants. The
    /// same pass-through `VolumeSpec.params` is at the agent, one tier up:
    /// this control plane routes on `driver` and reads nothing else.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
    /// The pool a volume lands in when it names none. At most one may say
    /// true, checked at write time — two defaults would make "which pool did
    /// my disk come out of" a question about ordering.
    #[serde(default, skip_serializing_if = "is_false")]
    pub default: bool,
    /// Per-tenant ceiling in GiB out of THIS pool, plus the one row that is
    /// about everybody: [`QUOTA_EVERYONE`].
    ///
    /// A tenant named here has that ceiling; one that is not has the `*` row;
    /// and a pool with neither has [`DEFAULT_QUOTA_STORAGE_GIB`]. The `*` row
    /// is what made the third case sayable: until runde 4 the hundred GiB was
    /// a constant in this file and nowhere else, so `storagepool ls` showed
    /// `QUOTA -` and the refusal ("its quota there is 100 GiB") named a
    /// number an operator could not find (D-P11). The read paths fill it in
    /// now, so every pool answers with the ceiling it actually applies.
    ///
    /// [`QUOTA_EVERYONE`]: StoragePoolSpec::QUOTA_EVERYONE
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub quota: BTreeMap<String, u64>,
    /// Which CLUSTER serves this pool — at the cloud tier only.
    ///
    /// A cloud pool is a cluster pool seen from above: the cloud does not
    /// create it down there (an admin does, or the cluster's own
    /// configuration), it only points at it. So this is a reference and not a
    /// definition, and an empty one at the cloud is a 422 — without a cluster
    /// there is nothing to dispatch a volume to.
    ///
    /// Empty at the CLUSTER tier, always: a cluster is what that process IS,
    /// and it has no object of its own there. One `StoragePoolSpec` serves
    /// both tiers for the same reason one `VmSpec` does — each tier writes
    /// its own binding and ignores the other's.
    ///
    /// Why the cloud does not schedule volumes across clusters: it would have
    /// to compare two pools on two clusters on facts it does not have (how
    /// full the thin pool is, which nodes mount the export), and the answer
    /// would go stale between the decision and the dispatch. The pool naming
    /// its cluster is the operator writing down what they already know.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cluster: String,
    /// The same statement for MORE than one cluster, when the bytes really
    /// are reachable from more than one.
    ///
    /// Additive, and `spec.cluster` stays the short form for the ordinary
    /// case of one — a pool that names only `cluster` reads exactly as it
    /// always did, and [`served_by`] is the one place that stops caring which
    /// of the two an operator wrote.
    ///
    /// Only two kinds of pool may say this truthfully, and the difference is
    /// the driver's rather than the operator's: a `networked` pool (an
    /// import provider pointing at a target both clusters can dial) and a
    /// `shared` one whose clusters mount THE SAME export. The second is the
    /// one that can be written down wrongly, so it is checked rather than
    /// believed — see `StoragePoolStatus::clusters`, which is what each
    /// cluster says its own pool of this name is made of.
    ///
    /// What it buys is the cloud-tier reschedule: a stopped VM may leave its
    /// cluster, and its disks can only follow it if something says they are
    /// reachable from where it is going.
    ///
    /// [`served_by`]: StoragePoolSpec::served_by
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub clusters: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
}

/// How much a tenant may hold in a pool nobody set a number for.
///
/// Not zero, and the difference from `DEFAULT_QUOTA_PUBLIC` next door is the
/// point: a routable address is something an operator was given by somebody
/// else and hands out one at a time, while disk is something the machine has.
/// A hundred GiB is a lab's worth — a few root disks and room to be wrong —
/// and an admin who wants a ticket per volume sets the number to zero.
pub const DEFAULT_QUOTA_STORAGE_GIB: u64 = 100;

impl StoragePoolSpec {
    /// The key in `quota` that is about every tenant nobody named.
    ///
    /// A reserved name and not a new field, because it is the same statement
    /// the other rows make and belongs in the same map: one place to read,
    /// one place to patch, and a table that renders it without being taught
    /// anything. `*` cannot collide with a tenant — a tenant's name is a DNS
    /// label, and no label contains a star.
    pub const QUOTA_EVERYONE: &'static str = "*";

    /// What this tenant may hold here: its own ceiling, the one for everybody
    /// nobody named, or the built-in default.
    pub fn quota_for(&self, tenant: &str) -> u64 {
        self.quota
            .get(tenant)
            .or_else(|| self.quota.get(Self::QUOTA_EVERYONE))
            .copied()
            .unwrap_or(DEFAULT_QUOTA_STORAGE_GIB)
    }

    /// Write the ceiling this pool applies to everybody else into the map, so
    /// that a client reading the object sees the number the server uses.
    ///
    /// On the way OUT and not at create, and that is what makes it true for
    /// the pools that already exist: the hundred GiB has been the answer
    /// since the field was added, and a pool written last month applies it
    /// exactly as one written today does. A pool whose operator has said a
    /// number keeps it — this only ever fills a gap.
    pub fn state_default_quota(&mut self) {
        self.quota
            .entry(Self::QUOTA_EVERYONE.to_string())
            .or_insert(DEFAULT_QUOTA_STORAGE_GIB);
    }

    /// Whether this pool is reachable from `node`. An empty list is every
    /// node — see the field.
    pub fn reaches(&self, node: &str) -> bool {
        self.nodes.is_empty() || self.nodes.iter().any(|n| n == node)
    }

    /// Every cluster that serves this pool, in the operator's own order.
    ///
    /// One function so that nothing else in the tree has to know there are
    /// two spellings: `spec.clusters` when it is a list, `spec.cluster` when
    /// it is the short form for one, and both when somebody wrote both (the
    /// short form first, and never twice). Empty is a pool that names no
    /// cluster at all, which the create edge refuses and which therefore only
    /// exists on an object somebody edited afterwards.
    pub fn served_by(&self) -> Vec<&str> {
        let mut out: Vec<&str> = Vec::with_capacity(1 + self.clusters.len());
        if !self.cluster.is_empty() {
            out.push(self.cluster.as_str());
        }
        for c in &self.clusters {
            if !c.is_empty() && !out.contains(&c.as_str()) {
                out.push(c.as_str());
            }
        }
        out
    }

    /// Where a volume out of this pool is made when nobody has said
    /// otherwise: the first cluster it names.
    ///
    /// A pool spanning clusters still has ONE home, because provisioning
    /// happens once and somewhere. Which cluster's record holds a given
    /// volume afterwards is the volume's own answer
    /// (`VolumeStatus::cluster`), and it is what moves when the VM does.
    pub fn home(&self) -> Option<&str> {
        self.served_by().first().copied()
    }

    /// Whether this pool is served by `cluster`.
    pub fn serves(&self, cluster: &str) -> bool {
        self.served_by().contains(&cluster)
    }

    /// Whether the clusters that serve this pool agree about what it IS.
    ///
    /// The check behind "a `shared` pool crosses clusters only if both mount
    /// the same export". It cannot be asked of `spec` — a cloud pool is a
    /// REFERENCE to a pool that exists on each cluster, and what those two
    /// pools are made of is written down there — so it is asked of the
    /// evidence each cluster sends up about its own object.
    ///
    /// `None` while fewer than two clusters have reported: silence is not
    /// disagreement, and a pool nobody has spoken about yet must not be a
    /// refusal. `Some((a, b))` names the first two that differ.
    pub fn disagreeing(status: &StoragePoolStatus) -> Option<(&str, &str)> {
        let mut seen: Option<&PoolAtCluster> = None;
        for entry in &status.clusters {
            match seen {
                None => seen = Some(entry),
                Some(first) if first.params != entry.params => {
                    return Some((first.cluster.as_str(), entry.cluster.as_str()));
                }
                Some(_) => {}
            }
        }
        None
    }
}

/// What ONE cluster says about its own pool of this name.
///
/// The cloud object is a reference to as many real pools as it names
/// clusters, and until this there was nowhere to put the second one's answer:
/// `status.locality` and `status.nodes` are single-valued and were written by
/// whichever cluster reported last. That was harmless while a pool named one
/// cluster and is a silent overwrite the moment it names two.
///
/// Evidence, whole: each cluster replaces its own entry and no other's.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PoolAtCluster {
    pub cluster: String,
    #[serde(default)]
    pub phase: StoragePoolPhaseKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locality: Option<Locality>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nodes: Vec<String>,
    /// The backend options that cluster's own pool carries, verbatim.
    ///
    /// The one field here that is not a repeat of the flat status beside it,
    /// and the reason this struct exists: two clusters claiming to serve one
    /// `shared` pool are only telling the truth if they mount the same
    /// export, and this is where that can be compared. `None` from a cluster
    /// whose pool names no options, and from every cluster older than the
    /// field — which reads as "did not say" and never as "the same".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Where a pool is, and where its bytes are.
///
/// No capacity in it, and honestly so: how much room is left is a question
/// about the volumes, which are their own objects and are counted when asked.
/// A number cached here would be a number that is wrong after every create.
///
/// What IS here is the one fact an operator cannot look up anywhere else. The
/// locality is not in `spec` and never will be — it is the DRIVER's answer,
/// collected from the nodes that run it, and an admin who could type it would
/// be able to tell the scheduler that an LVM pool is shared.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct StoragePoolStatus {
    #[serde(default)]
    pub phase: StoragePoolPhaseKind,
    /// Where this pool's bytes are, as the nodes that can reach it agree.
    /// `None` while nobody has said — no node in the pool runs the driver
    /// yet, or every one of them predates the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locality: Option<Locality>,
    /// The nodes that can reach this pool, as the tier that owns them says.
    ///
    /// At the CLUSTER this stays empty — `spec.nodes` is the operator's own
    /// statement there and status would only repeat it. At the CLOUD it is
    /// mirrored up from the cluster and is the only thing that knows: a cloud
    /// admin writes `spec.cluster` and nothing about machines, and the cloud
    /// still has to answer "could a VM using this disk run over there".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nodes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Which namespace of this pool belongs to which volume: the NQN as the
    /// pool's params spell it, to the volume's uid.
    ///
    /// Empty for every pool that does not hand out countable pieces, which is
    /// nearly all of them — an lvm-thin pool cuts a new logical volume per
    /// request and there is nothing to assign.
    ///
    /// The table is HERE, on the pool, because a compare-and-swap on one
    /// object is the whole of the lock: two replicas reaching for the last
    /// free namespace both write, one loses, and the loser reads the table
    /// again. A second object would have made the assignment two writes that
    /// can disagree.
    ///
    /// Why it is `status` and not `spec`: the pool's SPEC is what an operator
    /// wrote down (the target, its port, the namespaces it exports) and this
    /// is what the control plane has done with it. See the cluster's
    /// `reconcile::namespaces` for the defect it answers — a claim file on
    /// one node cannot lock a pool the whole cluster reaches.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub claims: BTreeMap<String, String>,
    /// The same three facts, once per cluster that serves this pool.
    ///
    /// The flat fields above stay what they always were — the HOME cluster's
    /// answer — so a pool naming one cluster reads exactly as before. This is
    /// what a pool naming two needs and could not have: which of them said
    /// what, and whether the two are describing the same bytes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub clusters: Vec<PoolAtCluster>,
}

reasons! {
    /// Why a pool is what it is.
    ///
    /// Five. `AwaitingNode` and `Disagreement` are the two sentences
    /// `reconcile_pools` already writes — "nobody has said anything about it
    /// yet" and "two binaries of different ages on one pool". The two
    /// cluster words come from D-C11: a pool at the CLOUD is a pointer at one
    /// a cluster admin already made, and a pointer at nothing stood on
    /// `Pending` for six minutes without saying which half was missing.
    StoragePoolReason [5] {
        /// Nobody recorded one — see `VmReason::Unrecorded`.
        #[default]
        Unrecorded => "Unrecorded",
        /// Nobody serving it has said anything yet: every node in it is down,
        /// or none runs the driver, or the pool is seconds old.
        AwaitingNode => "AwaitingNode",
        /// The nodes serving it do not agree about what it is.
        Disagreement => "Disagreement",
        /// At the cloud: the cluster this pointer names has not reported.
        ClusterSilent => "ClusterSilent",
        /// At the cloud: the cluster reports, and names no pool by this name.
        /// The whole of D-C11 — the cluster half was never made.
        ClusterHasNoPool => "ClusterHasNoPool",
    }
}

phases! {
    /// Whether this pool's own description holds together.
    ///
    /// Three states and no `Deleting`: a pool owns nothing, so there is no
    /// teardown to be in the middle of — the delete handler simply refuses while
    /// volumes point at it.
    StoragePoolPhase / StoragePoolPhaseKind / StoragePoolReason / StoragePoolPhaseWire [3] {
        /// Nobody has said anything about it yet. A pool whose nodes are all down,
        /// and every pool for the first few seconds of its life.
        Pending { reason, message, since } => "Pending",
        /// The nodes that serve it agree about what it is.
        Ready { message, since } => "Ready",
        /// They do not. See the message, and see `reconcile_pools` for the
        /// only way this happens: two binaries of different ages on one pool.
        Failed { reason, message, since } => "Failed",
    }
}

/// No finalizer: a pool owns nothing. What keeps it from vanishing under a
/// volume is the delete handler's refusal, exactly as with a floating pool.
pub type StoragePool = Object<StoragePoolSpec, StoragePoolStatus>;
