// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Storage pool configuration, reachability and reported backend state.

use super::*;

/// Storage backend configuration, reachable nodes, and per-tenant limits. Nodes explicitly
/// describe physical access; an empty list imposes no node constraint.
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
    /// Per-tenant quota in GiB. A named tenant overrides the `*` entry, which overrides
    /// DEFAULT_QUOTA_STORAGE_GIB. Read paths materialize the effective default.
    ///
    /// [`QUOTA_EVERYONE`]: StoragePoolSpec::QUOTA_EVERYONE
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub quota: BTreeMap<String, u64>,
    /// Home cluster for a cloud pool reference. Cloud pools refer to existing
    /// cluster pools; they do not define backend storage there. Empty at the
    /// cluster tier. `served_by` combines this field with `clusters`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cluster: String,
    /// Additional clusters reaching the same backend. Shared and networked storage can span
    /// clusters when their reported backend settings agree.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub clusters: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
}

/// Default tenant ceiling when neither a named quota nor the `*` entry is configured.
pub const DEFAULT_QUOTA_STORAGE_GIB: u64 = 100;

impl StoragePoolSpec {
    /// Quota map key used for tenants without an explicit entry.
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

    /// Materialize the effective default quota for API reads without changing a tenant-specific
    /// ceiling.
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

    /// All serving clusters in operator order, including the primary cluster without
    /// duplicates.
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

    /// Default cluster for a volume unless placement specifies another serving cluster.
    pub fn home(&self) -> Option<&str> {
        self.served_by().first().copied()
    }

    /// Whether this pool is served by `cluster`.
    pub fn serves(&self, cluster: &str) -> bool {
        self.served_by().contains(&cluster)
    }

    /// Compare the backend evidence reported by serving clusters. Return the first disagreeing
    /// pair, or None while fewer than two clusters have reported. Missing evidence alone is not
    /// disagreement.
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

/// One cluster's complete pool observation. Each cluster replaces only its own entry,
/// preserving evidence from other serving clusters.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PoolAtCluster {
    pub cluster: String,
    #[serde(default)]
    pub phase: StoragePoolPhaseKind,
    /// And WHY, in the same closed word the cluster derived it with — a pool
    /// has one vocabulary because no node ever says anything about one, so
    /// this travels up and back into the same enum unchanged.
    ///
    /// `Unrecorded` from a cluster older than the field, which is what a
    /// `Ready` also carries: a pool that holds together has nothing to add.
    #[serde(default, skip_serializing_if = "is_unrecorded_pool_reason")]
    pub reason: StoragePoolReason,
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

/// Observed pool locality and reachability. Capacity usage is computed from volumes; locality
/// comes from drivers rather than an administrator-supplied spec.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct StoragePoolStatus {
    /// The phase, with the reason it is that phase and since when.
    ///
    /// Flat on the wire — `phase`, `reason`, `message`, `since` as siblings
    /// right here — so every client that reads `status.phase` as a string
    /// goes on reading it as a string. See `resources::phase`.
    #[serde(flatten)]
    pub(super) phase: StoragePoolPhase,
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
    /// Namespace NQN to volume UID assignments for pools with finite namespaces.
    /// Assignments share the pool object so CAS prevents concurrent allocation of
    /// the same namespace. Empty for backends that allocate a new object per
    /// volume. Operator-provided namespaces remain in spec; assignments are status.
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
    /// Node pair reporting conflicting driver locality at the cluster tier. The phase
    /// derivation formats this evidence. Absent for healthy pools and cloud objects, which have
    /// no local nodes to compare.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disagreement: Option<PoolDisagreement>,
    /// Whether the named cluster has ever reported. This distinguishes an unseen cluster from a
    /// reporting cluster missing the pool. The value is retained when a cluster goes quiet;
    /// phase age is handled by stuck detection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pointer_target: Option<PoolPointer>,
}

/// Two nodes of one pool that do not agree about its driver.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PoolDisagreement {
    pub node: String,
    pub says: Locality,
    pub other: String,
    pub other_says: Locality,
}

/// That the cluster a cloud pool points at has spoken.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PoolPointer {
    /// Which cluster — compared against `spec.home()`, so that repointing a
    /// pool at another cluster does not read as evidence about the new one.
    pub cluster: String,
    /// When it last reported, whether or not it named this pool.
    pub reported_at: DateTime<Utc>,
}

reasons! {
    /// Pool reason categories derived by controllers from driver and cluster observations.
    /// Nodes report driver locality rather than pool reasons. Preserve the derived category
    /// when mirroring between controller tiers.
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
    StoragePoolPhase / StoragePoolPhaseKind / StoragePoolReason / StoragePoolPhaseWire / StoragePoolReported [3] {
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

impl StoragePoolPhaseKind {
    /// The nodes agree, and there is nothing in flight to be late.
    ///
    /// `Failed` is not an end, and that is deliberate: two binaries of
    /// different ages on one pool is a state a rollout leaves and a rollout
    /// clears, so a pool that has been inconsistent for a quarter of an hour
    /// is a rollout that stopped half way — which is worth a number.
    pub fn is_terminal(self) -> bool {
        matches!(self, StoragePoolPhaseKind::Ready)
    }
}

/// No finalizer: a pool owns nothing. What keeps it from vanishing under a
/// volume is the delete handler's refusal, exactly as with a floating pool.
pub type StoragePool = Object<StoragePoolSpec, StoragePoolStatus>;

fn is_unrecorded_pool_reason(reason: &StoragePoolReason) -> bool {
    *reason == StoragePoolReason::Unrecorded
}

/// Derive pool phase for both tiers. Pools naming clusters are cloud
/// references; pools without them describe cluster storage.
///
/// Local pools fail on conflicting locality reports, become Ready when a node
/// reports reachability, and otherwise wait for a node. Cloud references relay
/// cluster pool observations and distinguish a silent cluster from a cluster
/// that reported no pool of this name.
pub fn settle_storage_pool(
    name: &str,
    spec: &StoragePoolSpec,
    status: &StoragePoolStatus,
) -> StoragePoolPhase {
    if let Some(home) = spec.home() {
        // A pointer. `status.clusters` is evidence-whole per reporter, so the
        // home cluster's entry is there exactly while that cluster is saying
        // it has such a pool.
        if let Some(entry) = status.clusters.iter().find(|e| e.cluster == home) {
            return StoragePoolPhase::new(
                entry.phase,
                entry.reason,
                entry.message.clone(),
                UNSTAMPED,
            );
        }
        let spoken = status
            .pointer_target
            .as_ref()
            .is_some_and(|p| p.cluster == home);
        return StoragePoolPhase::new(
            StoragePoolPhaseKind::Pending,
            if spoken {
                StoragePoolReason::ClusterHasNoPool
            } else {
                StoragePoolReason::ClusterSilent
            },
            Some(if spoken {
                format!("{home} reports no pool named {name}")
            } else {
                format!("{home} has not reported")
            }),
            UNSTAMPED,
        );
    }
    if let Some(split) = &status.disagreement {
        return StoragePoolPhase::new(
            StoragePoolPhaseKind::Failed,
            StoragePoolReason::Disagreement,
            Some(format!(
                "nodes disagree about storage driver {}: {} says {}, {} says {}; \
                 that is a version mix, not a setting",
                spec.driver,
                split.other,
                split.other_says.as_str(),
                split.node,
                split.says.as_str()
            )),
            UNSTAMPED,
        );
    }
    match status.locality {
        Some(_) => StoragePoolPhase::said(StoragePoolPhaseKind::Ready, None, UNSTAMPED),
        None => StoragePoolPhase::new(
            StoragePoolPhaseKind::Pending,
            StoragePoolReason::AwaitingNode,
            Some(format!(
                "no node serving {name} has said anything about driver {} yet",
                spec.driver
            )),
            UNSTAMPED,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + secs, 0).expect("an instant")
    }

    fn pool(cluster: Option<&str>) -> StoragePool {
        StoragePool::declare(
            "mc-fs",
            StoragePoolSpec {
                driver: "nfs".to_string(),
                cluster: cluster.unwrap_or_default().to_string(),
                ..Default::default()
            },
        )
    }

    /// Cloud pool state distinguishes an unseen cluster from a reporting cluster that lacks the
    /// named pool.
    #[test]
    fn a_pointer_at_nothing_says_which_half_is_missing() {
        // Nothing has ever reported.
        let mut silent = pool(Some("cluster-1"));
        silent.settle(at(0));
        assert_eq!(silent.status.phase().kind(), StoragePoolPhaseKind::Pending);
        assert_eq!(
            silent.status.phase().reason(),
            Some(StoragePoolReason::ClusterSilent)
        );
        assert_eq!(
            silent.status.phase().message(),
            Some("cluster-1 has not reported")
        );

        // The cluster reported, and has no pool of that name. That is the
        // half nothing recorded: the ingest used to `continue` and leave the
        // object exactly as it was.
        let mut spoke = pool(Some("cluster-1"));
        spoke.status.pointer_target = Some(PoolPointer {
            cluster: "cluster-1".to_string(),
            reported_at: at(0),
        });
        spoke.settle(at(10));
        assert_eq!(
            spoke.status.phase().reason(),
            Some(StoragePoolReason::ClusterHasNoPool)
        );
        assert_eq!(
            spoke.status.phase().message(),
            Some("cluster-1 reports no pool named mc-fs")
        );

        // And a pointer repointed at another cluster does not read the old
        // cluster's report as evidence about the new one.
        let mut moved = pool(Some("cluster-2"));
        moved.status.pointer_target = Some(PoolPointer {
            cluster: "cluster-1".to_string(),
            reported_at: at(0),
        });
        moved.settle(at(10));
        assert_eq!(
            moved.status.phase().reason(),
            Some(StoragePoolReason::ClusterSilent)
        );
    }

    /// The cluster has such a pool: its own word, relayed and not reworded.
    /// One vocabulary, so the cloud parses back exactly what the cluster
    /// derived.
    #[test]
    fn a_pointer_at_a_real_pool_carries_the_clusters_own_word() {
        let mut pointer = pool(Some("cluster-1"));
        pointer.status.pointer_target = Some(PoolPointer {
            cluster: "cluster-1".to_string(),
            reported_at: at(0),
        });
        pointer.status.clusters = vec![PoolAtCluster {
            cluster: "cluster-1".to_string(),
            phase: StoragePoolPhaseKind::Ready,
            reason: StoragePoolReason::Unrecorded,
            locality: Some(Locality::Shared),
            nodes: vec!["agent-1a".to_string()],
            params: None,
            message: None,
        }];
        pointer.settle(at(0));
        assert_eq!(pointer.status.phase().kind(), StoragePoolPhaseKind::Ready);

        // A second serving cluster's entry does not speak for the pointer:
        // the flat fields are the HOME cluster's answer, and that has not
        // changed.
        pointer.status.clusters.push(PoolAtCluster {
            cluster: "cluster-2".to_string(),
            phase: StoragePoolPhaseKind::Failed,
            reason: StoragePoolReason::Disagreement,
            locality: None,
            nodes: Vec::new(),
            params: None,
            message: Some("two ages".to_string()),
        });
        pointer.settle(at(60));
        assert_eq!(pointer.status.phase().kind(), StoragePoolPhaseKind::Ready);
        assert_eq!(
            pointer.status.phase().since(),
            at(0),
            "the word did not move"
        );
    }

    /// The cluster tier, which has nodes instead of a pointer. Three rows,
    /// and the order matters: a disagreement is read BEFORE the locality,
    /// because the locality is deliberately kept through one.
    #[test]
    fn a_real_pool_is_what_the_nodes_that_reach_it_say() {
        let mut unheard = pool(None);
        unheard.settle(at(0));
        assert_eq!(unheard.status.phase().kind(), StoragePoolPhaseKind::Pending);
        assert_eq!(
            unheard.status.phase().reason(),
            Some(StoragePoolReason::AwaitingNode)
        );

        let mut agreed = pool(None);
        agreed.status.locality = Some(Locality::Shared);
        agreed.settle(at(0));
        assert_eq!(agreed.status.phase().kind(), StoragePoolPhaseKind::Ready);
        assert_eq!(agreed.status.phase().reason(), None, "a resting word");

        let mut split = pool(None);
        split.status.locality = Some(Locality::Shared);
        split.status.disagreement = Some(PoolDisagreement {
            node: "soller".to_string(),
            says: Locality::NodeLocal,
            other: "manacor".to_string(),
            other_says: Locality::Shared,
        });
        split.settle(at(0));
        assert_eq!(
            split.status.phase().kind(),
            StoragePoolPhaseKind::Failed,
            "the disagreement is read before the locality it kept"
        );
        assert_eq!(
            split.status.phase().reason(),
            Some(StoragePoolReason::Disagreement)
        );
    }
}
