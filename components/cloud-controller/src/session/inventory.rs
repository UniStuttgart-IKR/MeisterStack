// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The four kinds a cluster mirrors upward beside its vms: images, storage
//! pools, volume snapshots and volumes.
//!
//! Each is a report the cluster owns and this cloud only keeps a copy of, so
//! each writes the copy and none of them stops the others. Verbatim out of
//! `session.rs`.

use super::*;

/// What the fleet has learned about a base image, onto the Image object.
///
/// This is the whole reason the phase is not something the cloud decides by
/// itself: the NODE is what fetches a URL image, so whether the bytes are
/// obtainable and hash to what the spec said is a fact only a node can
/// establish. The report is that fact travelling up.
///
/// Written only when it CHANGED. A cluster reports every ten seconds and says
/// the same thing every time; a write per report would churn etcd revisions
/// and wake the image watch for nothing — the same rule
/// `controller_api::mirror` applies to a VM phase, applied by hand here
/// because there is one field and no index to build.
///
/// An image the cloud does not know is skipped rather than created: a cluster
/// naming one is a cluster with a stale spec or a node with a leftover cache
/// entry, and inventing a catalogue entry for it would be this control plane
/// making up an image nobody registered.
pub(super) async fn ingest_images(
    store: &EtcdStore,
    cluster: &str,
    reports: &[proto::ImageStateReport],
) {
    for (name, lines) in by_image(reports) {
        let Some((phase, message, mine)) = compute_union(cluster, name, &lines) else {
            continue;
        };
        let current = match store.get::<Image>(name).await {
            Ok(image) => image,
            Err(StoreError::NotFound(_)) => {
                debug!(cluster, image = %name, "status for an image this cloud has not got");
                continue;
            }
            Err(e) => {
                warn!(image = %name, error = format!("{e:#}"), "reading the image failed");
                continue;
            }
        };
        let merged = merged_lines(&current, cluster, mine);
        if current.status.phase().kind() == phase
            && current.status.phase().message() == message.as_deref()
            && same_node_states(&current.status.nodes, &merged)
        {
            continue;
        }
        let result = store
            .mutate::<Image, _>(name, |i| {
                #[allow(deprecated)]
                i.status.assign(controller_api::ImagePhase::new(
                    phase,
                    controller_api::ImageReason::Reported,
                    message.clone(),
                    chrono::Utc::now(),
                ));
                i.status.nodes = merged.clone();
            })
            .await;
        match result {
            Ok(_) => info!(image = %name, ?phase, cluster, nodes = merged.len(),
                           "image phase observed"),
            Err(e) => warn!(image = %name, error = format!("{e:#}"),
                            "writing image status failed"),
        }
    }
}

/// The report's lines, grouped by the image they are about.
///
/// One line per image per node since the cluster stopped merging. The merge
/// is here now, which is where both halves are wanted: the union is what
/// `status.phase` says, and the lines are what `status.nodes[]` is.
///
/// A cluster older than the field sends the already-merged form with an empty
/// `node`. It groups to one entry, the union of one thing is itself, and it
/// contributes no lines — which is exactly how it was read before.
fn by_image(
    reports: &[proto::ImageStateReport],
) -> std::collections::BTreeMap<&str, Vec<&proto::ImageStateReport>> {
    let mut by_image: std::collections::BTreeMap<&str, Vec<&proto::ImageStateReport>> =
        Default::default();
    for report in reports {
        by_image
            .entry(report.name.as_str())
            .or_default()
            .push(report);
    }
    by_image
}

/// What one cluster's lines about one image add up to: the phase the whole
/// cluster is at, the sentence that came with it, and this cluster's lines.
///
/// `None` when not one line could be read, which is the case in which there
/// is nothing to write.
fn compute_union(
    cluster: &str,
    name: &str,
    lines: &[&proto::ImageStateReport],
) -> Option<(
    ImagePhaseKind,
    Option<String>,
    Vec<controller_api::ImageNodeState>,
)> {
    let mut union: Option<(ImagePhaseKind, Option<String>)> = None;
    let mut nodes: Vec<controller_api::ImageNodeState> = Vec::new();
    for line in lines {
        let Some(phase) = ImagePhaseKind::parse(&line.phase) else {
            // A drifting peer should be visible, not silently "Pending" —
            // the rule VmPhaseKind::parse states one tier down.
            warn!(cluster, image = %name, phase = %line.phase,
                  "unknown image phase from cluster");
            continue;
        };
        let message = (!line.message.is_empty()).then(|| line.message.clone());
        // Failed wins over Ready where two nodes disagree: a checksum that
        // did not match is a fact about the BYTES, not about the node that
        // read them. The sentence travels with the phase that won, so a
        // Failed union carries the reason one of them gave.
        let beats = match &union {
            None => true,
            Some((held, _)) => *held != ImagePhaseKind::Failed && phase == ImagePhaseKind::Failed,
        };
        if beats {
            union = Some((phase, message.clone()));
        }
        if !line.node.is_empty() {
            nodes.push(controller_api::ImageNodeState {
                name: line.node.clone(),
                cluster: cluster.to_string(),
                phase,
                message,
            });
        }
    }
    let (phase, message) = union?;
    // This cluster's lines replace this cluster's lines and nobody else's.
    // That is what `ImageNodeState::cluster` is for: two clusters may each
    // have a `node-1`, and a list keyed by the bare name would let one
    // overwrite the other's word.
    nodes.sort_by(|a, b| (&a.cluster, &a.name).cmp(&(&b.cluster, &b.name)));
    Some((phase, message, nodes))
}

/// The image's node list with this cluster's share of it replaced.
fn merged_lines(
    current: &Image,
    cluster: &str,
    mine: Vec<controller_api::ImageNodeState>,
) -> Vec<controller_api::ImageNodeState> {
    let mut merged: Vec<controller_api::ImageNodeState> = current
        .status
        .nodes
        .iter()
        .filter(|n| n.cluster != cluster)
        .cloned()
        .collect();
    merged.extend(mine);
    merged.sort_by(|a, b| (&a.cluster, &a.name).cmp(&(&b.cluster, &b.name)));
    merged
}

/// Two node lists that say the same thing.
///
/// Written out rather than derived, because `ImageNodeState` is an API type
/// and giving it `PartialEq` would be making a promise about it that nothing
/// else needs. Every cluster reports every ten seconds and almost every
/// report says what the last one said; a write per report would churn etcd
/// revisions while nothing about the image happened.
pub(super) fn same_node_states(
    a: &[controller_api::ImageNodeState],
    b: &[controller_api::ImageNodeState],
) -> bool {
    a.len() == b.len()
        && a.iter().zip(b).all(|(x, y)| {
            x.name == y.name
                && x.cluster == y.cluster
                && x.phase == y.phase
                && x.message == y.message
        })
}

/// A cluster status is the cluster's heartbeat, the aggregate the cloud places
/// against, and the phase of every VM it holds for us.
///
/// Every session's status is a heartbeat; only the speaker's is a description
/// (see `SessionRegistry::speaker`). A standby replica reads the same cluster
/// etcd, so its aggregate is not wrong — it is merely a second, slightly older
/// account of the same thing, and letting two accounts write the same fields
/// buys nothing but a phase that walks backwards for one interval.
/// Mirror what a cluster says its storage pools ARE onto the cloud's pools.
///
/// A cloud pool is a pointer: an admin writes `spec.cluster` and a driver
/// name and nothing about machines. Everything else — whether the pool holds
/// together, where its bytes are, which nodes reach it — is decided down
/// there by the drivers that run, and this is the only road it travels.
///
/// The locality is the field that earns the whole message. Without it the
/// cloud cannot answer "could a VM that uses this disk run on that cluster",
/// because the answer for a `node-local` pool is "only on the one node that
/// holds the bytes" and for a `shared` one is "anywhere in the pool".
pub(super) async fn ingest_pools(
    store: &EtcdStore,
    cluster: &str,
    status: &ClusterStatus,
) -> anyhow::Result<()> {
    for pool in store.list::<controller_api::StoragePool>().await? {
        if !pool.spec.serves(cluster) {
            continue;
        }
        // The HOME cluster is the one whose answer the flat fields carry, so
        // a pool naming one cluster reads exactly as it always did. Every
        // serving cluster, home included, gets its own entry in
        // `status.clusters` — which is what a pool naming two needs and what
        // makes "do these two describe the same backend" a question with an
        // answer.
        let home = pool.spec.home() == Some(cluster);
        let Some(reported) = status.pools.iter().find(|p| p.name == pool.metadata.name) else {
            // The cluster does not have a pool of that name. Not an error and
            // not a reason to blank the status: a cloud pool may be written
            // before the cluster's own is, and the volumes in it stay Pending
            // with a sentence that says so.
            continue;
        };
        let entry = pool_entry(cluster, reported);
        let (phase, locality, message) = (entry.phase, entry.locality, entry.message.clone());
        if pool_unchanged(&pool, home, &entry, reported) {
            continue;
        }
        store
            .mutate::<controller_api::StoragePool, _>(&pool.metadata.name, |p| {
                if home {
                    p.status.locality = locality;
                    p.status.nodes = reported.nodes.clone();
                    #[allow(deprecated)]
                    p.status.assign(controller_api::StoragePoolPhase::new(
                        phase,
                        controller_api::StoragePoolReason::Reported,
                        message.clone(),
                        chrono::Utc::now(),
                    ));
                }
                // Each cluster replaces its own entry and no other's — the
                // same "evidence, whole" rule the node list one field over
                // follows, applied per reporter.
                p.status.clusters.retain(|e| e.cluster != cluster);
                p.status.clusters.push(entry.clone());
                p.status.clusters.sort_by(|a, b| a.cluster.cmp(&b.cluster));
            })
            .await?;
        debug!(pool = %pool.metadata.name, cluster, phase = phase.as_str(),
               "storage pool observed");
    }
    Ok(())
}

/// What one cluster says about one pool, as the cloud keeps it.
///
/// The translation and nothing else: every field comes out of the report, and
/// what the report leaves empty stays absent rather than becoming a default.
fn pool_entry(
    cluster: &str,
    reported: &proto::StoragePoolStatusReport,
) -> controller_api::PoolAtCluster {
    // Empty is "the cluster does not know", and it must not become
    // `node-local` on the way in — `parse` returning None is exactly that.
    let locality = controller_api::Locality::parse(&reported.locality);
    // Empty params are "did not say" and stay `None`, which is what makes
    // a cluster older than the field silent rather than disagreeing:
    // `disagreeing` compares two values, and one of them being absent is
    // not two values that differ.
    let params: Option<serde_json::Value> = (!reported.params_json.is_empty())
        .then(|| serde_json::from_str(&reported.params_json).ok())
        .flatten();
    controller_api::PoolAtCluster {
        cluster: cluster.to_string(),
        phase: controller_api::StoragePoolPhaseKind::parse(&reported.phase).unwrap_or_default(),
        locality,
        nodes: reported.nodes.clone(),
        params,
        message: (!reported.message.is_empty()).then(|| reported.message.clone()),
    }
}

/// Whether the object already says what this report says — this cluster's own
/// entry, and the flat fields too where this cluster is the home one.
fn pool_unchanged(
    pool: &controller_api::StoragePool,
    home: bool,
    entry: &controller_api::PoolAtCluster,
    reported: &proto::StoragePoolStatusReport,
) -> bool {
    pool.status.clusters.contains(entry)
        && (!home
            || (pool.status.phase().kind() == entry.phase
                && pool.status.locality == entry.locality
                && pool.status.nodes == reported.nodes
                && pool.status.phase().message() == entry.message.as_deref()))
}

/// The same road as `ingest_volumes`, one object over, with the one hop more
/// that a snapshot's home takes: it names a volume, the volume names the
/// pool, the pool names the cluster.
///
/// Everything written here is EVIDENCE, and absence from a COMPLETE list is
/// the proof that the copy is gone.
pub(super) async fn ingest_snapshots(
    store: &EtcdStore,
    cluster: &str,
    status: &ClusterStatus,
    at: DateTime<Utc>,
) -> anyhow::Result<()> {
    let ours = snapshots_of(store, cluster).await?;
    if ours.is_empty() {
        return Ok(());
    }
    for snapshot in &ours {
        let reported = status
            .snapshots
            .iter()
            .find(|r| r.uid == snapshot.metadata.uid);
        let Some(reported) = reported else {
            finish_snapshot_delete(store, snapshot, cluster, status, at).await?;
            continue;
        };
        let Some(phase) = controller_api::VolumeSnapshotPhaseKind::parse(&reported.phase) else {
            warn!(snapshot = %snapshot.metadata.name, phase = %reported.phase,
                  "unknown snapshot phase from cluster");
            continue;
        };
        if snapshot_unchanged(snapshot, reported, phase) {
            continue;
        }
        store
            .mutate::<controller_api::VolumeSnapshot, _>(&snapshot.metadata.name, |s| {
                write_snapshot_status(s, reported, phase, at)
            })
            .await?;
        debug!(snapshot = %snapshot.metadata.name, cluster, phase = phase.as_str(),
               "snapshot observed");
    }
    Ok(())
}

/// Mirror a cluster's word about its volumes onto this cloud's objects, and
/// finish a delete when the volume stops being named.
///
/// The uid is the key, exactly as it is for VMs: this cloud handed it out on
/// `CreateVolume` and the cluster speaks it back. Everything written here is
/// EVIDENCE — phase, node, holder, message — and this tier writes none of it
/// itself.
///
/// Absence from a COMPLETE list is the proof of teardown, and that is the one
/// place this differs from the road one tier further down: there the reporter
/// is a node, which knows only what it was told, so absence proves nothing;
/// here the reporter is a control plane that owns the objects and says
/// whether it managed to read all of them.
pub(super) async fn ingest_volumes(
    store: &EtcdStore,
    cluster: &str,
    status: &ClusterStatus,
    at: DateTime<Utc>,
) -> anyhow::Result<()> {
    let ours = volumes_of(store, cluster).await?;
    if ours.is_empty() {
        return Ok(());
    }
    for volume in &ours {
        let reported = status
            .volumes
            .iter()
            .find(|r| Some(r.uid.as_str()) == Some(volume.metadata.uid.as_str()));
        let Some(reported) = reported else {
            finish_volume_delete(store, volume, cluster, status, at).await?;
            continue;
        };
        let Some(phase) = VolumePhaseKind::parse(&reported.phase) else {
            warn!(volume = %volume.metadata.name, phase = %reported.phase,
                  "unknown volume phase from cluster");
            continue;
        };
        if volume_unchanged(volume, reported, phase) {
            continue;
        }
        store
            .mutate::<Volume, _>(&volume.metadata.name, |v| {
                write_volume_status(v, reported, phase, at)
            })
            .await?;
        debug!(volume = %volume.metadata.name, cluster, phase = phase.as_str(),
               "volume observed");
    }
    Ok(())
}

/// Which cluster each pool is at home on, read once for a whole report.
///
/// Per volume it would be a read amplification for a fact that barely ever
/// changes: a status arrives every ten seconds and names every object.
async fn pool_homes(
    store: &EtcdStore,
) -> anyhow::Result<std::collections::HashMap<String, String>> {
    Ok(store
        .list::<controller_api::StoragePool>()
        .await?
        .into_iter()
        .filter_map(|p| Some((p.metadata.name.clone(), p.spec.home()?.to_string())))
        .collect())
}

/// The volumes this cluster holds for the cloud.
///
/// Whose volume this is, is the VOLUME's answer now and the pool's only where
/// the volume has not been dispatched yet. A pool may name two clusters, and
/// then "the pool's cluster" is not a value — while `status.cluster` is
/// exactly the one the cloud handed this record to.
///
/// It matters most where it costs most: absence from a complete list is what
/// finishes a delete, and a volume that has MOVED is absent from its old
/// cluster's list for a reason that has nothing to do with deletion.
async fn volumes_of(store: &EtcdStore, cluster: &str) -> anyhow::Result<Vec<Volume>> {
    let serves = pool_homes(store).await?;
    let record_at = |v: &Volume| -> Option<String> {
        v.status
            .cluster
            .clone()
            .or_else(|| serves.get(&v.spec.pool).cloned())
    };
    Ok(store
        .list::<Volume>()
        .await?
        .into_iter()
        .filter(|v| record_at(v).as_deref() == Some(cluster))
        .collect())
}

/// The snapshots this cluster holds for the cloud, one hop further out than
/// the volumes: a snapshot names a volume, the volume names the pool, the
/// pool names the cluster.
///
/// A snapshot whose volume has already gone belongs to no cluster this pass
/// can name; it is left out rather than concluded about, because the
/// alternative is deleting an object on the strength of a list that was never
/// about it.
async fn snapshots_of(
    store: &EtcdStore,
    cluster: &str,
) -> anyhow::Result<Vec<controller_api::VolumeSnapshot>> {
    let serves = pool_homes(store).await?;
    let homes: std::collections::HashMap<String, String> = store
        .list::<Volume>()
        .await?
        .into_iter()
        .filter_map(|v| {
            let at = v
                .status
                .cluster
                .clone()
                .or_else(|| serves.get(&v.spec.pool).cloned())?;
            Some((v.metadata.name, at))
        })
        .collect();
    Ok(store
        .list::<controller_api::VolumeSnapshot>()
        .await?
        .into_iter()
        .filter(|s| homes.get(&s.spec.volume).map(String::as_str) == Some(cluster))
        .collect())
}

/// A volume the cluster did not name. Only a DELETED one may conclude
/// anything from that, and only from a list that is all of them: a volume
/// this cloud created a moment ago is simply not down there yet.
async fn finish_volume_delete(
    store: &EtcdStore,
    volume: &Volume,
    cluster: &str,
    status: &ClusterStatus,
    at: DateTime<Utc>,
) -> anyhow::Result<()> {
    if volume.metadata.deletion_timestamp.is_some()
        && status.volumes_complete
        && controller_api::mirror::is_current(
            volume.metadata.deletion_timestamp,
            volume.status.observed_at,
            at,
        )
    {
        store.delete::<Volume>(&volume.metadata.name).await?;
        info!(volume = %volume.metadata.name, cluster, "volume deleted");
    }
    Ok(())
}

/// The same rule for a snapshot the cluster did not name.
async fn finish_snapshot_delete(
    store: &EtcdStore,
    snapshot: &controller_api::VolumeSnapshot,
    cluster: &str,
    status: &ClusterStatus,
    at: DateTime<Utc>,
) -> anyhow::Result<()> {
    if snapshot.metadata.deletion_timestamp.is_some()
        && status.snapshots_complete
        && controller_api::mirror::is_current(
            snapshot.metadata.deletion_timestamp,
            snapshot.status.observed_at,
            at,
        )
    {
        store
            .delete::<controller_api::VolumeSnapshot>(&snapshot.metadata.name)
            .await?;
        info!(snapshot = %snapshot.metadata.name, cluster, "snapshot deleted");
    }
    Ok(())
}

/// What a reported name amounts to. Empty is silence — a cluster that has not
/// been told a name yet sends an empty string, and that is not a claim that
/// the name the cloud holds is wrong.
fn said(s: &str) -> Option<String> {
    (!s.is_empty()).then(|| s.to_string())
}

/// Whether the object already says everything this line says.
///
/// Every cluster reports every ten seconds, and a write per report would
/// churn etcd revisions while nothing about the volume happened. It does not
/// bite here as often as one tier up — this cluster's reconciler moves a
/// volume off Pending within a pass, and that IS a change — but a volume it
/// cannot move (no node serves the pool yet) sat at the default, was never
/// observed, and had its create re-sent every five seconds.
fn volume_unchanged(
    volume: &Volume,
    reported: &proto::VolumeStatusReport,
    phase: VolumePhaseKind,
) -> bool {
    // Seen at all: a volume nothing has ever been observed about is written
    // even when every field matches the default.
    let observed = volume.status.observed_at.is_some();
    // What the cluster decided about it.
    let same_verdict = volume.status.phase().kind() == phase
        && volume.status.node == said(&reported.node)
        && volume.status.attached_to == said(&reported.attached_to)
        && volume.status.phase().message() == said(&reported.message).as_deref();
    // What a node measured about it.
    let same_measurements =
        volume.status.size_gib == reported.size_gib && volume.status.open_on == reported.open_on;
    // The name only ever ARRIVES, so an empty one is silence and not a
    // difference — see `write_volume_status`.
    let same_backend = reported.backend.is_empty() || volume.status.backend == reported.backend;
    observed && same_verdict && same_measurements && same_backend
}

/// The reported line, onto the object.
fn write_volume_status(
    v: &mut Volume,
    reported: &proto::VolumeStatusReport,
    phase: VolumePhaseKind,
    at: DateTime<Utc>,
) {
    #[allow(deprecated)]
    v.status.assign(VolumePhase::new(
        phase,
        controller_api::VolumeReason::Reported,
        said(&reported.message),
        at,
    ));
    v.status.node = said(&reported.node);
    v.status.attached_to = said(&reported.attached_to);
    // The same rule as one tier down: the name only ever ARRIVES. A cluster
    // that has not been told it yet sends an empty string, and that is
    // silence, not a deletion.
    if !reported.backend.is_empty() {
        v.status.backend = reported.backend.clone();
    }
    // What the node MEASURED, beside what the spec asked for. Zero is "not
    // measured" and travels as it stands: a cluster older than the field says
    // nothing rather than saying zero.
    v.status.size_gib = reported.size_gib;
    // Who has it open, as the cluster sees it, whole: the cloud writes none
    // of this field itself, so mirroring the list is the only honest way to
    // hold it. A cluster older than the field sends nothing and the cloud
    // then shows nothing, which is what it knew before the field existed.
    v.status.open_on = reported.open_on.clone();
    v.status.observed_at = Some(at);
}

/// The same question one object over.
///
/// `observed_at` comes first here, because it is not a field of the report:
/// it is this cloud saying "the cluster has spoken about this", and the
/// dispatcher reads it to stop re-sending the create. A snapshot can
/// legitimately sit at Pending — nothing about it differs from the default
/// until a node takes the copy — so a mirror that wrote only on a CHANGE
/// would never write at all, and the create would go down every five seconds
/// for ever.
fn snapshot_unchanged(
    snapshot: &controller_api::VolumeSnapshot,
    reported: &proto::VolumeSnapshotStatusReport,
    phase: controller_api::VolumeSnapshotPhaseKind,
) -> bool {
    let observed = snapshot.status.observed_at.is_some();
    // What the cluster decided about the copy.
    let same_verdict = snapshot.status.phase().kind() == phase
        && snapshot.status.node == said(&reported.node)
        && snapshot.status.phase().message() == said(&reported.message).as_deref();
    // What a node measured about it.
    let same_size = snapshot.status.size_gib == reported.size_gib;
    // "Only ever arrives", as everywhere else.
    let same_backend = reported.backend.is_empty() || snapshot.status.backend == reported.backend;
    observed && same_verdict && same_size && same_backend
}

/// The reported line, onto the snapshot.
fn write_snapshot_status(
    s: &mut controller_api::VolumeSnapshot,
    reported: &proto::VolumeSnapshotStatusReport,
    phase: controller_api::VolumeSnapshotPhaseKind,
    at: DateTime<Utc>,
) {
    #[allow(deprecated)]
    s.status.assign(controller_api::VolumeSnapshotPhase::new(
        phase,
        controller_api::VolumeSnapshotReason::Reported,
        said(&reported.message),
        at,
    ));
    s.status.node = said(&reported.node);
    s.status.size_gib = reported.size_gib;
    // "Only ever arrives", as everywhere else: an empty name is silence and
    // not a claim that the old one is wrong.
    if !reported.backend.is_empty() {
        s.status.backend = reported.backend.clone();
    }
    s.status.observed_at = Some(at);
}
