// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Mirror cluster image, pool, volume and snapshot evidence.
//!
//! Each inventory is processed independently. Complete, sufficiently recent
//! volume and snapshot inventories can complete deletion; incomplete lists cannot.

use super::*;

/// Merge cluster evidence into registered catalogue images.
/// Complete node inventories contribute missing-file evidence. Unknown image
/// names do not create catalogue entries; unchanged evidence avoids a store write.
pub(super) async fn ingest_images(
    store: &EtcdStore,
    cluster: &str,
    reports: &[proto::ImageStateReport],
    nodes: &[proto::NodeReport],
) {
    let by_image = by_image(reports);
    // Nodes whose last report listed everything under their image directory.
    // For those, and only for those, a name that is not in the report is a
    // file that is not there (decision 4: `images_complete = false` means
    // "not saying", never "not there").
    let complete: Vec<&str> = nodes
        .iter()
        .filter(|n| n.images_complete)
        .map(|n| n.name.as_str())
        .collect();
    let catalogue = match store.list::<Image>().await {
        Ok(images) => images,
        Err(e) => {
            warn!(
                cluster,
                error = format!("{e:#}"),
                "reading the catalogue failed"
            );
            return;
        }
    };
    for current in catalogue {
        let name = current.metadata.name.clone();
        let lines: Vec<&proto::ImageStateReport> =
            by_image.get(name.as_str()).cloned().unwrap_or_default();
        let mine = lines_of(cluster, &name, &lines, &complete);
        let merged = merged_lines(&current, cluster, mine);
        if same_node_states(&current.status.nodes, &merged) {
            continue;
        }
        let result = store
            .mutate::<Image, _>(&name, |i| {
                // The FACT, and nothing else. What the fleet's words add up
                // to is `settle_image`, which the store runs on the way out —
                // so there is exactly one rule for "is this image usable" and
                // it cannot be written down in two places again.
                i.status.nodes = merged.clone();
                // Pinned once, inside the same read-modify-write `mutate`
                // already is: a second cluster reporting the same image at
                // the same moment re-reads `i.status.digest` fresh on every
                // retry, so the first write to land is the one that decides
                // it. Astra finding S02, 2026-09-23 (rest a).
                if i.status.digest.is_none() {
                    i.status.digest = controller_api::first_bound_digest(&merged);
                }
            })
            .await;
        match result {
            Ok(image) => info!(image = %name, phase = image.status.phase().kind().as_str(),
                               reason = image.status.phase().reason_word(), cluster,
                               nodes = merged.len(), "image observed"),
            Err(e) => warn!(image = %name, error = format!("{e:#}"),
                            "writing image status failed"),
        }
    }
}

/// Collect this cluster's image evidence, including absence from complete node
/// inventories. Incomplete or legacy inventories make no absence claim.
pub(super) fn lines_of(
    cluster: &str,
    name: &str,
    lines: &[&proto::ImageStateReport],
    complete: &[&str],
) -> Vec<controller_api::ImageNodeState> {
    let mut mine = node_states(cluster, name, lines);
    for node in complete {
        if mine.iter().any(|line| line.name == *node) {
            continue;
        }
        mine.push(controller_api::ImageNodeState {
            name: node.to_string(),
            cluster: cluster.to_string(),
            phase: ImagePhaseKind::Failed,
            reason: controller_api::ImageReason::NotFound,
            message: Some(format!("{node} has no file named {name}")),
            // Nothing was hashed: this line is a silence, not a look.
            digest: None,
        });
    }
    mine.sort_by(|a, b| (&a.cluster, &a.name).cmp(&(&b.cluster, &b.name)));
    mine
}

/// Group per-node image reports. Legacy merged reports have no node name
/// and contribute aggregate evidence without a per-node status entry.
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

/// Translate recognized per-node image reports into status entries.
/// Unknown phases and reports without a node name contribute no entry.
fn node_states(
    cluster: &str,
    name: &str,
    lines: &[&proto::ImageStateReport],
) -> Vec<controller_api::ImageNodeState> {
    let mut nodes: Vec<controller_api::ImageNodeState> = Vec::new();
    for line in lines {
        let Some(phase) = ImagePhaseKind::parse(&line.phase) else {
            // A drifting peer should be visible, not silently "Pending" —
            // the rule VmPhaseKind::parse states one tier down.
            warn!(cluster, image = %name, phase = %line.phase,
                  "unknown image phase from cluster");
            continue;
        };
        // A cluster older than `ImageStateReport.node` sends the already
        // merged form with an empty node, and there is nothing to file it
        // under. It only ever fed the union, and the union is `settle_image`
        // now — so such a cluster says nothing, which is the honest reading
        // of a line that names no machine.
        if line.node.is_empty() {
            continue;
        }
        let message = (!line.message.is_empty()).then(|| line.message.clone());
        // The node's own word for what is wrong with the bytes, which is why
        // the list is worth keeping per node at all: `FetchFailed` on one
        // machine during a roll-out and `ChecksumMismatch` everywhere are
        // both a failure, and only the second will never come right.
        let (reason, message) = controller_api::ImageReason::read(&line.reason, message);
        nodes.push(controller_api::ImageNodeState {
            name: line.node.clone(),
            cluster: cluster.to_string(),
            phase,
            reason,
            message,
            // Relayed and not re-derived, the same rule `reason` follows.
            // Astra finding S02, 2026-09-23 (rest a).
            digest: (!line.digest.is_empty()).then(|| line.digest.clone()),
        });
    }
    nodes
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

/// Compare image node evidence, including digest, to avoid unchanged writes.
pub(super) fn same_node_states(
    a: &[controller_api::ImageNodeState],
    b: &[controller_api::ImageNodeState],
) -> bool {
    a.len() == b.len()
        && a.iter().zip(b).all(|(x, y)| {
            x.name == y.name
                && x.cluster == y.cluster
                && x.phase == y.phase
                && x.reason == y.reason
                && x.message == y.message
                && x.digest == y.digest
        })
}

/// Mirror pool evidence from each serving cluster.
/// The home cluster also supplies the pointer status and compatibility flat fields.
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
        let reported = status.pools.iter().find(|p| p.name == pool.metadata.name);
        // D-C11. That the home cluster SPOKE is a fact of its own, and it is
        // the one nothing recorded: a pointer at a pool nobody made and a
        // pointer at a cluster that never connected both left the object at
        // its birth phase with no reason on it, and the chaos run watched one
        // do that for six minutes. Written before the `continue` below —
        // which is exactly the path that used to leave no trace at all.
        let spoke = home
            && pool
                .status
                .pointer_target
                .as_ref()
                .map(|p| p.cluster.as_str())
                != Some(cluster);
        let Some(reported) = reported else {
            // The cluster does not have a pool of that name. Not an error and
            // not a reason to blank the status: a cloud pool may be written
            // before the cluster's own is. What is new is that the object now
            // SAYS so — `settle_storage_pool` turns the pointer fact plus the
            // missing entry into `Pending { ClusterHasNoPool }`.
            if spoke || pool.status.clusters.iter().any(|e| e.cluster == cluster) {
                store
                    .mutate::<controller_api::StoragePool, _>(&pool.metadata.name, |p| {
                        note_pointer(p, cluster, home);
                        p.status.clusters.retain(|e| e.cluster != cluster);
                    })
                    .await?;
            }
            continue;
        };
        let entry = pool_entry(cluster, reported);
        let (locality, nodes) = (entry.locality, reported.nodes.clone());
        if !spoke && pool_unchanged(&pool, home, &entry, reported) {
            continue;
        }
        store
            .mutate::<controller_api::StoragePool, _>(&pool.metadata.name, |p| {
                note_pointer(p, cluster, home);
                if home {
                    p.status.locality = locality;
                    p.status.nodes = nodes.clone();
                }
                // Each cluster replaces its own entry and no other's — the
                // same "evidence, whole" rule the node list one field over
                // follows, applied per reporter. The FACT, and nothing else:
                // what the pointer therefore IS is `settle_storage_pool`.
                p.status.clusters.retain(|e| e.cluster != cluster);
                p.status.clusters.push(entry.clone());
                p.status.clusters.sort_by(|a, b| a.cluster.cmp(&b.cluster));
            })
            .await?;
        debug!(pool = %pool.metadata.name, cluster, phase = entry.phase.as_str(),
               "storage pool observed");
    }
    Ok(())
}

/// Record a report from the pool's home cluster for pointer status derivation.
fn note_pointer(pool: &mut controller_api::StoragePool, cluster: &str, home: bool) {
    if !home {
        return;
    }
    pool.status.pointer_target = Some(controller_api::PoolPointer {
        cluster: cluster.to_string(),
        reported_at: chrono::Utc::now(),
    });
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
        // A pool has ONE vocabulary: no node ever says a word about one, so
        // what arrives here is a word this tier's own enum spells and it is
        // parsed back rather than replaced with the name of the road it came
        // down. Empty from a cluster older than the field reads as
        // `Unrecorded`, which is what the object held before.
        reason: controller_api::StoragePoolReason::read(
            &reported.reason,
            (!reported.message.is_empty()).then(|| reported.message.clone()),
        )
        .0,
        locality,
        nodes: reported.nodes.clone(),
        params,
        message: controller_api::StoragePoolReason::read(
            &reported.reason,
            (!reported.message.is_empty()).then(|| reported.message.clone()),
        )
        .1,
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
    // Only the FACTS are compared now, and the phase is not among them: it is
    // derived from exactly these fields, so a write they do not change leaves
    // it where it was. One thing fewer to keep in step, and the trap it
    // removes is real — a guard that held a report's reason against a resting
    // phase's empty slot would write on every ten-second report (D-C7).
    pool.status.clusters.contains(entry)
        && (!home
            || (pool.status.locality == entry.locality && pool.status.nodes == reported.nodes))
}

/// Mirror snapshots assigned through their source volume's cluster or pool home.
/// Only sufficiently recent complete inventory absence can finish deletion.
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
        if snapshot_unchanged(snapshot, cluster, reported, phase) {
            continue;
        }
        store
            .mutate::<controller_api::VolumeSnapshot, _>(&snapshot.metadata.name, |s| {
                write_snapshot_status(s, cluster, reported, phase, at)
            })
            .await?;
        debug!(snapshot = %snapshot.metadata.name, cluster, phase = phase.as_str(),
               "snapshot observed");
    }
    Ok(())
}

/// Mirror volume evidence by UID from its owning cluster.
/// Only sufficiently recent complete inventory absence can finish deletion.
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
        if volume_unchanged(volume, cluster, reported, phase) {
            continue;
        }
        store
            .mutate::<Volume, _>(&volume.metadata.name, |v| {
                write_volume_status(v, cluster, reported, phase, at)
            })
            .await?;
        debug!(volume = %volume.metadata.name, cluster, phase = phase.as_str(),
               "volume observed");
    }
    Ok(())
}

/// Read each pool's home once for the whole report.
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

/// Select volumes by status.cluster, falling back to the pool home.
/// After movement, absence in the former cluster must not imply deletion.
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

/// Select snapshots using the source volume's cluster, then its pool home.
/// A snapshot whose source volume is missing has no owner resolved by this pass.
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

/// Compare reported volume facts before writing; unchanged heartbeats need no revision.
fn volume_unchanged(
    volume: &Volume,
    cluster: &str,
    reported: &proto::VolumeStatusReport,
    phase: VolumePhaseKind,
) -> bool {
    // Seen at all: a volume nothing has ever been observed about is written
    // even when every field matches the default.
    let observed = volume.status.observed_at.is_some();
    // What the cluster decided about it, as the FACT the write would leave
    // behind. The phase is derived from it, so there is one thing to compare.
    let same_verdict = volume
        .status
        .reported
        .as_ref()
        .is_some_and(|held| held.same_word(&volume_word(cluster, reported, phase)))
        && volume.status.node == said(&reported.node)
        && volume.status.attached_to == said(&reported.attached_to);
    // What a node measured about it.
    let same_measurements =
        volume.status.size_gib == reported.size_gib && volume.status.open_on == reported.open_on;
    // The name only ever ARRIVES, so an empty one is silence and not a
    // difference — see `write_volume_status`.
    let same_backend = reported.backend.is_empty() || volume.status.backend == reported.backend;
    observed && same_verdict && same_measurements && same_backend
}

/// One cluster's word about one volume, as the fact it becomes on the object.
///
/// One function because two callers must agree exactly: the churn guard and
/// the write. A guard that read the word differently from the write would
/// either write on every report or never write at all.
fn volume_word(
    cluster: &str,
    reported: &proto::VolumeStatusReport,
    phase: VolumePhaseKind,
) -> controller_api::VolumeReported {
    let (reason, message) =
        controller_api::VolumeReason::read(&reported.reason, said(&reported.message));
    controller_api::VolumeReported::by(cluster, phase, reason, message, chrono::Utc::now())
}

/// The reported line, onto the object.
fn write_volume_status(
    v: &mut Volume,
    cluster: &str,
    reported: &proto::VolumeStatusReport,
    phase: VolumePhaseKind,
    at: DateTime<Utc>,
) {
    let mut word = volume_word(cluster, reported, phase);
    word.at = at;
    v.status.reported = Some(word);
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

/// Compare snapshot evidence and require an observed timestamp.
/// Even an initial Pending report acknowledges that the cluster knows the object.
fn snapshot_unchanged(
    snapshot: &controller_api::VolumeSnapshot,
    cluster: &str,
    reported: &proto::VolumeSnapshotStatusReport,
    phase: controller_api::VolumeSnapshotPhaseKind,
) -> bool {
    let observed = snapshot.status.observed_at.is_some();
    // What the cluster decided about the copy, as the FACT the write would
    // leave behind. The phase is derived from it, so there is one thing to
    // compare and not four.
    let same_verdict = snapshot
        .status
        .reported
        .as_ref()
        .is_some_and(|held| held.same_word(&snapshot_word(cluster, reported, phase)))
        && snapshot.status.node == said(&reported.node);
    // What a node measured about it.
    let same_size = snapshot.status.size_gib == reported.size_gib;
    // "Only ever arrives", as everywhere else.
    let same_backend = reported.backend.is_empty() || snapshot.status.backend == reported.backend;
    observed && same_verdict && same_size && same_backend
}

/// One cluster's word about one copy, as the fact it becomes on the object.
///
/// One function because two callers must agree exactly: the churn guard and
/// the write. A guard that read the word differently from the write would
/// either write on every report or never write at all.
fn snapshot_word(
    cluster: &str,
    reported: &proto::VolumeSnapshotStatusReport,
    phase: controller_api::VolumeSnapshotPhaseKind,
) -> controller_api::VolumeSnapshotReported {
    let (reason, message) =
        controller_api::VolumeSnapshotReason::read(&reported.reason, said(&reported.message));
    controller_api::VolumeSnapshotReported::by(cluster, phase, reason, message, chrono::Utc::now())
}

/// The reported line, onto the snapshot.
fn write_snapshot_status(
    s: &mut controller_api::VolumeSnapshot,
    cluster: &str,
    reported: &proto::VolumeSnapshotStatusReport,
    phase: controller_api::VolumeSnapshotPhaseKind,
    at: DateTime<Utc>,
) {
    let mut word = snapshot_word(cluster, reported, phase);
    word.at = at;
    s.status.reported = Some(word);
    s.status.node = said(&reported.node);
    s.status.size_gib = reported.size_gib;
    // "Only ever arrives", as everywhere else: an empty name is silence and
    // not a claim that the old one is wrong.
    if !reported.backend.is_empty() {
        s.status.backend = reported.backend.clone();
    }
    s.status.observed_at = Some(at);
}
