// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! What a node says about itself and its guests, written down.
//!
//! One `StatusReport` per beat carries the node's own numbers and one line
//! per vm; each `ingest_*` below owns one kind of line and nothing else, and
//! `ingest_status` is the order they are read in. Verbatim out of
//! `session.rs`; the module path of every caller is unchanged.

use std::collections::BTreeSet;

use super::*;

/// What a node says about itself: its images into the cluster-wide view, the
/// rest into the objects. A report before the hello has no node to belong to.
pub(super) async fn on_status(
    session: &Session,
    node_id: Option<&str>,
    report: &proto::StatusReport,
) {
    let Some(id) = node_id else {
        warn!("status report before hello, ignoring");
        return;
    };
    // What the node says about base images goes into the cluster-wide view,
    // whatever the rest of the ingest does: it is a fact about that node's
    // disk and does not depend on any VM object being readable.
    session.registry.images.observe(id, &report.images);
    if let Err(e) = ingest_status(&session.store, &session.vms, id, report).await {
        warn!(node = id, error = format!("{e:#}"), "status ingest failed");
    }
    // The routers, out of their own listing and here rather than inside
    // `ingest_status`: a node that says it holds a router nothing stores has
    // to be TOLD, and the session is what can tell it.
    match ingest_routers(&session.store, id, report).await {
        Ok(orphans) => sweep_routers(session, id, &orphans),
        Err(e) => warn!(node = id, error = %format!("{e:#}"), "router status ingest failed"),
    }
}

/// Tell a node to let go of the routers nothing names any more.
///
/// The `Router` kind carries no finalizer, and this is why it does not need
/// one: a router deleted while its node was away leaves a netns on that
/// machine, and the machine says so in its very next status report. Exactly
/// the shape `SyncState` gives a VM at Hello — what is not in the list is
/// gone — one object over and continuously rather than once.
///
/// Sent and NOT waited for, and that is the whole of the second lesson the
/// lab taught here: this runs inside the reading of one status report, a
/// command is answered or times out after a minute, and a report that takes
/// a minute to read is a node whose heartbeat expires while it is talking.
/// The ack buys nothing anyway — the proof that the netns is gone is the
/// node's next report, which is where this decision is made again.
fn sweep_routers(session: &Session, node_id: &str, orphans: &[String]) {
    for id in orphans {
        info!(node = node_id, router_id = %id, "router nothing names; letting it go");
        let op = command::Op::DestroyRouter(proto::DestroyRouter { id: id.clone() });
        let registry = session.registry.clone();
        let node = node_id.to_string();
        let router = id.clone();
        tokio::spawn(async move {
            if let Err(e) = registry.send_command(&node, "", op).await {
                warn!(node = %node, router_id = %router, error = %format!("{e:#}"),
                      "letting an orphaned router go failed");
            }
        });
    }
}

/// A status report is the node's heartbeat and the phase of every VM on it.
///
/// A sequence of named steps, in this order because each one is read by the
/// next: the heartbeat and the node's own facts, the disks and their copies,
/// the VM listing that every VM step below is measured against, then the
/// bindings, the attachments, the migration arrivals and finally the phases.
pub(super) async fn ingest_status(
    store: &EtcdStore,
    index: &VmIndex,
    node_id: &str,
    report: &StatusReport,
) -> anyhow::Result<()> {
    beat_node(store, node_id, report).await?;

    // The volume half of the same report. Before the VM half and out of its
    // own listing, because the two share nothing: a volume's phase is not a
    // VM's, and a node that runs no VMs at all can still hold disks.
    if let Err(e) = ingest_volumes(store, node_id, report).await {
        warn!(node = node_id, error = %format!("{e:#}"), "volume status ingest failed");
    }
    // And the copies of them, out of their own listing for the same reason:
    // a snapshot outlives its volume, so its lifecycle cannot be read off
    // one.
    if let Err(e) = ingest_snapshots(store, node_id, report).await {
        warn!(node = node_id, error = %format!("{e:#}"), "snapshot status ingest failed");
    }

    let vms = vm_listing(store, index, report).await?;
    // Bound elsewhere disqualifies the reporter; not bound at all does not.
    // Deliberately looser than the cloud tier's, which takes an unplaced VM's
    // report from nobody.
    let ours = |vm: &Vm| {
        vm.spec
            .node_name
            .as_deref()
            .is_none_or(|bound| bound == node_id)
    };
    // One instant for the whole report, as one floor up: what is being
    // recorded is when this status was seen, not when each write of it landed.
    let at = Utc::now();

    // The reschedule half: a VM whose binding a client let go, whose old node
    // no longer names it. Before the phase half, because a report that does
    // not name a VM has nothing for the phase loop to do with it anyway.
    if let Err(e) = forget_unbound(store, &vms, node_id, report, at).await {
        warn!(node = node_id, error = %format!("{e:#}"), "unbind ingest failed");
    }

    // The attachment half, before the phase half and out of its own listing.
    // Its own pass because the two change independently: a disk arrives while
    // the VM stays Running, and `observe` — which is what the phase loop
    // below is driven by — would call that report unchanged and drop it.
    if let Err(e) = ingest_attachments(store, &vms, node_id, report, ours, at).await {
        warn!(node = node_id, error = %format!("{e:#}"), "volume attachment ingest failed");
    }

    // ...and the half of it that no VM can carry, because the VM is gone.
    if let Err(e) = ingest_released(store, node_id, report).await {
        warn!(node = node_id, error = %format!("{e:#}"), "volume release ingest failed");
    }

    // The address half, next to it and for the same reason: a tap says the
    // same thing for the life of the VM, so the phase loop below would carry
    // it never.
    if let Err(e) = ingest_addresses(store, &vms, node_id, report, ours).await {
        warn!(node = node_id, error = %format!("{e:#}"), "vm address ingest failed");
    }

    // What the DESTINATION of a live migration says about the guest moving to
    // it. Its own pass, in its own file, and it exists because `ours` below
    // refuses a report from a node the vm is not bound to — which is exactly
    // what a destination is until the migration finishes. It writes on the
    // migration object and never on the vm.
    if let Err(e) = crate::migration::ingest_arrivals(store, &vms, node_id, report).await {
        warn!(node = node_id, error = %format!("{e:#}"), "migration arrival ingest failed");
    }

    // And what the SOURCE says about the send itself. A different fact from a
    // VM phase — the guest is `Running` on the source right up to the moment
    // it is not — and it used to be the answer to `MigrateOut`, which is why
    // the reconcile pass awaited that answer for the length of a transfer
    // (D16).
    if let Err(e) = crate::migration::ingest_departures(store, &vms, node_id, report).await {
        warn!(node = node_id, error = %format!("{e:#}"), "migration departure ingest failed");
    }

    ingest_phases(store, node_id, &vms, report, ours, at).await;
    Ok(())
}

/// What a node says about the routers it holds.
///
/// Two rules, and both of them are the ones the rest of this file already
/// follows one object over.
///
/// **The active node's word decides the phase**, because it is the node whose
/// answer is "do packets go". A standby is deliberately silent — it holds the
/// netns, announces nothing and answers no ARP — so its `Standby` says
/// nothing the object does not already know. The exception is a standby that
/// says `Failed`: a failover that will not work is worth knowing about before
/// it is needed, and nothing else in this control plane would ever say so.
///
/// **A router nobody stores is one this node should let go of.** The same
/// rule `SyncState` states for VMs — what is not in the list is gone — and
/// the reason a `Router` needs no finalizer: an object deleted while its node
/// was away leaves a netns that nothing names, and this is where it is found.
/// The router this reported line is about, or `None` if NOBODY stores it.
///
/// The whole of what makes a reported router an orphan, and it is deliberately
/// only this one question. "Stored but not on this machine's list right now"
/// is NOT an orphan — see the caller for the loop that cost.
pub(super) fn held_here<'a>(
    stored: &'a [controller_api::Router],
    reported: &str,
) -> Option<&'a controller_api::Router> {
    stored.iter().find(|r| r.metadata.uid == reported)
}

/// The node's word for what it HAS, in the tier's word for what the router
/// IS.
///
/// Two vocabularies on purpose, and this is the hop that joins them. A node
/// knows one thing about a router — the namespace and its two legs are there,
/// or they are not — so it says `Ready` or `Failed` and nothing else. The
/// object above is about a router that lives on SEVERAL machines, so its
/// phases are `Active`, `Standby`, `Failed` and the rest, and which of the
/// first two a healthy node means depends on whether it is the one
/// announcing.
///
/// Parsing the node's word as this tier's own was the bug: `Ready` is not a
/// `RouterPhaseKind`, so every report from every healthy gateway node was dropped
/// with a warning, ten seconds apart, and the only thing a node could ever
/// tell this tier was that something had broken.
pub(super) fn observed_phase(said: &str, speaks: bool) -> Option<controller_api::RouterPhaseKind> {
    match said {
        proto::ROUTER_FAILED => Some(controller_api::RouterPhaseKind::Failed),
        proto::ROUTER_READY if speaks => Some(controller_api::RouterPhaseKind::Active),
        proto::ROUTER_READY => Some(controller_api::RouterPhaseKind::Standby),
        _ => None,
    }
}

pub(super) async fn ingest_routers(
    store: &EtcdStore,
    node_id: &str,
    report: &StatusReport,
) -> anyhow::Result<Vec<String>> {
    if report.routers.is_empty() {
        return Ok(Vec::new());
    }
    let stored = store.list::<controller_api::Router>().await?;
    let mut orphans = Vec::new();
    for line in &report.routers {
        let Some(router) = held_here(&stored, &line.id) else {
            orphans.push(line.id.clone());
            continue;
        };
        // A router this node holds that the list does not name right now.
        //
        // NOT an orphan, and the lab is why. It looks like one and it is not:
        // `status.nodes` is rewritten by every pass, so a machine can be off
        // the list for one pass — a heartbeat that expired a second ago, a
        // cordon somebody is about to take back — and a destroy ordered from
        // here would then fight the very next `EnsureRouter`. It did: a
        // chaos run left this firing once a minute against a machine that WAS
        // on the list, and because the send is awaited with the command
        // timeout, it held this node's whole status ingest for sixty seconds
        // each time. That starved the node's heartbeat, which took it off the
        // list for real, which made the next report look like an orphan
        // again. A loop with nobody outside it.
        //
        // Letting a machine go is the RECONCILER's to order, out of a plan
        // it just computed: `RouterPlan.release`, which names the machines
        // that dropped off the list and can be reached (see `plan_router`).
        // The case that path could not reach — a machine that was away while
        // it was dropped — is remembered there now as `status.releasing` and
        // paid the first pass the machine is back. It used to be argued away
        // with `run_dir` being a tmpfs, and that argument was half right: a
        // machine that REBOOTED comes back with no netns and no record, but a
        // machine whose AGENT was restarted comes back with both, and manacor
        // was the second kind on 2026-09-10.
        if !router.status.nodes.iter().any(|n| n == node_id) {
            debug!(router = %router.metadata.name, node = node_id,
                   "this node is not on the router's list; the reconciler releases it");
            continue;
        }
        let speaks = router.status.active_node == node_id;
        let Some(phase) = observed_phase(&line.phase, speaks) else {
            warn!(router = %router.metadata.name, phase = %line.phase,
                  "unknown router phase from agent");
            continue;
        };
        if !speaks && phase != controller_api::RouterPhaseKind::Failed {
            continue;
        }
        let message = (!line.message.is_empty()).then(|| {
            if speaks {
                line.message.clone()
            } else {
                format!("{node_id}: {}", line.message)
            }
        });
        if router.status.phase().kind() == phase
            && router.status.phase().message() == message.as_deref()
        {
            continue;
        }
        let name = router.metadata.name.clone();
        let tenant = router.spec.tenant.clone();
        let uid = router.metadata.uid.clone();
        store
            .mutate::<controller_api::Router, _>(&name, |r| {
                r.status.assign(controller_api::RouterPhase::new(
                    phase,
                    controller_api::RouterReason::Reported,
                    message.clone(),
                    chrono::Utc::now(),
                ));
            })
            .await?;
        info!(router = %name, node = node_id, phase = phase.as_str(), "router phase observed");
        events::record(
            store,
            Happening {
                kind: <controller_api::Router as Resource>::KIND,
                name: &name,
                uid: &uid,
                reason: events::reason::PHASE_CHANGED,
                message: match &message {
                    Some(said) => format!("{} ({said})", phase.as_str()),
                    None => phase.as_str().to_string(),
                },
                event_type: if phase == controller_api::RouterPhaseKind::Failed {
                    EventType::Warning
                } else {
                    EventType::Normal
                },
                tenant: Some(&tenant),
            },
        )
        .await;
    }
    Ok(orphans)
}

/// The heartbeat and the node's own facts: that it is up, how many VMs it
/// carries, how much room it has, and what it says is wrong with it.
pub(super) async fn beat_node(
    store: &EtcdStore,
    node_id: &str,
    report: &StatusReport,
) -> anyhow::Result<()> {
    // Borrowed and not moved: `NodeStatus` carries `conditions[]` since the
    // agent gained a way to say what is wrong with it, so it is no longer
    // `Copy`.
    let facts = report.node.as_ref();
    let count = report.vms.len() as u32;
    // Replaced wholesale by every beat and never merged: a condition is a
    // statement about NOW, and a node that has been given its disk space back
    // says so by not naming `DiskPressure` any more. Merged, a condition
    // would be something only a restart clears.
    //
    // A report with no `node` at all says nothing about health either, so it
    // leaves the list alone: that shape is the heartbeat-only report an agent
    // sends when it could not read its own state, and reading it as "nothing
    // is wrong" would clear a veto on the strength of a failure.
    let conditions: Option<Vec<controller_api::NodeCondition>> = facts.map(|f| {
        f.conditions
            .iter()
            .map(|c| controller_api::NodeCondition {
                type_: c.r#type.clone(),
                message: c.message.clone(),
            })
            .collect()
    });
    store
        .mutate::<Node, _>(node_id, |n| {
            n.status.ready = true;
            n.status.last_heartbeat = Some(Utc::now());
            n.status.vms = count;
            if let Some(f) = facts {
                n.status.capacity.vcpus = f.vcpus;
                n.status.capacity.mem_mib = f.mem_mib;
            }
            if let Some(conditions) = &conditions {
                n.status.conditions = conditions.clone();
            }
        })
        .await?;
    Ok(())
}

/// The VM objects every step below is measured against.
///
/// NOT short-circuited on an empty report, and that took an E2E to find:
/// a node that has just let go of its last VM reports exactly zero of
/// them, and the pass that has to notice is `forget_unbound`. The
/// listing is cached for a second (`VmIndex`), so what an empty report
/// costs is one shared read per ten seconds per node.
///
/// The agent speaks uids — that is the id it was handed on CreateInstance —
/// while the store is keyed by name, so the list doubles as the index. The
/// cloud tier reads its clusters' reports the same way, through
/// `controller_api::mirror`.
pub(super) async fn vm_listing(
    store: &EtcdStore,
    index: &VmIndex,
    report: &StatusReport,
) -> anyhow::Result<Arc<Vec<Vm>>> {
    let fetch = || async { store.list::<Vm>().await.map_err(anyhow::Error::from) };
    let (vms, fresh) = index.list(fetch).await?;
    // An uid the index cannot name is the one answer a reused list gets
    // wrong, and it is also the answer this tier throws a report away for.
    // Re-read once before believing it.
    if fresh || all_known(&vms, &report.vms) {
        Ok(vms)
    } else {
        index.refresh(fetch).await
    }
}

/// Write what a node said about its volumes onto the `Volume` objects.
///
/// The uid is the key, exactly as it is for VMs: the node was handed
/// `metadata.uid` on ProvisionVolume and speaks it back. A uid no stored
/// volume carries is somebody else's or one that has just been deleted, and
/// is dropped without a word — unlike the VM half, where an unknown uid is
/// worth a line, because a node cannot create a volume of its own.
///
/// `Gone` is written onto the object like any other phase and acted on by the
/// reconciler, not here. This function observes; deciding that an object may
/// now be deleted is a lifecycle question and lives in one place.
pub(super) async fn ingest_volumes(
    store: &EtcdStore,
    node_id: &str,
    report: &StatusReport,
) -> anyhow::Result<()> {
    if report.volumes.is_empty() {
        return Ok(());
    }
    // One instant for the whole report: what is being recorded is when this
    // status was seen, not when each write of it landed.
    let at = Utc::now();
    let volumes = store.list::<Volume>().await?;
    for reported in &report.volumes {
        let Some(volume) = volumes.iter().find(|v| v.metadata.uid == reported.id) else {
            continue;
        };
        // A node that is neither this volume's HOME nor one of the machines
        // holding it OPEN has no word about it.
        //
        // Two fields and not one, because a live migration separates them:
        // `status.node` is where the bytes were made, `status.openOn` is who
        // has them attached, and for the length of a migration those are two
        // different machines. A destination whose report was dropped here
        // would look to this tier like a node that never got the volume.
        //
        // DEBUG and not WARN for the rest, because the ordinary way to get
        // here is not a fault: after a record moves with its VM the OLD node
        // still holds a record of its own and goes on reporting the volume,
        // for ever — one warning per node per report, over minutes in the E2E
        // (migration D8). The honest repair is a `ForgetVolume` command to the
        // old node, which is a storage decision and not this one; until then
        // the line says what it is instead of shouting it.
        let home = volume.status.node.as_deref() == Some(node_id);
        let holds = volume.status.open_on.iter().any(|n| n == node_id);
        if !home && !holds {
            debug!(volume = %volume.metadata.name, node = node_id,
                   placed_on = volume.status.node.as_deref().unwrap_or("nowhere"),
                   "a node that does not hold this volume reported it; ignoring its word");
            continue;
        }
        // A report older than the last thing this tier did to the volume
        // describes it from BEFORE that. It matters most for the line below:
        // a stale `Gone` answering an older question would clear the node off
        // a volume whose bytes are on it.
        if !controller_api::mirror::is_current(
            volume.metadata.deletion_timestamp,
            volume.status.observed_at,
            at,
        ) {
            continue;
        }
        let name = volume.metadata.name.clone();

        // `Gone` is the one answer that is not a phase. It says the bytes are
        // not on this node any more — so the node comes OFF the volume, and
        // that is the whole of what this function does about it. What follows
        // from a volume with no node and no holder is `Release::Drop`, which
        // is a rule the reconciler already had; deciding here that an object
        // may be deleted would be a second lifecycle in a second place.
        if reported.phase == crate::reconcile::VOLUME_GONE {
            // From a holder that is not the home, `Gone` says only that THIS
            // node has let go — the bytes are still where the home says they
            // are. Clearing `status.node` on that word would strand a volume
            // whose destination tidied up after a migration that did not
            // happen.
            if !home {
                info!(volume = %name, node = node_id, "a holder let the volume go");
                store
                    .mutate::<Volume, _>(&name, |v| {
                        v.status.closed_here(node_id);
                    })
                    .await?;
                continue;
            }
            info!(volume = %name, node = node_id, "the node reports the volume is gone");
            store
                .mutate::<Volume, _>(&name, |v| {
                    v.status.node = None;
                    v.status.closed_here(node_id);
                    v.status.backend = String::new();
                    let kind = v.status.phase().kind();
                    v.status.assign(controller_api::VolumePhase::of(kind, at));
                    v.status.observed_at = Some(at);
                })
                .await?;
            continue;
        }

        let Some(phase) = VolumePhaseKind::parse(&reported.phase) else {
            warn!(volume = %name, phase = %reported.phase, "unknown volume phase from agent");
            continue;
        };
        let message = (!reported.message.is_empty()).then(|| reported.message.clone());
        let backend = reported.backend.clone();
        // GiB, rounded UP, because the number has to be comparable to
        // `spec.sizeGib` and lvm rounds an LV up to the extent size — a
        // 1.004 GiB volume reported as 1 would read as "not grown yet"
        // forever, and the resize would be re-sent every pass.
        let size_gib = reported.size_bytes.div_ceil(1024 * 1024 * 1024);
        // Only when something CHANGED. Every node reports every ten seconds,
        // and a write per report would churn etcd revisions and wake the
        // volume watch while nothing about the volume happened.
        if volume.status.phase().kind() == phase
            && volume.status.phase().message() == message.as_deref()
            && volume.status.size_gib == size_gib
            && (backend.is_empty() || volume.status.backend == backend)
        {
            continue;
        }
        store
            .mutate::<Volume, _>(&name, |v| {
                // A volume on its way out keeps `Releasing`: the node is
                // still reporting the bytes it has, and the phase is about
                // what the OBJECT is doing.
                // A volume on its way out keeps `Releasing`, so the word it
                // lands on is not always the word the node said — but the
                // sentence is the node's either way.
                let kind = if v.metadata.deletion_timestamp.is_none() {
                    phase
                } else {
                    v.status.phase().kind()
                };
                v.status.assign(controller_api::VolumePhase::new(
                    kind,
                    controller_api::VolumeReason::Reported,
                    message.clone(),
                    at,
                ));
                // The backend name only ever ARRIVES; a node that has not made
                // the volume yet sends an empty string, and that is not a
                // statement that the name is gone.
                if !backend.is_empty() {
                    v.status.backend = backend.clone();
                }
                // Zero is "did not say" — a node from before the field, or a
                // volume with no handle yet — and never "it shrank to
                // nothing".
                if size_gib > 0 {
                    v.status.size_gib = size_gib;
                }
                v.status.observed_at = Some(at);
            })
            .await?;
        debug!(volume = %name, node = node_id, phase = phase.as_str(), "volume observed");
    }
    Ok(())
}

/// Take a node off `openOn` when it still has the volume and no longer has a
/// guest on it.
///
/// # The defect this answers
///
/// `ingest_attachments` maintains `openOn` out of the VMs a node REPORTS, and
/// the comment there promises the list is self-healing: "a machine that has
/// let go — or that restarted without the disk — drops out on its next
/// report". It does not, in the one case that matters. A node whose VM is
/// gone does not report that VM at all, so the loop never reaches the disk
/// again and the node stays on the list for ever.
///
/// Round 4's e2e measured it. Three live migrations of `fabric-probe` onto
/// agent-1b failed in cloud-hypervisor; the destination tore everything down
/// correctly — no vmm, no record, no `nvme list-subsys` entry, which is
/// exactly what D-P5 asked for — and the volume object went on saying
/// `openOn: ["agent-1a","agent-1b"]`. The machine was right and the books
/// were wrong.
///
/// # Why these two conditions and no heuristic
///
/// A node's word about what it has ATTACHED is the union of
/// `attached_volumes` over the VMs it reports. Silence there is only evidence
/// if the node is speaking at all about that volume, so the second condition
/// is that the node reports the volume's own RECORD. Together they say: "I
/// still have this disk, and nothing here is using it."
///
/// That pair is also what keeps this off the dispatch's toes. `hold_volumes`
/// writes the node into `openOn` the moment a create goes out, before any
/// report — and a node that has not been told about the volume yet does not
/// report its record, so this pass says nothing about it. A heartbeat-only
/// report carries neither list and reaches nothing here at all, which is what
/// "not saying" has to mean.
pub(super) fn let_go_of(report: &StatusReport, uid: &str) -> bool {
    let attached: BTreeSet<&str> = report
        .vms
        .iter()
        .flat_map(|r| r.attached_volumes.iter().map(String::as_str))
        .collect();
    let known: BTreeSet<&str> = report.volumes.iter().map(|v| v.id.as_str()).collect();
    known.contains(uid) && !attached.contains(uid)
}

pub(super) async fn ingest_released(
    store: &EtcdStore,
    node_id: &str,
    report: &StatusReport,
) -> anyhow::Result<()> {
    if report.volumes.is_empty() {
        return Ok(());
    }
    for volume in store.list::<Volume>().await? {
        if !volume.status.open_on.iter().any(|n| n == node_id) {
            continue;
        }
        if !let_go_of(report, &volume.metadata.uid) {
            continue;
        }
        let name = volume.metadata.name.clone();
        store
            .mutate::<Volume, _>(&name, |v| {
                v.status.closed_here(node_id);
            })
            .await?;
        info!(volume = %name, node = node_id,
              "the node still has the disk and no guest on it; it comes off the open set");
    }
    Ok(())
}

/// Write what a node said about the disks it has OPEN onto the VM objects.
///
/// The evidence half of hot-plug, and the reason it is a pass of its own:
/// `spec.vm.volumes[]` is what a client asked for and this is what happened,
/// and the two move independently. A disk finishes attaching while the VM
/// stays exactly as Running as it was, so the phase loop — which writes only
/// on a change of phase or message — would see nothing to do.
///
/// Names and not uids on the object, because a person reads this field; uids
/// are what travel on the wire. The map between them costs one listing of the
/// volumes, and only for a report that mentions a VM with referenced disks —
/// which is no report at all on a cluster that has none.
pub(super) async fn ingest_attachments(
    store: &EtcdStore,
    vms: &[Vm],
    node_id: &str,
    report: &StatusReport,
    ours: impl Fn(&Vm) -> bool,
    at: DateTime<Utc>,
) -> anyhow::Result<()> {
    let relevant: Vec<(&Vm, &proto::VmStatusReport)> = report
        .vms
        .iter()
        .filter_map(|r| {
            let vm = vms.iter().find(|v| v.metadata.uid == r.id)?;
            (ours(vm) && !vm.spec.referenced_volumes().is_empty()).then_some((vm, r))
        })
        .collect();
    if relevant.is_empty() {
        return Ok(());
    }
    let volumes = store.list::<Volume>().await?;
    let by_uid: BTreeMap<String, String> = volumes
        .iter()
        .map(|v| (v.metadata.uid.clone(), v.metadata.name.clone()))
        .collect();

    for (vm, reported) in relevant {
        // Spec order, one entry per referenced disk, so the list reads like
        // the spec it answers. A uid the node named that this tier cannot
        // resolve to a name is simply not among the spec's volumes and
        // therefore not in the answer — the spec is the question.
        let held: Vec<&str> = reported
            .attached_volumes
            .iter()
            .filter_map(|uid| by_uid.get(uid).map(String::as_str))
            .collect();
        // `openOn` from the node's own word, and only ever about ITSELF.
        // Every other node's entry stays as that node's own report left it,
        // which is what makes the list self-healing: a machine that has let
        // go — or that restarted without the disk — drops out on its next
        // report, and nobody has to remember to take it out. The dispatch
        // half in `hold_volumes` puts the node in as soon as the create goes
        // out, so the reconciler never waits a heartbeat to see its own work;
        // this half is the evidence that keeps it honest.
        for volume in &volumes {
            let Some(name) = by_uid.get(&volume.metadata.uid) else {
                continue;
            };
            if !vm.spec.referenced_volumes().iter().any(|v| v == name) {
                continue;
            }
            let open_here = held.contains(&name.as_str());
            let listed = volume.status.open_on.iter().any(|n| n == node_id);
            if open_here == listed {
                continue;
            }
            store
                .mutate::<Volume, _>(name, |v| {
                    if open_here {
                        v.status.open_here(node_id);
                    } else {
                        v.status.closed_here(node_id);
                    }
                })
                .await?;
            debug!(volume = %name, node = node_id, open = open_here, "volume open-set observed");
        }
        let observed = observed_attachments(vm, &held);
        if vm.status.volumes == observed {
            continue;
        }
        let name = vm.metadata.name.clone();
        // The one place in this stack where dispatching is not observing.
        // `observedGeneration` for a spec that changed `volumes[]` closes
        // HERE, when the node has said it has them, and not when the command
        // went out — because an attach can fail inside the node with the
        // command long since acked. Every other spec change is a document the
        // node takes whole, and for those "told" really is all this tier can
        // honestly claim.
        let settled = observed.iter().all(|v| v.attached);
        let generation = vm.metadata.generation;
        store
            .mutate::<Vm, _>(&name, |v| {
                v.status.volumes = observed.clone();
                if settled {
                    v.status.observed_generation = v.status.observed_generation.max(generation);
                }
                v.status.observed_at = Some(at);
            })
            .await?;
        debug!(vm = %name, attached = held.len(), settled, "vm attachments observed");
    }
    Ok(())
}

/// Write the hardware addresses a node reported onto the VM objects.
///
/// The MAC half of `Vm.status.addresses[]`. Its own pass, next door to the
/// attachment half and for the same reason: a tap is made once and then says
/// the same thing for the life of the VM, so the phase loop — which writes
/// only when the phase or the message changed — would carry it exactly never.
///
/// The merge itself is `mirror::addresses_with`, shared with the tier above
/// because both apply it and the two have to agree exactly. What is decided
/// HERE is only which reports get that far: a node may speak for a VM the
/// binding gives it, and a report that names no tap at all is skipped before
/// anything is read or written.
pub(super) async fn ingest_addresses(
    store: &EtcdStore,
    vms: &[Vm],
    node_id: &str,
    report: &StatusReport,
    ours: impl Fn(&Vm) -> bool,
) -> anyhow::Result<()> {
    for reported in &report.vms {
        if reported.nics.is_empty() {
            continue;
        }
        let Some(vm) = vms.iter().find(|v| v.metadata.uid == reported.id) else {
            continue;
        };
        if !ours(vm) {
            continue;
        }
        let addresses = controller_api::addresses_with(&vm.status.addresses, &reported.nics);
        if vm.status.addresses == addresses {
            continue;
        }
        let name = vm.metadata.name.clone();
        store
            .mutate::<Vm, _>(&name, |v| v.status.addresses = addresses.clone())
            .await?;
        debug!(vm = %name, node = node_id, nics = reported.nics.len(), "vm addresses observed");
    }
    Ok(())
}

/// Write what a node said about its snapshots onto the `VolumeSnapshot`
/// objects.
///
/// The volume half's twin, and the same three rules: the uid is the key, a
/// uid no stored object carries is dropped without a word, and `Gone` is the
/// one answer that is not a phase — it is what lets the finalizer come off,
/// because absence from a report is "this node does not know".
///
/// One difference from the volume half, and it is the point of the object: a
/// snapshot is NOT checked against the node it was placed on. A snapshot
/// outlives its volume, and after the volume is gone the only record of which
/// machine holds the copy is `status.node` — which this function would then
/// be comparing against itself.
pub(super) async fn ingest_snapshots(
    store: &EtcdStore,
    node_id: &str,
    report: &StatusReport,
) -> anyhow::Result<()> {
    if report.snapshots.is_empty() {
        return Ok(());
    }
    let at = Utc::now();
    let snapshots = store.list::<VolumeSnapshot>().await?;
    for reported in &report.snapshots {
        let Some(snapshot) = snapshots
            .iter()
            .find(|s| s.metadata.uid == reported.snapshot_id)
        else {
            continue;
        };
        if snapshot.status.node.as_deref() != Some(node_id) {
            warn!(snapshot = %snapshot.metadata.name, node = node_id,
                  "snapshot status from a node it was not taken on");
            continue;
        }
        if !controller_api::mirror::is_current(
            snapshot.metadata.deletion_timestamp,
            snapshot.status.observed_at,
            at,
        ) {
            continue;
        }
        let name = snapshot.metadata.name.clone();

        // `Gone` is what completes a delete, and it is the only thing that
        // does: the copy is not on this node any more, so the finalizer comes
        // off and the object goes. A snapshot that is NOT being deleted and
        // reports Gone had its bytes removed underneath it — the node is
        // taken off, and the next dispatch makes it again.
        if reported.phase == crate::reconcile::SNAPSHOT_GONE {
            if snapshot.metadata.deletion_timestamp.is_some() {
                store
                    .mutate::<VolumeSnapshot, _>(&name, |s| {
                        s.metadata
                            .finalizers
                            .retain(|f| f != controller_api::VOLUME_RELEASE_FINALIZER);
                    })
                    .await?;
                store.delete::<VolumeSnapshot>(&name).await?;
                info!(snapshot = %name, node = node_id, "snapshot deleted; the copy is gone");
            } else {
                warn!(snapshot = %name, node = node_id,
                      "the node no longer has this snapshot; it will be taken again");
                store
                    .mutate::<VolumeSnapshot, _>(&name, |s| {
                        s.status.assign(controller_api::VolumeSnapshotPhase::new(
                            VolumeSnapshotPhaseKind::Pending,
                            controller_api::VolumeSnapshotReason::SourceGone,
                            None,
                            at,
                        ));
                        s.status.node = None;
                        s.status.backend = String::new();
                        s.status.observed_at = Some(at);
                    })
                    .await?;
            }
            continue;
        }

        let Some(phase) = VolumeSnapshotPhaseKind::parse(&reported.phase) else {
            warn!(snapshot = %name, phase = %reported.phase, "unknown snapshot phase from agent");
            continue;
        };
        let message = (!reported.message.is_empty()).then(|| reported.message.clone());
        let backend = reported.backend.clone();
        // GiB, rounded UP, because the number an operator reads beside a
        // volume's `sizeGib` has to be comparable to it — and rounding a
        // 1.5 GiB copy down to 1 would say it is smaller than the disk it
        // came from.
        let size_gib = reported.size_bytes.div_ceil(1024 * 1024 * 1024);
        // Only when something changed: every node reports every ten seconds.
        if snapshot.status.phase().kind() == phase
            && snapshot.status.phase().message() == message.as_deref()
            && snapshot.status.size_gib == size_gib
            && (backend.is_empty() || snapshot.status.backend == backend)
        {
            continue;
        }
        store
            .mutate::<VolumeSnapshot, _>(&name, |s| {
                s.status.assign(controller_api::VolumeSnapshotPhase::new(
                    phase,
                    controller_api::VolumeSnapshotReason::Reported,
                    message.clone(),
                    at,
                ));
                if !backend.is_empty() {
                    s.status.backend = backend.clone();
                }
                if size_gib > 0 {
                    s.status.size_gib = size_gib;
                }
                s.status.observed_at = Some(at);
            })
            .await?;
        debug!(snapshot = %name, node = node_id, phase = phase.as_str(), "snapshot observed");
    }
    Ok(())
}

/// Clear the old node off a VM whose binding was let go, once that node has
/// stopped naming it.
///
/// The second half of a reschedule. `spec.nodeName` is already `None` — a
/// client cleared it and the reconciler told the old node to destroy the
/// instance — and this is what says the old node is done, so the scheduler
/// may decide again.
///
/// # Absence, and why it is proof HERE
///
/// Absence from a node's report is not proof in general, and this file says
/// so about volumes at some length: a node that does not name something does
/// not KNOW it, and a restart before the first report would otherwise be read
/// as "gone". The question asked here is narrower, and it is exactly the one
/// absence answers: **does this node still name this VM?** A node lists every
/// record it has, minus the ones it is tearing down, so a report that does
/// not carry the uid is a node that is no longer serving it.
///
/// It applies to nothing else. A VM whose `spec.nodeName` is still set is
/// untouched however silent its node is — that is the heartbeat's business —
/// and a VM this tier did not deliberately unbind is never looked at here.
/// A false positive costs a placement that may land on the same node again
/// and is idempotent there; the alternative — waiting for a proof this road
/// cannot carry — costs a VM that never moves.
pub(super) async fn forget_unbound(
    store: &EtcdStore,
    vms: &[Vm],
    node_id: &str,
    report: &StatusReport,
    at: DateTime<Utc>,
) -> anyhow::Result<()> {
    let leaving: Vec<&Vm> = vms
        .iter()
        .filter(|vm| vm.spec.node_name.is_none() && vm.status.node_name.as_deref() == Some(node_id))
        .filter(|vm| !report.vms.iter().any(|r| r.id == vm.metadata.uid))
        .collect();
    for vm in leaving {
        let name = vm.metadata.name.clone();
        store
            .mutate::<Vm, _>(&name, |v| {
                v.status.node_name = None;
                // Pending and not Stopped: the VM has no node, and the phase
                // an operator reads has to say that rather than describing a
                // guest that no longer exists anywhere.
                v.status.assign(controller_api::VmPhase::new(
                    VmPhaseKind::Pending,
                    controller_api::VmReason::Unbound,
                    Some(format!("node {node_id} let go; waiting to be placed")),
                    at,
                ));
                v.status.volumes.clear();
                v.status.reschedules = v.status.reschedules.saturating_add(1);
                v.status.observed_at = Some(at);
            })
            .await?;
        info!(vm = %name, node = node_id, "the old node let go; the vm can be placed again");
    }
    Ok(())
}

/// One entry per referenced disk of the spec, in spec order, saying whether
/// the node reports having it.
///
/// Spec order and not report order, because the spec is the question: a list
/// that reordered itself as disks arrived would be a list an operator cannot
/// read against what they wrote. A uid the node named that is not among the
/// spec's volumes is simply not in the answer — it is a disk this VM is not
/// asking for, and the drift that follows is the reconciler's.
pub(super) fn observed_attachments(
    vm: &Vm,
    held: &[&str],
) -> Vec<controller_api::VolumeAttachmentStatus> {
    vm.spec
        .referenced_volumes()
        .into_iter()
        .map(|name| controller_api::VolumeAttachmentStatus {
            attached: held.contains(&name.as_str()),
            name,
        })
        .collect()
}

/// The phase half: what the node says each of its VMs is doing, written onto
/// the VM this tier holds.
pub(super) async fn ingest_phases(
    store: &EtcdStore,
    node_id: &str,
    vms: &[Vm],
    report: &StatusReport,
    ours: impl Fn(&Vm) -> bool,
    at: DateTime<Utc>,
) {
    for (reported, seen) in controller_api::observe(vms, &report.vms, ours) {
        let Some((vm, phase, message)) = changed(node_id, reported, seen) else {
            continue;
        };
        let name = vm.metadata.name.clone();
        // Read off the object before the mutate borrows it: the tenant is on
        // the spec and travels with the event, so a member sees its own VMs'
        // history and nobody else's.
        let vm_tenant = vm.spec.tenant.clone();
        let result = store
            .mutate::<Vm, _>(&name, |v| {
                v.status.assign(controller_api::VmPhase::new(
                    phase,
                    controller_api::VmReason::Reported,
                    message.clone(),
                    at,
                ));
                // From the binding, never from the reporter — the rule the
                // cloud tier states one floor up, and it matters more here
                // because `ours` deliberately accepts a report about a VM
                // that is not bound at all (an agent still running one should
                // still be able to say what phase it is in). Stamping the
                // reporter's name would let such an agent write itself into
                // the status of a VM nobody placed there, and `vm ls` would
                // then show a node the spec does not name.
                v.status.node_name = v.spec.node_name.clone();
                v.status.observed_at = Some(at);
            })
            .await;
        match result {
            Ok(_) => {
                note_phase(store, &name, &reported.id, phase, &message, &vm_tenant).await;
                info!(vm = %name, vm_id = %reported.id, ?phase, "phase observed")
            }
            Err(e) => warn!(vm = %name, error = format!("{e:#}"), "writing vm status failed"),
        }
    }
}

/// What one reported line says about one VM, where it says something this
/// tier acts on. `None` is a line that was already answered by saying so.
pub(super) fn changed<'a>(
    node_id: &str,
    reported: &proto::VmStatusReport,
    seen: Observation<'a>,
) -> Option<(&'a Vm, VmPhaseKind, Option<String>)> {
    match seen {
        Observation::Unknown => {
            // A VM created straight on the agent's own API: not ours.
            debug!(node = node_id, vm_id = %reported.id, "status for an unknown vm, ignoring");
            None
        }
        Observation::NotBound(vm) => {
            warn!(vm = %vm.metadata.name, node = node_id, "status from a node the vm is not bound to");
            None
        }
        Observation::BadPhase(vm) => {
            warn!(vm = %vm.metadata.name, phase = %reported.phase, "unknown phase from agent");
            None
        }
        Observation::Changed(vm, phase, message) => Some((vm, phase, message)),
    }
}

/// The event a landed phase leaves behind.
///
/// In the arm where the write LANDED, and only for a report that `observe`
/// already called a change — a peer reports every ten seconds and says the
/// same thing nearly every time, and the one that matters is the one that is
/// different. Warning for the two phases nothing automatic leaves on its own;
/// Normal for every ordinary transition.
pub(super) async fn note_phase(
    store: &EtcdStore,
    name: &str,
    uid: &str,
    phase: VmPhaseKind,
    message: &Option<String>,
    tenant: &Option<String>,
) {
    let kind = match phase {
        VmPhaseKind::Failed | VmPhaseKind::Quarantined => EventType::Warning,
        _ => EventType::Normal,
    };
    events::record(
        store,
        Happening {
            kind: Vm::KIND,
            name,
            uid,
            reason: events::reason::PHASE_CHANGED,
            message: match message {
                Some(said) => format!("{} ({said})", phase.as_str()),
                None => phase.as_str().to_string(),
            },
            event_type: kind,
            tenant: tenant.as_deref(),
        },
    )
    .await;
}
