// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Hello and goodbye: what a node has to say when it dials in, and what
//! the cluster does when it stops saying anything.
//!
//! Hello is the one message that creates a `Node` object, so it is also the
//! one that decides what the scheduler will find; `send_desired_state` is
//! the answer to it. Verbatim out of `session.rs`.

use super::*;

/// The node exists, it is who it says it is, it has been told what it is
/// supposed to be running, and from now on commands reach it. Returns the
/// node id the rest of the session speaks for, or None to end the session.
pub(super) async fn on_hello(session: &Session, hello: Hello) -> Option<String> {
    // The certificate said who dialled; the hello says which node it claims
    // to be. One node's key must not let it be told about another node's VMs.
    if let Err(e) =
        controller_api::grpc::check_session_identity(&session.who, "node", &hello.node_id)
    {
        // Error, not warn: an agent whose certificate does not match the
        // node it claims to be will redial with the same certificate for
        // ever. No pass and no reconnect repairs that; only a person
        // re-issuing it does.
        error!(node = %hello.node_id, error = format!("{e:#}"), "refusing the session");
        let _ = session.tx.send(Err(e)).await;
        return None;
    }
    info!(
        node = %hello.node_id,
        version = %hello.agent_version,
        drivers = hello.drivers.len(),
        "agent connected"
    );
    if let Err(e) = ingest_hello(&session.store, &hello, session.advertise.as_deref()).await {
        warn!(node = %hello.node_id, error = format!("{e:#}"), "recording the node failed");
    }
    // A Hello happens once per session, so this is a transition by
    // construction and needs no guard the way a reconcile branch does. An
    // agent that reconnects in a loop aggregates into one object with a count,
    // which is exactly the shape that story should have.
    events::record(
        &session.store,
        Happening {
            kind: Node::KIND,
            name: &hello.node_id,
            uid: "",
            reason: events::reason::PEER_READY,
            message: format!("agent {} connected", hello.agent_version),
            event_type: EventType::Normal,
            tenant: None,
        },
    )
    .await;
    // Snapshot first, registry second. The reconciler dispatches through the
    // registry, so a node that is not in it yet cannot be sent a command —
    // which is what keeps a Create issued right now from arriving ahead of a
    // snapshot taken a moment ago and being reaped by it as a VM the
    // controller never named.
    if !send_desired_state(
        &session.store,
        session.kek.as_deref(),
        &session.tx,
        &hello.node_id,
    )
    .await
    {
        return None;
    }
    // --- lane 5A: which certificate this session is ---
    session
        .registry
        .register(&hello.node_id, &session.tx, serial_of(&session.who));
    Some(hello.node_id)
}

/// Hello: the node exists from now on, with what it just told us about/// Hello: the node exists from now on, with what it just told us about
/// itself. Creating on first sight is what makes the inventory survive the
/// agent — a node that is down is NotReady, not absent.
pub(super) async fn ingest_hello(
    store: &EtcdStore,
    hello: &Hello,
    advertise: Option<&str>,
) -> anyhow::Result<()> {
    let name = hello.node_id.as_str();
    let profiles = capacity_profiles(&hello.drivers);
    let localities = capacity_localities(&hello.drivers);
    // This node dialled THIS replica, so this replica is the only one that
    // can ask it anything. Writing where it can be reached is what lets a
    // sibling forward a console read instead of answering 503 two times out
    // of three. `None` — a wildcard bind with no `advertise_api` — writes
    // nothing rather than an address that would point at the asker's own
    // loopback.
    let advertise = advertise.map(str::to_string);
    // Store the machine profile reported at Hello for migration compatibility.
    // Missing fields remain unknown; comparisons reject only values reported by
    // both source and destination.
    let machine = hello.machine.as_ref().map(machine_profile);
    let apply = |n: &mut Node| {
        n.status.ready = true;
        n.status.agent_version = Some(hello.agent_version.clone());
        n.status.capacity.capabilities = profiles.clone();
        n.status.capacity.volume_localities = localities.clone();
        n.status.session_endpoint = advertise.clone();
        if let Some(machine) = &machine {
            n.status.machine = Some(machine.clone());
        }
        // `status.conditions` is deliberately NOT cleared here. A node
        // re-introducing itself has said nothing about its health yet, and
        // the first status report replaces the list a moment later; clearing
        // it at Hello would make a machine that reboots BECAUSE its disk is
        // full schedulable for exactly as long as it takes to be given work.
    };

    if matches!(store.get::<Node>(name).await, Err(StoreError::NotFound(_))) {
        match store
            .create(&Node::declare(name, NodeSpec::default()))
            .await
        {
            // Two sessions for one node can race here; either object will do.
            Ok(_) | Err(StoreError::AlreadyExists(_)) => {}
            Err(e) => return Err(e.into()),
        }
    }
    store.mutate::<Node, _>(name, apply).await?;
    // The beat goes in its own key, here as in every other place a node
    // speaks (D-C7). A Hello IS a beat: it is the first thing the agent says
    // on a new session, and a node whose lease waited for the first status
    // report would read as expired for up to ten seconds after connecting.
    store.beat::<Node>(name, Utc::now()).await?;
    forget_router_refusals(store, name).await;
    Ok(())
}

/// Clear router refusals when a node starts a new session and republishes its
/// capabilities. This permits retry after repair; an unchanged defect can be
/// refused and recorded again.
async fn forget_router_refusals(store: &EtcdStore, node: &str) {
    let routers = match store.list::<controller_api::Router>().await {
        Ok(routers) => routers,
        Err(e) => {
            warn!(node, error = %format!("{e:#}"), "listing routers after hello failed");
            return;
        }
    };
    for router in routers
        .iter()
        .filter(|r| r.status.refused.iter().any(|n| n == node))
    {
        let name = router.metadata.name.clone();
        match store
            .mutate::<controller_api::Router, _>(&name, |r| r.status.refused.retain(|n| n != node))
            .await
        {
            Ok(_) => info!(router = %name, node, "a new session; asking this node again"),
            Err(e) => warn!(router = %name, node, error = %format!("{e:#}"),
                            "clearing the refusal failed"),
        }
    }
}

/// The wire form as the object's, field for field.
///
/// Written out rather than derived, because the two types are a contract
/// between two processes and a rename on either side should be a compile
/// error here rather than a field that quietly stops travelling. Every field
/// carries an empty string when the node said nothing, and empty is never
/// evidence one tier up.
pub(super) fn machine_profile(m: &proto::MachineProfile) -> controller_api::MachineProfile {
    controller_api::MachineProfile {
        cpu_vendor: m.cpu_vendor.clone(),
        cpu_model: m.cpu_model.clone(),
        cpu_flags: m.cpu_flags.clone(),
        nested: m.nested,
        hypervisor: m.hypervisor.clone(),
        cpu_profile: m.cpu_profile.clone(),
        hypervisor_version: m.hypervisor_version.clone(),
        kernel: m.kernel.clone(),
        host: m.host.clone(),
    }
}

/// Extract reported volume-driver locality. Missing or unknown values do not
/// imply node-local storage. Duplicate entries use the last value; pool logic
/// separately resolves disagreements between nodes.
pub(super) fn capacity_localities(drivers: &[DriverInfo]) -> BTreeMap<String, Locality> {
    let mut out = BTreeMap::new();
    for driver in drivers.iter().filter(|d| d.name == capability::VOLUME) {
        let Some(locality) = Locality::parse(&driver.locality) else {
            continue;
        };
        for profile in &driver.profiles {
            out.insert(profile.clone(), locality);
        }
    }
    out
}

pub(super) fn capacity_profiles(drivers: &[DriverInfo]) -> Vec<String> {
    drivers
        .iter()
        .flat_map(|d| {
            if d.profiles.is_empty() {
                // No profiles to choose between: the driver name IS the entry.
                vec![capability::entry(&d.name, None)]
            } else {
                d.profiles
                    .iter()
                    .map(|p| capability::entry(&d.name, Some(p)))
                    .collect()
            }
        })
        .collect()
}

/// The reconnect sweep: one message that says everything this node should be
/// running. False means the stream is gone.
pub(super) async fn send_desired_state(
    store: &EtcdStore,
    kek: Option<&controller_api::secrets::Kek>,
    tx: &CommandTx,
    node_id: &str,
) -> bool {
    let desired = match desired_snapshot(store, kek, node_id).await {
        Ok(desired) => desired,
        // Skipped, never truncated: see desired_snapshot. The session goes
        // on — the periodic reconcile pass is what heals a missed sweep.
        Err(e) => {
            warn!(node = %node_id, error = format!("{e:#}"),
                  "could not build the desired state, none sent");
            return true;
        }
    };
    info!(node = %node_id, vms = desired.len(), "sending desired state");
    let msg = ControllerMessage {
        kind: Some(proto::controller_message::Kind::Sync(proto::SyncState {
            desired,
        })),
    };
    if tx.send(Ok(msg)).await.is_err() {
        warn!(node = %node_id, "session closed before the desired state went out");
        return false;
    }
    true
}

/// Build a complete desired CreateInstance snapshot for reconnect synchronization.
/// Exclude deleting VMs so an agent that missed teardown can remove them.
/// Reject incomplete store listings: omitting an unreadable VM would authorize
/// its destruction. A failed snapshot leaves reconnect cleanup unperformed.
pub(super) async fn desired_snapshot(
    store: &EtcdStore,
    kek: Option<&controller_api::secrets::Kek>,
    node_id: &str,
) -> anyhow::Result<Vec<proto::CreateInstance>> {
    let vms = store.list::<Vm>().await?;
    // `list` drops what it cannot decode, and an object dropped here reads
    // at the agent as an object deleted. Count first, and say nothing at all
    // rather than something that means "the rest is gone".
    let stored = store.count::<Vm>().await?;
    if vms.len() != stored {
        bail!(
            "{} of {stored} vm objects did not decode; a snapshot missing them \
             would read as their deletion",
            stored - vms.len()
        );
    }

    let mut out = Vec::new();
    for vm in vms {
        if vm.is_deleting() || vm.spec.node_name.as_deref() != Some(node_id) {
            continue;
        }
        // The same uid rewrite the dispatch does. A snapshot is a replay of
        // the creates this node would have got anyway, so it has to be the
        // same document down to the last field.
        let uids = crate::reconcile::volume_uids(store, &vm)
            .await
            .with_context(|| format!("vm {}", vm.metadata.name))?;
        // Resolve cloud-init exactly as normal dispatch does. An unresolved secret
        // fails the whole snapshot; omitting just that VM would authorize agent teardown.
        let seed = match crate::reconcile::seed_for(store, kek, &vm).await? {
            crate::reconcile::Seed::None => None,
            crate::reconcile::Seed::Ready(plaintext) => Some(plaintext),
            crate::reconcile::Seed::NotReady(reason) => bail!(
                "vm {}: {reason}; a snapshot without it would read as its deletion",
                vm.metadata.name
            ),
        };
        let spec_json = build_spec_json(&vm, &uids, seed.as_deref())
            .with_context(|| format!("vm {}", vm.metadata.name))?;
        out.push(proto::CreateInstance {
            id: vm.metadata.uid.clone(),
            spec: None,
            spec_json,
        });
    }
    Ok(out)
}

/// Whether every uid in the report is one this list can name. False is the
/// only thing that makes a reused list worse than a fresh one, so it is the
/// only thing worth re-reading for.
pub(super) fn all_known(vms: &[Vm], reported: &[proto::VmStatusReport]) -> bool {
    let uids: HashSet<&str> = vms.iter().map(|v| v.metadata.uid.as_str()).collect();
    reported.iter().all(|line| uids.contains(line.id.as_str()))
}

/// The stream is over. Whether that means the node is down is a question
/// about the registry, not about this stream.
pub(super) async fn on_disconnect(session: &Session, node_id: &str) {
    // A reconnect that already replaced us keeps its own session and its own
    // readiness; only a real disconnect reports down. `same_channel` is what
    // decides that, so this session's own handle is the right one to ask
    // with — it is a clone of the one a Hello registered.
    if !session.registry.disconnect(node_id, &session.tx) {
        // A decision not taken: the node stays ready because a newer session
        // speaks for it. The cloud tier's twin says the same thing at the
        // same level.
        debug!(node = %node_id, "stale session closed, a newer one is live");
        return;
    }
    info!(node = %node_id, "agent disconnected");
    let result = session
        .store
        .mutate::<Node, _>(node_id, |n| {
            n.status.ready = false;
            // Nobody holds this node's session now, so nobody should be sent
            // here for its console. A stale endpoint is worse than none: it
            // is a 503 from the wrong process, one hop later.
            n.status.session_endpoint = None;
        })
        .await;
    if let Err(e) = result {
        warn!(node = %node_id, error = format!("{e:#}"), "marking the node not ready failed");
    }
}
