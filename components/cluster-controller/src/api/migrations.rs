// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Cluster migration requests, admission checks and ownership-aware deletion.

use super::*;

pub(super) async fn list_vm_migrations(
    State(st): State<ApiState>,
    axum::extract::Query(q): axum::extract::Query<controller_api::ListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let selector = controller_api::Selector::parse(q.label_selector.as_deref())?;
    let mut items = st.store.list::<controller_api::VmMigration>().await?;
    items.retain(|m| {
        q.tenant.as_deref().is_none_or(|t| m.spec.tenant == t)
            && selector.selects(&m.metadata.labels)
    });
    Ok(Json(
        json!({ "apiVersion": API_VERSION, "kind": "VmMigrationList", "items": items }),
    ))
}

pub(super) async fn get_vm_migration(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<controller_api::VmMigration>, ApiError> {
    Ok(Json(st.store.get(&name).await?))
}

/// Create migration intent after synchronous eligibility checks.
/// The reconciler selects and prepares the target, then drives the transfer.
/// An explicit migration ignores `evacuation: never`: that policy controls
/// automatic drains, while this request explicitly authorizes moving the VM.
pub(super) async fn create_vm_migration(
    State(st): State<ApiState>,
    dry: controller_api::DryRun,
    Json(body): Json<controller_api::VmMigration>,
) -> Result<(StatusCode, Json<controller_api::VmMigration>), ApiError> {
    check_envelope(&body)?;
    if body.metadata.name.is_empty() {
        return Err(invalid("metadata.name must be set"));
    }
    if body.spec.vm.is_empty() {
        return Err(invalid("spec.vm must name the vm to move"));
    }
    let vm: Vm = match st.store.get::<Vm>(&body.spec.vm).await {
        Ok(v) => v,
        // 404 and never 403, by the argument `check_volume_refs` makes: a 403
        // would confirm that a VM of that name exists somewhere.
        Err(StoreError::NotFound(_)) => {
            return Err(ApiError::new(
                StatusCode::NOT_FOUND,
                "NotFound",
                format!("no vm {:?} here", body.spec.vm),
            ));
        }
        Err(e) => return Err(e.into()),
    };
    let facts = migration_facts(&st, &vm).await?;
    if let Some(why) = migration_refusal(&vm, &facts, body.spec.target_node.as_deref()) {
        return Err(invalid(why));
    }

    let mut spec = body.spec;
    // Whose it is follows the VM and is not the caller's to state: a record
    // of what happened to somebody's VM belongs in their history.
    spec.tenant = vm.spec.tenant.clone().unwrap_or_default();
    let migration = controller_api::VmMigration::declare(&body.metadata.name, spec);
    let created = match dry.preview(&migration) {
        Some(preview) => preview,
        None => st.store.create(&migration).await?,
    };
    info!(migration = %created.metadata.name, vm = %created.spec.vm, "migration requested");
    Ok((StatusCode::CREATED, Json(created)))
}

/// In-flight records retain operation ownership and capacity reservations.
/// A version-checked delete prevents racing a pending migration's prepare claim.
pub(super) async fn delete_vm_migration(
    State(st): State<ApiState>,
    Path(name): Path<String>,
) -> Result<controller_api::Removed, ApiError> {
    let migration: controller_api::VmMigration = st.store.get(&name).await?;
    if !migration.status.phase().kind().is_final()
        && migration.status.phase().kind() != controller_api::VmMigrationPhaseKind::Pending
    {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "MigrationInFlight",
            "resolve the migration before deleting its ownership record",
        ));
    }
    st.store
        .delete_if::<controller_api::VmMigration>(&name, &migration.metadata.resource_version)
        .await?;
    Ok(controller_api::removed(
        controller_api::VmMigration::KIND,
        &name,
        controller_api::Removal::Gone,
    ))
}

/// Gather what [`migration_refusal`] decides on.
///
/// The reads are here and the rule is next door, so that the rule can be
/// exercised without a store — which matters, because it is the whole of what
/// this route does that is worth arguing about.
pub(super) async fn migration_facts(st: &ApiState, vm: &Vm) -> Result<MigrationFacts, ApiError> {
    let here = vm
        .spec
        .node_name
        .clone()
        .or_else(|| vm.status.node_name.clone());
    let mut facts = MigrationFacts::default();
    for name in vm.spec.referenced_volumes() {
        let volume: Volume = match st.store.get(&name).await {
            Ok(v) => v,
            Err(StoreError::NotFound(_)) => {
                facts.unready_disk = Some(name);
                break;
            }
            Err(e) => return Err(e.into()),
        };
        if volume.status.phase().kind() != controller_api::VolumePhaseKind::Ready {
            facts.unready_disk = Some(name);
            break;
        }
        let pool: StoragePool = match st.store.get(&volume.spec.pool).await {
            Ok(p) => p,
            Err(StoreError::NotFound(_)) => {
                facts.unready_disk = Some(name);
                break;
            }
            Err(e) => return Err(e.into()),
        };
        if pool.status.locality == Some(controller_api::Locality::NodeLocal) {
            facts.node_local_disk = Some(name);
            break;
        }
    }
    // Somewhere to go: connected, not drained, not cordoned, running a
    // hypervisor, and not the machine the VM is already on. Deliberately NOT
    // the scheduler — this is the edge answering "is there any point", and
    // the scheduler answers "which one" a pass later against capacity that
    // may have changed by then.
    let nodes = st.store.list::<controller_api::Node>().await?;
    // What this guest's saved state would have to be restored into. Read here
    // so that the rule next door needs no store, and read by NAME rather than
    // filtered, because the source is exactly the node the target list has cut
    // away.
    facts.source_machine = here
        .as_deref()
        .and_then(|name| nodes.iter().find(|n| n.metadata.name == name))
        .and_then(|n| n.status.machine.clone());
    facts.source_node = here.clone().unwrap_or_default();
    facts.machines = nodes
        .iter()
        .map(|n| (n.metadata.name.clone(), n.status.machine.clone()))
        .collect();
    facts.targets = nodes
        .into_iter()
        .filter(|n| n.status.ready && n.spec.schedulable && !n.spec.drain)
        .filter(|n| {
            common::capability::offers(
                &n.status.capacity.capabilities,
                common::capability::HYPERVISOR,
                None,
            )
        })
        .map(|n| n.metadata.name)
        .filter(|n| here.as_deref() != Some(n.as_str()))
        .collect();
    Ok(facts)
}

/// What [`migration_refusal`] decides on: the facts about one VM that its own
/// object does not carry.
#[derive(Clone, Debug, Default)]
pub(crate) struct MigrationFacts {
    /// A referenced volume whose bytes are on one machine, by name.
    pub node_local_disk: Option<String>,
    /// A referenced volume this tier cannot see the state of yet, by name.
    pub unready_disk: Option<String>,
    /// Nodes that are connected, schedulable, run a hypervisor, and are not
    /// the VM's own — in short, somewhere it could go.
    pub targets: Vec<String>,
    /// The machine this guest is on now, by name. Empty for a VM that is on
    /// no node, which the phase check refuses first anyway.
    pub source_node: String,
    /// What its saved state would have to come OUT of. `None` from a node
    /// whose agent predates the field.
    pub source_machine: Option<controller_api::MachineProfile>,
    /// And what every node in this cluster would restore it into, by name.
    ///
    /// Every node and not only the targets, so that a `targetNode` somebody
    /// NAMED is answered about even when the general list would not have
    /// contained it — the sentence has to be about the node they asked about.
    pub machines: std::collections::BTreeMap<String, Option<controller_api::MachineProfile>>,
}

/// Refuse unsupported VM state, devices/disks, missing targets or known machine
/// incompatibility. Missing machine profiles retain compatibility with older agents.
/// Explicit requests do not apply the drain-only evacuation policy.
pub(crate) fn migration_refusal(
    vm: &Vm,
    facts: &MigrationFacts,
    target: Option<&str>,
) -> Option<String> {
    if vm.status.phase().kind() != controller_api::VmPhaseKind::Running {
        return Some(format!(
            "vm {} is {} and only a running vm can migrate live; a stopped one moves with \
             `vm reschedule`",
            vm.metadata.name,
            vm.status.phase().kind().as_str()
        ));
    }
    if let Some(why) = crate::migration::device_refusal(vm) {
        return Some(why);
    }
    if let Some(disk) = inline_disk(&vm.spec.vm) {
        return Some(format!(
            "{disk} is an instance-store disk: its bytes were made on the machine {} is leaving \
             and there is no volume object that could follow it, so no live migration takes them \
             along",
            vm.metadata.name
        ));
    }
    if let Some(disk) = &facts.node_local_disk {
        return Some(format!(
            "volume {disk} is node-local, so its bytes are on the machine {} is leaving and no \
             live migration takes them along",
            vm.metadata.name
        ));
    }
    if let Some(disk) = &facts.unready_disk {
        return Some(format!(
            "volume {disk} is not ready here, so where its bytes are is not yet knowable"
        ));
    }
    match target {
        Some(named) if !facts.targets.iter().any(|t| t == named) => {
            return Some(format!(
                "node {named} cannot take this vm: it must be connected, schedulable, running a \
                 hypervisor, and not the node the vm is already on"
            ));
        }
        None if facts.targets.is_empty() => {
            return Some(format!(
                "no other node is connected, schedulable and running a hypervisor, so {} has \
                 nowhere to go",
                vm.metadata.name
            ));
        }
        _ => {}
    }
    // Check source/target machine compatibility before starting the migration,
    // using the shared live-migration rules rather than waiting for restore failure.
    let here = facts.source_machine.as_ref()?;
    let fits = |name: &String| -> Option<String> {
        let there = facts.machines.get(name)?.as_ref()?;
        controller_api::live_migration_refusal(&facts.source_node, here, name, there)
    };
    match target {
        // A node somebody NAMED is answered about by name: they asked about
        // that node, and "some other node would do" is not the answer.
        Some(named) => fits(&named.to_string()),
        // Nowhere to go is a refusal only when NOTHING fits. One machine that
        // can take it is the whole of what this verb needs.
        None => {
            let refusals: Vec<String> = facts.targets.iter().filter_map(fits).collect();
            (refusals.len() == facts.targets.len())
                .then(|| refusals.into_iter().next())
                .flatten()
        }
    }
}

/// Find an inline disk by its spec path. Its node-local bytes have no independent
/// Volume record that can follow a live migration.
pub(super) fn inline_disk(spec: &serde_json::Value) -> Option<String> {
    let volumes = spec.get("volumes")?.as_array()?;
    volumes
        .iter()
        .position(|v| v.get("volume").is_none_or(serde_json::Value::is_null))
        .map(|i| format!("spec.vm.volumes[{i}]"))
}
