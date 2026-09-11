// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! `vmmigrations` at the cloud: one verb, and it keeps nothing.
//!
//! The one resource this tier serves and does not store. Everywhere else the
//! cloud holds the object and the cluster holds a copy; here the object lives
//! at the cluster and this is a door to it, because a live migration is a
//! record of a guest moving between two MACHINES and machines are a cluster's
//! nouns. There is deliberately no live migration across clusters (the
//! storage is why: two clusters that could both reach one VM's disk is a
//! claim, and a live stream between two machines that do not share a control
//! plane is a second one), so there is nothing here for a cloud to own.
//!
//! What there WAS instead, until now, is a dead end. `meister vm migrate`
//! against a cloud answered `this endpoint is a cloud and has no
//! "vmmigrations"` — true, and useless to somebody whose credential works at
//! exactly one endpoint (D-P9). Every other write this tier forwards travels
//! down the cluster's own session; there was simply no message for this one,
//! and now there is: `CreateVmMigration`.
//!
//! **Create and nothing else, and the discovery document says so.** A listing
//! here would have to invent a mirror of an object this tier does not keep,
//! and `vmmigration ls` at a cloud already answers with the sentence that
//! names where the records are. One verb that works beats four that half do.

use super::*;

/// The document a client POSTs here.
///
/// Its own type rather than `controller_api::VmMigration`, and the reason is
/// what this route IS: nothing is stored, so there is no envelope to fill in,
/// no `status` to answer with and no `resourceVersion` to hand back. What
/// travels is an ask, and the four fields below are the whole of it.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct MigrationRequest {
    #[serde(default)]
    metadata: RequestMeta,
    #[serde(default)]
    spec: RequestSpec,
}

#[derive(Default, serde::Deserialize)]
struct RequestMeta {
    #[serde(default)]
    name: String,
}

#[derive(Default, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RequestSpec {
    #[serde(default)]
    vm: String,
    #[serde(default)]
    target_node: Option<String>,
    #[serde(default)]
    tenant: Option<String>,
}

/// `POST /apis/meister.io/v1/vmmigrations` — ask the cluster that runs this
/// guest to move it.
///
/// The node-patch forward, one noun over, and deliberately the same one: two
/// ends of one idea in two places is how a header name, a timeout and a loop
/// rule start disagreeing. What differs is only which command goes down the
/// session.
///
/// **Accepted, not done.** The answer is the object as the cluster will have
/// written it, with no status on it — because there is none yet, and inventing
/// `Pending` here would be this tier claiming to know something the cluster
/// has not said. `vmmigration get` at the cluster is where the phases are, and
/// the note the CLI prints says so.
pub(super) async fn create_vm_migration(
    State(st): State<ApiState>,
    caller: Caller,
    role: CallerRole,
    tenant: CallerTenant,
    headers: axum::http::HeaderMap,
    dry: controller_api::DryRun,
    Json(body): Json<MigrationRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    if body.metadata.name.is_empty() {
        return Err(invalid("metadata.name must be set"));
    }
    if body.spec.vm.is_empty() {
        return Err(invalid("spec.vm must name the vm to move"));
    }

    // The VM decides everything else: whose it is, and which cluster is being
    // asked. A migration of a guest this cloud does not know is a 404 about
    // the guest, which is the thing the caller got wrong.
    let vm: Vm = st.store.get(&body.spec.vm).await?;
    Grant::new(caller, role, tenant).allows(Scope::of(vm.spec.tenant.as_deref()), Verb::Write)?;

    let Some(cluster) = vm
        .spec
        .cluster_name
        .clone()
        .or_else(|| vm.status.cluster_name.clone())
    else {
        return Err(invalid(format!(
            "vm {} is not on a cluster yet, so there is nothing to move it between",
            body.spec.vm
        )));
    };

    let target = body.spec.target_node.clone().unwrap_or_default();
    // Whose it is, in the same words `CreateVm` uses: what the request said,
    // or the VM's own. The cluster carries it and never enforces it.
    let owner = body
        .spec
        .tenant
        .clone()
        .or_else(|| vm.spec.tenant.clone())
        .unwrap_or_default();
    let answer = serde_json::json!({
        "apiVersion": "meister.io/v1",
        "kind": controller_api::VmMigration::KIND,
        "metadata": { "name": body.metadata.name },
        "spec": {
            "vm": body.spec.vm,
            "tenant": owner,
            "targetNode": body.spec.target_node,
        },
    });

    // Nothing travels for a preview, the same rule the node patch applies:
    // the answer is already what the object will read as, so a preview is
    // that answer with the mark on it and no command sent.
    if dry.requested() {
        let mut object = answer;
        object["metadata"]["annotations"] =
            serde_json::json!({ controller_api::ANNOTATION_DRY_RUN: "true" });
        return Ok((StatusCode::ACCEPTED, Json(object)));
    }

    let command = proto::CreateVmMigration {
        name: body.metadata.name.clone(),
        vm: body.spec.vm.clone(),
        target_node: target,
        tenant: owner,
    };

    // Which replica can send it. A cluster dials ONE cloud replica, so two of
    // every three of these would answer 503 "no active session" and the
    // client would have to guess which replica to ask. See the same paragraph
    // on `patch_cluster_node`, which this is a copy of on purpose.
    match controller_api::forward::holder(
        super::vms::ABOUT,
        st.sessions.holds(&cluster),
        super::vms::session_endpoint(&st, &cluster)
            .await?
            .as_deref(),
        headers.contains_key(controller_api::forward::FORWARDED),
    ) {
        controller_api::forward::Holder::Here => {}
        controller_api::forward::Holder::Sibling(endpoint) => {
            info!(migration = %body.metadata.name, vm = %body.spec.vm, cluster, %endpoint,
                  "forwarding a migration request to the replica that holds the cluster session");
            let path = "/apis/meister.io/v1/vmmigrations".to_string();
            let raw = serde_json::to_vec(&serde_json::json!({
                "metadata": { "name": body.metadata.name },
                "spec": {
                    "vm": body.spec.vm,
                    "targetNode": body.spec.target_node,
                    "tenant": body.spec.tenant,
                },
            }))
            .map_err(|e| invalid(format!("re-encoding the request: {e}")))?;
            return match controller_api::forward::relay(
                &st.sibling,
                &endpoint,
                axum::http::Method::POST,
                &path,
                raw.into(),
            )
            .await
            {
                Ok(sibling) => forwarded_answer(&endpoint, sibling),
                Err(e) => Err(ApiError::new(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Unavailable",
                    format!("{e:#}"),
                )),
            };
        }
        controller_api::forward::Holder::Nowhere(why) => {
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "Unavailable",
                why,
            ));
        }
    }

    match st
        .sessions
        .send_command(&cluster, "", cloud_command::Op::CreateVmMigration(command))
        .await
    {
        Ok(controller_api::Ack::Acked(_)) => Ok((StatusCode::ACCEPTED, Json(answer))),
        // The cluster's own refusal, in its own words — no such VM there, a
        // name already taken by a different migration.
        Ok(controller_api::Ack::Rejected(refusal)) => Err(super::vms::refused(refusal)),
        Err(e) => Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Unavailable",
            format!("{e:#}"),
        )),
    }
}
