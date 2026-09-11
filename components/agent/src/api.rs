// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context as _;
use axum::{
    Json, Router,
    extract::{FromRequest, rejection::JsonRejection},
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use tracing::{info, instrument, warn};

use agent_api::VmId;
use tokio::net::UnixListener;

use crate::drivers::{DeviceCatalog, HypervisorCatalog, NetworkCatalog, VolumeCatalog};
use crate::provision::Provisioner;
use crate::reconcile::{Action, Reconciler, Trigger};
use crate::store::Store;
use crate::types::{Desired, Phase};
use crate::types::{NewVmSpec, NewVmSpecExt};
use agent_api::hypervisor::ConsoleStream;

#[derive(Serialize)]
struct CreatedResponse {
    id: String,
}

#[derive(Clone)]
pub struct ApiState {
    pub store: Arc<Store>,
    pub reconciler: Arc<Reconciler>,
    pub provisioner: Arc<Provisioner>,
    pub ops: Arc<tokio::sync::Mutex<()>>,
    pub pause_supported: bool,
    pub stop_grace: std::time::Duration,
    pub catalog: DeviceCatalog,
    pub volumes: VolumeCatalog,
    pub hypervisor: HypervisorCatalog,
    pub network: NetworkCatalog,
    pub default_bridge: String,
    /// The volumes this node owns on their own. Read-only from here: a
    /// volume is created and destroyed over the controller session and
    /// nowhere else, so this socket can SHOW one and cannot make one.
    pub volumes_owned: Arc<crate::volumes::Volumes>,
}

pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }

    fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    /// Somebody else has it, or it is not there to be had. Two different
    /// sentences, one status: the caller acts on the words.
    fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, message)
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        // A spec a driver rejects is the caller's error, not an agent fault.
        let invalid_spec = e.chain().any(|c| {
            matches!(
                c.downcast_ref::<agent_api::device::DeviceError>(),
                Some(agent_api::device::DeviceError::InvalidSpec(_))
            ) || matches!(
                c.downcast_ref::<agent_api::storage::StorageError>(),
                Some(agent_api::storage::StorageError::InvalidSpec(_))
            ) || matches!(
                c.downcast_ref::<agent_api::hypervisor::HypervisorError>(),
                Some(agent_api::hypervisor::HypervisorError::InvalidSpec(_))
            )
        });
        let status = if invalid_spec {
            StatusCode::UNPROCESSABLE_ENTITY
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        };
        Self::new(status, format!("{e:#}"))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        #[derive(Serialize)]
        struct Body {
            error: String,
        }
        (
            self.status,
            Json(Body {
                error: self.message,
            }),
        )
            .into_response()
    }
}

pub struct ApiJson<T>(pub T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    axum::Json<T>: FromRequest<S, Rejection = JsonRejection>,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(req: axum::extract::Request, state: &S) -> Result<Self, Self::Rejection> {
        match axum::Json::<T>::from_request(req, state).await {
            Ok(axum::Json(value)) => Ok(ApiJson(value)),
            Err(rejection) => Err(ApiError::bad_request(rejection.body_text())),
        }
    }
}

fn parse_id(raw: &str) -> Result<VmId, ApiError> {
    raw.parse()
        .map_err(|e| ApiError::bad_request(format!("invalid vm id {raw:?}: {e}")))
}

pub fn router(state: ApiState) -> Router {
    let router = Router::new()
        .route("/healthz", get(healthz))
        .route("/vms", get(list_vms).post(create_vm))
        .route("/vms/{id}", get(inspect_vm).delete(destroy_vm))
        .route("/vms/{id}/observe", get(observe_vm))
        .route("/vms/{id}/logs", get(vm_logs))
        .route("/vms/{id}/console", get(vm_console))
        .route("/vms/{id}/state", get(vm_state))
        .route("/vms/{id}/reconcile", post(reconcile_vm))
        .route("/vms/{id}/start", post(start_vm))
        .route("/vms/{id}/stop", post(stop_vm))
        .route("/vms/{id}/pause", post(pause_vm))
        .route("/vms/{id}/resume", post(resume_vm))
        // Read-only, deliberately. Provision and deprovision arrive over the
        // controller session because the LIFECYCLE of a volume belongs to the
        // object one tier up; a write route here would be a second owner of
        // somebody's data, reachable by anybody in the socket group.
        .route("/volumes", get(list_volumes))
        .route("/volumes/{id}", get(get_volume));

    #[cfg(feature = "debug-mutations")]
    let router = router
        .route("/vms/{id}/record", axum::routing::delete(delete_record))
        .route("/vms/{id}/phase", axum::routing::put(set_phase));

    router.with_state(state)
}

/// The socket and the directory it lives in, with the access rule on them.
///
/// `group` is `[paths] socket_group` resolved to a gid (`PathsConfig::
/// socket_gid`). `None` is 0700/0600 and root only, which is how every node
/// has run so far. `Some` is 0750/0660 owned by that group, so its members
/// reach the node's local admin API without sudo.
///
/// chmod before chown, in that order and never the other way round: between
/// the two calls the mode is already the narrow one, so the widening step is
/// the last thing that happens and the socket is never both group-owned and
/// group-writable to a group that was not meant to have it.
fn bind_socket(socket_path: &std::path::Path, group: Option<u32>) -> anyhow::Result<UnixListener> {
    let (dir_mode, socket_mode) = match group {
        Some(_) => (0o750, 0o660),
        None => (0o700, 0o600),
    };

    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating socket dir {}", parent.display()))?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(dir_mode))
            .with_context(|| format!("chmod {dir_mode:04o} on {}", parent.display()))?;
        if let Some(gid) = group {
            std::os::unix::fs::chown(parent, None, Some(gid))
                .with_context(|| format!("chgrp {gid} on {}", parent.display()))?;
        }
    }

    match std::fs::remove_file(socket_path) {
        Ok(()) => warn!("removed stale socket from a previous run"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("removing {}", socket_path.display())),
    }

    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("binding {}", socket_path.display()))?;

    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(socket_mode))
        .with_context(|| format!("chmod {socket_mode:04o} on {}", socket_path.display()))?;
    if let Some(gid) = group {
        std::os::unix::fs::chown(socket_path, None, Some(gid))
            .with_context(|| format!("chgrp {gid} on {}", socket_path.display()))?;
    }

    Ok(listener)
}

#[instrument(skip_all, fields(socket = %socket_path.display()))]
pub async fn serve(
    socket_path: PathBuf,
    group: Option<u32>,
    state: ApiState,
) -> anyhow::Result<()> {
    let listener = bind_socket(&socket_path, group)?;

    info!(shared_with_group = group.is_some(), "http api listening");
    axum::serve(listener, router(state))
        .await
        .context("http api server")
}

async fn healthz() -> &'static str {
    "ok\n"
}

#[derive(Deserialize)]
struct ListProbe {
    phase: Phase,
    #[serde(default)]
    desired: Desired,
    #[serde(default)]
    unhealthy: Option<String>,
}

#[derive(Serialize)]
struct VmListEntry {
    id: String,
    desired: Option<Desired>,
    phase: Option<Phase>,
    unhealthy: Option<String>,
    readable: bool,
}

/// One volume as this node holds it, for `meister agent volume ls|get`.
///
/// Flat rather than the record verbatim: `backend` is the one field of the
/// handle an operator reads, and a whole `VolumeHandle` in the answer would
/// publish a shape that is the driver's business.
#[derive(Serialize)]
struct VolumeEntry {
    id: String,
    phase: &'static str,
    /// What the backend calls it — the path, the device. Empty until there is
    /// one, which is the window between "told to make it" and "made it".
    backend: String,
    size_bytes: u64,
    driver: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    base_image: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    /// The VM on this node holding it, if one is. Asked of the VM records,
    /// because the attachment belongs to the consumer.
    #[serde(skip_serializing_if = "Option::is_none")]
    attached_to: Option<String>,
}

fn volume_entry(
    id: agent_api::storage::VolumeId,
    record: crate::types::VolumeRecord,
    holders: &std::collections::HashMap<agent_api::storage::VolumeId, String>,
) -> VolumeEntry {
    VolumeEntry {
        phase: record.phase.as_str(),
        backend: record.backend().to_string(),
        size_bytes: record
            .handle
            .as_ref()
            .map(|h| h.size_bytes)
            .unwrap_or(record.spec.size_bytes),
        driver: record
            .spec
            .driver
            .clone()
            .unwrap_or_else(agent_api::storage::default_volume_driver),
        base_image: record.spec.base_image.clone(),
        message: record.message.clone(),
        attached_to: holders.get(&id).cloned(),
        id: id.to_string(),
    }
}

/// Which VM holds which volume, read once for the whole listing.
fn holders(st: &ApiState) -> std::collections::HashMap<agent_api::storage::VolumeId, String> {
    let mut out = std::collections::HashMap::new();
    for (vm, record) in st.store.list().unwrap_or_default() {
        for volume in &record.volumes {
            out.insert(volume.id(), vm.to_string());
        }
    }
    out
}

async fn list_volumes(State(st): State<ApiState>) -> Result<Json<Vec<VolumeEntry>>, ApiError> {
    let holders = holders(&st);
    Ok(Json(
        st.volumes_owned
            .list()?
            .into_iter()
            .map(|(id, record)| volume_entry(id, record, &holders))
            .collect(),
    ))
}

async fn get_volume(
    State(st): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<VolumeEntry>, ApiError> {
    let id: agent_api::storage::VolumeId = id
        .parse()
        .map_err(|_| ApiError::new(StatusCode::BAD_REQUEST, "invalid volume id"))?;
    let record = st
        .volumes_owned
        .get(&id)?
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "no record for this volume"))?;
    Ok(Json(volume_entry(id, record, &holders(&st))))
}

#[instrument(level = "debug", skip_all)]
async fn list_vms(State(st): State<ApiState>) -> Result<Json<Vec<VmListEntry>>, ApiError> {
    let entries = st
        .store
        .list_raw()?
        .into_iter()
        .map(
            |(id, bytes)| match serde_json::from_slice::<ListProbe>(&bytes) {
                Ok(p) => VmListEntry {
                    id,
                    desired: Some(p.desired),
                    phase: Some(p.phase),
                    unhealthy: p.unhealthy,
                    readable: true,
                },
                Err(_) => VmListEntry {
                    id,
                    desired: None,
                    phase: None,
                    unhealthy: None,
                    readable: false,
                },
            },
        )
        .collect();
    Ok(Json(entries))
}

#[instrument(level = "debug", skip_all, fields(vm_id = %id))]
async fn inspect_vm(
    State(st): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    let vm_id = parse_id(&id)?;
    let Some(bytes) = st.store.get_raw(&vm_id)? else {
        return Err(ApiError::not_found(format!("no record for vm {id}")));
    };
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        bytes,
    )
        .into_response())
}

#[derive(Serialize)]
struct ObserveResponse {
    desired: Desired,
    phase: Phase,
    unhealthy: Option<String>,
    observed: crate::reconcile::Observed,
    action: String,
}

#[instrument(level = "debug", skip_all, fields(vm_id = %id))]
async fn observe_vm(
    State(st): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<ObserveResponse>, ApiError> {
    let vm_id = parse_id(&id)?;
    let Some(preview) = st.reconciler.dry_run(&vm_id).await? else {
        return Err(ApiError::not_found(format!("no record for vm {id}")));
    };
    Ok(Json(ObserveResponse {
        desired: preview.desired,
        phase: preview.phase,
        unhealthy: preview.unhealthy,
        observed: preview.observed,
        action: format!("{:?}", preview.action),
    }))
}

/// One stream's worth of what the guest printed.
#[derive(Serialize)]
struct LogStream {
    stream: &'static str,
    text: String,
}

/// What the caller wants of a console: how much, and which lines.
///
/// Read as raw pairs rather than a struct because `hide` and `only` repeat —
/// `?hide=a&hide=b` — and the form encoding behind a typed `Query` has no way
/// to spell a repeated key. Pairs are what the wire actually carries, so this
/// parses what is there rather than what a struct wishes were there.
fn log_request(
    pairs: &[(String, String)],
) -> (usize, crate::console::LogFilter, Vec<ConsoleStream>) {
    let mut lines = crate::console::DEFAULT_LINES;
    let mut keep = crate::console::LogFilter::default();
    let mut wanted: Vec<ConsoleStream> = Vec::new();
    for (key, value) in pairs {
        match key.as_str() {
            // A `lines` that is not a number keeps the default rather than
            // refusing: this is a read, and answering with a screenful is a
            // better answer than a 422 about a typo.
            "lines" => lines = value.parse().unwrap_or(lines),
            "hide" if !value.is_empty() => keep.hide.push(value.clone()),
            "only" if !value.is_empty() => keep.only.push(value.clone()),
            // Repeatable AND comma-separated, because both spellings are
            // what people try. A word this node does not serve is skipped
            // rather than refused — see `ConsoleStream::parse`.
            "streams" => wanted.extend(value.split(',').filter_map(ConsoleStream::parse)),
            _ => {}
        }
    }
    // Naming none is naming the default, which is the guest's two and not the
    // VMM's noise.
    if wanted.is_empty() {
        wanted.extend(ConsoleStream::ALL);
    }
    (lines, keep, wanted)
}

/// What the guest printed before anything inside it was reachable.
///
/// One way, and deliberately only that: no input channel, no attach, no
/// follow. An interactive console is a different feature with different
/// questions — exactly one attach at a time, a controller that pipes without
/// storing, an audit line per session — and none of them are answered by a
/// read of a ring buffer.
///
/// A VM with no output at all answers with an empty list rather than a 404:
/// "it printed nothing" is the commonest true answer there is, and it is not
/// an error. A vm id this node has no record of still is.
#[instrument(level = "debug", skip_all, fields(vm_id = %id))]
async fn vm_logs(
    State(st): State<ApiState>,
    Path(id): Path<String>,
    Query(q): Query<Vec<(String, String)>>,
) -> Result<Json<Vec<LogStream>>, ApiError> {
    let vm_id = parse_id(&id)?;
    if st.store.get_raw(&vm_id)?.is_none() {
        return Err(ApiError::not_found(format!("no record for vm {id}")));
    }
    let (lines, keep, wanted) = log_request(&q);
    Ok(Json(
        st.reconciler
            .console(&vm_id, lines, &keep, &wanted)
            .into_iter()
            .map(|(stream, text)| LogStream {
                stream: stream.as_str(),
                text,
            })
            .collect(),
    ))
}

#[derive(Serialize)]
struct ReconcileResponse {
    action: String,
}

#[instrument(skip_all, fields(vm_id = %id))]
async fn reconcile_vm(
    State(st): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<ReconcileResponse>, ApiError> {
    let vm_id = parse_id(&id)?;
    if st.store.get_raw(&vm_id)?.is_none() {
        return Err(ApiError::not_found(format!("no record for vm {id}")));
    }
    let action = st.reconciler.reconcile(vm_id, Trigger::Manual).await?;
    Ok(Json(ReconcileResponse {
        action: format!("{action:?}"),
    }))
}

#[instrument(level = "debug", skip_all, fields(vm_id = %id))]
async fn vm_state(
    State(st): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<ObserveResponse>, ApiError> {
    observe_vm(State(st), Path(id)).await
}

/// Every lifecycle endpoint is the reconciler's one transition plus the HTTP
/// shape around it; the semantics live in `Reconciler::set_desired`, shared
/// with the controller session.
async fn set_desired_and_reconcile(
    st: &ApiState,
    id: &str,
    desired: Desired,
    stop_deadline: Option<std::time::SystemTime>,
) -> Result<Json<ReconcileResponse>, ApiError> {
    let vm_id = parse_id(id)?;
    let Some(action) = st
        .reconciler
        .set_desired(vm_id, desired, stop_deadline)
        .await?
    else {
        return Err(ApiError::not_found(format!("no record for vm {id}")));
    };
    Ok(Json(ReconcileResponse {
        action: format!("{action:?}"),
    }))
}

#[instrument(skip_all, fields(vm_id = %id))]
async fn start_vm(
    State(st): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<ReconcileResponse>, ApiError> {
    set_desired_and_reconcile(&st, &id, Desired::Running, None).await
}

#[derive(Deserialize)]
struct StopParams {
    grace_secs: Option<u64>,
}

#[instrument(skip_all, fields(vm_id = %id))]
async fn stop_vm(
    State(st): State<ApiState>,
    Path(id): Path<String>,
    Query(params): Query<StopParams>,
) -> Result<Json<ReconcileResponse>, ApiError> {
    let grace = params
        .grace_secs
        .map(std::time::Duration::from_secs)
        .unwrap_or(st.stop_grace);
    let deadline = std::time::SystemTime::now() + grace;
    set_desired_and_reconcile(&st, &id, Desired::Stopped, Some(deadline)).await
}

#[instrument(skip_all, fields(vm_id = %id))]
async fn pause_vm(
    State(st): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<ReconcileResponse>, ApiError> {
    if !st.pause_supported {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "hypervisor driver does not support pausing",
        ));
    }
    set_desired_and_reconcile(&st, &id, Desired::Paused, None).await
}

#[instrument(skip_all, fields(vm_id = %id))]
async fn resume_vm(
    State(st): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<ReconcileResponse>, ApiError> {
    set_desired_and_reconcile(&st, &id, Desired::Running, None).await
}

#[derive(Serialize)]
struct OkResponse {
    ok: bool,
}

#[cfg(feature = "debug-mutations")]
#[instrument(skip_all, fields(vm_id = %id))]
async fn delete_record(
    State(st): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<OkResponse>, ApiError> {
    let vm_id = parse_id(&id)?;
    let _guard = st.ops.lock().await;
    if st.store.get_raw(&vm_id)?.is_none() {
        return Err(ApiError::not_found(format!("no record for vm {id}")));
    }
    warn!("deleting record via http api, resources may be orphaned");
    st.store.delete(&vm_id)?;
    Ok(Json(OkResponse { ok: true }))
}

#[cfg(feature = "debug-mutations")]
#[derive(Deserialize)]
struct SetPhaseRequest {
    phase: Phase,
}

#[cfg(feature = "debug-mutations")]
#[instrument(skip_all, fields(vm_id = %id))]
async fn set_phase(
    State(st): State<ApiState>,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<SetPhaseRequest>,
) -> Result<Json<OkResponse>, ApiError> {
    let vm_id = parse_id(&id)?;
    let _guard = st.ops.lock().await;
    let Some(mut record) = st.store.get(&vm_id)? else {
        return Err(ApiError::not_found(format!(
            "no readable record for vm {id}"
        )));
    };
    warn!(from = ?record.phase, to = ?req.phase, "overriding phase via http api");
    record.phase = req.phase;
    st.store.put(&vm_id, &record)?;
    Ok(Json(OkResponse { ok: true }))
}

#[instrument(skip_all)]
async fn create_vm(
    State(st): State<ApiState>,
    ApiJson(req): ApiJson<NewVmSpec>,
) -> Result<(StatusCode, Json<CreatedResponse>), ApiError> {
    let (id, spec, desired) = req
        .into_spec(&st.default_bridge)
        .map_err(|e| ApiError::bad_request(format!("{e:#}")))?;

    st.hypervisor
        .validate()
        .map_err(|e| ApiError::bad_request(format!("{e:#}")))?;
    st.catalog
        .validate(&spec.devices)
        .map_err(|e| ApiError::bad_request(format!("{e:#}")))?;
    st.volumes
        .validate(&spec.volumes)
        .map_err(|e| ApiError::bad_request(format!("{e:#}")))?;
    st.network
        .validate(&spec.nics)
        .map_err(|e| ApiError::bad_request(format!("{e:#}")))?;

    let _guard = st.ops.lock().await;
    info!(vm_id = %id, desired = ?desired, "creating vm via api");
    // Not managed: a VM born on this socket stays out of reach of the
    // controller's desired-state snapshot.
    st.provisioner.provision(id, spec, desired, false).await?;

    Ok((
        StatusCode::CREATED,
        Json(CreatedResponse { id: id.to_string() }),
    ))
}

#[instrument(skip_all, fields(vm_id = %id))]
async fn destroy_vm(
    State(st): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<ReconcileResponse>, ApiError> {
    let vm_id = parse_id(&id)?;
    info!(desired = ?Desired::Absent, "destroy requested");
    // A record that is already gone is exactly the outcome asked for.
    let action = st
        .reconciler
        .set_desired(vm_id, Desired::Absent, None)
        .await?
        .unwrap_or(Action::None);
    Ok(Json(ReconcileResponse {
        action: format!("{action:?}"),
    }))
}

/// Take this VM's serial line and speak to it.
///
/// An HTTP upgrade to a RAW byte stream in both directions, and not a
/// WebSocket: a console already is a byte stream, framing would add a header
/// per keystroke, and the one party that needs frames is a browser — which
/// never reaches this socket. The tier a browser does reach can wrap this;
/// here the honest shape is the one the guest already speaks.
///
/// Three answers rather than two, because they are three different problems:
/// no such VM is 404, a VM whose line is not being recorded is 409 (it is not
/// running, or the recorder has not caught up), and a line somebody else
/// holds is 409 with different words. A client that cannot tell them apart
/// cannot say anything useful to a person.
///
/// Reading is untouched: `vm logs` works while somebody holds the line, for
/// as many readers as ask, because reading is the file.
#[instrument(level = "debug", skip_all, fields(vm_id = %id))]
async fn vm_console(
    State(st): State<ApiState>,
    Path(id): Path<String>,
    req: axum::extract::Request,
) -> Result<axum::response::Response, ApiError> {
    let vm_id = parse_id(&id)?;
    if st.store.get_raw(&vm_id)?.is_none() {
        return Err(ApiError::not_found(format!("no record for vm {id}")));
    }

    let (mut parts, body) = req.into_parts();
    drop(body);
    let Some(on_upgrade) = parts.extensions.remove::<hyper::upgrade::OnUpgrade>() else {
        return Err(ApiError::bad_request(
            "a console is an upgraded connection; send Connection: upgrade",
        ));
    };

    // Taken BEFORE the upgrade is answered, so that a second client learns it
    // cannot have the line while it is still speaking HTTP and can be told
    // why. After the upgrade there is no status code left to say it with.
    let held = match st.reconciler.consoles.attach(&vm_id) {
        None => {
            return Err(ApiError::conflict(format!(
                "vm {id} has no console line right now; it is not running, or its serial \
                 line has not been picked up yet"
            )));
        }
        Some(Err(e)) => return Err(ApiError::conflict(format!("{e:#}"))),
        Some(Ok(held)) => held,
    };

    tokio::spawn(async move {
        match on_upgrade.await {
            // `held` moves in here, and its Drop frees the line whatever ends
            // the session: a clean detach, a dropped connection, a panic.
            Ok(upgraded) => pump(hyper_util::rt::TokioIo::new(upgraded), held).await,
            Err(e) => warn!(error = format!("{e:#}"), "console upgrade failed"),
        }
    });

    Ok(axum::response::Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(axum::http::header::CONNECTION, "upgrade")
        .header(axum::http::header::UPGRADE, CONSOLE_PROTOCOL)
        .body(axum::body::Body::empty())
        .expect("a fixed response"))
}

/// What this upgrade is called on the wire. Named rather than borrowed from
/// something else, because it is not WebSocket and a client that assumed so
/// would frame every keystroke.
pub const CONSOLE_PROTOCOL: &str = "meister-console";

/// Both directions of one console session, until either end stops.
///
/// `select!` and not two tasks: when one direction ends the other has nothing
/// left to serve, and two tasks would need a way to tell each other so —
/// exactly the bookkeeping a session that owns both halves does not need.
async fn pump<S>(stream: S, mut held: crate::attach::Held)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut from_client, mut to_client) = tokio::io::split(stream);
    let mut buf = vec![0u8; crate::attach::MAX_INPUT];
    loop {
        tokio::select! {
            chunk = held.output.recv() => match chunk {
                Some(bytes) => {
                    if to_client.write_all(&bytes).await.is_err() {
                        break;
                    }
                }
                None => break,
            },
            read = from_client.read(&mut buf) => match read {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if let Err(e) = held.write(&buf[..n]).await {
                        warn!(error = format!("{e:#}"), "console write failed");
                        break;
                    }
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mode_of(path: &std::path::Path) -> u32 {
        std::fs::metadata(path).expect("stat").permissions().mode() & 0o777
    }

    fn gid_of(path: &std::path::Path) -> u32 {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(path).expect("stat").gid()
    }

    /// A fresh directory per test: bind_socket creates and chmods the parent,
    /// so it must not find one somebody else's modes are already on.
    ///
    /// The guard comes back with the path and the caller binds it. It is what
    /// makes "fresh" true — a name derived from the pid is a name that comes
    /// back, and a run that crashed leaves its modes on the directory for
    /// whoever gets that pid next.
    ///
    /// `bind_socket` makes the directory itself, so what is handed over is a
    /// path INSIDE the temp directory that does not exist yet.
    fn scratch(name: &str) -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::Builder::new()
            .prefix(&format!("meister-socket-{name}-"))
            .tempdir()
            .expect("a temp dir");
        let path = temp.path().join("sockets").join("agent.sock");
        (temp, path)
    }

    /// No group: the socket and its directory belong to the user running the
    /// agent and to nobody else. This is how every node has run so far, and
    /// changing it silently would be the kind of change nobody notices until
    /// it is a finding.
    #[tokio::test]
    async fn without_a_group_the_socket_stays_private() {
        let (_temp, sock) = scratch("private");
        let _listener = bind_socket(&sock, None).expect("bind");

        assert_eq!(mode_of(sock.parent().unwrap()), 0o700);
        assert_eq!(mode_of(&sock), 0o600);
    }

    /// With a group: 0750 on the directory and 0660 on the socket, both owned
    /// by it — the traversal bit is on the directory, the write bit on the
    /// socket, and neither on anything else. The only group a test can chown
    /// to without privileges is one it is already in, so it uses its own.
    #[tokio::test]
    async fn a_group_reaches_the_socket_without_becoming_root() {
        let gid = nix::unistd::getgid().as_raw();
        let (_temp, sock) = scratch("group");
        let _listener = bind_socket(&sock, Some(gid)).expect("bind");

        let dir = sock.parent().unwrap();
        assert_eq!(mode_of(dir), 0o750);
        assert_eq!(gid_of(dir), gid);
        assert_eq!(mode_of(&sock), 0o660);
        assert_eq!(gid_of(&sock), gid);
    }

    /// The socket of a killed agent is in the way of the next one, and has
    /// been swept since long before this change. The sweep has to keep
    /// working now that the mode is decided a step earlier.
    #[tokio::test]
    async fn a_stale_socket_is_swept_and_the_mode_is_set_again() {
        let (_temp, sock) = scratch("stale");
        {
            let _first = bind_socket(&sock, None).expect("first bind");
        }
        assert!(sock.exists(), "a closed listener leaves its socket behind");

        let gid = nix::unistd::getgid().as_raw();
        let _second = bind_socket(&sock, Some(gid)).expect("second bind over the stale socket");
        assert_eq!(mode_of(&sock), 0o660);
        assert_eq!(gid_of(&sock), gid);
    }
}
