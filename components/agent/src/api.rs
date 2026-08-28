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
use macros::generated;
use serde::{Deserialize, Serialize};
use tracing::{info, instrument, warn};

use agent_api::VmId;

use crate::drivers::{DeviceCatalog, NetworkCatalog, VolumeCatalog};
use crate::provision::Provisioner;
use crate::reconcile::{Action, Reconciler, Trigger};
use crate::store::Store;
use crate::types::NewVmSpec;
use crate::types::{Desired, Phase};

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
    pub network: NetworkCatalog,
    pub default_bridge: String,
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

#[generated(model = ClaudeOpus, version = "4.8")]
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

#[generated(model = ClaudeOpus, version = "4.8")]
pub fn router(state: ApiState) -> Router {
    let router = Router::new()
        .route("/healthz", get(healthz))
        .route("/vms", get(list_vms).post(create_vm))
        .route("/vms/{id}", get(inspect_vm).delete(destroy_vm))
        .route("/vms/{id}/observe", get(observe_vm))
        .route("/vms/{id}/logs", get(vm_logs))
        .route("/vms/{id}/state", get(vm_state))
        .route("/vms/{id}/reconcile", post(reconcile_vm))
        .route("/vms/{id}/start", post(start_vm))
        .route("/vms/{id}/stop", post(stop_vm))
        .route("/vms/{id}/pause", post(pause_vm))
        .route("/vms/{id}/resume", post(resume_vm));

    #[cfg(feature = "debug-mutations")]
    let router = router
        .route("/vms/{id}/record", axum::routing::delete(delete_record))
        .route("/vms/{id}/phase", axum::routing::put(set_phase));

    router.with_state(state)
}

#[generated(model = ClaudeOpus, version = "4.8")]
#[instrument(skip_all, fields(socket = %socket_path.display()))]
pub async fn serve(socket_path: PathBuf, state: ApiState) -> anyhow::Result<()> {
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating socket dir {}", parent.display()))?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod 0700 on {}", parent.display()))?;
    }

    match std::fs::remove_file(&socket_path) {
        Ok(()) => warn!("removed stale socket from a previous run"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("removing {}", socket_path.display())),
    }

    let listener = tokio::net::UnixListener::bind(&socket_path)
        .with_context(|| format!("binding {}", socket_path.display()))?;

    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 on {}", socket_path.display()))?;

    info!("http api listening");
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

#[generated(model = ClaudeFable, version = "5")]
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

#[generated(model = ClaudeOpus, version = "4.8")]
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

#[generated(model = ClaudeFable, version = "5")]
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

/// How many lines the caller wants, from the end.
#[derive(Deserialize)]
struct LogQuery {
    #[serde(default)]
    lines: Option<usize>,
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
#[generated(model = ClaudeOpus, version = "5")]
#[instrument(level = "debug", skip_all, fields(vm_id = %id))]
async fn vm_logs(
    State(st): State<ApiState>,
    Path(id): Path<String>,
    Query(q): Query<LogQuery>,
) -> Result<Json<Vec<LogStream>>, ApiError> {
    let vm_id = parse_id(&id)?;
    if st.store.get_raw(&vm_id)?.is_none() {
        return Err(ApiError::not_found(format!("no record for vm {id}")));
    }
    let lines = q.lines.unwrap_or(crate::console::DEFAULT_LINES);
    Ok(Json(
        st.reconciler
            .console(&vm_id, lines)
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

#[generated(model = ClaudeOpus, version = "4.8")]
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

#[generated(model = ClaudeFable, version = "5")]
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
#[generated(model = ClaudeFable, version = "5")]
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

#[generated(model = ClaudeFable, version = "5")]
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

#[generated(model = ClaudeFable, version = "5")]
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

#[generated(model = ClaudeFable, version = "5")]
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

#[generated(model = ClaudeFable, version = "5")]
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
#[generated(model = ClaudeOpus, version = "4.8")]
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
#[generated(model = ClaudeOpus, version = "4.8")]
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

#[generated(model = ClaudeFable, version = "5")]
#[instrument(skip_all)]
async fn create_vm(
    State(st): State<ApiState>,
    ApiJson(req): ApiJson<NewVmSpec>,
) -> Result<(StatusCode, Json<CreatedResponse>), ApiError> {
    let (id, spec, desired) = req
        .into_spec(&st.default_bridge)
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

#[generated(model = ClaudeFable, version = "5")]
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
