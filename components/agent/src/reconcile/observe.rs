// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Observe host resources and derive VM status reports from persisted records.
//!
//! Process identity, cgroup membership, socket responsiveness and guest state are
//! separate observations. A socket response alone does not prove guest liveness.

use super::*;

// Observation values are copied throughout finite-space planner tests.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Observed {
    pub tracked: bool,
    pub vmm_alive: bool,
    pub socket_responsive: bool,
    /// Whether all device and volume backend processes remain in the VM slice.
    /// Attachments without a process impose no liveness check.
    pub backends_alive: bool,
    pub guest: Option<VmState>,
    /// Driver-reported receive failure. Deadlines in the VM record do not set
    /// this field; the current CH adapter also reports uncertain API errors here.
    pub receive_failed: bool,
}

/// Backend PIDs from device and volume attachments.
/// Attachments without a process contribute nothing; recorded detached
/// volume attachments are still present in this iterator.
pub(crate) fn backend_pids(record: &VmRecord) -> impl Iterator<Item = u32> + '_ {
    record
        .devices
        .iter()
        .filter_map(|d| match &d.attachment {
            DeviceAttachment::VhostUser { pid, .. } => Some(*pid),
            _ => None,
        })
        .chain(
            record
                .volumes
                .iter()
                .filter_map(|v| v.attachment.backend_pid()),
        )
}

/// Why a VM with a dead backend is quarantined. One string for the
/// marking, the report and the operator, so a status report can never word
/// the condition differently from the record it anticipates.
pub const BACKEND_DIED_REASON: &str = "backend process died while the vmm is running, automatic restart \
     is disabled - use start/stop/destroy to repair";

/// Detect a missing backend while the VMM remains alive. Both reconciliation
/// and dry-run use this condition to predict quarantine.
///
/// A dead VMM instead follows normal reprovisioning. A live VMM with a lost
/// backend requires intervention because its device cannot be reconnected safely.
pub fn backend_died_under_vmm(record: &VmRecord, obs: &Observed) -> bool {
    record.phase == Phase::Provisioned
        && matches!(record.desired, Desired::Running | Desired::Paused)
        && obs.vmm_alive
        && !obs.backends_alive
}

/// The phase the controller shows for a VM. Spelled exactly like the
/// controller's `VmPhase` variants — the agent must not depend on

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportedPhase {
    Provisioning,
    Running,
    Stopped,
    Paused,
    Failed,
    Quarantined,
}

impl ReportedPhase {
    /// All phases in declaration order, including zero-count metric series.
    pub const ALL: [ReportedPhase; 6] = [
        ReportedPhase::Provisioning,
        ReportedPhase::Running,
        ReportedPhase::Stopped,
        ReportedPhase::Paused,
        ReportedPhase::Failed,
        ReportedPhase::Quarantined,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ReportedPhase::Provisioning => "Provisioning",
            ReportedPhase::Running => "Running",
            ReportedPhase::Stopped => "Stopped",
            ReportedPhase::Paused => "Paused",
            ReportedPhase::Failed => "Failed",
            ReportedPhase::Quarantined => "Quarantined",
        }
    }
}

// ---------------------------------------------------------------------------
// Reason enums supply stable wire values separately from operator messages.
// The agent avoids a controller-api dependency; tests compare this vocabulary
// with proto::reasons, which both sides of the connection share.

/// Reason for a reported VM phase. Running, Stopped and Paused omit a reason;
/// other phases explain whether the VM is waiting, failing or quarantined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmReason {
    /// `Provisioning`: a pass is building this VM and the last attempt did
    /// not fail. The ordinary road up to `Running`.
    Working,
    /// `Provisioning`: waiting to retry a failed attempt; the message retains its error.
    Backoff,
    /// `Provisioning`: the migration destination has not observed guest arrival.
    AwaitingGuest,
    /// `Provisioning`: this node WAS a live migration's source and the guest
    /// is on the other machine now.
    GuestLeft,
    /// `Failed`: receiver failure was reported and cleanup is pending.
    /// This observation alone does not establish source-side guest liveness.
    ReceiveFailed,
    /// `Failed`: the VMM is absent or unresponsive and recovery attempts failed.
    VmmGone,
    /// `Quarantined`: a backend died under a live VMM; automatic repair is blocked.
    BackendGone,
    /// `Quarantined`: the guest did not come back from a pause however often
    /// it was resumed. See `act::RESUME_INEFFECTIVE_REASON`.
    ResumeIneffective,
    /// Deletion is requested but teardown has not finished. Keep reporting the
    /// VM and its referenced volumes until the record is removed.
    Stopping,
    /// An unknown persisted marker. Preserve its message so version drift remains visible.
    Unrecorded,
}

impl VmReason {
    /// Every variant, in declaration order — see `ReportedPhase::ALL`.
    pub const ALL: [VmReason; 10] = [
        VmReason::Working,
        VmReason::Backoff,
        VmReason::AwaitingGuest,
        VmReason::GuestLeft,
        VmReason::ReceiveFailed,
        VmReason::VmmGone,
        VmReason::BackendGone,
        VmReason::ResumeIneffective,
        VmReason::Stopping,
        VmReason::Unrecorded,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            VmReason::Working => "Working",
            VmReason::Backoff => "Backoff",
            VmReason::AwaitingGuest => "AwaitingGuest",
            VmReason::GuestLeft => "GuestLeft",
            VmReason::ReceiveFailed => "ReceiveFailed",
            VmReason::VmmGone => "VmmGone",
            VmReason::BackendGone => "BackendGone",
            VmReason::ResumeIneffective => "ResumeIneffective",
            VmReason::Stopping => "Stopping",
            VmReason::Unrecorded => "Unrecorded",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.as_str() == s)
    }
}

/// Reason persisted by the last volume operation. Unlike VM status, this
/// report is not recomputed from a fresh backend observation each heartbeat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum VolumeReason {
    /// `Provisioning`: the record is written and the driver has been asked,
    /// or is being asked right now.
    Working,
    /// `Failed`: the backend said no. `message` is what it said.
    DriverRefused,
    /// Startup adoption could not find previously recorded data on the backend.
    /// This differs from a driver refusing a new provisioning request.
    NotOnBackend,
    /// `Gone`: explicit completed deprovision evidence retained as a tombstone.
    Deprovisioned,
    /// Legacy record without a reason; preserve its message.
    Unrecorded,
}

impl VolumeReason {
    pub const ALL: [VolumeReason; 5] = [
        VolumeReason::Working,
        VolumeReason::DriverRefused,
        VolumeReason::NotOnBackend,
        VolumeReason::Deprovisioned,
        VolumeReason::Unrecorded,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            VolumeReason::Working => "Working",
            VolumeReason::DriverRefused => "DriverRefused",
            VolumeReason::NotOnBackend => "NotOnBackend",
            VolumeReason::Deprovisioned => "Deprovisioned",
            VolumeReason::Unrecorded => "Unrecorded",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.as_str() == s)
    }
}

/// Reason persisted by the last snapshot operation. Startup adoption currently
/// checks volumes only, so there is no snapshot NotOnBackend reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SnapshotReason {
    /// `Creating`: the record is written and the driver has been asked, or is
    /// being asked right now.
    Working,
    /// `Failed`: the backend said no. `message` is what it said.
    DriverRefused,
    /// `Gone`: explicit completed snapshot-drop evidence retained as a tombstone.
    Dropped,
    /// Legacy record without a reason; preserve its message.
    Unrecorded,
}

impl SnapshotReason {
    pub const ALL: [SnapshotReason; 4] = [
        SnapshotReason::Working,
        SnapshotReason::DriverRefused,
        SnapshotReason::Dropped,
        SnapshotReason::Unrecorded,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            SnapshotReason::Working => "Working",
            SnapshotReason::DriverRefused => "DriverRefused",
            SnapshotReason::Dropped => "Dropped",
            SnapshotReason::Unrecorded => "Unrecorded",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.as_str() == s)
    }
}

/// Failure reason held in the in-memory image cache; there are no legacy
/// persisted reasons requiring an Unrecorded variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageReason {
    /// `Failed`: the configured local image path is absent.
    NotFound,
    /// `Failed`: something IS at that path and it is a directory. Saying
    /// `Ready` about one would hand a storage driver a path it cannot open.
    NotAFile,
    /// `Failed`: downloaded image bytes do not match the specified checksum.
    ChecksumMismatch,
    /// `Failed`: image transfer or publication failed.
    FetchFailed,
}

impl ImageReason {
    pub const ALL: [ImageReason; 4] = [
        ImageReason::NotFound,
        ImageReason::NotAFile,
        ImageReason::ChecksumMismatch,
        ImageReason::FetchFailed,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ImageReason::NotFound => "NotFound",
            ImageReason::NotAFile => "NotAFile",
            ImageReason::ChecksumMismatch => "ChecksumMismatch",
            ImageReason::FetchFailed => "FetchFailed",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.as_str() == s)
    }
}

/// Collect the VM, volume, snapshot, image and router reason vocabulary.
/// Tests compare it with proto::reasons. Storage-pool reasons belong to the
/// controller because the agent reports drivers and volumes, not pool objects.
pub fn reason_table() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        ("Vm", VmReason::ALL.iter().map(|r| r.as_str()).collect()),
        (
            "Volume",
            VolumeReason::ALL.iter().map(|r| r.as_str()).collect(),
        ),
        (
            "Snapshot",
            SnapshotReason::ALL.iter().map(|r| r.as_str()).collect(),
        ),
        (
            "Image",
            ImageReason::ALL.iter().map(|r| r.as_str()).collect(),
        ),
        (
            "Router",
            agent_api::RouterReason::ALL
                .iter()
                .map(|r| r.as_str())
                .collect(),
        ),
    ]
}

/// Derived phase, stable reason and operator message for a VM.
pub struct Reported {
    pub phase: ReportedPhase,
    /// Absent only for Running, Stopped and Paused; other phases carry a reason.
    pub reason: Option<VmReason>,
    pub message: Option<String>,
}

impl Reported {
    /// A phase that explains itself.
    fn settled(phase: ReportedPhase) -> Self {
        Self {
            phase,
            reason: None,
            message: None,
        }
    }

    /// Construct a non-settled phase with a required machine-readable reason.
    fn because(phase: ReportedPhase, reason: VmReason, message: Option<String>) -> Self {
        Self {
            phase,
            reason: Some(reason),
            message,
        }
    }
}

/// Map known persisted quarantine messages to stable reasons. Preserve unknown
/// messages as Unrecorded rather than guessing their meaning.
fn quarantine_reason(marker: &str) -> VmReason {
    match marker {
        BACKEND_DIED_REASON => VmReason::BackendGone,
        RESUME_INEFFECTIVE_REASON => VmReason::ResumeIneffective,
        _ => VmReason::Unrecorded,
    }
}

/// IDs present in both the recorded attachments and referenced-volume spec.
/// This list excludes inline disks but retains recorded detached attachments;
/// VolumeStateReport.open is derived separately.
pub fn attached_volumes(record: &VmRecord) -> Vec<agent_api::VolumeId> {
    record
        .volumes
        .iter()
        .map(|v| v.id())
        .filter(|id| {
            record
                .spec
                .volumes
                .iter()
                .any(|v| &v.id == id && v.referenced)
        })
        .collect()
}

/// Report recorded NICs with known MACs. Positions follow the record
/// list; requested NICs without a recorded attachment contribute no entry.
pub fn reported_nics(record: &VmRecord) -> Vec<ReportedNic> {
    record
        .nics
        .iter()
        .enumerate()
        .filter_map(|(i, nic)| {
            Some(ReportedNic {
                name: format!("nics[{i}]"),
                mac: nic.mac?.to_string(),
            })
        })
        .collect()
}

/// NIC identity and addresses included in a VM status report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportedNic {
    /// `nics[0]`, `nics[1]` — the spec's own way of pointing at a NIC.
    pub name: String,
    /// Lower case with colons, as `MacAddr` prints it.
    pub mac: String,
}

/// Shared report and log message for failed-receive cleanup.
pub const RECEIVE_FAILED_REASON: &str = "the guest did not arrive; this node is giving back the vmm, the disks and the taps it \
     made for it, and the vm is still running where it was";

/// Shared report and log message for incomplete VM teardown.
pub const STOPPING_REASON: &str = "the intent for this vm is gone and this node has not finished taking it apart; its \
     vmm and its disks may still be here";

pub fn report_status(
    record: &VmRecord,
    obs: &Observed,
    failures: u32,
    last_error: Option<&str>,
) -> Reported {
    if let Some(marker) = &record.unhealthy {
        return Reported::because(
            ReportedPhase::Quarantined,
            quarantine_reason(marker),
            Some(marker.clone()),
        );
    }
    // Stop leaves the phase at Provisioned (volumes and taps stay), so the
    // desired state is what tells a stopped VM from an unprovisioned one.
    if record.desired == Desired::Stopped && !obs.vmm_alive {
        return Reported::settled(ReportedPhase::Stopped);
    }
    // Report migration progress separately from ordinary stopped state.
    // Observed Running can establish destination arrival before the phase updates.
    match record.phase {
        Phase::Receiving => {
            // Report observed arrival immediately rather than waiting for the next
            // reconcile pass to change Receiving to Provisioned.
            return match obs.guest {
                Some(VmState::Running) => Reported::settled(ReportedPhase::Running),
                // Report an explicit receive failure while cleanup is pending.
                _ if obs.receive_failed => Reported::because(
                    ReportedPhase::Failed,
                    VmReason::ReceiveFailed,
                    Some(RECEIVE_FAILED_REASON.to_string()),
                ),
                _ => Reported::because(
                    ReportedPhase::Provisioning,
                    VmReason::AwaitingGuest,
                    Some("waiting for the guest to arrive from another node".to_string()),
                ),
            };
        }
        Phase::Migrated => {
            return Reported::because(
                ReportedPhase::Provisioning,
                VmReason::GuestLeft,
                Some("the guest has left this node; the destination has it".to_string()),
            );
        }
        _ => {}
    }
    if record.phase != Phase::Provisioned {
        return building(failures, last_error);
    }
    if !obs.vmm_alive || !obs.socket_responsive {
        // A missing VMM initially reports Provisioning; repeated failed repairs
        // report Failed with the last error and VmmGone reason.
        return if failures > 0 {
            Reported::because(
                ReportedPhase::Failed,
                VmReason::VmmGone,
                Some(match last_error {
                    Some(said) => format!(
                        "{failures} failed reconcile attempt(s), retrying with backoff: {said}"
                    ),
                    None => {
                        format!("{failures} failed reconcile attempt(s), retrying with backoff")
                    }
                }),
            )
        } else {
            Reported::because(ReportedPhase::Provisioning, VmReason::Working, None)
        };
    }
    match obs.guest {
        Some(VmState::Running) => Reported::settled(ReportedPhase::Running),
        Some(VmState::Paused) => Reported::settled(ReportedPhase::Paused),
        Some(VmState::Defined) | Some(VmState::Stopped) => {
            Reported::settled(ReportedPhase::Stopped)
        }
        // VMM alive but its state is unreadable: the pass will re-provision.
        None => building(failures, last_error),
    }
}

/// Distinguish ongoing work from retry backoff and include the last failure message.
fn building(failures: u32, last_error: Option<&str>) -> Reported {
    if failures == 0 {
        return Reported::because(ReportedPhase::Provisioning, VmReason::Working, None);
    }
    Reported::because(
        ReportedPhase::Provisioning,
        VmReason::Backoff,
        last_error.map(|said| {
            format!("{failures} failed reconcile attempt(s), retrying with backoff: {said}")
        }),
    )
}

/// Collect IPv4 floating host routes from records selected by the caller.
/// The caller filters for running guests. Routed subnet advertisements come
/// from the router driver, not individual VM records.
pub fn floating_prefixes<'a>(
    running: impl Iterator<Item = &'a VmRecord>,
) -> std::collections::BTreeSet<String> {
    running
        .flat_map(|record| record.spec.nics.iter())
        .flat_map(|nic| nic.spec.floating_ips.iter())
        .map(|address| linux_network_driver::frr::host_prefix(address))
        .collect()
}

/// One VM's line in a status report.
pub struct VmReport {
    pub id: VmId,
    pub phase: ReportedPhase,
    /// Machine-readable phase reason; see `Reported`.
    pub reason: Option<VmReason>,
    pub message: Option<String>,
    /// Referenced-volume IDs recorded on the VM, excluding inline disks.
    /// Compare with the requested list to track attachment changes; this field
    /// does not independently establish that a backend connection remains open.
    pub volumes: Vec<agent_api::VolumeId>,
    /// NICs known from this VM's record. An empty list alone is not deletion evidence.
    pub nics: Vec<ReportedNic>,
    /// What this node has to say about a guest it was told to SEND, if it was
    /// told to send this one. See [`departure`].
    pub departure: Option<Departure>,
}

/// What became of a guest this node was told to send away.
/// Durable evidence from either endpoint of one migration attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Departure {
    pub migration_id: String,
    /// The peer address remains attached to terminal reports.
    pub peer: String,
    pub outcome: DepartureOutcome,
    /// An abort reason or the reason the outcome is unknown.
    pub message: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DepartureOutcome {
    /// The stream is open and this node is watching its own VMM.
    Sending,
    Unknown,
    Receiving,
    Arrived,
    /// The VMM exited, which is how cloud-hypervisor states that a send took.
    Gone,
    /// v53 gave the guest back and is serving it here.
    StillHere,
}

impl DepartureOutcome {
    /// The spelling that goes on the wire (control.proto: MigrationReport).
    pub fn as_str(self) -> &'static str {
        match self {
            DepartureOutcome::Sending => "Sending",
            DepartureOutcome::Unknown => "Unknown",
            DepartureOutcome::Receiving => "Receiving",
            DepartureOutcome::Arrived => "Arrived",
            DepartureOutcome::Gone => "Gone",
            DepartureOutcome::StillHere => "StillHere",
        }
    }
}

/// Missing legacy identities produce no attempt-bound evidence.
pub fn departure(record: &VmRecord) -> Option<Departure> {
    let attempt = record.migration.as_ref()?;
    let outcome = if attempt.incoming {
        if record.phase == Phase::Provisioned {
            DepartureOutcome::Arrived
        } else {
            DepartureOutcome::Receiving
        }
    } else if matches!(
        record.operation,
        Some(crate::types::Operation::MigratingOut { .. })
    ) {
        if attempt.unknown.is_some() || !attempt.accepted {
            DepartureOutcome::Unknown
        } else {
            DepartureOutcome::Sending
        }
    } else if record.send_failed.is_some() {
        DepartureOutcome::StillHere
    } else if record.phase == Phase::Migrated {
        DepartureOutcome::Gone
    } else {
        return None;
    };
    Some(Departure {
        migration_id: attempt.id.clone(),
        peer: attempt.peer.clone(),
        outcome,
        message: attempt
            .unknown
            .clone()
            .or_else(|| record.send_failed.clone()),
    })
}

impl Reconciler {
    /// Observe readable VM records and derive reports without persisting preview
    /// quarantine markers. Uses the same observation logic as reconciliation.
    #[instrument(level = "debug", skip_all)]
    pub async fn report(&self) -> Result<Vec<VmReport>> {
        let mut out = Vec::new();
        for (id, mut record) in self.store.list()? {
            // Retain deleting VMs in reports until teardown removes their records.
            // Omitting them early could release their controller binding while
            // the VMM or its storage connections still exist.
            if record.desired == Desired::Absent {
                out.push(VmReport {
                    id,
                    phase: ReportedPhase::Provisioning,
                    reason: Some(VmReason::Stopping),
                    message: Some(STOPPING_REASON.to_string()),
                    volumes: attached_volumes(&record),
                    nics: reported_nics(&record),
                    departure: departure(&record),
                });
                continue;
            }
            let observed = self.observe(&id, &record).await;
            // The periodic pass may not have marked the record yet; report
            // what it is about to write, not a preview of it.
            if record.unhealthy.is_none() && backend_died_under_vmm(&record, &observed) {
                record.unhealthy = Some(BACKEND_DIED_REASON.to_string());
            }
            let (failures, last_error) = self.backoff_state(&id);
            let reported = report_status(&record, &observed, failures, last_error.as_deref());
            let volumes = attached_volumes(&record);
            let nics = reported_nics(&record);
            out.push(VmReport {
                id,
                phase: reported.phase,
                reason: reported.reason,
                message: reported.message,
                volumes,
                nics,
                departure: departure(&record),
            });
        }
        Ok(out)
    }

    pub(super) async fn observe(&self, id: &VmId, record: &VmRecord) -> Observed {
        // Without a hypervisor, observe no tracked process, responsive socket or guest.
        let hypervisor = self.drivers.hypervisor.as_ref();
        let tracked = hypervisor.is_some_and(|h| h.is_tracked(id));

        let slice_pids = self
            .drivers
            .confiner
            .pids_in_slice(&id.to_string())
            .unwrap_or_default();

        // Require cgroup membership and process identity before treating the
        // recorded PID as this VM's live VMM.
        let vmm_alive = match (record.vmm_pid, hypervisor) {
            (Some(pid), Some(h)) => slice_pids.contains(&pid) && h.owns_pid(id, pid),
            _ => false,
        };

        let backends_alive = backend_pids(record).all(|pid| slice_pids.contains(&pid));

        let socket_responsive = match hypervisor {
            Some(h) => h.probe(id).await,
            None => false,
        };

        let guest = match hypervisor.filter(|_| tracked && socket_responsive) {
            Some(h) => h.get_state(id).await.ok(),
            None => None,
        };

        // Read receive failure after get_state, which may inspect receive events.
        let receive_failed = self.receive_failed(id, record, hypervisor);

        Observed {
            tracked,
            vmm_alive,
            socket_responsive,
            backends_alive,
            guest,
            receive_failed,
        }
    }

    /// Only explicit driver evidence can authorize failed-receive cleanup.
    fn receive_failed(
        &self,
        id: &VmId,
        record: &VmRecord,
        hypervisor: Option<&std::sync::Arc<dyn agent_api::hypervisor::Hypervisor>>,
    ) -> bool {
        if record.phase != Phase::Receiving {
            return false;
        }
        if let Some(said) = hypervisor
            .and_then(|h| h.as_migratable())
            .and_then(|m| m.receive_failed(id))
        {
            warn!(vm_id = %id, reason = %said, "the guest is not coming");
            return true;
        }
        // A deadline says nothing about whether the stream is still active.
        false
    }
}
