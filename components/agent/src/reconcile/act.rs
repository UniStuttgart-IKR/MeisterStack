// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Doing it: the one place in the pass that changes anything.
//!
//! `execute` is a match over the action `plan` returned and nothing else —
//! no second decision, no re-reading of the record, no error handling that
//! could turn into one. What it cannot do is decide, and that is the point of
//! the split: every reason lives next door in `plan`, where it can be walked.
//!
//! Moved out of `reconcile.rs` unchanged.

use super::*;

/// How many resumes may fail to take before the VM is quarantined.
///
/// Three, and the reason for a number rather than one is a race: the guest
/// state is asked immediately after the resume, and a hypervisor that has
/// answered the call but not yet flipped its own state would look like a
/// failure once. It cannot look like one three times over three passes.
pub(crate) const RESUME_ATTEMPTS: u32 = 3;

/// Why a VM whose resume never takes is quarantined. One string for the
/// marking, the report and the operator, for the reason `BACKEND_DIED_REASON`
/// is one.
pub const RESUME_INEFFECTIVE_REASON: &str = "the hypervisor accepted three resumes and the guest is still not running; it needs a look \
     - use start/stop/destroy to repair";

impl Reconciler {
    /// The marker a backend that died under a live VMM leaves behind.
    ///
    /// Cloud Hypervisor cannot reconnect a vhost-user backend — not a gpu,
    /// not a virtiofs share — and restarting the VM automatically is not
    /// wanted here: the VM is marked and quarantined until a human acts
    /// (start/stop/destroy clears the marker).
    ///
    /// Error and not warn: quarantine is the one state no pass ever leaves on
    /// its own. The reason string says as much — only start/stop/destroy
    /// clears the marker, and all three need a human.
    ///
    /// Through `mutate` and NOT `put`: the caller's `observe` awaited a probe
    /// of the VMM's socket, so the record in hand is a snapshot from before
    /// that wait. Writing the whole thing back would drop anything that
    /// landed meanwhile — a Stop from the controller most of all, whose
    /// `set_desired` writes the same record from another task. Only the
    /// marker is ours to set, and the fresh record is handed back so the
    /// caller can go on with what the store now holds.
    pub(super) fn quarantine_if_backend_died(
        &self,
        id: &VmId,
        record: &VmRecord,
        observed: &Observed,
    ) -> Result<Option<VmRecord>> {
        if record.unhealthy.is_some() || !backend_died_under_vmm(record, observed) {
            return Ok(None);
        }
        error!(reason = BACKEND_DIED_REASON, "marking vm unhealthy");
        // Counted where the marker is SET and not where it is reported: the
        // report repeats the same quarantine every ten seconds, and a counter
        // fed from there would measure the reporting interval rather than the
        // events.
        telemetry::metrics::agent().quarantined();
        self.store
            .mutate(id, |r| r.unhealthy = Some(BACKEND_DIED_REASON.to_string()))
    }

    pub(super) async fn execute(
        &self,
        id: &VmId,
        planned: (Phase, Desired),
        action: Action,
    ) -> Result<()> {
        if matches!(action, Action::None | Action::Blocked | Action::Quarantined) {
            return Ok(());
        }

        let _guard = self.ops.lock().await;

        let Some(current) = self.store.get(id)? else {
            debug!("record gone before execute, skipping");
            return Ok(());
        };
        if (current.phase, current.desired) != planned {
            debug!(
                phase = ?current.phase,
                desired = ?current.desired,
                "record changed before execute, skipping"
            );
            return Ok(());
        }

        match action {
            Action::None | Action::Blocked | Action::Quarantined => Ok(()),

            Action::Adopt { vmm_pid } => self
                .drivers
                .hypervisor()?
                .adopt(id, vmm_pid)
                .await
                .map_err(|e| anyhow::anyhow!("adopting vmm: {e}")),

            Action::Provision => {
                self.drivers
                    .confiner
                    .kill_slice(&id.to_string())
                    .map_err(|e| anyhow::anyhow!("killing cgroup slice: {e}"))?;
                self.provisioner.resume(id, current).await
            }

            Action::Start => self
                .drivers
                .hypervisor()?
                .start(id)
                .await
                .map_err(|e| anyhow::anyhow!("starting vm: {e}")),

            Action::SignalShutdown => self
                .drivers
                .hypervisor()?
                .power_button(id)
                .await
                .map_err(|e| anyhow::anyhow!("sending power button: {e}")),

            Action::Stop => self.provisioner.stop(id, current).await,

            Action::Pause => {
                let p =
                    self.drivers.hypervisor()?.as_pausable().ok_or_else(|| {
                        anyhow::anyhow!("hypervisor driver does not support pausing")
                    })?;
                p.pause(id)
                    .await
                    .map_err(|e| anyhow::anyhow!("pausing vm: {e}"))
            }

            Action::Resume => {
                let p =
                    self.drivers.hypervisor()?.as_pausable().ok_or_else(|| {
                        anyhow::anyhow!("hypervisor driver does not support pausing")
                    })?;
                p.resume(id)
                    .await
                    .map_err(|e| anyhow::anyhow!("resuming vm: {e}"))?;
                self.confirm_resume(id).await
            }

            Action::Teardown => self.provisioner.teardown(id).await,

            Action::Arrived => self.provisioner.migration_arrived(id).await,
        }
    }

    /// Did the resume take? Asked of the guest, not of the call.
    ///
    /// D7: a snapshot failed after the quiesce pause, the resume behind it was
    /// issued, it did not work, and the agent went on issuing it every five
    /// seconds without a WARN, an event or an escalation. The guest stayed
    /// `Paused` under `runStrategy = Running`, and nothing anywhere said so.
    ///
    /// The hypervisor's answer to `vm.resume` is that it took the REQUEST.
    /// What this asks is `vm.info`, which is the only thing that knows whether
    /// the guest is running — the same distinction the detach path had to
    /// learn, one verb over.
    ///
    /// Three of these in a row is not a race any more, and the marker is the
    /// quarantine this stack already has for "a human has to look at this":
    /// the VM reports `Quarantined` with the sentence, which is what becomes
    /// the event one tier up, and no further pass will resume it until
    /// start/stop/destroy clears the marker.
    async fn confirm_resume(&self, id: &VmId) -> Result<()> {
        let seen = self.drivers.hypervisor()?.get_state(id).await;
        if let Ok(VmState::Running) = seen {
            self.resume_failures.lock().unwrap().remove(id);
            return Ok(());
        }
        let guest = match &seen {
            Ok(state) => format!("{state:?}"),
            Err(e) => format!("unreadable ({e})"),
        };
        let attempt = {
            let mut map = self.resume_failures.lock().unwrap();
            let n = map.entry(*id).or_insert(0);
            *n += 1;
            *n
        };
        if attempt >= RESUME_ATTEMPTS {
            error!(
                attempt,
                guest = %guest,
                reason = RESUME_INEFFECTIVE_REASON,
                "marking vm unhealthy"
            );
            telemetry::metrics::agent().quarantined();
            self.store.mutate(id, |r| {
                r.unhealthy = Some(RESUME_INEFFECTIVE_REASON.to_string())
            })?;
        } else {
            warn!(
                attempt,
                guest = %guest,
                "the hypervisor took the resume and the guest is still not running"
            );
        }
        bail!("the resume did not take: the guest is {guest} (attempt {attempt})")
    }
}
