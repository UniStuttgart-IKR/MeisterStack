// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Execute planned actions under the operations lock.
//!
//! Revalidate the plan against the current record before applying side effects;
//! observations and the planning instant are reused from the caller.

use super::*;

/// Consecutive accepted resumes without an observed Running state before quarantine.
/// The allowance accommodates delayed guest-state updates after the API reply.
pub(crate) const RESUME_ATTEMPTS: u32 = 3;

/// Shared quarantine reason for an accepted resume that repeatedly fails to run the guest.
pub const RESUME_INEFFECTIVE_REASON: &str = "the hypervisor accepted three resumes and the guest is still not running; it needs a look \
     - use start/stop/destroy to repair";

impl Reconciler {
    /// Quarantine a live VMM whose vhost-user backend died. Automatic repair
    /// cannot reconnect that backend; a lifecycle command must clear the marker.
    ///
    /// Mutate only the marker because observation may have awaited I/O while
    /// another task updated the persisted record.
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
        // Count a new quarantine once, rather than on each status report.
        telemetry::metrics::agent().quarantined();
        self.store
            .mutate(id, |r| r.unhealthy = Some(BACKEND_DIED_REASON.to_string()))
    }

    /// Execute only if the current record still produces the planned action.
    ///
    /// The operations lock serializes this check with migration ownership changes.
    /// Reusing the observation avoids holding the lock during a probe; driver
    /// actions must tolerate host state changing after that observation.
    pub(super) async fn execute(
        &self,
        id: &VmId,
        planned: Planned<'_>,
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
        if (current.phase, current.desired) != (planned.record.phase, planned.record.desired) {
            debug!(
                phase = ?current.phase,
                desired = ?current.desired,
                "record changed before execute, skipping"
            );
            return Ok(());
        }
        let now_it_is = plan(&current, planned.observed, planned.at);
        if now_it_is != action {
            debug!(planned = ?action, now = ?now_it_is, operation = ?current.operation,
                   "the plan no longer holds for the record as it is now, skipping");
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

    /// Confirm Running after an accepted resume. Repeated unsuccessful observations
    /// quarantine the VM until a lifecycle command clears the marker.
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
