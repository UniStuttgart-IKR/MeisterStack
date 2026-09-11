// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The passed-through hardware: who may have it, and how it is handed over.
//!
//! Admission is the driver's judgement and never this file's — only the agent
//! can read the store and say what the other VMs on this node already claim,
//! and only the driver knows what a conflict is. See
//! `check_device_admission`.
//!
//! Moved out of `provision.rs` unchanged.

use super::*;

/// Which driver created this device, read back off the spec the record was
/// built from. The fallback is the spec default rather than a literal: a
/// record whose device is not in its own spec should not be routed to
/// whichever driver happened to be default the day this line was written.
pub(crate) fn device_driver_name(record: &VmRecord, id: &DeviceId) -> String {
    record
        .spec
        .devices
        .iter()
        .find(|d| &d.id == id)
        .map(|d| d.spec.driver.clone())
        .unwrap_or_else(default_device_driver)
}

impl Provisioner {
    /// Ask every driver this spec names whether it can serve the request
    /// alongside what the other VMs on this node already claim from it.
    ///
    /// The agent supplies the facts and the driver supplies the judgement:
    /// only this side can read the store, and only the driver knows what a
    /// conflict is — which param names the resource, whether two VMs may
    /// share it, what to say when they may not. Before this, the agent
    /// carried a second parser for vfio's `params.pci_address` next to the
    /// one the vfio driver already had.
    ///
    /// A driver the spec names but the node does not have is passed over
    /// here; `run_chain` is where that becomes an error, with the message
    /// that names the configured drivers.
    pub(super) fn check_device_admission(&self, id: &VmId, spec: &AgentVmSpec) -> Result<()> {
        if spec.devices.is_empty() {
            return Ok(());
        }
        let mut requested: HashMap<&str, Vec<(DeviceId, DeviceSpec)>> = HashMap::new();
        for d in &spec.devices {
            requested
                .entry(d.spec.driver.as_str())
                .or_default()
                .push((d.id, d.spec.clone()));
        }

        let mut claimed: HashMap<String, Vec<(VmId, DeviceSpec)>> = HashMap::new();
        for (other_id, record) in self.store.list()? {
            if &other_id == id {
                continue;
            }
            for d in &record.spec.devices {
                claimed
                    .entry(d.spec.driver.clone())
                    .or_default()
                    .push((other_id, d.spec.clone()));
            }
        }

        for (name, requested) in requested {
            let Some(driver) = self.drivers.devices.get(name) else {
                continue;
            };
            let held = claimed.get(name).map(Vec::as_slice).unwrap_or(&[]);
            driver
                .admit(&requested, held)
                .with_context(|| format!("device admission refused by driver {name:?}"))?;
        }
        Ok(())
    }

    /// The third link of the chain: one backend per device the spec names,
    /// inside this VM's slice.
    pub(super) async fn create_devices(
        &self,
        id: &VmId,
        record: &mut VmRecord,
        spec: &AgentVmSpec,
        cgroup: &agent_api::CgroupHandle,
    ) -> Result<()> {
        for d in &spec.devices {
            let driver = self.drivers.devices.get(&d.spec.driver).ok_or_else(|| {
                anyhow!(
                    "vm spec requests device driver {:?} which is not configured on this node",
                    d.spec.driver
                )
            })?;
            let dev = timed_driver(
                &d.spec.driver,
                "create",
                driver.create(&d.id, &d.spec, Some(cgroup)),
            )
            .await
            .with_context(|| format!("creating device {} via {}", d.id, d.spec.driver))?;
            record.devices.push(dev);
        }
        record.phase = Phase::DevicesDone;
        self.store.put(id, record)?;
        info!(count = record.devices.len(), "devices ready");
        Ok(())
    }
}
