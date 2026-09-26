// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Device admission and creation. The agent gathers persisted claims; each
//! driver decides which requests conflict.

use super::*;

/// Resolve the creating driver from the persisted device spec. Missing entries
/// use the spec default rather than a separately maintained driver name.
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
    /// Ask configured drivers to admit this request alongside other persisted VM
    /// specifications. Missing drivers are reported when the chain creates devices.
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
