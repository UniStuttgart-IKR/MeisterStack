// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

use std::collections::HashSet;
use std::path::Path;

use agent_api::CgroupHandle;
use agent_api::device::{
    self, Device, DeviceAttachment, DeviceDriver, DeviceError, DeviceId, DeviceSpec, PartitionSpec,
};
use agent_api::types::pci::PciAddress;
use tracing::{debug, info, instrument, warn};

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct VfioParams {
    pci_address: PciAddress,
}

const GROUP_SAFE_DRIVERS: [&str; 3] = ["vfio-pci", "pci-stub", "pcieport"];

pub struct VfioPciDriver {
    inventory: HashSet<PciAddress>,
}

impl VfioPciDriver {
    pub fn new(inventory: Vec<PciAddress>) -> device::Result<Self> {
        for addr in &inventory {
            if !addr.sysfs_path().exists() {
                warn!(pci_address = %addr, "managed pci device not present in sysfs");
            }
        }
        Ok(Self {
            inventory: inventory.into_iter().collect(),
        })
    }

    fn validated_address(&self, spec: &DeviceSpec) -> device::Result<PciAddress> {
        if spec.partition != PartitionSpec::Exclusive {
            return Err(DeviceError::InvalidSpec(format!(
                "vfio driver only supports Exclusive, got {:?}",
                spec.partition
            )));
        }
        if let Some(profile) = &spec.profile {
            return Err(DeviceError::InvalidSpec(format!(
                "vfio driver has no profiles (got {profile:?})"
            )));
        }
        let params = spec.params.as_ref().ok_or_else(|| {
            DeviceError::InvalidSpec(
                "vfio device requires params, e.g. {\"pci_address\": \"0000:23:00.0\"}".into(),
            )
        })?;
        let params: VfioParams = serde_json::from_value(params.clone())
            .map_err(|e| DeviceError::InvalidSpec(format!("invalid vfio params: {e}")))?;

        if !self.inventory.contains(&params.pci_address) {
            let mut known: Vec<String> = self.inventory.iter().map(ToString::to_string).collect();
            known.sort_unstable();
            return Err(DeviceError::InvalidSpec(format!(
                "pci device {} is not in this node's managed inventory: [{}]",
                params.pci_address,
                known.join(", ")
            )));
        }
        Ok(params.pci_address)
    }

    /// The address a spec asks for, without the inventory and IOMMU checks
    /// `create` makes. Admission is about which VM may have the device;
    /// whether the host can hand it over at all is a question for the moment
    /// it is handed over.
    fn requested_address(spec: &DeviceSpec) -> device::Result<PciAddress> {
        let params = spec.params.as_ref().ok_or_else(|| {
            DeviceError::InvalidSpec(
                "vfio device requires params.pci_address (e.g. \"0000:23:00.0\")".into(),
            )
        })?;
        let params: VfioParams = serde_json::from_value(params.clone())
            .map_err(|e| DeviceError::InvalidSpec(format!("invalid vfio params: {e}")))?;
        Ok(params.pci_address)
    }

    fn addr_from_attachment(
        id: &DeviceId,
        attachment: &DeviceAttachment,
    ) -> device::Result<PciAddress> {
        let DeviceAttachment::VfioPci { sysfs_path } = attachment else {
            return Err(DeviceError::InvalidSpec(format!(
                "device {id} has a non-vfio attachment: {attachment:?}"
            )));
        };
        sysfs_path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.parse::<PciAddress>().ok())
            .ok_or_else(|| {
                DeviceError::InvalidSpec(format!(
                    "cannot derive pci address from attachment path {}",
                    sysfs_path.display()
                ))
            })
    }

    fn current_driver(dev: &Path) -> Option<String> {
        std::fs::read_link(dev.join("driver"))
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
    }

    fn check_iommu_group(addr: &PciAddress) -> device::Result<()> {
        let group_devices = addr.sysfs_path().join("iommu_group/devices");
        let entries = std::fs::read_dir(&group_devices).map_err(|e| {
            DeviceError::Backend(anyhow::anyhow!(
                "reading iommu group of {addr} ({}): {e}; is the IOMMU enabled \
                 (intel_iommu=on / amd_iommu=on)?",
                group_devices.display()
            ))
        })?;

        let self_name = addr.to_string();
        let mut offenders = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| DeviceError::Backend(e.into()))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == self_name {
                continue;
            }
            match Self::current_driver(&entry.path()) {
                None => {}
                Some(drv) if GROUP_SAFE_DRIVERS.contains(&drv.as_str()) => {}
                Some(drv) => offenders.push(format!("{name} ({drv})")),
            }
        }

        if offenders.is_empty() {
            Ok(())
        } else {
            Err(DeviceError::InvalidSpec(format!(
                "iommu group of {addr} is not viable for vfio; these group members \
                 are bound to host drivers: {}; unbind them or pass them through too",
                offenders.join(", ")
            )))
        }
    }

    fn sysfs_write(path: &Path, content: &str) -> device::Result<()> {
        std::fs::write(path, content)
            .map_err(|e| DeviceError::Backend(anyhow::anyhow!("writing {}: {e}", path.display())))
    }

    fn bind_vfio(addr: &PciAddress) -> device::Result<()> {
        let dev = addr.sysfs_path();
        if !dev.exists() {
            return Err(DeviceError::Backend(anyhow::anyhow!(
                "pci device {addr} not present in sysfs; \
                 was the VF / partition created on the host?"
            )));
        }

        if Self::current_driver(&dev).as_deref() == Some("vfio-pci") {
            debug!(pci_address = %addr, "already bound to vfio-pci");
            return Ok(());
        }

        if !Path::new("/sys/bus/pci/drivers/vfio-pci").exists() {
            return Err(DeviceError::Backend(anyhow::anyhow!(
                "vfio-pci driver is not available on this host; modprobe vfio-pci"
            )));
        }

        Self::sysfs_write(&dev.join("driver_override"), "vfio-pci")?;

        if let Some(cur) = Self::current_driver(&dev) {
            info!(pci_address = %addr, from = %cur, "unbinding from host driver");
            Self::sysfs_write(&dev.join("driver/unbind"), &addr.to_string())?;
        }

        Self::sysfs_write(Path::new("/sys/bus/pci/drivers_probe"), &addr.to_string())?;

        match Self::current_driver(&dev).as_deref() {
            Some("vfio-pci") => Ok(()),
            other => Err(DeviceError::Backend(anyhow::anyhow!(
                "device {addr} did not bind to vfio-pci (currently: {})",
                other.unwrap_or("<none>")
            ))),
        }
    }
}

#[async_trait::async_trait]
impl DeviceDriver for VfioPciDriver {
    #[instrument(skip_all, fields(device_id = %id))]
    async fn create(
        &self,
        id: &DeviceId,
        spec: &DeviceSpec,
        cgroup: Option<&CgroupHandle>,
    ) -> device::Result<Device> {
        let _ = cgroup;

        let addr = self.validated_address(spec)?;
        Self::check_iommu_group(&addr)?;
        Self::bind_vfio(&addr)?;

        info!(pci_address = %addr, "pci device ready for passthrough");
        Ok(Device {
            id: *id,
            attachment: DeviceAttachment::VfioPci {
                sysfs_path: addr.sysfs_path(),
            },
        })
    }

    #[instrument(skip_all, fields(device_id = %id))]
    async fn destroy(&self, id: &DeviceId, attachment: &DeviceAttachment) -> device::Result<()> {
        let addr = Self::addr_from_attachment(id, attachment)?;
        let dev = addr.sysfs_path();

        if !dev.exists() {
            debug!(pci_address = %addr, "device no longer in sysfs, nothing to unbind");
            return Ok(());
        }
        if Self::current_driver(&dev).as_deref() != Some("vfio-pci") {
            debug!(pci_address = %addr, "not bound to vfio-pci, nothing to do");
            return Ok(());
        }

        // Clearing the override lets drivers_probe match the default host driver
        // again, so no record of the original driver is needed.
        Self::sysfs_write(&dev.join("driver_override"), "\n")?;
        Self::sysfs_write(&dev.join("driver/unbind"), &addr.to_string())?;
        Self::sysfs_write(Path::new("/sys/bus/pci/drivers_probe"), &addr.to_string())?;

        match Self::current_driver(&dev) {
            // A device without a matching host driver stays unbound; that is fine.
            Some(drv) if drv == "vfio-pci" => Err(DeviceError::Backend(anyhow::anyhow!(
                "device {addr} re-bound to vfio-pci despite cleared override"
            ))),
            drv => {
                info!(pci_address = %addr, driver = drv.as_deref().unwrap_or("<none>"),
                      "device returned to host");
                Ok(())
            }
        }
    }

    #[instrument(level = "trace", skip_all, fields(device_id = %id))]
    async fn get(&self, id: &DeviceId, attachment: &DeviceAttachment) -> device::Result<Device> {
        let addr = Self::addr_from_attachment(id, attachment)?;
        match Self::current_driver(&addr.sysfs_path()).as_deref() {
            Some("vfio-pci") => Ok(Device {
                id: *id,
                attachment: attachment.clone(),
            }),
            _ => Err(DeviceError::NotFound(*id)),
        }
    }

    /// A passthrough device belongs to exactly one VM: it is handed to the
    /// guest whole, and a second guest given the same address would be
    /// handed a device the first one is driving. Refused here rather than at
    /// bind time, where the first VM would already be running on it.
    ///
    /// Specs already on the node are read leniently on purpose: one stored
    /// spec that no longer parses is not a reason to refuse the VM being
    /// created now, and the address it names is one nothing can be using.
    fn admit(
        &self,
        requested: &[(DeviceId, DeviceSpec)],
        claimed: &[(agent_api::VmId, DeviceSpec)],
    ) -> device::Result<()> {
        let mut wanted: Vec<(PciAddress, DeviceId)> = Vec::new();
        for (dev_id, spec) in requested {
            let addr = Self::requested_address(spec)
                .map_err(|e| DeviceError::InvalidSpec(format!("device {dev_id}: {e}")))?;
            if let Some((_, first)) = wanted.iter().find(|(a, _)| *a == addr) {
                return Err(DeviceError::InvalidSpec(format!(
                    "pci device {addr} is requested twice in this spec \
                     (devices {first} and {dev_id})"
                )));
            }
            wanted.push((addr, *dev_id));
        }
        if wanted.is_empty() {
            return Ok(());
        }
        for (vm, spec) in claimed {
            let Ok(addr) = Self::requested_address(spec) else {
                continue;
            };
            if wanted.iter().any(|(a, _)| *a == addr) {
                return Err(DeviceError::InvalidSpec(format!(
                    "pci device {addr} is already assigned to vm {vm}"
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    /// The driver under test claims nothing about sysfs: `admit` is pure, and
    /// the inventory is only consulted at bind time.
    fn driver() -> VfioPciDriver {
        VfioPciDriver {
            inventory: HashSet::new(),
        }
    }

    fn spec(pci: Option<&str>) -> DeviceSpec {
        DeviceSpec {
            driver: "vfio".into(),
            partition: PartitionSpec::Exclusive,
            profile: None,
            params: pci.map(|a| serde_json::json!({ "pci_address": a })),
        }
    }

    fn dev(n: u128, pci: Option<&str>) -> (DeviceId, DeviceSpec) {
        (Uuid::from_u128(n), spec(pci))
    }

    fn held(n: u128, pci: &str) -> (agent_api::VmId, DeviceSpec) {
        (Uuid::from_u128(n), spec(Some(pci)))
    }

    #[test]
    fn a_free_device_is_admitted() {
        driver()
            .admit(&[dev(1, Some("0000:23:00.0"))], &[held(9, "0000:24:00.0")])
            .expect("a different address is nobody's conflict");
    }

    /// A passthrough device is handed to the guest whole; a second guest given
    /// the same address would be handed a device the first one is driving.
    #[test]
    fn a_device_another_vm_holds_is_refused_by_name() {
        let err = driver()
            .admit(&[dev(1, Some("0000:23:00.0"))], &[held(9, "0000:23:00.0")])
            .unwrap_err();
        assert!(matches!(err, DeviceError::InvalidSpec(_)), "{err:?}");
        let msg = err.to_string();
        assert!(msg.contains("0000:23:00.0"), "{msg}");
        assert!(
            msg.contains(&Uuid::from_u128(9).to_string()),
            "must name the holder: {msg}"
        );
    }

    #[test]
    fn the_same_device_twice_in_one_spec_is_refused() {
        let err = driver()
            .admit(
                &[dev(1, Some("0000:23:00.0")), dev(2, Some("0000:23:00.0"))],
                &[],
            )
            .unwrap_err();
        assert!(err.to_string().contains("twice"), "{err}");
    }

    /// An address written in the short form is the same device as the long
    /// one — the comparison is on parsed addresses, not on strings, which is
    /// exactly what moving this into the driver bought.
    #[test]
    fn the_conflict_is_on_the_address_not_on_its_spelling() {
        let err = driver()
            .admit(&[dev(1, Some("23:00.0"))], &[held(9, "0000:23:00.0")])
            .unwrap_err();
        assert!(err.to_string().contains("already assigned"), "{err}");
    }

    /// The message a spec without params has to produce, because it is the
    /// one an operator sees when they forget the field.
    #[test]
    fn a_vfio_device_without_an_address_is_refused_before_anything_is_built() {
        let err = driver().admit(&[dev(1, None)], &[]).unwrap_err();
        assert!(matches!(err, DeviceError::InvalidSpec(_)));
        assert!(err.to_string().contains("pci_address"), "{err}");
        let err = driver()
            .admit(
                &[(
                    Uuid::from_u128(1),
                    DeviceSpec {
                        driver: "vfio".into(),
                        partition: PartitionSpec::Exclusive,
                        profile: None,
                        params: Some(serde_json::json!({ "pci_address": "not-an-address" })),
                    },
                )],
                &[],
            )
            .unwrap_err();
        assert!(err.to_string().contains("invalid vfio params"), "{err}");
    }

    /// A stored spec that no longer parses is not a reason to refuse the VM
    /// being created now: the address it names is one nothing can be using.
    #[test]
    fn an_unparseable_stored_spec_does_not_block_a_new_vm() {
        let broken = (
            Uuid::from_u128(9),
            DeviceSpec {
                driver: "vfio".into(),
                partition: PartitionSpec::Exclusive,
                profile: None,
                params: Some(serde_json::json!({ "pci_address": 42 })),
            },
        );
        driver()
            .admit(&[dev(1, Some("0000:23:00.0"))], &[broken])
            .expect("admitted");
    }

    #[test]
    fn nothing_requested_is_nothing_to_refuse() {
        driver()
            .admit(&[], &[held(9, "0000:23:00.0")])
            .expect("admitted");
    }
}
