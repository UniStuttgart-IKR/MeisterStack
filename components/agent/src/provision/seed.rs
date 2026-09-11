// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! What the VMM is handed: the cloud-init seed, and the instance spec that
//! names it alongside every disk, tap and device the chain just built.
//!
//! The seed is state derived from the spec and rebuilt on every provision, so
//! nothing about it has to be remembered — which is what lets a re-provision
//! after a dead VMM produce the same bytes.
//!
//! Moved out of `provision.rs` unchanged.

use super::*;

impl Provisioner {
    /// The fourth link of the chain: this VM's cloud-init seed, or nothing at
    /// all for a VM that has no cloud-init block.
    pub(super) fn write_seed(&self, id: &VmId, spec: &AgentVmSpec) -> Result<()> {
        // The seed, written before the VMM is created and rebuilt every time
        // this chain runs: it is derived from the spec, so a re-provision
        // after a dead VMM produces the same bytes and nothing has to be
        // remembered about it.
        if let Some(config) = &spec.cloud_init {
            let seed = crate::cloudinit::seed_path(&self.run_dir, id);
            crate::cloudinit::write_seed(&seed, id, config)
                .context("building the cloud-init seed")?;
            info!(path = %seed.display(), "cloud-init seed ready");
        }
        Ok(())
    }

    /// Where this VM's seed lives, and `None` for a VM that has no
    /// cloud-init block — which is what keeps such a VM's hypervisor config
    /// byte for byte what it was.
    fn seed_path(&self, id: &VmId, spec: &AgentVmSpec) -> Option<PathBuf> {
        spec.cloud_init
            .as_ref()
            .map(|_| crate::cloudinit::seed_path(&self.run_dir, id))
    }

    pub(super) fn build_instance_spec(
        &self,
        id: &VmId,
        spec: &AgentVmSpec,
        record: &VmRecord,
    ) -> Result<InstanceSpec> {
        let volumes: Vec<AttachedVolume> = record
            .volumes
            .iter()
            .map(|v| AttachedVolume {
                id: v.handle.id,
                attachment: v.attachment.clone(),
            })
            .collect();
        // A share is not something a guest can boot from, so the requirement
        // is a block volume and not merely a volume.
        if !volumes.iter().any(|v| v.attachment.is_block()) {
            bail!("vm spec contains no block volume; a boot disk is required");
        }

        let nics = record
            .nics
            .iter()
            .zip(spec.nics.iter())
            .map(|(created, requested)| NicAttachment {
                tap_name: created.tap_name.clone(),
                mac: requested.spec.mac,
                mtu: created.mtu,
            })
            .collect();

        let devices = record
            .devices
            .iter()
            .map(|d| d.attachment.clone())
            .collect();

        let boot = match &spec.boot {
            BootSourceSpec::DirectKernel {
                kernel,
                cmdline,
                initramfs,
            } => BootSource::DirectKernel {
                kernel: self.image_dir.join(kernel),
                cmdline: cmdline.clone(),
                initramfs: initramfs.as_ref().map(|n| self.image_dir.join(n)),
            },
            BootSourceSpec::Firmware { firmware } => BootSource::Firmware {
                firmware: self.image_dir.join(firmware),
            },
        };

        Ok(InstanceSpec {
            boot,
            volumes,
            vcpus: spec.vcpus,
            memory_mib: spec.memory_mib,
            nics,
            devices,
            cloud_init_seed: self.seed_path(id, spec),
        })
    }
}
