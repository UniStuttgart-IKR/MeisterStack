// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Independent volume operations and guest attachment resizing.

use super::*;

impl Agent {
    /// Provision an independent volume without taking the VM operations lock.
    /// Backend identity is derived from the volume ID for retry recovery.
    pub(super) async fn handle_provision_volume(
        &self,
        v: proto::ProvisionVolume,
    ) -> anyhow::Result<()> {
        let id: VolumeId = v.id.parse().context("invalid volume id")?;
        let spec = crate::volumes::parse_spec(&v.spec_json)?;
        self.volumes
            .validate_driver(spec.driver.as_deref())
            .context("invalid volume spec")?;
        // Snapshot-based creation uses a separate driver operation from empty or base-image creation.
        match v.from_snapshot.as_str() {
            "" => self.volumes_owned.provision(id, spec).await,
            named => {
                if spec.base_image.is_some() {
                    // Recheck mutually exclusive source fields at the node boundary.
                    bail!(
                        "a volume starts from a base image or from a snapshot, not both; \
                         drop one"
                    );
                }
                let snapshot: agent_api::storage::SnapshotId =
                    named.parse().context("invalid snapshot id")?;
                self.volumes_owned.provision_from(id, snapshot, spec).await
            }
        }
    }

    /// Destroy a volume and its data — unless a VM here is holding it.
    pub(super) async fn handle_deprovision_volume(
        &self,
        v: proto::DeprovisionVolume,
    ) -> anyhow::Result<()> {
        let id: VolumeId = v.id.parse().context("invalid volume id")?;
        self.volumes_owned.deprovision(id).await
    }

    /// Remove node-local volume ownership while preserving data; see `Volumes::forget`.
    pub(super) async fn handle_forget_volume(&self, v: proto::ForgetVolume) -> anyhow::Result<()> {
        let id: VolumeId = v.id.parse().context("invalid volume id")?;
        self.volumes_owned.forget(id).await
    }

    /// Request a backend snapshot without taking the VM operations lock or
    /// pausing a guest. Required writer coordination belongs to the controller.
    pub(super) async fn handle_snapshot_volume(
        &self,
        v: proto::SnapshotVolume,
    ) -> anyhow::Result<()> {
        let volume: VolumeId = v.id.parse().context("invalid volume id")?;
        let id: agent_api::storage::SnapshotId =
            v.snapshot_id.parse().context("invalid snapshot id")?;
        self.volumes_owned.snapshot(id, volume).await
    }

    /// Grow the bytes of a volume this node owns. The first half.
    pub(super) async fn handle_resize_volume(&self, v: proto::ResizeVolume) -> anyhow::Result<()> {
        let id: VolumeId = v.id.parse().context("invalid volume id")?;
        self.volumes_owned.resize(id, v.size_bytes).await
    }

    /// Notify the guest of a grown disk under the VM operations lock.
    /// This does not resize backend data. Unsupported hypervisors return an error.
    pub(super) async fn handle_resize_attachment(
        &self,
        v: proto::ResizeAttachment,
    ) -> anyhow::Result<()> {
        let vm: VmId = v.vm.parse().context("invalid vm id")?;
        let volume: VolumeId = v.volume_id.parse().context("invalid volume id")?;
        let _guard = self.ops.lock().await;
        self.provisioner
            .resize_attachment(&vm, &volume, v.size_bytes)
            .await
    }

    /// Destroy a snapshot and its data.
    pub(super) async fn handle_drop_snapshot(&self, v: proto::DropSnapshot) -> anyhow::Result<()> {
        let id: agent_api::storage::SnapshotId =
            v.snapshot_id.parse().context("invalid snapshot id")?;
        self.volumes_owned.drop_snapshot(id).await
    }
}
