// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The verbs about a volume this node owns on its own, and the one about a
//! volume a guest already has.

use super::*;

impl Agent {
    /// Make bytes for a volume the control plane owns.
    ///
    /// No `ops` lock, and that is deliberate: the lock serialises work on ONE
    /// VM's devices and slices, and a volume with no consumer touches neither.
    /// Two provisions of the same volume at once are safe by the driver
    /// contract — every backend derives its name from the id and hands the
    /// same volume back.
    pub(super) async fn handle_provision_volume(
        &self,
        v: proto::ProvisionVolume,
    ) -> anyhow::Result<()> {
        let id: VolumeId = v.id.parse().context("invalid volume id")?;
        let spec = crate::volumes::parse_spec(&v.spec_json)?;
        self.volumes
            .validate_driver(spec.driver.as_deref())
            .context("invalid volume spec")?;
        // Three ways a volume starts, and the third is new: empty, from a
        // catalogue image, or from a snapshot this node holds. The last one
        // is a different driver call and not a flag on the same one, which is
        // the cut the trait makes and the reason it is a branch here.
        match v.from_snapshot.as_str() {
            "" => self.volumes_owned.provision(id, spec).await,
            named => {
                if spec.base_image.is_some() {
                    // Refused at the API edge too, where a person can read
                    // it. Said again here because this is the refusal nobody
                    // can go around, and because a spec that reached a node
                    // with both would otherwise get whichever the code
                    // happened to try first.
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

    /// Stop being a node that holds a volume, and keep every byte of it.
    ///
    /// The sibling of the one above, and the distance between the two is
    /// somebody's data: that one destroys an LV and unlinks a file, this one
    /// removes a record. See `Volumes::forget`.
    pub(super) async fn handle_forget_volume(&self, v: proto::ForgetVolume) -> anyhow::Result<()> {
        let id: VolumeId = v.id.parse().context("invalid volume id")?;
        self.volumes_owned.forget(id).await
    }

    /// Freeze what a volume holds right now.
    ///
    /// No `ops` lock, for the reason `handle_provision_volume` gives: the
    /// lock serialises work on one VM's devices and slices, and a snapshot
    /// touches neither. If the VM had to be paused for this, it was paused by
    /// the tier that sent the command — see `SnapshotVolume` in the proto.
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

    /// Tell a guest that its disk has grown. The second half, and it changes
    /// no data at all.
    ///
    /// Under the `ops` lock, unlike the first half: this touches a running
    /// VM's device model, and that is exactly what the lock serialises.
    ///
    /// A hypervisor that cannot do it is an error and not a silent success —
    /// the tier above puts the sentence on the object, and "the backend grew
    /// and the guest was not told" is a state an operator has to be able to
    /// read.
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
