// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The `nvmeof` ATTACHER: a kernel NVMe-oF initiator, and the first consumer
//! of the `networked` locality axis.
//!
//! ## What it is for
//!
//! Every backend in this tree until now put the bytes on the node — an LV, a
//! file, an NFS mount. This one does not: the namespace lives on a storage
//! target, and what an attach does is make it appear as a block device HERE.
//! That is what `Locality::Networked` has always meant on the axis Storage A
//! built, and until this driver nothing claimed it — the arm in
//! `VolumeBinding::required` said so in a comment and named this position.
//!
//! ## The split, and why there are two crates
//!
//! A namespace is provisioned by whoever owns the target (`nvmeof-import`
//! next door, for namespaces that already exist) and attached by whichever
//! compute node runs the VM. Two roles, two crates, because they run in
//! different places: the catalogue says so and the lab proves the degenerate
//! case, where both happen to be the same machine.
//!
//! ## Why `nvme-cli` and not a library
//!
//! The same argument `lvm-thin` makes about LVM: the kernel's fabrics
//! interface is `/dev/nvme-fabrics` and a line of `key=value` pairs, and
//! `nvme-cli` is the thing that has been getting that line right for a
//! decade. What is left here is parsing `nvme list-subsys -o json`, which is
//! what the tests below are about — a misread path name is a VM handed
//! somebody else's disk.

use std::path::{Path, PathBuf};

use agent_api::CgroupHandle;
use agent_api::storage::{
    Locality, StorageError, VolumeAttacher, VolumeAttachment, VolumeHandle, VolumeId,
    VolumeProvider, VolumeSpec, VolumeState,
};
use tracing::{debug, info, instrument, warn};

/// How long to wait for the kernel to publish the block device after a
/// successful connect.
///
/// `nvme connect` returns when the controller is created, and the namespace
/// scan that turns it into `/dev/nvmeXnY` finishes a moment later. Polling is
/// the honest answer — the alternative is a udev settle, which needs udev to
/// be the thing that made the node, and it is not on every host this runs on.
///
/// Five seconds: a healthy connect on this fabric publishes in milliseconds,
/// and anything past five seconds is a target that took the connection and
/// then did not answer the identify.
const SCAN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const SCAN_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

/// Where the kernel publishes RDMA devices. Empty or missing = this host has
/// no RDMA, whatever a pool asks for.
const INFINIBAND: &str = "/sys/class/infiniband";

/// The one port this driver refuses outright.
///
/// 4420 is the IANA default and, in this lab, the DPU's own target
/// (`dpu-nvmet.service` on magaluf, loop devices out of `/opt`). Connecting a
/// tenant's VM to it would be a VM reading a device nobody meant to export to
/// it — and the mistake is one keystroke away from the ports that are ours.
/// A refusal with a sentence beats a disk that is silently the wrong disk.
pub const RESERVED_PORT: u16 = 4420;

/// What a pool says about where its namespaces live, and how to speak to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Tcp,
    Rdma,
}

impl Transport {
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Tcp => "tcp",
            Transport::Rdma => "rdma",
        }
    }
}

/// The connection an attach makes, carried on the handle because the
/// attacher is given a handle and nothing else.
///
/// The provider puts it there (`nvmeof-import`), and an operator can put it
/// there by hand for a namespace this control plane did not provision — which
/// is the whole shape of an import.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NvmeofTarget {
    pub nqn: String,
    pub addr: String,
    pub port: u16,
    pub transport: Transport,
}

impl NvmeofTarget {
    /// Read the target off a handle's `params`.
    ///
    /// A handle with none is not this driver's, and saying so by name is the
    /// difference between a clear refusal and a connect to nowhere.
    pub fn of(handle: &VolumeHandle) -> agent_api::storage::Result<Self> {
        let params = handle.params.clone().ok_or_else(|| {
            StorageError::InvalidSpec(format!(
                "volume {} carries no nvmeof target; its handle was not made by nvmeof-import",
                handle.id
            ))
        })?;
        let target: NvmeofTarget = serde_json::from_value(params).map_err(|e| {
            StorageError::InvalidSpec(format!("volume {}: unusable nvmeof target: {e}", handle.id))
        })?;
        target.check()?;
        Ok(target)
    }

    /// The two refusals that are about the FABRIC rather than about a spec.
    pub fn check(&self) -> agent_api::storage::Result<()> {
        if self.nqn.is_empty() || self.addr.is_empty() {
            return Err(StorageError::InvalidSpec(
                "an nvmeof target needs an nqn and an addr".into(),
            ));
        }
        if self.port == RESERVED_PORT {
            return Err(StorageError::InvalidSpec(format!(
                "port {RESERVED_PORT} is the DPU's own nvmet target and is not this control \
                 plane's to connect to; name the port your namespaces are exported on"
            )));
        }
        Ok(())
    }
}

pub struct NvmeofAttacherConfig {
    /// Where `nvme` lives. `None` = whatever PATH says, which is right on a
    /// NixOS node and wrong nowhere in particular — the same escape
    /// `lvm-thin` has.
    pub bin_dir: Option<PathBuf>,
}

pub struct NvmeofAttacher {
    config: NvmeofAttacherConfig,
}

impl NvmeofAttacher {
    pub fn new(config: NvmeofAttacherConfig) -> Self {
        Self { config }
    }

    fn nvme(&self) -> PathBuf {
        match &self.config.bin_dir {
            Some(dir) => dir.join("nvme"),
            None => PathBuf::from("nvme"),
        }
    }

    async fn run(&self, args: &[&str]) -> agent_api::storage::Result<String> {
        let out = tokio::process::Command::new(self.nvme())
            .args(args)
            .output()
            .await
            .map_err(|e| {
                StorageError::Backend(anyhow::anyhow!(
                    "running `nvme {}`: {e}. Is nvme-cli installed, and is this process root?",
                    args.join(" ")
                ))
            })?;
        if !out.status.success() {
            return Err(StorageError::Backend(anyhow::anyhow!(
                "`nvme {}` failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// The device this subsystem is published as, or `None` while the kernel
    /// has not finished scanning it.
    async fn device_of(&self, nqn: &str) -> agent_api::storage::Result<Option<PathBuf>> {
        let json = self.run(&["list-subsys", "-o", "json"]).await?;
        Ok(device_in_listing(&json, nqn))
    }
}

/// Which block device a subsystem's controller is, out of
/// `nvme list-subsys -o json`.
///
/// A free function so that the shape of that document — the one thing that
/// can change under us on a distribution upgrade — is testable against
/// captured output with no target, no root and no kernel module.
///
/// Namespace 1, and only namespace 1. An imported namespace is exported as a
/// subsystem of its own by every target in this lab, so `nvmeXn1` is the
/// whole of it; a subsystem with several namespaces is a shape this driver
/// does not claim to handle, and picking the first of them silently would be
/// the wrong kind of guess about somebody's data.
pub fn device_in_listing(json: &str, nqn: &str) -> Option<PathBuf> {
    let doc: serde_json::Value = serde_json::from_str(json).ok()?;
    // Two shapes in the wild: nvme-cli 2.x wraps the subsystems in a
    // host-keyed array, older ones hand back the array itself.
    let hosts = doc.as_array().cloned().unwrap_or_else(|| vec![doc.clone()]);
    for host in hosts {
        let subsystems = host
            .get("Subsystems")
            .or_else(|| host.get("subsystems"))
            .and_then(|s| s.as_array())
            .cloned()
            .unwrap_or_default();
        for subsystem in subsystems {
            if subsystem.get("NQN").and_then(|n| n.as_str()) != Some(nqn) {
                continue;
            }
            let paths = subsystem
                .get("Paths")
                .and_then(|p| p.as_array())
                .cloned()
                .unwrap_or_default();
            // A live path, and never a dead one: a subsystem can carry a
            // controller that is `connecting` or `deleting`, and handing a
            // VMM the device of one is handing it a disk that answers EIO.
            for path in paths {
                let live = path
                    .get("State")
                    .and_then(|s| s.as_str())
                    .is_some_and(|s| s == "live");
                let Some(name) = path.get("Name").and_then(|n| n.as_str()) else {
                    continue;
                };
                if live && !name.is_empty() {
                    return Some(PathBuf::from(format!("/dev/{name}n1")));
                }
            }
        }
    }
    None
}

/// Whether this host has an RDMA device at all.
///
/// Checked before the connect and not after, because the failure without it
/// is `nvme connect` returning ENODEV — a number, for a fact an operator can
/// read off a directory. Out of a VM without a VF there is only `tcp`, and
/// that is the sentence to give.
pub fn has_rdma(sysfs: &Path) -> bool {
    std::fs::read_dir(sysfs).is_ok_and(|mut entries| entries.next().is_some())
}

#[async_trait::async_trait]
impl VolumeAttacher for NvmeofAttacher {
    #[instrument(skip_all, fields(volume = %handle.id))]
    async fn attach(
        &self,
        handle: &VolumeHandle,
        _cgroup: Option<&CgroupHandle>,
    ) -> agent_api::storage::Result<VolumeAttachment> {
        // No cgroup, and that is a statement rather than an omission: there
        // is no backend PROCESS here. The initiator is the kernel, the disk
        // is a block device, and cloud-hypervisor opens it itself — exactly
        // as it opens an LV. What a cgroup confines is a process somebody
        // spawned, and nobody spawned one.
        let target = NvmeofTarget::of(handle)?;
        if target.transport == Transport::Rdma && !has_rdma(Path::new(INFINIBAND)) {
            return Err(StorageError::Backend(anyhow::anyhow!(
                "this node has no rdma device ({INFINIBAND} is empty), so it cannot reach \
                 {} over rdma; a pool on a host without a VF has to say transport = \"tcp\"",
                target.nqn
            )));
        }

        // Idempotent, and it has to be: a re-sent create, a reconnect after a
        // controller restart, two VMs on one node using two namespaces of one
        // subsystem. `nvme connect` says "already connected" and exits
        // non-zero on some builds, so the state is asked FIRST and the
        // command is only run when there is nothing there.
        if let Some(device) = self.device_of(&target.nqn).await? {
            debug!(nqn = %target.nqn, device = %device.display(), "already connected");
            return Ok(VolumeAttachment::Path(device));
        }

        let port = target.port.to_string();
        self.run(&[
            "connect",
            "-t",
            target.transport.as_str(),
            "-a",
            &target.addr,
            "-s",
            &port,
            "-n",
            &target.nqn,
        ])
        .await?;

        // The scan, polled. See SCAN_TIMEOUT.
        let deadline = std::time::Instant::now() + SCAN_TIMEOUT;
        loop {
            if let Some(device) = self.device_of(&target.nqn).await? {
                info!(nqn = %target.nqn, device = %device.display(),
                      transport = target.transport.as_str(), "namespace attached");
                return Ok(VolumeAttachment::Path(device));
            }
            if std::time::Instant::now() >= deadline {
                // The connection stays up on purpose: it is evidence, and an
                // operator with `nvme list-subsys` can see what the kernel
                // thinks. Tearing it down here would leave nothing to look at.
                return Err(StorageError::Backend(anyhow::anyhow!(
                    "connected to {} but no block device appeared within {}s; \
                     `nvme list-subsys` says what the kernel has",
                    target.nqn,
                    SCAN_TIMEOUT.as_secs()
                )));
            }
            tokio::time::sleep(SCAN_INTERVAL).await;
        }
    }

    #[instrument(skip_all, fields(volume = %handle.id))]
    async fn detach(
        &self,
        handle: &VolumeHandle,
        _attachment: &VolumeAttachment,
    ) -> agent_api::storage::Result<()> {
        let target = NvmeofTarget::of(handle)?;
        // Idempotent by the same argument attach is: `nvme disconnect` of a
        // subsystem that is not connected removes zero controllers and
        // succeeds, and a detach that failed because there was nothing to
        // detach would make every second teardown an error.
        match self.run(&["disconnect", "-n", &target.nqn]).await {
            Ok(out) => {
                info!(nqn = %target.nqn, answer = out.trim(), "namespace detached");
                Ok(())
            }
            // Warn and succeed: the bytes are on the target and are not this
            // node's to lose. A connection this node could not take down is
            // an operator's problem and not a reason to keep a VM's teardown
            // from finishing.
            Err(e) => {
                warn!(nqn = %target.nqn, error = %format!("{e:#}"),
                      "disconnect failed; the connection may still be up on this node");
                Ok(())
            }
        }
    }

    async fn stat(
        &self,
        handle: &VolumeHandle,
        attachment: &VolumeAttachment,
    ) -> agent_api::storage::Result<VolumeState> {
        let VolumeAttachment::Path(device) = attachment else {
            return Err(StorageError::InvalidSpec(
                "an nvmeof attachment is a block device path".into(),
            ));
        };
        let target = NvmeofTarget::of(handle)?;
        // The CONNECTION and not the data: a subsystem that has gone away
        // takes its device with it, and that is exactly the difference
        // between this question and the provider's `describe`.
        if self.device_of(&target.nqn).await?.is_none() {
            return Err(StorageError::NotFound(handle.id));
        }
        let json = self
            .run(&["id-ns", &device.to_string_lossy(), "-o", "json"])
            .await?;
        let size_bytes = size_in_id_ns(&json).ok_or_else(|| {
            StorageError::Backend(anyhow::anyhow!(
                "could not read a size out of `nvme id-ns {}`",
                device.display()
            ))
        })?;
        Ok(VolumeState { size_bytes })
    }
}

/// The namespace's size in bytes, out of `nvme id-ns -o json`.
///
/// `nsze` is in LOGICAL BLOCKS and the block size is in the LBA format the
/// namespace is formatted with — `flbas`' low nibble selects the entry, and
/// `ds` is its base-2 exponent. Multiplying by 512 because that is the usual
/// answer would be right on most namespaces and quietly wrong by 8x on a 4k
/// one, which is the size an operator then sees on a disk that is fine.
pub fn size_in_id_ns(json: &str) -> Option<u64> {
    let doc: serde_json::Value = serde_json::from_str(json).ok()?;
    let blocks = doc.get("nsze")?.as_u64()?;
    let selected = doc.get("flbas")?.as_u64()? & 0xf;
    let formats = doc
        .get("lbafs")
        .or_else(|| doc.get("lbaf"))
        .and_then(|f| f.as_array())?;
    let exponent = formats
        .iter()
        .find(|f| f.get("lbaf").and_then(serde_json::Value::as_u64) == Some(selected))
        .or_else(|| formats.get(selected as usize))
        .and_then(|f| f.get("ds"))
        .and_then(serde_json::Value::as_u64)?;
    // A namespace with a block size this control plane cannot represent is
    // not a namespace anybody should be handed.
    (9..=16).contains(&exponent).then(|| blocks << exponent)
}

/// The provider half, which this driver does not have.
///
/// It exists because the agent's registry hands back one `Arc<dyn
/// VolumeDriver>` per row and that trait is the two halves together — the
/// degenerate case every backend in this tree has been so far. This is the
/// first one that is genuinely half a driver, and the honest way to say so is
/// `Unsupported` on every provider verb rather than a `provision` that makes
/// something.
///
/// `locality` is the exception and is answered for real: it is what the
/// scheduler reads to know that a node with this claim can reach bytes that
/// are not on it, and it is the whole reason the axis exists.
#[async_trait::async_trait]
impl VolumeProvider for NvmeofAttacher {
    async fn provision(
        &self,
        _id: &VolumeId,
        _spec: &VolumeSpec,
    ) -> agent_api::storage::Result<VolumeHandle> {
        Err(StorageError::Unsupported(
            "nvmeof attaches namespaces and makes none; a pool's driver is nvmeof-import (or \
             whatever owns the target) and its attacher is nvmeof"
                .into(),
        ))
    }

    async fn deprovision(&self, _handle: &VolumeHandle) -> agent_api::storage::Result<()> {
        Err(StorageError::Unsupported(
            "nvmeof owns no bytes and destroys none".into(),
        ))
    }

    async fn describe(&self, _handle: &VolumeHandle) -> agent_api::storage::Result<VolumeState> {
        Err(StorageError::Unsupported(
            "nvmeof cannot describe a namespace it does not own; ask its provider".into(),
        ))
    }

    fn locality(&self) -> Locality {
        Locality::Networked
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The document `nvme list-subsys -o json` really produces, captured from
    /// the target this position was written against. The parsing is the one
    /// thing that can change under us on a distribution upgrade, and a
    /// misread path name is a VM handed somebody else's disk.
    const LISTING: &str = r#"[{
      "HostNQN": "nqn.2014-08.org.nvmexpress:uuid:ce9cf739",
      "Subsystems": [
        { "Name": "nvme-subsys0",
          "NQN": "nqn.2014.08.org.nvmexpress:144d144dS4EVNJ0N109176J     Samsung SSD 970",
          "Paths": [{"Name":"nvme0","Transport":"pcie","Address":"0000:01:00.0","State":"live"}] },
        { "Name": "nvme-subsys2",
          "NQN": "nqn.2026-09.local.calvia:meisterstack-test1",
          "Paths": [{"Name":"nvme2","Transport":"tcp",
                     "Address":"traddr=10.33.0.21,trsvcid=4422,src_addr=10.33.0.13",
                     "State":"live"}] }
      ]}]"#;

    #[test]
    fn the_device_of_a_subsystem_is_found_by_its_nqn_and_no_other_way() {
        assert_eq!(
            device_in_listing(LISTING, "nqn.2026-09.local.calvia:meisterstack-test1"),
            Some(PathBuf::from("/dev/nvme2n1"))
        );
        // A subsystem this host does not have is not an error and not a
        // guess: it is "not yet", which is what the attach polls on.
        assert_eq!(
            device_in_listing(LISTING, "nqn.2026-09.local.calvia:meisterstack-test9"),
            None
        );
        // And a local PCIe disk is never handed back for a fabrics nqn.
        assert_eq!(device_in_listing(LISTING, "nvme0"), None);
    }

    /// A controller that is not `live` is a controller whose device answers
    /// EIO. Handing it to a VMM would be worse than waiting.
    #[test]
    fn a_path_that_is_not_live_is_not_a_device_yet() {
        // Only the fabrics subsystem's state is flipped: the local PCIe one
        // above it stays `live`, so this is about the right subsystem.
        let doc = LISTING.replace(
            r#""Name":"nvme2","Transport":"tcp"#,
            r#""Name":"nvme2","State":"connecting","Transport":"tcp"#,
        );
        // The path now carries `connecting` first; serde_json keeps the last
        // duplicate key, so flip the trailing one too.
        let doc = doc.replace(
            r#"src_addr=10.33.0.13",
                     "State":"live""#,
            r#"src_addr=10.33.0.13",
                     "State":"connecting""#,
        );
        assert_eq!(
            device_in_listing(&doc, "nqn.2026-09.local.calvia:meisterstack-test1"),
            None,
            "a connecting controller is not a disk"
        );
        // And the local disk is untouched by the edit, so the test is about
        // the subsystem it says it is about.
        assert!(doc.contains(
            r#""Name":"nvme0","Transport":"pcie","Address":"0000:01:00.0","State":"live""#
        ));
    }

    /// Rubbish is refused rather than panicking: this is the output of a
    /// program on the host, and a distribution upgrade is exactly the moment
    /// it changes shape.
    #[test]
    fn an_unreadable_listing_is_no_device_rather_than_a_panic() {
        for bad in ["", "not json", "{}", "[]", r#"[{"Subsystems":"nope"}]"#] {
            assert_eq!(device_in_listing(bad, "nqn.x"), None, "{bad:?}");
        }
    }

    /// The size arithmetic, and the 8x mistake it exists to avoid.
    #[test]
    fn a_namespace_is_measured_in_its_own_block_size() {
        let id_ns = |ds: u64, blocks: u64| {
            format!(
                r#"{{"nsze":{blocks},"ncap":{blocks},"flbas":0,
                     "lbafs":[{{"lbaf":0,"ms":0,"ds":{ds},"rp":0,"in_use":1}}]}}"#
            )
        };
        // The real one: 26214400 blocks of 4096 = 100 GiB.
        assert_eq!(
            size_in_id_ns(&id_ns(12, 26_214_400)),
            Some(100 * 1024 * 1024 * 1024)
        );
        // The same block count at 512 bytes is an eighth of that, and reading
        // one as the other is the defect this guards.
        assert_eq!(
            size_in_id_ns(&id_ns(9, 26_214_400)),
            Some(100 * 1024 * 1024 * 1024 / 8)
        );
        // A second format, selected by flbas.
        let two = r#"{"nsze":1000,"flbas":1,
                      "lbafs":[{"lbaf":0,"ds":9},{"lbaf":1,"ds":12}]}"#;
        assert_eq!(size_in_id_ns(two), Some(1000 * 4096));
        // Nonsense is None, never a number.
        for bad in [
            "",
            "{}",
            r#"{"nsze":1}"#,
            r#"{"nsze":1,"flbas":0,"lbafs":[]}"#,
            r#"{"nsze":1,"flbas":0,"lbafs":[{"lbaf":0,"ds":99}]}"#,
        ] {
            assert_eq!(size_in_id_ns(bad), None, "{bad:?}");
        }
    }

    /// The port that is not ours, refused by name.
    #[test]
    fn the_dpus_own_port_is_refused_with_a_sentence() {
        let target = |port| NvmeofTarget {
            nqn: "nqn.2026-09.local.calvia:meisterstack-test1".into(),
            addr: "10.33.0.21".into(),
            port,
            transport: Transport::Tcp,
        };
        target(4422).check().expect("ours");
        target(4421).check().expect("ours");
        let refused = target(RESERVED_PORT).check().expect_err("the dpu's");
        assert!(format!("{refused}").contains("4420"), "{refused}");
        assert!(format!("{refused}").contains("DPU"), "{refused}");

        // And the two fields without which there is nothing to dial.
        let mut empty = target(4422);
        empty.addr = String::new();
        assert!(empty.check().is_err());
    }

    /// A handle from another backend is refused by name rather than dialled.
    #[test]
    fn a_handle_that_is_not_this_drivers_is_refused_by_name() {
        let handle = |params: Option<serde_json::Value>| VolumeHandle {
            id: uuid::Uuid::nil(),
            backend: "/dev/vg0/vm-x".into(),
            size_bytes: 1024,
            params,
        };
        let refused = NvmeofTarget::of(&handle(None)).expect_err("no target");
        assert!(
            format!("{refused}").contains("nvmeof-import"),
            "it says whose handle this should have been: {refused}"
        );
        // Params that are somebody else's shape.
        assert!(
            NvmeofTarget::of(&handle(Some(serde_json::json!({ "pool": "vg0/thin" })))).is_err()
        );
        // And the real thing.
        let good = NvmeofTarget::of(&handle(Some(serde_json::json!({
            "nqn": "nqn.2026-09.local.calvia:meisterstack-test1",
            "addr": "10.33.0.21", "port": 4422, "transport": "tcp"
        }))))
        .expect("a target");
        assert_eq!(good.transport, Transport::Tcp);
        assert_eq!(good.port, 4422);
    }

    /// RDMA is a property of the HOST, and the sentence for a host without it
    /// names the directory rather than an errno.
    #[test]
    fn rdma_is_answered_by_the_host_and_not_by_the_pool() {
        let (_temp, empty) = tempdir();
        assert!(!has_rdma(&empty), "a directory with nothing in it");
        assert!(!has_rdma(Path::new("/nonexistent/infiniband")), "or none");
        std::fs::create_dir_all(empty.join("rocep35s0f0")).expect("a device");
        assert!(has_rdma(&empty));
        let _ = std::fs::remove_dir_all(&empty);
    }

    /// A directory of this test's own, and the guard that removes it again —
    /// however the test ends, panic included.
    fn tempdir() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::Builder::new()
            .prefix("nvmeof-test-")
            .tempdir()
            .expect("a directory");
        let dir = temp.path().to_path_buf();
        (temp, dir)
    }
}
