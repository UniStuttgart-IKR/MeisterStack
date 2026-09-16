// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The cloud hypervisor driver: one VMM process per VM, driven over its own
//! unix socket.
//!
//! This file is the face the agent sees — the struct, and the four traits it
//! answers to. Every trait method here is one line of substance at most; what
//! it does lives in one of three files, split the way the driver's own
//! concerns split:
//!
//! * `config` — building the VM document, pure and therefore testable
//! * `process` — starting, adopting and killing the VMM, and the files
//!   beside it
//! * `api` — talking to it over the socket, migration included
//!
//! They were one file of 1 660 lines, whose fifteen methods Repowise read as
//! five groups sharing no state (LCOM4 = 5). These are those groups.

use agent_api::hypervisor;
use agent_api::{
    AttachedVolume, BootSource, CgroupHandle, ConsoleStream, DeviceAttachment, HotPluggable,
    Hypervisor, HypervisorError, InstanceSpec, Pausable, VmId, VmState, VolumeAttachment,
};
use anyhow::{Context, bail};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Mutex;
use std::time::Duration;
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tracing::{debug, info, instrument, warn};

mod api;
mod config;
mod process;

pub(crate) use api::*;
pub(crate) use config::*;
pub(crate) use process::*;

/// How long a hot-unplug may take before this driver stops believing in it,
/// when nobody has said.
///
/// Generous on purpose: the deadline is not the guest's response time, it is
/// the point at which "the guest is thinking about it" becomes "the guest is
/// never going to do it", and being wrong here in the fast direction is what
/// D3 was. A detach that takes ten seconds is unusual and fine; a detach that
/// is reported done while the fd is still open is a VM that will not boot.
///
/// A default and no longer the whole answer: it is a number about GUESTS and
/// not about this stack — how long a kernel takes to let go of a virtio
/// device is a property of the images a fleet runs — so a fleet whose guests
/// need forty seconds sets `[hypervisor.cloud-hypervisor] unplug_timeout_secs`
/// rather than living with a detach that reports a failure over a device that
/// did in fact go.
///
/// **Public because the config's default is this value and must stay this
/// value.** `AgentConfig`'s serde default reads it from here rather than
/// spelling `30` a second time: two literals for one number is how a driver
/// and an option table start disagreeing about what "the default" is.
pub const DEFAULT_UNPLUG_TIMEOUT: Duration = Duration::from_secs(30);

pub struct CloudHypervisorDriver {
    binary: PathBuf,
    socket_dir: PathBuf,
    vms: Mutex<HashMap<VmId, RunningVm>>,
    ch_timeout: Duration,
    /// How long a hot-unplug may take before this driver stops believing in
    /// it. `[hypervisor.cloud-hypervisor] unplug_timeout_secs`, defaulting to
    /// [`DEFAULT_UNPLUG_TIMEOUT`] — which is where the number is argued, and
    /// `remove_disk` is where being wrong about it is paid for.
    unplug_timeout: Duration,
    /// The backend path of every disk a `remove_disk` has asked the guest to
    /// let go of and not yet seen closed, by vm and disk id.
    ///
    /// Kept because the path is only readable off `vm.info` BEFORE the
    /// request: cloud hypervisor drops the disk from `config.disks` the
    /// moment it accepts `vm.remove-device`, which is what made the config a
    /// false witness (see `remove_disk`). A retry after a guest that took too
    /// long has nothing left to read the path from but this.
    unplugging: Mutex<HashMap<(VmId, String), PathBuf>>,
}

impl CloudHypervisorDriver {
    pub fn new(
        binary: PathBuf,
        socket_dir: PathBuf,
        ch_timeout: Duration,
        unplug_timeout: Duration,
    ) -> hypervisor::Result<Self> {
        std::fs::create_dir_all(&socket_dir).map_err(|e| {
            HypervisorError::Backend(anyhow::anyhow!(
                "creating socket dir {}: {e}",
                socket_dir.display()
            ))
        })?;
        Ok(Self {
            binary,
            socket_dir,
            vms: Mutex::new(HashMap::new()),
            ch_timeout,
            unplug_timeout,
            unplugging: Mutex::new(HashMap::new()),
        })
    }
}

#[async_trait::async_trait]
impl Hypervisor for CloudHypervisorDriver {
    #[instrument(skip_all, fields(vm_id = %id))]
    async fn create(
        &self,
        id: &VmId,
        spec: &InstanceSpec,
        cgroup: Option<&CgroupHandle>,
    ) -> hypervisor::Result<u32> {
        self.create_vm(id, spec, cgroup).await
    }

    #[instrument(skip_all, fields(vm_id = %id))]
    async fn start(&self, id: &VmId) -> hypervisor::Result<()> {
        self.vm_known(id)?;
        self.api(id, Method::PUT, "vm.boot", None).await.map(|_| ())
    }

    #[instrument(skip_all, fields(vm_id = %id))]
    async fn shutdown(&self, id: &VmId) -> hypervisor::Result<()> {
        self.vm_known(id)?;
        self.api(id, Method::PUT, "vm.shutdown", None)
            .await
            .map(|_| ())
    }
    #[instrument(skip_all, fields(vm_id = %id))]
    async fn power_button(&self, id: &VmId) -> hypervisor::Result<()> {
        self.vm_known(id)?;
        self.api(id, Method::PUT, "vm.power-button", None)
            .await
            .map(|_| ())
    }
    // telemetry with RUST_LOG=...=trace
    #[instrument(level = "trace", skip_all, fields(vm_id = %id))]
    async fn get_state(&self, id: &VmId) -> hypervisor::Result<VmState> {
        self.state(id).await
    }

    #[instrument(skip_all, fields(vm_id = %id))]
    async fn destroy(&self, id: &VmId) -> hypervisor::Result<()> {
        self.destroy_vm(id).await
    }

    fn console_paths(&self, id: &VmId) -> Vec<(ConsoleStream, PathBuf)> {
        ConsoleStream::ALL
            .into_iter()
            .map(|s| (s, self.console_path(id, s)))
            .collect()
    }

    /// The live log, and every one this driver kept from a VMM of the same id
    /// that has been torn down — oldest first, so the newest is what a reader
    /// sees last.
    ///
    /// D-P19. `-v` was turned on for the receiving VMM to get one line out of
    /// it, and the tidy-up removed that log the moment the reception was
    /// given back: `vm logs --streams vmm` could never show a receiving VMM
    /// at all, which is the one case the flag was turned on for. Two fixes of
    /// one round cancelling each other out.
    ///
    /// They are `diagnostic_paths` and not `console_paths` for the reason
    /// that split exists: this is the hypervisor's own noise and never the
    /// guest's, and `vm logs` mixes the two only when somebody asks for
    /// `--streams vmm` by name.
    fn diagnostic_paths(&self, id: &VmId) -> Vec<PathBuf> {
        let mut paths = self.kept_logs(id);
        paths.push(self.vmm_log_path(id));
        paths
    }

    fn console_socket(&self, id: &VmId) -> Option<PathBuf> {
        Some(self.serial_socket_path(id))
    }

    #[instrument(skip_all, fields(vm_id = %id, pid))]
    async fn adopt(&self, id: &VmId, pid: u32) -> hypervisor::Result<()> {
        self.adopt_vm(id, pid).await
    }

    #[instrument(level = "trace", skip_all, fields(vm_id = %id))]
    async fn probe(&self, id: &VmId) -> bool {
        self.api(id, Method::GET, "vmm.ping", None).await.is_ok()
    }

    fn is_tracked(&self, id: &VmId) -> bool {
        self.vms.lock().unwrap().contains_key(id)
    }

    async fn strays(&self, known: &[VmId]) -> Vec<VmId> {
        self.stray_vms(known).await
    }

    #[instrument(skip_all, fields(vm_id = %id))]
    async fn end_stray(&self, id: &VmId) -> hypervisor::Result<()> {
        self.end_stray_vm(id).await
    }

    /// `<binary> --version`, asked once at start-up.
    ///
    /// A subprocess, and the only one this driver runs that is not a VMM —
    /// which is affordable because it happens once per agent and answers a
    /// question nothing else can: a v53 and a v54 look identical in every
    /// other field of a machine profile, and a saved state does not
    /// necessarily cross between them.
    ///
    /// Every failure is `None`: a binary that is not there yet is a node with
    /// no hypervisor, which the catalogue says at length elsewhere, and an
    /// agent must not refuse to start over a version string.
    async fn version(&self) -> Option<String> {
        let out = Command::new(&self.binary)
            .arg("--version")
            .stdin(Stdio::null())
            .output()
            .await
            .ok()?;
        let said = String::from_utf8_lossy(&out.stdout);
        let line = said.lines().next().unwrap_or_default().trim();
        (!line.is_empty()).then(|| line.to_string())
    }

    /// v53's `CpuProfile` has one variant. See the trait.
    fn cpu_profile(&self) -> &'static str {
        "Host"
    }

    fn as_pausable(&self) -> Option<&dyn Pausable> {
        Some(self)
    }

    fn as_migratable(&self) -> Option<&dyn agent_api::Migratable> {
        Some(self)
    }

    fn as_hotpluggable(&self) -> Option<&dyn HotPluggable> {
        Some(self)
    }
}

#[async_trait::async_trait]
impl HotPluggable for CloudHypervisorDriver {
    /// `vm.add-disk` with the same body one entry of `disks` carries at
    /// create — the id included, which is what makes the disk removable and
    /// resizable afterwards by a name this stack chose.
    ///
    /// A share is refused rather than silently ignored: virtio-fs has its own
    /// verb (`vm.add-fs`), and a caller who plugged a share and got a
    /// successful "nothing happened" would have a VM whose record says a
    /// mount is there and a guest that never sees one.
    #[instrument(skip_all, fields(vm_id = %id, disk = %volume.disk_id()))]
    async fn add_disk(&self, id: &VmId, volume: &AttachedVolume) -> hypervisor::Result<()> {
        self.vm_known(id)?;
        let config = disk_config(volume).ok_or_else(|| {
            HypervisorError::InvalidSpec(format!(
                "volume {} is a filesystem share, not a disk; it cannot be hot-plugged",
                volume.id
            ))
        })?;
        self.api(id, Method::PUT, "vm.add-disk", Some(config))
            .await
            .map(|_| ())
    }

    /// `vm.resize-disk` by the id the disk was given, with the size the
    /// BACKEND has already grown to.
    ///
    /// The order is not symmetric and not reversible — see the trait. For a
    /// block device this call is a check rather than a change, and its
    /// failure message ("Block device size X does not match requested size
    /// Y") is exactly the sentence an operator needs when the two halves have
    /// come apart.
    #[instrument(skip_all, fields(vm_id = %id, disk = %disk_id, size_bytes))]
    async fn resize_disk(
        &self,
        id: &VmId,
        disk_id: &str,
        size_bytes: u64,
    ) -> hypervisor::Result<()> {
        self.vm_known(id)?;
        self.api(
            id,
            Method::PUT,
            "vm.resize-disk",
            Some(serde_json::json!({ "id": disk_id, "desired_size": size_bytes })),
        )
        .await
        .map(|_| ())
    }

    /// `vm.remove-device` by the id `add_disk` (or `create`) gave the disk,
    /// and then the evidence that it is really gone.
    ///
    /// Not idempotent at this level and deliberately not made to look it: CH
    /// answers 404 for a disk it does not have, and a driver that swallowed
    /// that would turn "the guest still holds it" into "done".
    ///
    /// **The 200 is not the answer, and neither is `vm.info`.** virtio
    /// hot-unplug is cooperative: v53 signals the guest and returns, and a
    /// guest that does not acknowledge — a kernel without the driver, a
    /// device with a mount on it, a guest that is simply busy — keeps the
    /// device and the VMM keeps the file open. The chaos run measured exactly
    /// that: the control plane reported the volume free within two seconds,
    /// the fd was still on `/proc/<vmm>/fd` a minute later, and the next VM
    /// to use the volume died on cloud hypervisor's own write lock with "The
    /// file is already locked" — reported to the operator as a scheduling
    /// problem.
    ///
    /// The first repair asked `vm.info` until the disk left `config.disks`,
    /// and the lab showed that to be no witness at all: the config is what
    /// the VMM INTENDS, and it drops the disk the moment it accepts the
    /// request — 774 µs after the call, with the fd still open sixty seconds
    /// later (struktur 4, M2). What the guest has actually done shows in one
    /// place only, the VMM's own fd table, so that is what is asked, by the
    /// disk's path, until it no longer names the file. The config is still
    /// read, because a VMM that still LISTS the disk has not even been asked
    /// yet. The caller detaches the backend after this returns, which is the
    /// ordering that must not be reversed.
    ///
    /// A disk without a path to ask about — a vhost-user disk holds a socket,
    /// not the file — falls back to the config, which is the weaker witness
    /// and says so in the log.
    #[instrument(skip_all, fields(vm_id = %id, disk = %disk_id))]
    async fn remove_disk(&self, id: &VmId, disk_id: &str) -> hypervisor::Result<()> {
        self.vm_known(id)?;
        // The path first, while the config still names it (see `unplugging`).
        let key = (*id, disk_id.to_string());
        let path = match self.disk_path(id, disk_id).await? {
            Some(path) => {
                self.unplugging
                    .lock()
                    .unwrap()
                    .insert(key.clone(), path.clone());
                Some(path)
            }
            None => self.unplugging.lock().unwrap().get(&key).cloned(),
        };
        match self
            .api(
                id,
                Method::PUT,
                "vm.remove-device",
                Some(serde_json::json!({ "id": disk_id })),
            )
            .await
        {
            Ok(_) => {}
            // 404 is CH saying the disk is not in its config any more — which
            // is exactly what an earlier pass's request leaves behind while
            // the guest is still thinking. With a path to ask about, the fd
            // table decides whether that is "done" or "still held"; without
            // one it stays the error it always was, because a driver that
            // swallowed it would turn "the guest still holds it" into "done".
            Err(e) if path.is_some() && is_not_found(&e) => {
                debug!("the vmm has already been asked; waiting on the fd");
            }
            Err(e) => return Err(e),
        }
        let pid = self.pid_of(id);
        let witness = path.as_deref().zip(pid);
        if witness.is_none() {
            warn!(
                path = path.is_some(),
                pid = pid.is_some(),
                "no fd witness for this disk; trusting the vmm's config, which is weaker"
            );
        }
        until_the_disk_is_gone(
            disk_id,
            || async {
                let bytes = self.api(id, Method::GET, "vm.info", None).await?;
                serde_json::from_slice(&bytes).map_err(|e| HypervisorError::Backend(e.into()))
            },
            || match witness {
                Some((path, pid)) => vmm_holds(pid, path).map(Some),
                None => Ok(None),
            },
            self.unplug_timeout,
            UNPLUG_POLL,
        )
        .await?;
        self.unplugging.lock().unwrap().remove(&key);
        Ok(())
    }
}

#[async_trait::async_trait]
impl Pausable for CloudHypervisorDriver {
    #[instrument(skip_all, fields(vm_id = %id))]
    async fn pause(&self, id: &VmId) -> hypervisor::Result<()> {
        self.vm_known(id)?;
        self.api(id, Method::PUT, "vm.pause", None)
            .await
            .map(|_| ())
    }

    #[instrument(skip_all, fields(vm_id = %id))]
    async fn resume(&self, id: &VmId) -> hypervisor::Result<()> {
        self.vm_known(id)?;
        self.api(id, Method::PUT, "vm.resume", None)
            .await
            .map(|_| ())
    }
}

#[async_trait::async_trait]
impl agent_api::Migratable for CloudHypervisorDriver {
    /// Make this machine ready to receive `id`, and return once it is
    /// listening.
    ///
    /// `peer` is where to listen, in cloud hypervisor's own spelling:
    /// `tcp:<addr>:<port>` — a bare `tcp:` prefix and not `tcp://`, which is
    /// what v53's `strip_prefix("tcp:")` accepts and nothing else.
    ///
    /// **No `vm.create` here, and that is not an oversight.** The brief asked
    /// for the VM to be made at the destination with the same config; v53
    /// refuses exactly that — `vm_receive_migration` answers "Can't receive a
    /// migration when a VM is already created" — and builds the destination's
    /// VM from a `VmMigrationConfig` that travels in the stream. What the
    /// destination DOES have to have ready is everything the arriving config
    /// NAMES: the tap devices, the disk files, the same paths. Those are the
    /// agent's to make, and it makes them before calling this.
    ///
    /// The call blocks the VMM's whole API until the migration is over, so it
    /// is issued into a task and this returns when the listener is up. Which
    /// is knowable: `migration-receive-ready` is written to the event file
    /// just before the accept.
    ///
    /// # The guest's two output devices, and why they cannot be pointed
    ///
    /// They travel in the config and this side has no say in it. v53's
    /// `vm_receive_config` does `self.vm_config = Some(received)` — the
    /// destination's own config, if it had one, is thrown away with a
    /// warning — and then calls `pre_create_console_devices` on the received
    /// one straight away. `VmReceiveMigrationData` carries a receiver URL, a
    /// TLS directory and a memory mode, and nothing else; there is no
    /// endpoint in the whole of v53's route table that re-points a console or
    /// a serial line afterwards. So neither half of the question the first
    /// migration run left open can be answered yes: the destination cannot
    /// set the paths before, and cannot change them after.
    ///
    /// What follows from that is a REQUIREMENT rather than a workaround, and
    /// it is the same one the disks and the kernel already impose: both nodes
    /// must have the same `run_dir`, so that the paths in the arriving config
    /// name this node's own files. On a fleet that is how the agent is
    /// deployed and nothing has to be done. Two agents on ONE machine
    /// sharing a run_dir is a different thing and it does not work — see the
    /// unlink below and the report.
    ///
    /// The two devices then behave differently, and only one of them needs
    /// anything done about it:
    ///
    ///   * `console` is `mode: File`, and v53 opens it with `File::create` —
    ///     which truncates. The destination's own file, on its own node, is
    ///     empty anyway, so nothing is lost. Output written on the SOURCE
    ///     stays in the source's file and does not follow the guest, which is
    ///     honest: it happened there.
    /// # The guest announcing itself, and why nothing here does it
    ///
    /// A guest that has moved is behind a different switch port, and until
    /// something is sent from its MAC every switch on the segment forwards
    /// its traffic to the machine it left. Somebody has to make it talk.
    ///
    /// **v53 already does, and it is the only component that can.** On every
    /// restore — a migration included — `Net::new` sets the announcement
    /// pending (`virtio-devices/src/net.rs:555-565`, "Always mark the
    /// announcement pending if the device was restored so the device
    /// announces itself"), and the announcer then does two things:
    /// `build_rarp_announce` (`net.rs:784`) writes a broadcast RARP frame
    /// with the guest's MAC as source straight into the tap, and
    /// `VIRTIO_NET_F_GUEST_ANNOUNCE` asks the guest to announce itself as
    /// well. Both are retried.
    ///
    /// An agent could not do the first half if it wanted to. The frame has to
    /// enter the bridge as if it came FROM the guest, which means writing to
    /// the tap's character device — and that file descriptor belongs to the
    /// VMM. An `AF_PACKET` socket on the tap interface sends the other way,
    /// towards the guest, and would announce nothing to any switch.
    ///
    /// RARP and not a gratuitous ARP, and that is the right choice rather
    /// than a lesser one: a switch learns a port from the SOURCE MAC of any
    /// frame, so an announcement needs no IP address — which is as well,
    /// because the host does not know the guest's. It is what QEMU has always
    /// sent for the same reason.
    ///
    ///   * `serial` is `mode: Socket`, and v53 does a bare `UnixListener::bind`
    ///     with no unlink first. A path with a file at it fails with
    ///     `EADDRINUSE`, and that failure happens inside `vm_receive_config`,
    ///     which aborts the whole migration after the source has already
    ///     connected. So the leftover is removed here, exactly as `create`
    ///     removes it for a boot, and for the same reason.
    #[instrument(skip_all, fields(vm_id = %id, peer = %peer))]
    async fn migrate_in(&self, id: &VmId, peer: &str) -> hypervisor::Result<u32> {
        self.receive_migration(id, peer).await
    }

    /// What the event file says about a receive that did not happen.
    ///
    /// The event file and not the api socket, and the difference is the whole
    /// of why this method exists. A failed receive leaves v53 with a VMM that
    /// answers, a `vm.info` that says `Created`, and no guest — which from
    /// the outside is the same picture as a VMM that is still waiting for
    /// one. `migration-receive-failed` is the only place the two are told
    /// apart, and it is written once and stays written.
    fn receive_failed(&self, id: &VmId) -> Option<String> {
        self.receive_failure(id)
    }

    /// Whether this VMM is serving its guest again, which after a send has
    /// been started can only mean the send failed.
    ///
    /// **v53 writes no event for a send.** The event monitor carries
    /// `migration-receive-ready`, `-started`, `-finished` and `-failed` and
    /// nothing at all for the other end (`vmm/src/lib.rs`), so there is no
    /// file to read here and the question has to be put to the VMM itself.
    ///
    /// What it is asked is `vm.counters`, and the choice is about what the
    /// answer MEANS rather than about the counters. While a send runs, the
    /// VMM has handed its VM to the migration worker
    /// (`VmOwnership::Migration`) and every verb that wants the VM answers
    /// "VM is currently migrating and can't be modified"; when the worker
    /// joins, a failure gives the VM back (`VmOwnership::Owned`, the guest
    /// resumed) and a success shuts the guest down and exits the process. So
    /// an ANSWER to this question is a guest that is here again — and a
    /// success is not a race with it, because a VMM that succeeded is not
    /// answering anything.
    ///
    /// `vm.counters` and not `vm.info`, which is the trap next door: v53
    /// answers `vm.info` during a migration out of a snapshot taken before
    /// it started, so it says `Running` throughout and says it afterwards
    /// too. A read-only verb that REFUSES while migrating is the only shape
    /// that distinguishes the two.
    ///
    /// Every other error is `None` and not a failure. An answer this driver
    /// cannot read must not be able to declare a running transfer dead; the
    /// cost of being conservative here is that such a node waits out
    /// the agent's own migrate-out ceiling, which is what it did before this
    /// existed.
    async fn send_failed(&self, id: &VmId) -> Option<String> {
        match self.api(id, Method::GET, "vm.counters", None).await {
            Ok(_) => Some(
                "cloud-hypervisor is serving the guest here again, so the transfer ended \
                 without it leaving"
                    .to_string(),
            ),
            Err(_) => None,
        }
    }

    /// Send this VM to `peer`, which is the address the destination answered
    /// with — `tcp:<addr>:<port>`, the same spelling.
    ///
    /// **204 means "started", not "done".** v53 spawns a worker and answers
    /// at once; what happens afterwards is not on this connection. On success
    /// the source VM is shut down and the source VMM process EXITS, so the
    /// api socket simply stops answering — which is what the agent sees as
    /// the VM going away. On failure the VM is resumed here and goes on
    /// running, which is the invariant the tier above is built on: the source
    /// is never given up before the destination has the guest.
    ///
    /// There is **no TLS on this stream** in v1. It is a deliberate limit and
    /// it is written down in the reference: the migration rides the cluster
    /// network, the same one the session rode without TLS until the image
    /// round gave it PKI, and adding `tls_dir` here means a second certificate
    /// distribution problem with no client for it yet.
    #[instrument(skip_all, fields(vm_id = %id, peer = %peer))]
    async fn migrate_out(&self, id: &VmId, peer: &str) -> hypervisor::Result<()> {
        self.vm_known(id)?;
        self.api(
            id,
            Method::PUT,
            "vm.send-migration",
            Some(serde_json::json!({ "destination_url": peer })),
        )
        .await
        .map(|_| ())
    }
}

/// Whether a `ch_api` error was cloud hypervisor answering 404 — the shape
/// `api()` gives it is "ch <endpoint> -> 404 Not Found: ...".
fn is_not_found(e: &HypervisorError) -> bool {
    format!("{e}").contains("-> 404")
}

#[cfg(test)]
mod tests;
