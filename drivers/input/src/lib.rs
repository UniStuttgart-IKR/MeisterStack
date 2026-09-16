// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Device driver for Leandro's vhost-user-input backend (virtio-input).
//!
//! cloud-hypervisor has no virtio-input device of its own, so a guest that
//! needs a keyboard or a mouse gets one from outside: `vhost-user-input`
//! serves the device over a unix socket and CH attaches it through its
//! generic vhost-user device. That is the same shape `nvrm` has, and this
//! driver is deliberately the smaller sibling of it — one process, one
//! socket, one source.
//!
//! The source is what the two profiles are about:
//!
//! * `fifo` makes a named pipe next to the socket and reads `type code value`
//!   lines from it. It is what makes the input path testable at all — a gate
//!   presses a key with `printf`, and no human and no host device is
//!   involved.
//! * `evdev` forwards a host input node (`/dev/input/eventN`) verbatim. The
//!   VM then eats the events of whoever is sitting at the machine, which is
//!   why the node has to be named explicitly and is never a default — and why
//!   one node is admitted to one guest at a time (`admit`).
//!
//! One backend serves exactly one VM and is never reused. Unlike
//! `vhost-user-nvrm` this one does NOT end itself when the VMM hangs up
//! (`Leandro/scripts/lib/rig.sh:567` counted seven orphans from that, the
//! oldest four hours old), so teardown here is the only thing that ever
//! collects it.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use agent_api::CgroupHandle;
use agent_api::device::{
    self, Device, DeviceAttachment, DeviceDriver, DeviceError, DeviceId, DeviceSpec, PartitionSpec,
};
use backend::{Backend, BackendIo, BackendKind};
use tokio::sync::Mutex;
use tracing::{debug, info, instrument};

/// VIRTIO_ID_INPUT, the device id the guest's `virtio_input` module binds to.
/// The same number cloud-hypervisor's CLI means by `device_type=input`.
const VIRTIO_ID_INPUT: u32 = 18;

/// eventq (host→guest) and statusq (guest→host), both 256 — what Leandro's
/// rig passes and what the guest module expects to find. A single queue would
/// leave the device without its event ring.
const INPUT_QUEUE_SIZES: [u16; 2] = [256, 256];

/// `RLIMIT_NOFILE` for one backend. Three descriptors do the work — the
/// listening socket, the source, the epoll — plus one per guest memory
/// region, so the ordinary default is already generous. It is set anyway, and
/// set as the HARD limit too, because that is the honest ceiling for a
/// process that serves one keyboard: nothing here should be able to raise
/// itself past it. (nvrm needs 65536 for the opposite reason — one host fd
/// per guest RM client.)
const NOFILE_LIMIT: u64 = 1024;

/// The profile that reads `type code value` lines from a named pipe.
pub const PROFILE_FIFO: &str = "fifo";
/// The profile that forwards a host `/dev/input/eventN`.
pub const PROFILE_EVDEV: &str = "evdev";

/// How long the driver waits for a freshly spawned backend to answer on its
/// socket. The agent's config takes this as its default, so the number lives
/// with the process it is about rather than in the config that names it.
pub const DEFAULT_SOCKET_TIMEOUT_MS: u64 = 5000;

/// Per-device tunables, from `spec.params`.
///
/// Two fields and no merge ladder, unlike nvrm's: there is nothing here a
/// node would want to preset. `evdev` names one specific host node and is
/// meaningless as a default; `name` is what one guest reads back.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputParams {
    /// The host input node to forward, for the `evdev` profile. Required
    /// there and refused everywhere else.
    pub evdev: Option<PathBuf>,
    /// What the guest reads back as the device's name
    /// (`/sys/class/input/inputN/name`). Unset leaves the backend's own.
    pub name: Option<String>,
}

pub struct InputDriverConfig {
    pub binary: PathBuf,
    pub run_dir: PathBuf,
    pub socket_timeout: Duration,
    /// Who the backend runs as. `None` is the agent, which is every node that
    /// has ever run this; `Some` is Stufe 3, where the backend is
    /// unprivileged alongside the VMM because vhost-user is not a boundary
    /// between them.
    pub vmm_user: Option<agent_api::VmmUser>,
}

/// Where one backend's events come from — the resolved profile.
#[derive(Clone, Debug, PartialEq)]
enum Source {
    /// The named pipe this driver makes, under its own run directory.
    Fifo(PathBuf),
    /// A host node this driver did not make and must not remove.
    Evdev(PathBuf),
}

impl Source {
    /// The argument pair the backend takes for this source. Leandro's
    /// `crates/vhost-user-input/src/main.rs` accepts exactly `--evdev` and
    /// `--fifo`, and exactly one of them.
    fn arg(&self) -> (&'static str, &Path) {
        match self {
            Source::Fifo(p) => ("--fifo", p),
            Source::Evdev(p) => ("--evdev", p),
        }
    }
}

pub struct InputDriver {
    config: InputDriverConfig,
    /// One backend serves one VM, in a session of its own, and is signalled
    /// as a process GROUP. See `BackendKind::detached`.
    process: BackendKind,
    active: Mutex<HashMap<DeviceId, Backend>>,
}

impl InputDriver {
    pub fn new(config: InputDriverConfig) -> device::Result<Self> {
        std::fs::create_dir_all(&config.run_dir).map_err(|e| DeviceError::Backend(e.into()))?;
        if !config.binary.exists() {
            return Err(DeviceError::Backend(anyhow::anyhow!(
                "vhost-user-input binary not found at {}",
                config.binary.display()
            )));
        }
        Ok(Self {
            // The name is the backend's own and not the configured binary's:
            // `comm` is what the process calls itself, whatever a node has
            // called the file it lives in.
            process: BackendKind::detached("vhost-user-input", "vhost-user-input", NOFILE_LIMIT)
                .as_user(config.vmm_user.clone()),
            config,
            active: Mutex::new(HashMap::new()),
        })
    }

    /// Unique and stable per device for its whole lifetime: it is also what
    /// tells one backend from its siblings after an agent restart, see
    /// `BackendKind::is_ours`.
    fn socket_path(&self, id: &DeviceId) -> PathBuf {
        self.config.run_dir.join(format!("{id}.sock"))
    }

    fn fifo_path(&self, id: &DeviceId) -> PathBuf {
        self.config.run_dir.join(format!("{id}.fifo"))
    }

    fn log_path(&self, id: &DeviceId) -> PathBuf {
        self.config.run_dir.join(format!("{id}.log"))
    }

    /// Which source this spec asks for and what else it says, refused with a
    /// sentence when the profile and the params do not agree.
    ///
    /// No profile resolves to `fifo`, and that is the catalogue's own rule
    /// rather than an invention here: a request that names no profile is
    /// answered by any profile of the driver and "the node picks in that
    /// case" (`common::capability::offers`). `fifo` is the only pick a node
    /// may make unasked — `evdev` would hand the guest a device belonging to
    /// whoever is sitting at the machine.
    fn plan(&self, id: &DeviceId, spec: &DeviceSpec) -> device::Result<(Source, InputParams)> {
        let params: InputParams = match &spec.params {
            Some(params) => serde_json::from_value(params.clone())
                .map_err(|e| DeviceError::InvalidSpec(format!("invalid input params: {e}")))?,
            None => InputParams::default(),
        };
        let source = self.source(id, spec.profile.as_deref(), &params)?;
        Ok((source, params))
    }

    fn source(
        &self,
        id: &DeviceId,
        profile: Option<&str>,
        params: &InputParams,
    ) -> device::Result<Source> {
        match profile.unwrap_or(PROFILE_FIFO) {
            PROFILE_FIFO => {
                // Silently ignoring it would be worse: somebody who names a
                // host node means it, and a fifo device would look like it
                // had been honoured.
                if let Some(evdev) = &params.evdev {
                    return Err(DeviceError::InvalidSpec(format!(
                        "the {PROFILE_FIFO:?} profile reads a named pipe, so params.evdev \
                         ({}) has nothing to do; ask for the {PROFILE_EVDEV:?} profile",
                        evdev.display()
                    )));
                }
                Ok(Source::Fifo(self.fifo_path(id)))
            }
            PROFILE_EVDEV => {
                let evdev = params.evdev.clone().ok_or_else(|| {
                    DeviceError::InvalidSpec(format!(
                        "the {PROFILE_EVDEV:?} profile forwards one host input device and \
                         params.evdev must name it (e.g. \"/dev/input/event0\")"
                    ))
                })?;
                // Fail here rather than in a log tail: a path that is not
                // there is a spec somebody has to fix, and the backend's own
                // refusal would arrive as a dead process.
                if !evdev.exists() {
                    return Err(DeviceError::InvalidSpec(format!(
                        "params.evdev {} does not exist on this node",
                        evdev.display()
                    )));
                }
                Ok(Source::Evdev(evdev))
            }
            other => Err(DeviceError::InvalidSpec(format!(
                "unknown input profile {other:?}; this driver serves \
                 [{PROFILE_FIFO}, {PROFILE_EVDEV}]"
            ))),
        }
    }

    /// The host node this spec CLAIMS, or None for a spec that claims none.
    ///
    /// Only the `evdev` profile claims anything: a `fifo` device's source is
    /// a file this driver makes under its own run directory, named after the
    /// device's own uuid, so two of them cannot be the same file.
    ///
    /// Deliberately not validating: a spec that is malformed, or that names
    /// no node at all, cannot be in conflict over one, and `create` is where
    /// its sentence lives (`source`). Admission that also validated would
    /// answer a broken spec with the wrong complaint — and it is asked about
    /// OTHER VMs' specs too, where a refusal would be about somebody else's
    /// mistake.
    fn claimed_node(spec: &DeviceSpec) -> Option<PathBuf> {
        if spec.profile.as_deref().unwrap_or(PROFILE_FIFO) != PROFILE_EVDEV {
            return None;
        }
        let params: InputParams = serde_json::from_value(spec.params.clone()?).ok()?;
        params.evdev
    }

    fn attachment(socket: PathBuf, pid: u32) -> DeviceAttachment {
        DeviceAttachment::VhostUser {
            socket,
            pid,
            device_type: VIRTIO_ID_INPUT,
            queue_sizes: INPUT_QUEUE_SIZES.to_vec(),
        }
    }
}

/// Make the named pipe the `fifo` profile reads, replacing whatever is there.
///
/// The backend would `mkfifo` it too, but only once it gets round to opening
/// its source — and everything that writes into the pipe is on the other side
/// of that race, so a gate's first `printf` would find no such file. The
/// driver owns the file either way, because teardown has to take it away: a
/// named pipe whose reader is gone is worse than no pipe at all, a writer
/// blocks on it forever instead of failing.
/// `user` is who will READ it. The two ends of this pipe are not the same
/// process and stopped being the same user in Stufe 3: the backend reads it,
/// the agent (or whoever writes through the agent) writes it. So it is the
/// backend's file, `0660`, and the writing side reaches it by being root or
/// by being in the backend's group.
fn make_fifo(path: &Path, user: Option<&agent_api::VmmUser>) -> device::Result<()> {
    // A leftover from a killed run may be anything by now — a regular file
    // somebody's stray redirect made, a pipe with no reader. Replace it.
    let _ = std::fs::remove_file(path);
    let mode = match user {
        Some(_) => 0o660,
        None => 0o600,
    };
    nix::unistd::mkfifo(path, nix::sys::stat::Mode::from_bits_truncate(mode))
        .map_err(|e| DeviceError::Backend(anyhow::anyhow!("mkfifo {}: {e}", path.display())))?;
    if let Some(user) = user {
        user.take(path).map_err(|e| {
            DeviceError::Backend(anyhow::anyhow!("giving {} to {user}: {e}", path.display()))
        })?;
    }
    Ok(())
}

#[async_trait::async_trait]
impl DeviceDriver for InputDriver {
    #[instrument(skip_all, fields(device_id = %id))]
    async fn create(
        &self,
        id: &DeviceId,
        spec: &DeviceSpec,
        cgroup: Option<&CgroupHandle>,
    ) -> device::Result<Device> {
        if spec.partition != PartitionSpec::Mediated {
            return Err(DeviceError::InvalidSpec(format!(
                "input driver only supports Mediated, got {:?}",
                spec.partition
            )));
        }

        let socket = self.socket_path(id);
        {
            let mut active = self.active.lock().await;
            if let Some(running) = active.get_mut(id) {
                if running.is_reusable(&socket) {
                    let pid = running.pid().unwrap_or(0);
                    return Ok(Device {
                        id: *id,
                        attachment: Self::attachment(socket, pid),
                    });
                }
                // A dead backend is not handed back: it is replaced.
                active.remove(id);
            }
        }

        let (source, params) = self.plan(id, spec)?;
        if let Source::Fifo(path) = &source {
            make_fifo(path, self.config.vmm_user.as_ref())?;
        }

        let (flag, path) = source.arg();
        debug!(
            profile = spec.profile.as_deref().unwrap_or(PROFILE_FIFO),
            source = %path.display(),
            "starting vhost-user-input backend"
        );

        let mut cmd = tokio::process::Command::new(&self.config.binary);
        cmd.arg("--socket")
            .arg(&socket)
            .arg(flag)
            .arg(path)
            // A backend inherits nothing but the two variables it may need to
            // find itself: everything else in the agent's environment is the
            // agent's business.
            .env_clear()
            .envs(std::env::vars().filter(|(k, _)| k == "PATH" || k == "HOME"));
        if let Some(name) = &params.name {
            cmd.arg("--name").arg(name);
        }

        // The backend must be listening before cloud-hypervisor connects.
        let (pid, child) = self
            .process
            .spawn(
                cmd,
                BackendIo {
                    socket: &socket,
                    log: &self.log_path(id),
                    timeout: self.config.socket_timeout,
                    cgroup,
                    span: tracing::info_span!("backend_spawn", driver = "input", device_id = %id),
                },
            )
            .await?;
        info!(pid, source = %path.display(), "input backend ready");

        self.active.lock().await.insert(*id, child);

        Ok(Device {
            id: *id,
            attachment: Self::attachment(socket, pid),
        })
    }

    #[instrument(skip_all, fields(device_id = %id))]
    async fn destroy(&self, id: &DeviceId, attachment: &DeviceAttachment) -> device::Result<()> {
        let entry = self.active.lock().await.remove(id);

        match entry {
            Some(child) => self.process.stop(child).await,
            // Not our child: the agent restarted since create, and the
            // record's pid is the only handle left on the backend. Leaving it
            // is not an option — this one does not end itself when the VMM
            // goes away.
            None => {
                if let DeviceAttachment::VhostUser { socket, pid, .. } = attachment {
                    self.process.stop_adopted(*pid, socket);
                }
            }
        }

        // The fifo goes with the socket even under the evdev profile, where
        // there is none: teardown is idempotent and a file that was never
        // there is a file removed. The host node an evdev device forwarded is
        // NOT in this list — it is not ours.
        for p in [self.socket_path(id), self.fifo_path(id), self.log_path(id)] {
            backend::remove_if_present(&p)
                .await
                .map_err(|e| DeviceError::Backend(e.into()))?;
        }
        Ok(())
    }

    #[instrument(level = "trace", skip_all, fields(device_id = %id))]
    async fn get(&self, id: &DeviceId, attachment: &DeviceAttachment) -> device::Result<Device> {
        let DeviceAttachment::VhostUser { socket, pid, .. } = attachment else {
            return Err(DeviceError::NotFound(*id));
        };
        // Liveness by pid and by IDENTITY, for the reason nvrm's `get` spells
        // out: after an agent restart the recorded pid may have been
        // recycled, and reporting a stranger's process as this device would
        // leave a VM in the inventory with a dead backend. `is_ours` checks
        // this kind's `comm` AND this device's socket on the command line,
        // and a dead pid has neither to read.
        if !self.process.is_ours(*pid, socket) {
            return Err(DeviceError::NotFound(*id));
        }
        Ok(Device {
            id: *id,
            attachment: attachment.clone(),
        })
    }

    /// Fixed, unlike nvrm's: these are the backend's two sources and not a
    /// node's configuration. A node with the driver serves both, and says so
    /// as `input/fifo` and `input/evdev`.
    fn profiles(&self) -> Vec<String> {
        vec![PROFILE_FIFO.to_string(), PROFILE_EVDEV.to_string()]
    }

    /// A host input node belongs to ONE guest at a time.
    ///
    /// Two backends on one `/dev/input/eventN` both open it and both read
    /// from it, and evdev hands each event to whichever reader takes it — so
    /// a keypress goes to one of the two guests and nobody can say which.
    /// That is not sharing, it is a coin toss, and neither guest's operator
    /// asked for one. The `fifo` profile has no such question: its source is
    /// this driver's own file, named after the device's uuid.
    ///
    /// Over what is DECLARED and not over what is running, which is what the
    /// trait asks of this method and what makes it survive an agent restart:
    /// the specs come from the caller's store, so a VM that was torn down has
    /// no record, holds no claim, and the node is free again — without this
    /// driver having to remember anything across its own lifetime.
    fn admit(
        &self,
        requested: &[(DeviceId, DeviceSpec)],
        claimed: &[(agent_api::VmId, DeviceSpec)],
    ) -> device::Result<()> {
        for (index, (id, spec)) in requested.iter().enumerate() {
            let Some(node) = Self::claimed_node(spec) else {
                continue;
            };

            // Somebody else's guest first: that is the case the operator
            // cannot see from their own spec, so the message has to name the
            // vm that holds it.
            if let Some((holder, _)) = claimed
                .iter()
                .find(|(_, held)| Self::claimed_node(held).as_deref() == Some(node.as_path()))
            {
                return Err(DeviceError::InvalidSpec(format!(
                    "host input device {} is already claimed by vm {holder} on this node; \
                     one evdev node belongs to one guest at a time (device {id})",
                    node.display()
                )));
            }

            // And the same spec asking for it twice, which is the same
            // conflict with both halves in one hand. Only the devices BEFORE
            // this one are compared, so the pair is reported once.
            if let Some((twin, _)) = requested[..index]
                .iter()
                .find(|(_, other)| Self::claimed_node(other).as_deref() == Some(node.as_path()))
            {
                return Err(DeviceError::InvalidSpec(format!(
                    "host input device {} is named twice by this vm, by device {twin} and \
                     by device {id}; one evdev node belongs to one guest at a time",
                    node.display()
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn driver(run_dir: &Path) -> InputDriver {
        InputDriver {
            config: InputDriverConfig {
                binary: PathBuf::from("/nonexistent/vhost-user-input"),
                run_dir: run_dir.to_path_buf(),
                socket_timeout: Duration::from_millis(1),
                vmm_user: None,
            },
            process: BackendKind::detached("vhost-user-input", "vhost-user-input", NOFILE_LIMIT),
            active: Mutex::new(HashMap::new()),
        }
    }

    fn spec(profile: Option<&str>, params: Option<serde_json::Value>) -> DeviceSpec {
        DeviceSpec {
            driver: "input".into(),
            partition: PartitionSpec::Mediated,
            profile: profile.map(str::to_string),
            params,
        }
    }

    fn evdev_spec(node: &str) -> DeviceSpec {
        spec(
            Some(PROFILE_EVDEV),
            Some(serde_json::json!({ "evdev": node })),
        )
    }

    /// The claim a spec makes, which is the whole input to admission. A fifo
    /// device claims nothing at all — its source is this driver's own file.
    #[test]
    fn only_an_evdev_spec_claims_a_host_node() {
        assert_eq!(
            InputDriver::claimed_node(&evdev_spec("/dev/input/event0")),
            Some(PathBuf::from("/dev/input/event0"))
        );
        assert_eq!(
            InputDriver::claimed_node(&spec(Some(PROFILE_FIFO), None)),
            None
        );
        assert_eq!(InputDriver::claimed_node(&spec(None, None)), None);
        // An evdev spec that names nothing claims nothing: it cannot be in
        // conflict over a node, and `create` is where its sentence lives.
        assert_eq!(
            InputDriver::claimed_node(&spec(Some(PROFILE_EVDEV), None)),
            None
        );
    }

    /// Two guests on one `/dev/input/eventN` is a coin toss over every
    /// keypress, so the second one is refused — and the message has to name
    /// both the node and the vm that holds it, because the operator of the
    /// second guest can see neither from their own spec.
    #[test]
    fn a_host_node_already_held_by_another_vm_is_refused_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let d = driver(dir.path());
        let holder = agent_api::VmId::new_v4();
        let wanted = DeviceId::new_v4();

        let err = d
            .admit(
                &[(wanted, evdev_spec("/dev/input/event0"))],
                &[(holder, evdev_spec("/dev/input/event0"))],
            )
            .expect_err("the node is taken");
        let msg = err.to_string();
        assert!(msg.contains("/dev/input/event0"), "{msg}");
        assert!(msg.contains(&holder.to_string()), "{msg}");
        assert!(msg.contains(&wanted.to_string()), "{msg}");

        // Another node on the same node is not a conflict, and neither is
        // another vm's fifo device.
        d.admit(
            &[(wanted, evdev_spec("/dev/input/event1"))],
            &[(holder, evdev_spec("/dev/input/event0"))],
        )
        .expect("two different host devices are two different claims");
        d.admit(
            &[(wanted, evdev_spec("/dev/input/event0"))],
            &[(holder, spec(Some(PROFILE_FIFO), None))],
        )
        .expect("a fifo device holds no host node");
    }

    /// The claim travels with the RECORD, which is what makes a teardown give
    /// the node back: the caller reads the store, a vm that is gone is not in
    /// it, and this driver has to remember nothing across its own lifetime.
    #[test]
    fn a_node_nobody_holds_any_more_is_free_again() {
        let dir = tempfile::tempdir().unwrap();
        let d = driver(dir.path());
        let wanted = DeviceId::new_v4();
        d.admit(&[(wanted, evdev_spec("/dev/input/event0"))], &[])
            .expect("nothing holds it");
    }

    /// The same conflict with both halves in one hand.
    #[test]
    fn one_vm_naming_a_host_node_twice_is_the_same_conflict() {
        let dir = tempfile::tempdir().unwrap();
        let d = driver(dir.path());
        let first = DeviceId::new_v4();
        let second = DeviceId::new_v4();

        let err = d
            .admit(
                &[
                    (first, evdev_spec("/dev/input/event0")),
                    (second, evdev_spec("/dev/input/event0")),
                ],
                &[],
            )
            .expect_err("one node, two devices of one vm");
        let msg = err.to_string();
        assert!(msg.contains("named twice"), "{msg}");
        assert!(
            msg.contains(&first.to_string()) && msg.contains(&second.to_string()),
            "{msg}"
        );

        // Two fifo devices in one vm are fine and always were: each gets its
        // own pipe, named after its own uuid.
        d.admit(
            &[
                (first, spec(Some(PROFILE_FIFO), None)),
                (second, spec(Some(PROFILE_FIFO), None)),
            ],
            &[],
        )
        .expect("two pipes are two files");
    }

    #[test]
    fn the_fifo_lives_beside_the_socket_and_carries_the_device_id() {
        let dir = tempfile::tempdir().unwrap();
        let d = driver(dir.path());
        let id = DeviceId::new_v4();
        assert_eq!(
            d.plan(&id, &spec(Some(PROFILE_FIFO), None)).unwrap().0,
            Source::Fifo(dir.path().join(format!("{id}.fifo")))
        );
        assert_eq!(
            d.socket_path(&id).parent(),
            d.fifo_path(&id).parent(),
            "both files are this driver's and live in its run dir"
        );
    }

    /// A request that names no profile is answered by any profile of the
    /// driver, so the node picks — and the pick may never be the one that
    /// hands the guest a real keyboard.
    #[test]
    fn no_profile_is_the_fifo_and_never_a_host_device() {
        let dir = tempfile::tempdir().unwrap();
        let d = driver(dir.path());
        let id = DeviceId::new_v4();
        assert!(matches!(
            d.plan(&id, &spec(None, None)).unwrap().0,
            Source::Fifo(_)
        ));
    }

    #[test]
    fn evdev_without_a_node_is_refused_with_a_sentence() {
        let dir = tempfile::tempdir().unwrap();
        let d = driver(dir.path());
        let err = d
            .plan(&DeviceId::new_v4(), &spec(Some(PROFILE_EVDEV), None))
            .expect_err("no source to forward");
        let msg = err.to_string();
        assert!(msg.contains("params.evdev"), "{msg}");
        assert!(msg.contains("/dev/input/event0"), "{msg}");
    }

    #[test]
    fn evdev_naming_a_node_that_is_not_there_is_refused_here_and_not_in_a_log() {
        let dir = tempfile::tempdir().unwrap();
        let d = driver(dir.path());
        let err = d
            .plan(
                &DeviceId::new_v4(),
                &spec(
                    Some(PROFILE_EVDEV),
                    Some(serde_json::json!({ "evdev": "/dev/input/event-nope" })),
                ),
            )
            .expect_err("nothing at that path");
        assert!(err.to_string().contains("does not exist"), "{err}");
    }

    /// The evdev node exists here because the test made it: what is under
    /// test is that a named, present source is taken verbatim.
    #[test]
    fn evdev_takes_the_node_it_was_given() {
        let dir = tempfile::tempdir().unwrap();
        let node = dir.path().join("event0");
        std::fs::write(&node, b"").unwrap();
        let d = driver(dir.path());
        assert_eq!(
            d.plan(
                &DeviceId::new_v4(),
                &spec(
                    Some(PROFILE_EVDEV),
                    Some(serde_json::json!({ "evdev": node })),
                ),
            )
            .unwrap()
            .0,
            Source::Evdev(node)
        );
    }

    #[test]
    fn a_host_node_on_the_fifo_profile_is_a_contradiction_and_not_an_extra() {
        let dir = tempfile::tempdir().unwrap();
        let d = driver(dir.path());
        let err = d
            .plan(
                &DeviceId::new_v4(),
                &spec(
                    Some(PROFILE_FIFO),
                    Some(serde_json::json!({ "evdev": "/dev/input/event0" })),
                ),
            )
            .expect_err("the two disagree");
        assert!(err.to_string().contains("nothing to do"), "{err}");
    }

    #[test]
    fn an_unknown_profile_names_the_two_that_exist() {
        let dir = tempfile::tempdir().unwrap();
        let d = driver(dir.path());
        let err = d
            .plan(&DeviceId::new_v4(), &spec(Some("touchscreen"), None))
            .expect_err("no such profile");
        let msg = err.to_string();
        assert!(msg.contains("fifo") && msg.contains("evdev"), "{msg}");
    }

    #[test]
    fn a_typo_in_params_is_refused_rather_than_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let d = driver(dir.path());
        let err = d
            .plan(
                &DeviceId::new_v4(),
                &spec(Some(PROFILE_FIFO), Some(serde_json::json!({ "evdevs": 1 }))),
            )
            .expect_err("deny_unknown_fields");
        assert!(err.to_string().contains("invalid input params"), "{err}");
    }

    /// The device id the guest module binds to and the two rings it expects.
    /// Numbers with a spec behind them: a wrong device_type gives the guest a
    /// device of another kind, a single queue a device with no event ring.
    #[test]
    fn the_attachment_is_a_virtio_input_device_with_both_queues() {
        let a = InputDriver::attachment(PathBuf::from("/run/input/x.sock"), 4242);
        let DeviceAttachment::VhostUser {
            device_type,
            queue_sizes,
            pid,
            ..
        } = &a
        else {
            panic!("a vhost-user attachment");
        };
        assert_eq!(*device_type, 18);
        assert_eq!(queue_sizes, &vec![256, 256]);
        assert_eq!(*pid, 4242);
        assert!(
            a.needs_shared_memory(),
            "a vhost-user backend maps guest memory"
        );
    }

    #[test]
    fn a_fifo_is_made_and_is_really_a_pipe() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("in.fifo");
        make_fifo(&path, None).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        assert!(
            std::os::unix::fs::FileTypeExt::is_fifo(&meta.file_type()),
            "mkfifo made a pipe"
        );

        // A leftover of the wrong kind is replaced rather than kept: the
        // backend would open it and read nothing forever.
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"not a pipe").unwrap();
        make_fifo(&path, None).unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        assert!(std::os::unix::fs::FileTypeExt::is_fifo(&meta.file_type()));
    }

    #[test]
    fn both_sources_are_offered_and_spelled_the_way_the_catalogue_reads_them() {
        let dir = tempfile::tempdir().unwrap();
        let d = driver(dir.path());
        assert_eq!(d.profiles(), vec!["fifo", "evdev"]);
    }

    /// A missing binary is a node that is configured for something it does
    /// not have, and that has to be visible at agent start rather than at the
    /// first VM boot.
    #[test]
    fn a_driver_without_its_binary_refuses_to_exist() {
        let dir = tempfile::tempdir().unwrap();
        let Err(err) = InputDriver::new(InputDriverConfig {
            binary: dir.path().join("vhost-user-input"),
            run_dir: dir.path().join("input"),
            socket_timeout: Duration::from_millis(1),
            vmm_user: None,
        }) else {
            panic!("a driver was built without its binary");
        };
        assert!(err.to_string().contains("not found"), "{err}");
    }

    #[tokio::test]
    async fn only_a_mediated_device_is_this_driver_s_business() {
        let dir = tempfile::tempdir().unwrap();
        let d = driver(dir.path());
        let mut s = spec(Some(PROFILE_FIFO), None);
        s.partition = PartitionSpec::Exclusive;
        let err = d
            .create(&DeviceId::new_v4(), &s, None)
            .await
            .expect_err("passthrough is vfio's job");
        assert!(err.to_string().contains("Mediated"), "{err}");
    }

    /// Teardown of a device this driver never had is Ok: the trait says
    /// `destroy` is idempotent, and a reconciler that retries one has to be
    /// able to finish.
    #[tokio::test]
    async fn destroying_what_was_never_there_is_done() {
        let dir = tempfile::tempdir().unwrap();
        let d = driver(dir.path());
        let id = DeviceId::new_v4();
        // A pid that cannot exist, so `stop_adopted` finds nothing to signal.
        let attachment = InputDriver::attachment(d.socket_path(&id), i32::MAX as u32);
        d.destroy(&id, &attachment).await.expect("idempotent");
    }
}
