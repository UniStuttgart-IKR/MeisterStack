// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! What a base image has to be before a node writes it onto a disk.
//!
//! Astra finding S01, 2026-09-23: both block backends ran `qemu-img convert
//! -O raw <src> <dst>` with no `-f`, so the SOURCE format was whatever
//! qemu-img decided the file was at the moment it opened it — and they
//! refused nothing. Two things follow from that, and neither is theoretical:
//!
//! * A qcow2 with a `backing file` is a file that NAMES another file, and
//!   `qemu-img convert` reads it. So is a qcow2 with an external `data file`.
//!   The name is inside the image and is not a path this stack chose, so an
//!   image somebody uploaded could say `/etc/shadow` — or another tenant's
//!   volume — and the converter would faithfully copy it into a disk that
//!   tenant then boots and reads. The converter runs as the agent, which on
//!   a node with `unprivileged = false` (the default in `nix/agent.nix`) is
//!   root.
//! * Without `-f`, format detection happens twice: once when the size is
//!   measured and once when the bytes are converted. A file that changed
//!   between the two is converted as something other than what was judged.
//!
//! So: one probe, which refuses a backing file, an external data file, a
//! format that is not on the short list, and anything that is not a regular
//! file — and then a convert that is TOLD the format the probe saw.
//!
//! Here rather than in either driver because both do the same thing and both
//! got it wrong the same way. `filesystem` and `lvm-thin` already depend on
//! this crate, and a check that exists twice is a check that will diverge.
//!
//! # Where qemu-img runs
//!
//! Astra finding S01, 2026-09-23, second half: judging the image is only
//! half of it. `qemu-img` is a parser for a file somebody else wrote --
//! qcow2 L1 and L2 tables, refcount blocks, compressed clusters -- and it
//! ran in the agent's own process, which on a node with
//! `unprivileged = false` (the default in `nix/agent.nix`) is root with
//! every capability the agent holds. The probe above refuses the images this
//! stack knows how to say no to; it cannot refuse the parser bug nobody has
//! found yet. So the program that touches those bytes is moved out of the
//! agent into a transient systemd unit that holds nothing:
//!
//! ```text
//! systemd-run --wait --pipe --collect --quiet
//!   -p User=meister-convert            an account with no shell and no home
//!   -p NoNewPrivileges=yes             no setuid binary widens it again
//!   -p CapabilityBoundingSet=          and there is nothing to widen to
//!   -p AmbientCapabilities=
//!   -p PrivateNetwork=yes              a converter has nobody to talk to
//!   -p RestrictAddressFamilies=        not even over a unix socket (an
//!                                      empty allow-list denies every
//!                                      family; see `argv`)
//!   -p ProtectSystem=strict            the hierarchy read-only
//!   -p ProtectHome=yes
//!   -p PrivateTmp=yes
//!   -p SystemCallFilter=@system-service
//!   -p MemoryMax= -p CPUQuota= -p RuntimeMaxSec=   a convert that does not
//!                                      end, ends
//!   -p BindReadOnlyPaths=<the image>   the one file it may read
//!   -p BindPaths=<the destination>     the one it may write, or
//!   -p DeviceAllow=<the node> rw       the one block device it may write
//!   -- <qemu-img> convert -f <format> -O raw <image> <destination>
//! ```
//!
//! plus the ones that cost nothing to add and would cost an afternoon to
//! argue about after an incident: `ProtectKernelTunables`,
//! `ProtectKernelModules`, `ProtectKernelLogs`, `ProtectControlGroups`,
//! `ProtectClock`, `ProtectHostname`, `ProtectProc=invisible`,
//! `RestrictNamespaces`, `RestrictRealtime`, `RestrictSUIDSGID`,
//! `LockPersonality`, `SystemCallArchitectures=native`.
//!
//! **What this buys and what it does not.** `ProtectSystem=strict` makes the
//! hierarchy read-ONLY; it does not make it unreadable, so a qemu-img that
//! was taken over can still read whatever any local account can read. What
//! it can no longer do is write anywhere but the one destination, open a
//! socket, keep a capability, outlive its deadline, take the node's memory,
//! or leave a unit behind. And the one file it can write is the disk the
//! caller was about to hand that guest anyway. Making the tree unreadable
//! as well wants `TemporaryFileSystem=/` and a bind of the binary's whole
//! store closure, which is a second thing to keep right at every qemu
//! update; that is a later step and it is not this one.
//!
//! `qemu-img info` is inside the same boundary, because it is the same
//! parser reading the same file. A probe that ran as the agent would be the
//! finding with one more step in front of it.
//!
//! # Why a static account and not `DynamicUser=yes`
//!
//! `DynamicUser=yes` is the obvious answer and it cannot work here. Its uid
//! is allocated when the unit starts, so there is no uid to give the
//! destination to BEFORE it starts -- and the destination always exists
//! before it starts and belongs to the agent: the filesystem driver's
//! `<id>.tmp`, which `write_volume_file` renames into place once the image
//! is whole, and lvm-thin's `/dev/<vg>/<lv>.staging`, a device node that
//! LVM made and udev owns `root:disk`. A dynamic uid can write neither, and
//! the ways around that are worse than the problem:
//! `SupplementaryGroups=disk` hands the converter every disk on the node,
//! and a world-writable destination hands it to everybody.
//!
//! So: one system account, `meister-convert` (nix/services.nix, behind the
//! agent role), and the agent gives it the destination for the length of the
//! conversion and takes it back afterwards. That is libvirt's
//! `dynamic_ownership` in miniature and the shape `vmm_user::take` /
//! `give_back` already has in this crate. Taking it back is not best effort:
//! a device node still owned by the converter after the unit is gone is the
//! hole this exists to close, so a restore that fails fails the conversion
//! -- and both drivers drop the half-written volume when a conversion fails.
//!
//! # There is no fallback
//!
//! If `systemd-run` is not on this node, if the account does not exist, or
//! if the unit does not start, the conversion is REFUSED with a sentence
//! naming which of the three it was. It is never run in the agent instead.
//! A fallback would mean the most privileged path is the one that runs when
//! something is wrong, which is this finding written the other way round.
//!
//! # What changes when the agent is not root (stage 2)
//!
//! Today the agent is root, and asking systemd for a transient unit needs no
//! argument for that. An agent under `unprivileged = true` runs as `meister`
//! and its D-Bus call is refused unless polkit says otherwise, so that lane
//! has to ship either a polkit rule for
//! `org.freedesktop.systemd1.manage-units` narrowed to this user and this
//! unit prefix, or a small root helper the agent asks. The same lane owns
//! the other half of it: an unprivileged agent cannot chown a destination to
//! another account either, so there the destination has to be made by
//! something that already runs as `meister-convert`, and the volume
//! directory (`0750 meister meister` in nix/agent.nix) has to let that
//! account walk to it. None of that is implemented here and nothing in this
//! file pretends it is.

use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::storage::{self, StorageError};

/// The formats a base image may be in.
///
/// Short on purpose. `raw` is a disk and nothing else; `qcow2` is what every
/// cloud image in this lab ships as. Everything else — vmdk, vdi, vhdx, and
/// the qcow2 variants that reference other files — is a format whose
/// behaviour on `convert` somebody would have to read the source of QEMU to
/// state, and a base image is not the place to find out.
pub const CONVERTIBLE_FORMATS: [&str; 2] = ["raw", "qcow2"];

/// The account the conversion runs as. See the module note on why it is a
/// name and not `DynamicUser=yes`.
pub const CONVERT_USER: &str = "meister-convert";

/// A base image this node is willing to convert, and the two facts about it
/// that the caller needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaseImage {
    /// What qemu-img says the file IS, handed straight back to it as `-f` so
    /// that the conversion cannot decide something else.
    pub format: String,
    /// What the file occupies once written out raw. For a qcow2 this is the
    /// disk it describes and not the length of the file, which is the number
    /// a size check has to use.
    pub virtual_size: u64,
}

/// How much of the node one sandboxed run may take.
///
/// Bounds and not guesses at what qemu-img needs: `MemoryMax` is what the
/// unit is killed at, `CPUQuota` is what it may not exceed while other
/// guests are running on the same node, and `RuntimeMaxSec` is the one that
/// matters most — a convert that never returns used to be a provision that
/// never returned, holding the driver's lock while it did not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    /// `MemoryMax=`, in systemd's spelling (`512M`, `2G`).
    pub memory_max: String,
    /// `CPUQuota=`, in systemd's spelling (`100%` is one core's worth).
    pub cpu_quota: String,
    /// `RuntimeMaxSec=`, rounded to whole seconds.
    pub runtime_max: Duration,
}

impl Limits {
    /// For `qemu-img info`: it reads a header and prints a page of JSON.
    /// A minute is already two orders of magnitude more than it takes, and a
    /// probe that has not answered in a minute is a probe that will not.
    pub fn probe() -> Self {
        Self {
            memory_max: "512M".to_string(),
            cpu_quota: "100%".to_string(),
            runtime_max: Duration::from_secs(60),
        }
    }

    /// For `qemu-img convert`: measured in this lab at well under 300 MiB
    /// for the cloud images it boots, and single-threaded unless it is told
    /// otherwise, so one core's worth is what it can use. Half an hour is
    /// the deadline; a 64 GiB image onto a slow disk is minutes, and an hour
    /// would be a stuck provision nobody notices during a shift.
    pub fn convert() -> Self {
        Self {
            memory_max: "2G".to_string(),
            cpu_quota: "100%".to_string(),
            runtime_max: Duration::from_secs(1800),
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::convert()
    }
}

/// The one thing a conversion may write.
///
/// Two variants because the two drivers write two different kinds of object
/// and systemd reaches them differently: a file is made writable by binding
/// it into the unit (everything else is read-only under
/// `ProtectSystem=strict`), and a device node is reached through the cgroup
/// device controller, which a bind mount does not touch.
#[derive(Clone, Copy, Debug)]
pub enum Destination<'a> {
    /// A regular file the agent has already created — the filesystem
    /// driver's `<id>.tmp`. Bound into the unit by itself and not by its
    /// directory: a writable directory is a writable directory, and the
    /// volumes of other guests are in it.
    File(&'a Path),
    /// A block device node, already resolved to the real node rather than a
    /// symlink to it — lvm-thin's `/dev/<vg>/<lv>.staging`.
    Device(&'a Path),
}

impl Destination<'_> {
    /// The path itself, whichever kind it is.
    pub fn path(&self) -> &Path {
        match self {
            Destination::File(p) | Destination::Device(p) => p,
        }
    }
}

/// What the sandbox is being asked to do.
///
/// Both jobs read the same untrusted file, which is why both are jobs of
/// this type and not one job and one shortcut.
#[derive(Clone, Copy, Debug)]
pub enum Job<'a> {
    /// `qemu-img info --output=json <src>`, whose answer [`judge`] reads.
    Probe { src: &'a Path },
    /// `qemu-img convert -f <format> -O raw <src> <dst>`.
    Convert {
        image: &'a BaseImage,
        src: &'a Path,
        dst: Destination<'a>,
    },
}

/// How the destination is given to the converter and taken back.
///
/// A function and not a call, so that a test can watch the hand-over happen
/// without being root and without a block device. See [`Sandbox::resolved_as`].
pub type ChangeOwner = Arc<dyn Fn(&Path, u32, u32) -> std::io::Result<()> + Send + Sync>;

/// The destination, for as long as the converter has it.
///
/// A value and not a pair of calls, because the giving back has to happen on
/// every way out of a conversion — the failure, the deadline, the panic —
/// and "remember to chown it back" is an instruction that survives exactly
/// until somebody adds a `?`.
#[must_use = "the destination belongs to the converter until it is given back"]
pub struct HandedOver {
    path: PathBuf,
    /// Who owned it before, read off the destination rather than assumed to
    /// be root: an agent that is not root owns its own files.
    uid: u32,
    gid: u32,
    chown: ChangeOwner,
    given_back: bool,
}

impl HandedOver {
    /// Take the destination back, and say so if that failed.
    ///
    /// Not best effort: see the module note. A device node left owned by the
    /// converter is the hole this whole file is about.
    pub fn give_back(mut self) -> Result<(), String> {
        self.given_back = true;
        (self.chown)(&self.path, self.uid, self.gid).map_err(|e| {
            format!(
                "the conversion is over but {} could not be given back to {}:{} ({e}); it is \
                 still owned by the converter, so this volume is refused rather than handed on",
                self.path.display(),
                self.uid,
                self.gid
            )
        })
    }
}

impl Drop for HandedOver {
    fn drop(&mut self) {
        // Only reached when a panic unwound past `give_back`. Nothing can be
        // reported from here, and the alternative to a silent attempt is no
        // attempt at all.
        if !self.given_back {
            let _ = (self.chown)(&self.path, self.uid, self.gid);
        }
    }
}

/// The transient unit a base image is read inside.
///
/// Cheap to clone and to hold: it is four fields and no state, so a driver
/// keeps one in its config and hands it to every conversion.
#[derive(Clone)]
pub struct Sandbox {
    /// `systemd-run`. Resolved by the OS from the agent's own `PATH`, which
    /// is the one place a binary name is still allowed to be one.
    systemd_run: PathBuf,
    /// The account the unit runs as.
    user: String,
    /// What a CONVERT may take. A probe takes [`Limits::probe`].
    limits: Limits,
    /// Set by [`Sandbox::resolved_as`], and only by tests.
    resolved: Option<(u32, u32)>,
    chown: ChangeOwner,
}

impl std::fmt::Debug for Sandbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sandbox")
            .field("systemd_run", &self.systemd_run)
            .field("user", &self.user)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl Default for Sandbox {
    fn default() -> Self {
        Self::new("systemd-run")
    }
}

impl Sandbox {
    /// The sandbox a node has unless somebody said otherwise: this
    /// `systemd-run`, the [`CONVERT_USER`] account, and [`Limits::convert`].
    pub fn new(systemd_run: impl Into<PathBuf>) -> Self {
        Self {
            systemd_run: systemd_run.into(),
            user: CONVERT_USER.to_string(),
            limits: Limits::convert(),
            resolved: None,
            chown: Arc::new(|path, uid, gid| {
                nix::unistd::chown(
                    path,
                    Some(nix::unistd::Uid::from_raw(uid)),
                    Some(nix::unistd::Gid::from_raw(gid)),
                )
                .map_err(std::io::Error::from)
            }),
        }
    }

    /// Run the conversion under a different account than [`CONVERT_USER`].
    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user = user.into();
        self
    }

    /// What a conversion may take. The driver decides, because the driver is
    /// what knows how big the disks on this backend get.
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// The one seam this type has, and it is here for tests.
    ///
    /// A test cannot create `meister-convert`, and a test that is not root
    /// cannot chown anything to it. So a test says what the account resolves
    /// to and watches the hand-over instead of performing it — everything
    /// else, the argv included, is the code a node runs. Nothing but a test
    /// calls this: on a node the account is looked up with `getpwnam` and
    /// the ownership really changes.
    pub fn resolved_as(mut self, uid: u32, gid: u32, chown: ChangeOwner) -> Self {
        self.resolved = Some((uid, gid));
        self.chown = chown;
        self
    }

    /// Where `systemd-run` is, for the sentence that says it is not there.
    pub fn systemd_run(&self) -> &Path {
        &self.systemd_run
    }

    /// Look the account up, or say why the conversion cannot happen.
    ///
    /// `getpwnam` through `nix` rather than a `systemd-run` that fails with
    /// "Failed to start transient service unit": the name is the thing that
    /// is wrong, and this is the only place that can say so.
    fn resolve(&self) -> Result<(u32, u32), String> {
        if let Some(known) = self.resolved {
            return Ok(known);
        }
        let user = nix::unistd::User::from_name(&self.user)
            .map_err(|e| format!("looking up the user {:?}: {e}", self.user))?
            .ok_or_else(|| {
                format!(
                    "there is no user {:?} on this node, so a base image cannot be converted in \
                     a sandbox — and it is not converted outside one. The account is declared by \
                     this stack's NixOS module (nix/services.nix, behind the agent role); a node \
                     that does not have it is a node whose deployment is older than this agent",
                    self.user
                )
            })?;
        if user.uid.as_raw() == 0 {
            return Err(format!(
                "the user {:?} is uid 0. Converting a base image as root is what this sandbox \
                 exists to stop",
                self.user
            ));
        }
        Ok((user.uid.as_raw(), user.gid.as_raw()))
    }

    /// The whole command line, `systemd-run` included.
    ///
    /// Pure, and public for that reason: what the sandbox IS is this list,
    /// so the tests read the list rather than a node's journal.
    pub fn argv(&self, qemu_img: &Path, job: &Job<'_>) -> Result<Vec<OsString>, String> {
        let (src, description, limits) = match job {
            Job::Probe { src } => (*src, "MeisterStack base image probe", Limits::probe()),
            Job::Convert { src, .. } => (
                *src,
                "MeisterStack base image conversion",
                self.limits.clone(),
            ),
        };
        nameable(src, "the base image")?;
        if let Job::Convert { dst, .. } = job {
            nameable(dst.path(), "the destination")?;
        }

        // The description is fixed text and carries no image name. A unit
        // property is not a shell and nothing here is interpolated into one,
        // but the catalogue name is the one string on this path that came
        // from outside the node, and it is already in the log line, the
        // error and the span.
        let mut argv: Vec<OsString> = vec![
            "--wait".into(),
            "--pipe".into(),
            "--collect".into(),
            "--quiet".into(),
            format!("--description={description}").into(),
        ];
        let mut prop = |value: OsString| {
            argv.push("-p".into());
            argv.push(value);
        };
        // The account and everything that keeps it from becoming another one.
        prop(text("User", &self.user));
        prop(text("NoNewPrivileges", "yes"));
        prop(text("CapabilityBoundingSet", ""));
        prop(text("AmbientCapabilities", ""));
        prop(text("RestrictSUIDSGID", "yes"));
        prop(text("LockPersonality", "yes"));
        prop(text("RestrictNamespaces", "yes"));
        prop(text("RestrictRealtime", "yes"));
        // A converter has nobody to talk to. `PrivateNetwork` takes the
        // stack away and the line below takes the socket syscalls with it,
        // unix sockets included.
        //
        // And it is EMPTY on purpose, where a unit file would say `none`.
        // The two are not the same word for the same thing: `none` is
        // understood by the unit-file parser and refused by the transient
        // one, so `systemd-run -p RestrictAddressFamilies=none` fails with
        // "Failed to set unit properties: Invalid argument" and the
        // conversion never runs at all. Over the bus the property is a
        // (allow-list?, families) pair, and an EMPTY allow-list is what
        // denies everything — measured on systemd 261: a probe under
        // `RestrictAddressFamilies=` got EAFNOSUPPORT for AF_INET and for
        // AF_UNIX, and the same probe with no property at all got neither.
        // Changing this line to the word that reads better breaks every
        // conversion on every node.
        prop(text("PrivateNetwork", "yes"));
        prop(text("RestrictAddressFamilies", ""));
        // The filesystem: read-only everywhere, with the two exceptions
        // below, and no home directories at all.
        prop(text("ProtectSystem", "strict"));
        prop(text("ProtectHome", "yes"));
        prop(text("PrivateTmp", "yes"));
        prop(text("ProtectProc", "invisible"));
        prop(text("ProtectKernelTunables", "yes"));
        prop(text("ProtectKernelModules", "yes"));
        prop(text("ProtectKernelLogs", "yes"));
        prop(text("ProtectControlGroups", "yes"));
        prop(text("ProtectClock", "yes"));
        prop(text("ProtectHostname", "yes"));
        prop(text("SystemCallArchitectures", "native"));
        prop(text("SystemCallFilter", "@system-service"));
        // What it may take of the node, and how long it has.
        prop(text("MemoryMax", &limits.memory_max));
        prop(text("CPUQuota", &limits.cpu_quota));
        prop(text(
            "RuntimeMaxSec",
            &limits.runtime_max.as_secs().to_string(),
        ));
        // The one file it may read.
        prop(path("BindReadOnlyPaths", src));
        // ... and the one thing it may write, if it writes anything.
        match job {
            Job::Probe { .. } => prop(text("PrivateDevices", "yes")),
            Job::Convert { dst, .. } => match dst {
                Destination::File(file) => {
                    prop(path("BindPaths", file));
                    prop(text("PrivateDevices", "yes"));
                }
                Destination::Device(node) => {
                    // No `PrivateDevices`: it would hide the very node this
                    // conversion is for. `DeviceAllow` names it instead, and
                    // naming one device sets `DevicePolicy=closed`, so the
                    // unit reaches that node and the handful systemd always
                    // allows (null, zero, full, random, urandom) and nothing
                    // else on the machine.
                    let mut allow = path("DeviceAllow", node);
                    allow.push(" rw");
                    prop(allow);
                }
            },
        }

        argv.push("--".into());
        argv.push(qemu_img.as_os_str().to_os_string());
        match job {
            Job::Probe { src } => {
                argv.push("info".into());
                argv.push("--output=json".into());
                argv.push(src.as_os_str().to_os_string());
            }
            Job::Convert { image, src, dst } => {
                argv.extend(convert_argv(image, src, dst.path()));
            }
        }
        Ok(argv)
    }

    /// Run one job and hand back what it printed. Blocking, for the
    /// filesystem driver, which does its writing inside `spawn_blocking`.
    pub fn run_blocking(&self, qemu_img: &Path, job: &Job<'_>) -> Result<Vec<u8>, String> {
        let tool = absolute(qemu_img)?;
        let (argv, handed) = self.plan(&tool, job)?;
        let spawned = std::process::Command::new(&self.systemd_run)
            .args(&argv)
            .output();
        self.finish(&tool, handed, spawned)
    }

    /// The same, for a driver that is already on an async path.
    ///
    /// Two functions and not one because the two callers are two kinds of
    /// call site, and everything they do differently is on the line that
    /// starts the process — the argv, the hand-over and the reading of what
    /// came back are the same code for both.
    pub async fn run(&self, qemu_img: &Path, job: &Job<'_>) -> Result<Vec<u8>, String> {
        let tool = absolute(qemu_img)?;
        let (argv, handed) = self.plan(&tool, job)?;
        let spawned = tokio::process::Command::new(&self.systemd_run)
            .args(&argv)
            .output()
            .await;
        self.finish(&tool, handed, spawned)
    }

    /// Everything that has to be true before the unit starts: the account
    /// exists, the command line is buildable, and the destination belongs to
    /// the converter.
    fn plan(
        &self,
        qemu_img: &Path,
        job: &Job<'_>,
    ) -> Result<(Vec<OsString>, Option<HandedOver>), String> {
        let (uid, gid) = self.resolve()?;
        let argv = self.argv(qemu_img, job)?;
        let handed = match job {
            Job::Probe { .. } => None,
            Job::Convert { dst, .. } => Some(self.hand_over(dst.path(), uid, gid)?),
        };
        Ok((argv, handed))
    }

    /// Give the destination to the converter until the returned value is
    /// dropped or given back.
    fn hand_over(&self, path: &Path, uid: u32, gid: u32) -> Result<HandedOver, String> {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::metadata(path)
            .map_err(|e| format!("the destination {} cannot be stat'ed: {e}", path.display()))?;
        // What it goes back to afterwards. Normally whoever owns it now:
        // the agent for a tmp file it has just made, `root:disk` for a
        // device node udev made — restoring what was there is what keeps
        // this from deciding anything about a device it did not create.
        //
        // Unless what is there is the converter itself. That is what a run
        // which died between the hand-over and the hand-back leaves, and
        // giving such a destination "back" to the converter would make the
        // leftover permanent — and in the filesystem driver's case it would
        // then be renamed into place as the guest's volume. So that one case
        // goes to whoever runs this agent instead, which is the answer
        // `vmm_user::give_back` gives for the same reason.
        let (mut back_uid, mut back_gid) = (meta.uid(), meta.gid());
        if back_uid == uid {
            back_uid = nix::unistd::Uid::effective().as_raw();
            back_gid = nix::unistd::Gid::effective().as_raw();
        }
        let handed = HandedOver {
            path: path.to_path_buf(),
            uid: back_uid,
            gid: back_gid,
            chown: self.chown.clone(),
            given_back: false,
        };
        (self.chown)(path, uid, gid).map_err(|e| {
            format!(
                "the destination {} could not be given to {} ({uid}:{gid}): {e}. Converting a \
                 base image needs a destination the sandboxed converter can write, and nothing \
                 is converted outside the sandbox",
                path.display(),
                self.user
            )
        })?;
        Ok(handed)
    }

    /// Read what came back, and take the destination back whatever it says.
    fn finish(
        &self,
        qemu_img: &Path,
        handed: Option<HandedOver>,
        spawned: std::io::Result<std::process::Output>,
    ) -> Result<Vec<u8>, String> {
        let ran = self.interpret(qemu_img, spawned);
        let given_back = match handed {
            Some(handed) => handed.give_back(),
            None => Ok(()),
        };
        match (ran, given_back) {
            (Ok(out), Ok(())) => Ok(out),
            // The bytes may well be right, and the node is still wrong: the
            // destination is owned by the converter. Both drivers drop the
            // half-written volume on an error, and dropping it is what takes
            // the file or the device node with it.
            (Ok(_), Err(back)) => Err(back),
            (Err(ran), Ok(())) => Err(ran),
            (Err(ran), Err(back)) => Err(format!("{ran} — and worse: {back}")),
        }
    }

    fn interpret(
        &self,
        qemu_img: &Path,
        spawned: std::io::Result<std::process::Output>,
    ) -> Result<Vec<u8>, String> {
        let out = match spawned {
            Ok(out) => out,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(format!(
                    "there is no {} on this node, so {} cannot be run in a sandbox — and it is \
                     not run outside one. A base image is a file somebody else wrote, and the \
                     agent is root on this node (Astra finding S01)",
                    self.systemd_run.display(),
                    qemu_img.display()
                ));
            }
            Err(e) => {
                return Err(format!(
                    "starting {}: {e}. The base image is not converted without it",
                    self.systemd_run.display()
                ));
            }
        };
        if out.status.success() {
            return Ok(out.stdout);
        }
        Err(format!(
            "the sandboxed {} failed ({}): {}. Either the unit did not start — the {:?} account \
             and a systemd this agent may ask for a transient unit are what it needs — or \
             qemu-img itself refused the image or ran past MemoryMax={} / RuntimeMaxSec={}s",
            qemu_img.display(),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim(),
            self.user,
            self.limits.memory_max,
            self.limits.runtime_max.as_secs()
        ))
    }
}

/// `KEY=VALUE`, for the properties whose value is text.
fn text(key: &str, value: &str) -> OsString {
    OsString::from(format!("{key}={value}"))
}

/// `KEY=<path>`, built without going through a `String`: a path is bytes and
/// a node's filesystem is allowed to hold bytes that are not UTF-8.
fn path(key: &str, value: &Path) -> OsString {
    let mut out = OsString::from(key);
    out.push("=");
    out.push(value.as_os_str());
    out
}

/// Refuse a path systemd would read as more than one path.
///
/// `BindPaths=` and `BindReadOnlyPaths=` are `source:destination:options`,
/// so a colon in a path is a second path — and the left half of a base image
/// name is a path this node did not choose. A newline ends a property. Both
/// are refused here rather than escaped, because an image whose name needs
/// escaping is an image nobody meant to boot.
fn nameable(value: &Path, what: &str) -> Result<(), String> {
    let bytes = value.as_os_str().as_bytes();
    if bytes.contains(&b':') || bytes.contains(&b'\n') {
        return Err(format!(
            "{what} is {}, and a colon or a newline in it would be read by systemd as a second \
             path. This node does not convert it",
            value.display()
        ));
    }
    Ok(())
}

/// Where the tool really is.
///
/// systemd resolves a bare `ExecStart=` name against the MANAGER's `PATH`,
/// which is not the agent's: on a NixOS node `qemu-img` is on the unit's
/// path (`systemd.services.meister-agent.path`) and need not be anywhere the
/// manager would look. So the agent resolves it itself, with its own
/// environment, and hands systemd an absolute path.
fn absolute(tool: &Path) -> Result<PathBuf, String> {
    let looks_like_a_path = tool.components().count() > 1;
    if looks_like_a_path {
        return std::fs::canonicalize(tool)
            .map_err(|e| format!("{} is not there: {e}", tool.display()));
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .map(|dir| dir.join(tool))
        .find(|candidate| candidate.is_file())
        .and_then(|candidate| std::fs::canonicalize(candidate).ok())
        .ok_or_else(|| {
            format!(
                "{} is not on this agent's PATH, so there is nothing to convert a base image \
                 with. The sandbox is handed an absolute path because systemd would look on its \
                 own PATH and not on the agent's",
                tool.display()
            )
        })
}

/// Run `qemu-img info --output=json` over the file and judge what it says.
///
/// One subprocess, in the sandbox, where there used to be one per backend in
/// the agent for the size alone. `name` is the catalogue name and is only
/// ever used to write the sentence a person reads.
pub async fn probe(
    sandbox: &Sandbox,
    qemu_img: &Path,
    path: &Path,
    name: &str,
) -> storage::Result<BaseImage> {
    // A directory, a fifo or a device node under a catalogue name is not an
    // image. Asked before qemu-img is started, because "qemu-img could not
    // open it" is a worse sentence than this one and because a fifo would
    // hang the probe rather than fail it — the sandbox's `RuntimeMaxSec`
    // would end it a minute later, which is still a minute of a provision.
    let meta = tokio::fs::metadata(path)
        .await
        .map_err(|e| StorageError::ImageNotFound(format!("{name}: {} ({e})", path.display())))?;
    if !meta.is_file() {
        return Err(StorageError::InvalidSpec(format!(
            "the base image {name} is not a regular file ({})",
            path.display()
        )));
    }

    let info = sandbox
        .run(qemu_img, &Job::Probe { src: path })
        .await
        .map_err(|e| {
            StorageError::Backend(anyhow::anyhow!("measuring the base image {name}: {e}"))
        })?;
    judge(name, &info)
}

/// Write the image out as raw, in the sandbox, onto `dst`.
///
/// The destination belongs to the converter for the length of this call and
/// to the agent again when it returns — see [`HandedOver`].
pub async fn convert(
    sandbox: &Sandbox,
    qemu_img: &Path,
    image: &BaseImage,
    src: &Path,
    dst: Destination<'_>,
    name: &str,
) -> storage::Result<()> {
    sandbox
        .run(qemu_img, &Job::Convert { image, src, dst })
        .await
        .map(|_| ())
        .map_err(|e| {
            StorageError::Backend(anyhow::anyhow!(
                "writing the base image {name} onto {}: {e}",
                dst.path().display()
            ))
        })
}

/// The same, for a caller that is already on a blocking thread.
pub fn convert_blocking(
    sandbox: &Sandbox,
    qemu_img: &Path,
    image: &BaseImage,
    src: &Path,
    dst: Destination<'_>,
    name: &str,
) -> std::io::Result<()> {
    sandbox
        .run_blocking(qemu_img, &Job::Convert { image, src, dst })
        .map(|_| ())
        .map_err(|e| {
            std::io::Error::other(format!(
                "writing the base image {name} onto {}: {e}",
                dst.path().display()
            ))
        })
}

/// Read one `qemu-img info --output=json` document and say whether the file
/// it describes may be converted.
///
/// Split from [`probe`] so that the judgement can be tested against the
/// documents qemu-img really writes, without a qemu-img.
pub fn judge(name: &str, info: &[u8]) -> storage::Result<BaseImage> {
    let info: serde_json::Value = serde_json::from_slice(info).map_err(|e| {
        StorageError::Backend(anyhow::anyhow!("qemu-img info json for {name}: {e}"))
    })?;

    // A backing file is the whole finding in one field: it names a SECOND
    // file, that name is inside the image and was chosen by whoever made it,
    // and `qemu-img convert` reads it as part of the conversion. Both
    // spellings, because qemu-img writes the resolved one beside the one the
    // image holds and an image may carry either.
    for field in ["backing-filename", "full-backing-filename"] {
        if let Some(named) = info.get(field).and_then(serde_json::Value::as_str) {
            return Err(StorageError::InvalidSpec(format!(
                "the base image {name} has a backing file ({named:?}); this node converts an \
                 image that is whole in itself and nothing that reads a second file of its own \
                 choosing"
            )));
        }
    }
    // The same thing said the other way round: a qcow2 whose data lives in an
    // external file is metadata pointing at bytes somewhere else.
    if let Some(named) = info
        .pointer("/format-specific/data/data-file")
        .and_then(serde_json::Value::as_str)
    {
        return Err(StorageError::InvalidSpec(format!(
            "the base image {name} keeps its data in an external file ({named:?}); this node \
             converts an image that is whole in itself"
        )));
    }

    let format = info
        .get("format")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            StorageError::Backend(anyhow::anyhow!(
                "qemu-img info for {name} does not say what format it is"
            ))
        })?;
    if !CONVERTIBLE_FORMATS.contains(&format) {
        return Err(StorageError::InvalidSpec(format!(
            "the base image {name} is a {format:?}; this node converts [{}] and nothing else",
            CONVERTIBLE_FORMATS.join(", ")
        )));
    }

    // Parsed and not scanned. The document is not flat: `children[0].info`
    // carries a `virtual-size` of its own for the FILE node — a few hundred
    // kilobytes for a fresh qcow2 — before the top-level one that describes
    // the disk. Taking the first match is how a 64M image passes a check
    // meant to reject it.
    let virtual_size = info
        .get("virtual-size")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            StorageError::Backend(anyhow::anyhow!(
                "qemu-img info for {name} has no virtual-size"
            ))
        })?;

    Ok(BaseImage {
        format: format.to_string(),
        virtual_size,
    })
}

/// The argv of the one conversion this stack performs — the qemu-img half of
/// it, which the sandbox puts after its own `--`.
///
/// `-f` is the point of it: without it qemu-img decides for itself what the
/// source is, every time it opens it, and the decision it makes at convert
/// time is not the one the probe judged.
pub fn convert_argv(image: &BaseImage, src: &Path, dst: &Path) -> Vec<OsString> {
    vec![
        OsString::from("convert"),
        OsString::from("-f"),
        OsString::from(&image.format),
        OsString::from("-O"),
        OsString::from("raw"),
        src.as_os_str().to_os_string(),
        dst.as_os_str().to_os_string(),
    ]
}

/// Every argument as a string, for a test that reads a command line.
#[cfg(test)]
fn said(argv: &[OsString]) -> Vec<String> {
    argv.iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;

    /// What `qemu-img info --output=json` writes for a plain qcow2, with
    /// whatever this test wants to add to it.
    fn info(extra: serde_json::Value) -> Vec<u8> {
        let mut doc = serde_json::json!({
            "virtual-size": 16777216,
            "filename": "/var/lib/meister/images/noble.qcow2",
            "cluster-size": 65536,
            "format": "qcow2",
            "actual-size": 200704,
            "format-specific": { "type": "qcow2", "data": { "compat": "1.1" } },
            "dirty-flag": false
        });
        let (Some(doc), Some(extra)) = (doc.as_object_mut(), extra.as_object()) else {
            panic!("both are objects");
        };
        for (k, v) in extra {
            doc.insert(k.clone(), v.clone());
        }
        serde_json::to_vec(&serde_json::Value::Object(doc.clone())).expect("json")
    }

    /// An image that is whole in itself is converted, and the size that comes
    /// back is the disk it describes rather than the length of the file.
    #[test]
    fn an_image_that_is_whole_in_itself_is_accepted() {
        let judged = judge("noble.qcow2", &info(serde_json::json!({}))).expect("accepted");
        assert_eq!(judged.format, "qcow2");
        assert_eq!(judged.virtual_size, 16777216);

        let raw = judge(
            "noble.raw",
            &info(serde_json::json!({ "format": "raw", "format-specific": null })),
        )
        .expect("raw is an image too");
        assert_eq!(raw.format, "raw");
    }

    /// Astra finding S01, 2026-09-23: a backing file names a SECOND file, the
    /// name is inside the image, and `qemu-img convert` reads it. An image
    /// somebody uploaded could name a path on the node, and the converter
    /// runs as the agent.
    #[test]
    fn an_image_that_reads_another_file_is_refused() {
        for field in ["backing-filename", "full-backing-filename"] {
            let err = judge(
                "noble.qcow2",
                &info(serde_json::json!({ field: "/etc/shadow" })),
            )
            .expect_err("must not be converted");
            let said = err.to_string();
            assert!(said.contains("backing file"), "{said}");
            assert!(said.contains("/etc/shadow"), "and names it: {said}");
        }
    }

    /// The same thing said the other way round: the metadata is here and the
    /// data is somewhere else.
    #[test]
    fn an_image_whose_data_is_elsewhere_is_refused() {
        let err = judge(
            "noble.qcow2",
            &info(serde_json::json!({
                "format-specific": {
                    "type": "qcow2",
                    "data": { "compat": "1.1", "data-file": "/srv/other-tenant/disk.raw" }
                }
            })),
        )
        .expect_err("must not be converted");
        let said = err.to_string();
        assert!(said.contains("external file"), "{said}");
        assert!(said.contains("other-tenant"), "and names it: {said}");
    }

    /// A format nobody here has reasoned about is refused by name, so the
    /// operator learns which one it was.
    #[test]
    fn a_format_that_is_not_on_the_list_is_refused() {
        let err = judge(
            "somebody.vmdk",
            &info(serde_json::json!({ "format": "vmdk" })),
        )
        .expect_err("not a format this node converts");
        let said = err.to_string();
        assert!(said.contains("vmdk"), "{said}");
        assert!(said.contains("raw, qcow2"), "and says what it does: {said}");

        // And a document that says nothing about the format at all is not
        // read as one that says "raw".
        let mut headless = serde_json::json!({ "virtual-size": 1, "actual-size": 1 });
        headless.as_object_mut().expect("an object");
        assert!(judge("x.raw", serde_json::to_vec(&headless).unwrap().as_slice()).is_err());
    }

    /// The conversion is TOLD what it is reading.
    ///
    /// Astra finding S01, 2026-09-23: without `-f` the format is detected
    /// again at convert time, which is a second decision about a file that
    /// may have changed since the first one — and the first one is the only
    /// one anything checked.
    #[test]
    fn the_conversion_is_told_the_format_that_was_judged() {
        let image = BaseImage {
            format: "qcow2".into(),
            virtual_size: 1 << 24,
        };
        let argv = convert_argv(
            &image,
            Path::new("/images/noble.qcow2"),
            Path::new("/dev/vg/lv"),
        );
        assert_eq!(
            said(&argv),
            vec![
                "convert",
                "-f",
                "qcow2",
                "-O",
                "raw",
                "/images/noble.qcow2",
                "/dev/vg/lv"
            ]
        );
    }

    fn an_image() -> BaseImage {
        BaseImage {
            format: "qcow2".into(),
            virtual_size: 1 << 24,
        }
    }

    /// Every property the sandbox is, in the command line that makes it.
    ///
    /// Astra finding S01, 2026-09-23, second half: the conversion used to be
    /// a subprocess of the agent, which is root by default. This list is
    /// what it is instead, and a test that reads the list is the only test
    /// that can be written without a systemd and a node.
    #[test]
    fn the_sandbox_carries_every_property_the_finding_asks_for() {
        let dst = PathBuf::from("/var/lib/meister/volumes/v.tmp");
        let argv = Sandbox::default()
            .argv(
                Path::new("/nix/store/qemu/bin/qemu-img"),
                &Job::Convert {
                    image: &an_image(),
                    src: Path::new("/var/lib/meister/images/noble.qcow2"),
                    dst: Destination::File(&dst),
                },
            )
            .expect("a command line");
        let said = said(&argv);

        for flag in ["--wait", "--pipe", "--collect", "--quiet"] {
            assert!(
                said.contains(&flag.to_string()),
                "{flag} is missing: {said:?}"
            );
        }
        for property in [
            "User=meister-convert",
            "NoNewPrivileges=yes",
            "CapabilityBoundingSet=",
            "AmbientCapabilities=",
            "PrivateNetwork=yes",
            // Empty, and not the word `none` a unit file would use: see
            // `argv`. `systemd-run` refuses `none` outright.
            "RestrictAddressFamilies=",
            "ProtectSystem=strict",
            "ProtectHome=yes",
            "PrivateTmp=yes",
            "SystemCallFilter=@system-service",
            "MemoryMax=2G",
            "CPUQuota=100%",
            "RuntimeMaxSec=1800",
            "BindReadOnlyPaths=/var/lib/meister/images/noble.qcow2",
            "BindPaths=/var/lib/meister/volumes/v.tmp",
            "PrivateDevices=yes",
        ] {
            assert!(
                said.contains(&property.to_string()),
                "{property} is missing: {said:?}"
            );
        }
        // The destination is bound by itself and never by the directory it
        // is in: the other guests' volumes are in that directory.
        assert!(
            !said
                .iter()
                .any(|a| a == "BindPaths=/var/lib/meister/volumes"),
            "the pool is not handed over whole: {said:?}"
        );
        // Every property is a `-p` of its own, and the tool comes after `--`.
        let separator = said.iter().position(|a| a == "--").expect("a separator");
        assert_eq!(
            said[separator + 1..],
            [
                "/nix/store/qemu/bin/qemu-img",
                "convert",
                "-f",
                "qcow2",
                "-O",
                "raw",
                "/var/lib/meister/images/noble.qcow2",
                "/var/lib/meister/volumes/v.tmp",
            ]
        );
        let first = said.iter().position(|a| a == "-p").expect("a property");
        assert!(
            said[first..separator]
                .chunks(2)
                .all(|pair| pair.len() == 2 && pair[0] == "-p"),
            "properties come one per -p: {said:?}"
        );
    }

    /// A block device is reached through the device controller, because a
    /// bind mount does not open a device node and `PrivateDevices` would
    /// hide the one the conversion is for.
    #[test]
    fn a_block_destination_is_named_as_a_device_and_not_bound() {
        let node = PathBuf::from("/dev/dm-7");
        let argv = Sandbox::default()
            .argv(
                Path::new("/nix/store/qemu/bin/qemu-img"),
                &Job::Convert {
                    image: &an_image(),
                    src: Path::new("/var/lib/meister/images/noble.qcow2"),
                    dst: Destination::Device(&node),
                },
            )
            .expect("a command line");
        let said = said(&argv);
        assert!(
            said.contains(&"DeviceAllow=/dev/dm-7 rw".to_string()),
            "the one node it may write: {said:?}"
        );
        assert!(
            !said.iter().any(|a| a.starts_with("BindPaths=")),
            "and nothing is bound writable: {said:?}"
        );
        assert!(
            !said.iter().any(|a| a == "PrivateDevices=yes"),
            "a private /dev would hide the node: {said:?}"
        );
        assert!(
            said.contains(&"BindReadOnlyPaths=/var/lib/meister/images/noble.qcow2".to_string()),
            "the image is still read-only: {said:?}"
        );
    }

    /// The probe is inside the same boundary — same parser, same file — and
    /// it may write nothing at all.
    #[test]
    fn the_probe_is_in_the_same_sandbox_and_writes_nothing() {
        let argv = Sandbox::default()
            .argv(
                Path::new("/nix/store/qemu/bin/qemu-img"),
                &Job::Probe {
                    src: Path::new("/var/lib/meister/images/noble.qcow2"),
                },
            )
            .expect("a command line");
        let said = said(&argv);
        assert!(
            said.contains(&"User=meister-convert".to_string()),
            "{said:?}"
        );
        assert!(
            said.contains(&"ProtectSystem=strict".to_string()),
            "{said:?}"
        );
        assert!(
            said.contains(&"BindReadOnlyPaths=/var/lib/meister/images/noble.qcow2".to_string()),
            "{said:?}"
        );
        assert!(
            !said
                .iter()
                .any(|a| a.starts_with("BindPaths=") || a.starts_with("DeviceAllow=")),
            "a probe writes nothing: {said:?}"
        );
        // Its own deadline, because `qemu-img info` reads a header.
        assert!(said.contains(&"RuntimeMaxSec=60".to_string()), "{said:?}");
        let separator = said.iter().position(|a| a == "--").expect("a separator");
        assert_eq!(
            said[separator + 1..],
            [
                "/nix/store/qemu/bin/qemu-img",
                "info",
                "--output=json",
                "/var/lib/meister/images/noble.qcow2",
            ]
        );
    }

    /// A path with a colon in it would be two paths to systemd. It is
    /// refused rather than quoted, at the one place that knows.
    #[test]
    fn a_path_a_property_cannot_hold_is_refused() {
        let err = Sandbox::default()
            .argv(
                Path::new("/nix/store/qemu/bin/qemu-img"),
                &Job::Probe {
                    src: Path::new("/var/lib/meister/images/no:ble.qcow2"),
                },
            )
            .expect_err("not a name this node converts");
        assert!(err.contains("colon"), "{err}");
        assert!(err.contains("no:ble.qcow2"), "and names it: {err}");
    }

    /// `systemd-run` and `qemu-img` as shell scripts, so that the whole path
    /// — argv, hand-over, what came back — can be run by a test that is not
    /// root and has no systemd to ask.
    struct Fake {
        temp: tempfile::TempDir,
        chowns: Arc<Mutex<Vec<(PathBuf, u32, u32)>>>,
    }

    impl Fake {
        /// `runs` says whether the fake `systemd-run` starts the command
        /// after `--` or fails the way a node without the account does.
        fn new(runs: bool) -> Self {
            let temp = tempfile::Builder::new()
                .prefix("meister-sandbox-")
                .tempdir()
                .expect("a temp dir");
            std::fs::create_dir_all(temp.path().join("bin")).expect("a bin dir");
            let log = temp.path().join("log").display().to_string();
            let ran = temp.path().join("qemu-ran").display().to_string();
            let systemd_run = if runs {
                format!(
                    "echo \"$@\" >> \"{log}\"\n\
                     while [ $# -gt 0 ] && [ \"$1\" != \"--\" ]; do shift; done\n\
                     shift\n\
                     exec \"$@\"\n"
                )
            } else {
                format!(
                    "echo \"$@\" >> \"{log}\"\n\
                     echo 'Failed to start transient service unit: Unit ... failed' >&2\n\
                     exit 1\n"
                )
            };
            let scripts = [
                ("systemd-run", systemd_run),
                (
                    "qemu-img",
                    format!(
                        "echo \"$@\" >> \"{ran}\"\n\
                         if [ \"$1\" = info ]; then\n\
                         echo '{{\"virtual-size\": 16777216, \"format\": \"qcow2\"}}'\n\
                         fi\n"
                    ),
                ),
            ];
            for (name, body) in scripts {
                let path = temp.path().join("bin").join(name);
                std::fs::write(&path, format!("#!/bin/sh\n{body}")).expect("the script");
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                    .expect("runnable");
            }
            Self {
                temp,
                chowns: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn sandbox(&self) -> Sandbox {
            let chowns = self.chowns.clone();
            Sandbox::new(self.bin("systemd-run")).resolved_as(
                4242,
                4343,
                Arc::new(move |path, uid, gid| {
                    chowns.lock().expect("the recorded hand-overs").push((
                        path.to_path_buf(),
                        uid,
                        gid,
                    ));
                    Ok(())
                }),
            )
        }

        fn bin(&self, name: &str) -> PathBuf {
            self.temp.path().join("bin").join(name)
        }

        /// A file with something in it, under the fake's own directory.
        fn file(&self, name: &str) -> PathBuf {
            let path = self.temp.path().join(name);
            std::fs::write(&path, b"an image").expect("the bytes");
            path
        }

        /// Whether qemu-img was started at all.
        fn qemu_ran(&self) -> bool {
            self.temp.path().join("qemu-ran").exists()
        }

        fn chowns(&self) -> Vec<(PathBuf, u32, u32)> {
            self.chowns.lock().expect("the recorded hand-overs").clone()
        }
    }

    /// The destination belongs to the converter while it runs and to the
    /// agent again afterwards, and the order is the point.
    #[tokio::test]
    async fn the_destination_is_handed_over_and_taken_back() {
        use std::os::unix::fs::MetadataExt;
        let fake = Fake::new(true);
        let src = fake.file("noble.qcow2");
        let dst = fake.file("v.tmp");
        let mine = std::fs::metadata(&dst).expect("stat");

        convert(
            &fake.sandbox(),
            &fake.bin("qemu-img"),
            &an_image(),
            &src,
            Destination::File(&dst),
            "noble.qcow2",
        )
        .await
        .expect("converted");

        assert_eq!(
            fake.chowns(),
            vec![
                (dst.clone(), 4242, 4343),
                (dst.clone(), mine.uid(), mine.gid()),
            ],
            "given to the converter, then taken back"
        );
        assert!(fake.qemu_ran(), "and the conversion really happened");
    }

    /// A destination that is ALREADY the converter's is what a run that died
    /// halfway leaves. It goes back to the agent and not to the converter,
    /// because the filesystem driver renames that very file into place as
    /// the guest's volume.
    #[tokio::test]
    async fn a_leftover_destination_goes_back_to_the_agent_and_not_to_the_converter() {
        use std::os::unix::fs::MetadataExt;
        let fake = Fake::new(true);
        let src = fake.file("noble.qcow2");
        let dst = fake.file("v.tmp");
        let mine = std::fs::metadata(&dst).expect("stat");
        // The sandbox is told the account resolves to whoever owns the
        // destination, which is the state a crashed run leaves behind.
        let chowns = fake.chowns.clone();
        let sandbox = Sandbox::new(fake.bin("systemd-run")).resolved_as(
            mine.uid(),
            mine.gid(),
            Arc::new(move |path, uid, gid| {
                chowns.lock().expect("the recorded hand-overs").push((
                    path.to_path_buf(),
                    uid,
                    gid,
                ));
                Ok(())
            }),
        );

        convert(
            &sandbox,
            &fake.bin("qemu-img"),
            &an_image(),
            &src,
            Destination::File(&dst),
            "noble.qcow2",
        )
        .await
        .expect("converted");

        let recorded = fake.chowns();
        let back = &recorded[1];
        assert_eq!(
            (back.1, back.2),
            (
                nix::unistd::Uid::effective().as_raw(),
                nix::unistd::Gid::effective().as_raw()
            ),
            "the leftover is given to the agent, not back to the converter"
        );
    }

    /// A destination that cannot be taken back fails the conversion, even
    /// though the bytes are written: a device node still owned by the
    /// converter is what this sandbox exists to prevent.
    #[tokio::test]
    async fn a_destination_that_cannot_be_taken_back_fails_the_conversion() {
        let fake = Fake::new(true);
        let src = fake.file("noble.qcow2");
        let dst = fake.file("v.tmp");
        let calls = Arc::new(Mutex::new(0usize));
        let seen = calls.clone();
        let sandbox = Sandbox::new(fake.bin("systemd-run")).resolved_as(
            4242,
            4343,
            Arc::new(move |_, _, _| {
                let mut seen = seen.lock().expect("the count");
                *seen += 1;
                if *seen == 1 {
                    Ok(())
                } else {
                    Err(std::io::Error::other("no"))
                }
            }),
        );

        let err = convert(
            &sandbox,
            &fake.bin("qemu-img"),
            &an_image(),
            &src,
            Destination::File(&dst),
            "noble.qcow2",
        )
        .await
        .expect_err("the node is not left like that");
        let said = format!("{err}");
        assert!(said.contains("given back"), "{said}");
        assert_eq!(*calls.lock().expect("the count"), 2, "it did try");
    }

    /// No `systemd-run`, no conversion — and no qemu-img either. There is no
    /// road on which the agent reads the image itself.
    ///
    /// Astra finding S01, 2026-09-23: a fallback would mean the most
    /// privileged path is the one that runs when something is wrong.
    #[tokio::test]
    async fn without_systemd_run_the_image_is_refused_rather_than_read_by_the_agent() {
        let fake = Fake::new(true);
        let src = fake.file("noble.qcow2");
        let dst = fake.file("v.tmp");
        // A node that has everything except the one binary this depends on.
        let sandbox = Sandbox::new(fake.bin("no-systemd-run")).resolved_as(
            4242,
            4343,
            Arc::new(|_, _, _| Ok(())),
        );

        let err = convert(
            &sandbox,
            &fake.bin("qemu-img"),
            &an_image(),
            &src,
            Destination::File(&dst),
            "noble.qcow2",
        )
        .await
        .expect_err("refused");
        let said = format!("{err}");
        assert!(said.contains("no-systemd-run"), "{said}");
        assert!(!fake.qemu_ran(), "qemu-img was never started: {said}");
    }

    /// A unit that does not start is a refusal that says so, and again
    /// nothing runs outside the sandbox.
    #[tokio::test]
    async fn a_unit_that_does_not_start_is_a_refusal_and_not_a_fallback() {
        let fake = Fake::new(false);
        let src = fake.file("noble.qcow2");
        let dst = fake.file("v.tmp");

        let err = probe(&fake.sandbox(), &fake.bin("qemu-img"), &src, "noble.qcow2")
            .await
            .expect_err("refused");
        let said = format!("{err:#}");
        assert!(
            said.contains("Failed to start transient service unit"),
            "{said}"
        );
        assert!(!fake.qemu_ran(), "qemu-img was never started: {said}");

        let err = convert_blocking(
            &fake.sandbox(),
            &fake.bin("qemu-img"),
            &an_image(),
            &src,
            Destination::File(&dst),
            "noble.qcow2",
        )
        .expect_err("refused");
        assert!(!fake.qemu_ran(), "not on the blocking path either: {err}");
        // The destination was still given back, so the failed conversion
        // leaves nothing owned by the converter.
        assert_eq!(fake.chowns().len(), 2, "handed over and taken back: {err}");
    }

    /// What the sandbox printed is what the probe judges.
    #[tokio::test]
    async fn the_probe_reads_what_the_unit_wrote() {
        let fake = Fake::new(true);
        let src = fake.file("noble.qcow2");
        let judged = probe(&fake.sandbox(), &fake.bin("qemu-img"), &src, "noble.qcow2")
            .await
            .expect("measured");
        assert_eq!(judged.virtual_size, 16777216);
        assert_eq!(judged.format, "qcow2");
        assert!(fake.chowns().is_empty(), "a probe hands nothing over");
    }

    /// The sandbox as it really is, on a node that really has one.
    ///
    /// Ignored, and it says why rather than skipping quietly: this needs a
    /// systemd SYSTEM instance, the right to ask it for a transient unit
    /// (root, on this fleet), the `meister-convert` account from
    /// nix/services.nix and a qemu-img. A `--user` unit would not do — a
    /// user manager has no `User=`, no `DeviceAllow=` worth the name and no
    /// account to hand a destination to, so a test built on one would be
    /// green about something else. Run it on an agent node with
    /// `cargo test -p meister-agent-api -- --ignored`.
    #[tokio::test]
    #[ignore = "needs a systemd system instance, root and the meister-convert account"]
    async fn the_sandbox_really_converts_on_a_node() {
        use std::os::unix::fs::MetadataExt;
        let temp = tempfile::tempdir().expect("a temp dir");
        let src = temp.path().join("base.qcow2");
        assert!(
            std::process::Command::new("qemu-img")
                .args(["create", "-f", "qcow2"])
                .arg(&src)
                .arg("16M")
                .status()
                .expect("qemu-img")
                .success()
        );
        // 0755/0644: the converter is not the agent, and it has to be able
        // to walk to the image and read it. On a node that is what
        // `imageDir` is (nix/agent.nix).
        for path in [temp.path(), src.as_path()] {
            let mode = if path.is_dir() { 0o755 } else { 0o644 };
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("mode");
        }
        let dst = temp.path().join("v.tmp");
        std::fs::File::create(&dst).expect("the destination");

        let sandbox = Sandbox::default();
        let image = probe(&sandbox, Path::new("qemu-img"), &src, "base.qcow2")
            .await
            .expect("measured");
        assert_eq!(image.format, "qcow2");
        assert_eq!(image.virtual_size, 16 * 1024 * 1024);

        convert(
            &sandbox,
            Path::new("qemu-img"),
            &image,
            &src,
            Destination::File(&dst),
            "base.qcow2",
        )
        .await
        .expect("converted");

        assert_eq!(
            std::fs::metadata(&dst).expect("stat").len(),
            16 * 1024 * 1024,
            "the raw disk the qcow2 described"
        );
        assert_eq!(
            std::fs::metadata(&dst).expect("stat").uid(),
            nix::unistd::Uid::effective().as_raw(),
            "and the destination belongs to the agent again"
        );
    }

    /// A tool named without a directory is resolved against the AGENT's
    /// PATH, because systemd would resolve it against the manager's.
    #[test]
    fn the_tool_is_handed_over_as_an_absolute_path() {
        let fake = Fake::new(true);
        let found = absolute(Path::new("sh")).expect("sh is somewhere");
        assert!(found.is_absolute(), "{}", found.display());
        assert!(
            absolute(Path::new("meister-no-such-tool-b7f3")).is_err(),
            "and a tool that is nowhere is a sentence, not a spawn"
        );
        assert_eq!(
            absolute(&fake.bin("qemu-img")).expect("it is there"),
            std::fs::canonicalize(fake.bin("qemu-img")).expect("canonical")
        );
    }
}
