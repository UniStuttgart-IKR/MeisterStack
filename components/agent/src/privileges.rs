// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! What this agent may do on this host, measured rather than assumed.
//!
//! The agent has always been root, and every driver in it was written on that
//! assumption: `lvs` works, `mount` works, a tap can be created, `nft` can be
//! programmed. Run the same binary as an ordinary user and it comes up
//! claiming all of it and fails at the first VM that needs any of it — a node
//! the scheduler keeps placing on, which is the shape of defect the node
//! conditions exist to end.
//!
//! The form is Incus'. Its VM driver answers `Info()` with a `Features` map
//! and one `Error` sentence in plain words (`driver_qemu.go`: "KVM support is
//! missing (no /dev/kvm)"), and the client never has to guess. The content is
//! Podman's: `podman info` publishes the PRIMITIVES — `host.security.
//! capabilities`, `host.cgroupControllers`, `host.idMappings` — and lets the
//! reader draw the conclusion. Both are here: one sentence per driver this
//! node configured and cannot build, and one line of primitives to check the
//! sentences against.
//!
//! Every number in the needs below was MEASURED on 2026-09-16 with a
//! throw-away probe, three times: as an ordinary user with `CapEff=0`, then
//! under `AmbientCapabilities=CAP_NET_ADMIN`, then under `CAP_SYS_ADMIN`,
//! each in a unit with its own network and mount namespace so that a success
//! left nothing behind. Two of the results contradicted what the code had
//! been read to mean, and both are in the table: a router needs
//! `CAP_SYS_ADMIN` and not `CAP_NET_ADMIN`, and device-mapper needs
//! `CAP_DAC_OVERRIDE` beside `CAP_SYS_ADMIN`.
//!
//! What is deliberately NOT here: a build-time switch. No reference does it
//! that way — Docker, Podman, Incus and libvirt ship one binary and decide at
//! run time — and a node whose capabilities depend on how it was compiled is
//! a node whose Hello nobody can predict.

use std::path::Path;
use std::sync::Arc;

/// The capabilities this stack's drivers actually need. Three, and not the
/// whole of `capabilities(7)`: what is not in this list is not needed by
/// anything the agent builds, and adding a fourth should be a measurement
/// rather than a guess.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Capability {
    /// Taps, bridges, VXLAN, and the nftables tap guard.
    NetAdmin,
    /// `mount(2)`, device-mapper ioctls, `unshare(CLONE_NEWNET)`, the vfio
    /// sysfs bind. capabilities(7) on this one: "It can plausibly be called
    /// 'the new root'".
    SysAdmin,
    /// The file permissions in front of those: `/dev/mapper/control` is 0600
    /// root:root and `/run/lock/lvm` is root-only, so `CAP_SYS_ADMIN` alone
    /// gets EACCES before it ever reaches an ioctl (measured).
    DacOverride,
}

impl Capability {
    /// The bit in `CapEff`/`CapAmb`, from `linux/capability.h` — and checked
    /// against the measurement: a unit with `AmbientCapabilities=
    /// CAP_NET_ADMIN` showed `CapEff: 0000000000001000`, one with
    /// `CAP_SYS_ADMIN` `0000000000200000`.
    const fn bit(self) -> u64 {
        match self {
            Self::DacOverride => 1 << 1,
            Self::NetAdmin => 1 << 12,
            Self::SysAdmin => 1 << 21,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::DacOverride => "CAP_DAC_OVERRIDE",
            Self::NetAdmin => "CAP_NET_ADMIN",
            Self::SysAdmin => "CAP_SYS_ADMIN",
        }
    }
}

/// Why a device node cannot be used — and it matters which, because the two
/// produce the SAME errno at the driver that shells out to a tool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Denial {
    /// The node is not there at all. On a Linux host that almost always means
    /// a module nobody loaded (`/dev/nvme-fabrics` without `nvme_tcp`), and
    /// the fix is `boot.kernelModules`, not a permission.
    Absent,
    /// It is there and this process may not open it. The fix is a group.
    Refused(String),
}

/// What a driver needs from the host before it is worth registering.
///
/// `'static` and a table entry rather than a method on the driver, for the
/// reason `DriverEntry` exists at all: a need that lived in the driver would
/// have to be asked by building the driver, and building is the thing that
/// fails.
#[derive(Debug)]
pub struct Needs {
    /// All of them, not any of them.
    pub caps: &'static [Capability],
    /// Openable read/write. A trailing `*` is a glob over one directory —
    /// `/dev/dri/renderD*` is a node whose number nobody can write down in
    /// advance.
    pub devices: &'static [&'static str],
    /// The half sentence after "needs", in the voice of Incus' `Error`
    /// field: "CAP_SYS_ADMIN for device-mapper".
    pub what: &'static str,
    /// What this node LOSES when the driver is left out — set only where
    /// that is a promise somebody made and not just a feature nobody gets.
    /// See `TAPS`.
    pub then: Option<&'static str>,
}

impl Needs {
    /// The sentence this node owes about `driver`, or `None` when it has
    /// everything the driver needs.
    pub fn missing(&self, driver: &str, rights: &dyn Probe) -> Option<String> {
        let then = |s: &mut String| {
            if let Some(then) = self.then {
                s.push_str("; ");
                s.push_str(then);
            }
        };
        for cap in self.caps {
            if !rights.holds(*cap) {
                let mut said = format!(
                    "{driver}: needs {}; running as uid {} without it",
                    self.what,
                    rights.euid()
                );
                then(&mut said);
                return Some(said);
            }
        }
        for device in self.devices {
            match rights.opens(device) {
                Ok(()) => {}
                // The two causes of one symptom, told apart. A driver that
                // shells out to `nvme` or `lvs` reports both as the same
                // ENOENT from the tool, which is how "the module is not
                // loaded" gets read as "wrong permissions" for an hour.
                Err(Denial::Absent) => {
                    let mut said = format!(
                        "{driver}: needs {device}, which does not exist on this node; \
                         that is a module nobody loaded and not a permission"
                    );
                    then(&mut said);
                    return Some(said);
                }
                Err(Denial::Refused(why)) => {
                    let mut said = format!(
                        "{driver}: needs {device} and may not open it ({why}); running as uid \
                         {} — put that user in the group that owns the node",
                        rights.euid()
                    );
                    then(&mut said);
                    return Some(said);
                }
            }
        }
        None
    }
}

/// A driver that needs nothing of the host: `filesystem` (files and
/// `qemu-img`), `nvmeof-import` (files in its state directory), `input`
/// (whose `fifo` profile is a named pipe the driver makes itself — the
/// `evdev` profile needs `/dev/input/eventN` and that is a property of the
/// profile, not of the driver; see the report).
pub static NOTHING: Needs = Needs {
    caps: &[],
    devices: &[],
    what: "",
    then: None,
};

/// Measured: `open("/dev/kvm", O_RDWR)` as an ordinary user with `CapEff=0`
/// succeeds — here the node is 0666 root:kvm. On a node where it is 0660 the
/// group `kvm` decides, which is why the unit carries
/// `SupplementaryGroups=kvm` and not a capability.
pub static KVM: Needs = Needs {
    caps: &[],
    devices: &["/dev/kvm"],
    what: "/dev/kvm",
    then: None,
};

/// Measured: `TUNSETIFF` on a new name is EPERM as an ordinary user and
/// succeeds under `CAP_NET_ADMIN` alone; so does `RTM_NEWLINK` for a vxlan
/// link, and so does `nft -f -`. Under `CAP_SYS_ADMIN` all three are EPERM —
/// the capability is exactly the right one and exactly enough.
///
/// `then` is the security sentence, and it is the reason this row has one:
/// the mac-pinning and anti-spoofing guard is promised for every VM this
/// stack boots (`drivers/linux-network/src/nftables.rs`), and a node that
/// cannot write those rules is a node where the promise does not hold. It is
/// said out loud rather than quietly dropped.
pub static TAPS: Needs = Needs {
    caps: &[Capability::NetAdmin],
    devices: &["/dev/net/tun"],
    what: "CAP_NET_ADMIN for taps, bridges, vxlan and the nftables tap guard",
    then: Some("tap guard off: guests on this node are not filtered"),
};

/// The router half of the same driver, and NOT a driver of its own — which is
/// why it is screened separately (see `drivers::screen`).
///
/// Measured, and it corrects the halt report: `unshare(CLONE_NEWNET)` is
/// EPERM under `CAP_NET_ADMIN` and succeeds under `CAP_SYS_ADMIN`. A node
/// with `CAP_NET_ADMIN` makes every tap, bridge and overlay it ever made —
/// and cannot hold a tenant router.
pub static ROUTER: Needs = Needs {
    caps: &[Capability::SysAdmin],
    devices: &[],
    what: "CAP_SYS_ADMIN for ip netns (unshare(CLONE_NEWNET) and the bind mount under /run/netns)",
    then: Some("no tenant router can run here, though this node claims network/gateway"),
};

/// Measured: `open("/dev/mapper/control", O_RDWR)` is EACCES as an ordinary
/// user AND under `CAP_SYS_ADMIN` alone (the node is 0600 root:root); with
/// `CAP_SYS_ADMIN CAP_DAC_OVERRIDE` it opens and `lvs` returns 0. Two
/// capabilities, not one.
pub static DEVICE_MAPPER: Needs = Needs {
    caps: &[Capability::SysAdmin, Capability::DacOverride],
    devices: &[],
    what: "CAP_SYS_ADMIN and CAP_DAC_OVERRIDE for device-mapper (lvs, lvcreate, lvremove)",
    then: None,
};

/// Measured: `mount(2)` of a tmpfs is EPERM as an ordinary user and under
/// `CAP_NET_ADMIN`, and succeeds under `CAP_SYS_ADMIN`. The driver shells out
/// to `mount(8)` rather than calling `mount(2)`, which changes nothing about
/// the capability the kernel asks for.
pub static MOUNT: Needs = Needs {
    caps: &[Capability::SysAdmin],
    devices: &[],
    what: "CAP_SYS_ADMIN for mount(2), which mount.nfs needs",
    then: None,
};

/// `nvme connect` writes to `/dev/nvme-fabrics`, which is 0600 root:root on a
/// node that has it — so both halves are needed. Measured here only as
/// `Absent`: this machine has no `nvme_tcp` loaded, which is precisely the
/// case `Denial::Absent` exists to name.
pub static NVME_FABRICS: Needs = Needs {
    caps: &[Capability::SysAdmin, Capability::DacOverride],
    devices: &["/dev/nvme-fabrics"],
    what: "CAP_SYS_ADMIN and CAP_DAC_OVERRIDE for nvme connect",
    then: None,
};

/// Measured: `/dev/vfio/vfio` is 0666 and opens for anybody — the kernel
/// wants it that way ("/dev/vfio/vfio provides no capabilities on its own and
/// is therefore expected to be set to mode 0666"). What does not work is the
/// BIND: `access("/sys/bus/pci/drivers_probe", W_OK)` is EACCES as a user,
/// under `CAP_NET_ADMIN` and under `CAP_SYS_ADMIN` alone.
pub static VFIO_BIND: Needs = Needs {
    caps: &[Capability::SysAdmin, Capability::DacOverride],
    devices: &["/dev/vfio/vfio"],
    what: "CAP_SYS_ADMIN and CAP_DAC_OVERRIDE to bind a device to vfio-pci through sysfs",
    then: None,
};

/// Measured: `open("/dev/dri/renderD128", O_RDWR)` succeeds as an ordinary
/// user here (0666 root:render). On a node where it is 0660 the group
/// `render` decides.
pub static RENDER_NODE: Needs = Needs {
    caps: &[],
    devices: &["/dev/dri/renderD*", "/dev/kvm"],
    what: "a DRM render node",
    then: None,
};

/// The GPU nodes. `/dev/nvidiactl` opened as an ordinary user here; the mdev
/// half of this driver writes sysfs and therefore needs what `VFIO_BIND`
/// needs, which is NOT screened because this machine has no card to measure
/// it on (see the report's "Offen").
pub static NVIDIA: Needs = Needs {
    caps: &[],
    devices: &["/dev/nvidiactl"],
    what: "the nvidia device nodes",
    then: None,
};

/// The rights this process holds, asked one question at a time.
///
/// A trait and not a struct of measurements, so that a test can lie: every
/// interesting case here — an agent with `CAP_NET_ADMIN` and no
/// `CAP_SYS_ADMIN`, a `/dev/kvm` that is there and not openable — is one this
/// machine cannot be put into for the length of a test.
pub trait Probe: Send + Sync {
    /// The effective uid. In the sentences only, and on purpose: `euid == 0`
    /// is not what decides anything here. A root agent holds every
    /// capability and passes every check by holding it, not by being root.
    fn euid(&self) -> u32;

    /// Effective OR ambient. Ambient counts because it is what a child of
    /// this process inherits — and the drivers that need capabilities all
    /// work by shelling out to `lvs`, `mount`, `nft`, `nvme`.
    fn holds(&self, cap: Capability) -> bool;

    fn opens(&self, device: &str) -> Result<(), Denial>;

    /// The primitives, in Podman's `info` spirit: not the verdict, the
    /// numbers the verdict was drawn from. One line at start-up, and an empty
    /// field in it is a statement too.
    fn primitives(&self, cgroup_root: &Path) -> String;
}

/// The real one.
pub struct Host;

impl Probe for Host {
    fn euid(&self) -> u32 {
        nix::unistd::geteuid().as_raw()
    }

    fn holds(&self, cap: Capability) -> bool {
        let (effective, ambient) = cap_sets();
        (effective | ambient) & cap.bit() != 0
    }

    fn opens(&self, device: &str) -> Result<(), Denial> {
        let path = match resolve(device) {
            Some(path) => path,
            None => return Err(Denial::Absent),
        };
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
        {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(Denial::Absent),
            Err(e) => Err(Denial::Refused(e.to_string())),
        }
    }

    fn primitives(&self, cgroup_root: &Path) -> String {
        let (effective, ambient) = cap_sets();
        let groups = nix::unistd::getgroups()
            .map(|gids| {
                gids.iter()
                    .map(|gid| match nix::unistd::Group::from_gid(*gid) {
                        Ok(Some(group)) => group.name,
                        _ => gid.as_raw().to_string(),
                    })
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default();
        // The cgroup half of the same line. `cgroup.controllers` of the
        // configured root is the one primitive that says whether a delegated
        // subtree is usable at all — an empty field there is a node that can
        // make slices and limit nothing in them.
        let controllers = std::fs::read_to_string(cgroup_root.join("cgroup.controllers"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let writable = nix::unistd::access(cgroup_root, nix::unistd::AccessFlags::W_OK).is_ok();
        format!(
            "euid={} CapEff={effective:016x} CapAmb={ambient:016x} groups=[{groups}] \
             cgroup_root={} writable={writable} controllers=[{controllers}]",
            self.euid(),
            cgroup_root.display(),
        )
    }
}

/// `CapEff` and `CapAmb` out of `/proc/self/status`.
///
/// Read there and not through `capget(2)`, because that is where an operator
/// reads them too: a sentence this agent says about its own rights has to be
/// checkable with `grep Cap /proc/<pid>/status` and nothing else.
fn cap_sets() -> (u64, u64) {
    let mut effective = 0;
    let mut ambient = 0;
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines() {
            let hex = |rest: &str| u64::from_str_radix(rest.trim(), 16).unwrap_or(0);
            if let Some(rest) = line.strip_prefix("CapEff:") {
                effective = hex(rest);
            } else if let Some(rest) = line.strip_prefix("CapAmb:") {
                ambient = hex(rest);
            }
        }
    }
    (effective, ambient)
}

/// A device path, with a trailing `*` resolved against its directory.
///
/// `/dev/dri/renderD*` is the honest spelling: which number the render node
/// has is a property of the host's boot order, and a config that had to name
/// it would be wrong on the next machine.
fn resolve(device: &str) -> Option<std::path::PathBuf> {
    let Some(prefix) = device.strip_suffix('*') else {
        return Some(std::path::PathBuf::from(device));
    };
    let path = Path::new(prefix);
    let (dir, stem) = (path.parent()?, path.file_name()?.to_str()?);
    let mut matches: Vec<_> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(stem))
        })
        .collect();
    // Sorted, so that a host with two render nodes gets the same answer on
    // every start rather than whatever the directory happened to list first.
    matches.sort();
    matches.into_iter().next()
}

/// One driver this node configured, and what it needs — kept so that the
/// heartbeat can ask the same question again.
pub struct Watched {
    pub driver: &'static str,
    pub needs: &'static Needs,
}

/// The `Unprivileged` condition, re-measured on every report.
///
/// Level-triggered, like every other condition in this agent: a condition
/// here is a statement about NOW and not a log of what was once true
/// (`conditions.rs`, and the controller's `ingest.rs` reads them that way).
/// The rights of a running process barely change — but the things they are
/// measured against do: a udev rule that arrives late, a `/dev/nvme-fabrics`
/// that appears when the module loads, a group added to the unit and a
/// restart that has not happened yet. Measuring once at start-up would make
/// the report a statement about the second the agent came up, which is the
/// exact defect `check_cgroup_root` was moved into the reconcile loop to fix.
pub struct Watch {
    rights: Arc<dyn Probe>,
    watched: Vec<Watched>,
}

impl Watch {
    pub fn new(rights: Arc<dyn Probe>, watched: Vec<Watched>) -> Self {
        Self { rights, watched }
    }

    /// Raise or drop the condition, by what is true right now.
    pub fn refresh(&self, conditions: &crate::conditions::Conditions) {
        let gaps: Vec<String> = self
            .watched
            .iter()
            .filter_map(|w| w.needs.missing(w.driver, self.rights.as_ref()))
            .collect();
        if gaps.is_empty() {
            conditions.clear(crate::conditions::UNPRIVILEGED);
        } else {
            // One condition, the sentences joined: the controller gets ONE
            // statement per type (`conditions.rs`), and a node missing three
            // drivers is one unprivileged node and not three conditions.
            conditions.raise(crate::conditions::UNPRIVILEGED, gaps.join(" | "));
        }
    }
}

#[cfg(test)]
pub mod fake {
    //! Rights this machine cannot be put into for the length of a test.

    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    pub struct Fake {
        pub euid: u32,
        pub caps: Vec<Capability>,
        /// Missing from the map = there and openable. This way a test names
        /// only what it wants to be wrong.
        pub devices: HashMap<String, Denial>,
    }

    impl Fake {
        /// An agent with nothing: uid 1000, no capability, every device
        /// openable. The starting point of every test below.
        pub fn unprivileged() -> Self {
            Self {
                euid: 1000,
                caps: Vec::new(),
                devices: HashMap::new(),
            }
        }

        pub fn with(mut self, cap: Capability) -> Self {
            self.caps.push(cap);
            self
        }

        pub fn without_device(mut self, device: &str, why: Denial) -> Self {
            self.devices.insert(device.to_string(), why);
            self
        }

        /// Every capability there is — the agent as root, as far as anything
        /// here can tell.
        pub fn root() -> Self {
            Self {
                euid: 0,
                caps: vec![
                    Capability::NetAdmin,
                    Capability::SysAdmin,
                    Capability::DacOverride,
                ],
                devices: HashMap::new(),
            }
        }
    }

    impl Probe for Fake {
        fn euid(&self) -> u32 {
            self.euid
        }
        fn holds(&self, cap: Capability) -> bool {
            self.caps.contains(&cap)
        }
        fn opens(&self, device: &str) -> Result<(), Denial> {
            match self.devices.get(device) {
                Some(denial) => Err(denial.clone()),
                None => Ok(()),
            }
        }
        fn primitives(&self, _cgroup_root: &Path) -> String {
            format!("euid={} caps={:?} (fake)", self.euid, self.caps)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fake::Fake;
    use super::*;

    /// The sentence names the driver, the need and the fact — Incus' `Error`
    /// field, in words an operator can act on.
    #[test]
    fn a_missing_capability_is_one_sentence() {
        let said = DEVICE_MAPPER
            .missing("lvm-thin", &Fake::unprivileged())
            .expect("it is missing");
        assert!(said.starts_with("lvm-thin: needs CAP_SYS_ADMIN"), "{said}");
        assert!(said.contains("device-mapper"), "{said}");
        assert!(said.contains("uid 1000"), "{said}");
    }

    /// Both capabilities, not either: that is the measurement.
    #[test]
    fn one_of_two_capabilities_is_not_enough() {
        let half = Fake::unprivileged().with(Capability::SysAdmin);
        assert!(DEVICE_MAPPER.missing("lvm-thin", &half).is_some());
        let both = half.with(Capability::DacOverride);
        assert!(DEVICE_MAPPER.missing("lvm-thin", &both).is_none());
    }

    /// The network driver's sentence carries the security statement, because
    /// what is lost with it is a promise and not a feature.
    #[test]
    fn the_tap_guard_says_what_falls_with_it() {
        let said = TAPS
            .missing("linux", &Fake::unprivileged())
            .expect("it is missing");
        assert!(said.contains("CAP_NET_ADMIN"), "{said}");
        assert!(
            said.contains("tap guard off: guests on this node are not filtered"),
            "{said}"
        );
        // And with the capability, nothing is said at all.
        assert!(
            TAPS.missing("linux", &Fake::unprivileged().with(Capability::NetAdmin))
                .is_none()
        );
    }

    /// A router is not a tap: measured, and the sentence says which one it
    /// needs.
    #[test]
    fn a_router_needs_more_than_the_taps_do() {
        let net = Fake::unprivileged().with(Capability::NetAdmin);
        assert!(TAPS.missing("linux", &net).is_none());
        let said = ROUTER.missing("router", &net).expect("still missing");
        assert!(said.contains("CAP_SYS_ADMIN"), "{said}");
        assert!(said.contains("unshare(CLONE_NEWNET)"), "{said}");
    }

    /// The two causes of one ENOENT are two different sentences with two
    /// different fixes.
    #[test]
    fn a_device_that_is_not_there_is_not_a_permission() {
        let absent = Fake::root().without_device("/dev/nvme-fabrics", Denial::Absent);
        let said = NVME_FABRICS
            .missing("nvmeof", &absent)
            .expect("it is missing");
        assert!(said.contains("does not exist on this node"), "{said}");
        assert!(said.contains("not a permission"), "{said}");

        let refused = Fake::root().without_device(
            "/dev/nvme-fabrics",
            Denial::Refused("Permission denied (os error 13)".into()),
        );
        let said = NVME_FABRICS
            .missing("nvmeof", &refused)
            .expect("it is missing");
        assert!(said.contains("may not open it"), "{said}");
        assert!(said.contains("group that owns the node"), "{said}");
    }

    /// The hypervisor needs no capability at all — only a device. That is the
    /// whole reason a node without root can run a guest.
    #[test]
    fn a_guest_needs_a_device_and_not_a_capability() {
        assert!(
            KVM.missing("cloud-hypervisor", &Fake::unprivileged())
                .is_none()
        );
        let said = KVM
            .missing(
                "cloud-hypervisor",
                &Fake::unprivileged()
                    .without_device("/dev/kvm", Denial::Refused("Permission denied".into())),
            )
            .expect("no kvm, no vms");
        assert!(said.contains("/dev/kvm"), "{said}");
    }

    /// Nothing needs nothing, whoever asks.
    #[test]
    fn the_drivers_that_need_nothing_say_nothing() {
        assert!(
            NOTHING
                .missing("filesystem", &Fake::unprivileged())
                .is_none()
        );
        assert!(NOTHING.missing("input", &Fake::unprivileged()).is_none());
    }

    /// The condition is what is true now: raised while a right is missing,
    /// dropped when it is there.
    #[test]
    fn the_condition_follows_the_rights() {
        let conditions = crate::conditions::Conditions::default();
        let watched = || {
            vec![
                Watched {
                    driver: "lvm-thin",
                    needs: &DEVICE_MAPPER,
                },
                Watched {
                    driver: "linux",
                    needs: &TAPS,
                },
            ]
        };

        Watch::new(Arc::new(Fake::unprivileged()), watched()).refresh(&conditions);
        let said = conditions
            .message(crate::conditions::UNPRIVILEGED)
            .expect("the node says it");
        assert!(
            said.contains("lvm-thin") && said.contains("linux"),
            "{said}"
        );
        assert_eq!(
            conditions.report().len(),
            1,
            "three missing drivers are one unprivileged node"
        );

        // The same node, with everything: the condition goes away rather
        // than staying as a history of what was once wrong.
        Watch::new(Arc::new(Fake::root()), watched()).refresh(&conditions);
        assert!(conditions.report().is_empty());
    }
}
