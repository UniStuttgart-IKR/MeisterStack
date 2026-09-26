// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Screen configured drivers against host capabilities and device access.
//! Requirements are checked before construction and refreshed as a node
//! condition on reports. These probes are prerequisites, not a complete test
//! of each driver's runtime operations or backend sandbox.

use std::path::Path;
use std::sync::Arc;

/// Linux capabilities represented by the driver prerequisite table.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Capability {
    /// Taps, bridges, VXLAN, and the nftables tap guard.
    NetAdmin,
    /// Mounts, device-mapper ioctls, network namespace creation, and VFIO setup.
    SysAdmin,
    /// Bypass filesystem access checks on privileged control paths.
    DacOverride,
}

impl Capability {
    /// Bit position from the Linux capability definitions.
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

/// Distinguish missing device nodes from denied access.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Denial {
    /// Device node absent, potentially because its kernel module is not loaded.
    Absent,
    /// It is there and this process may not open it. The fix is a group.
    Refused(String),
}

/// Prerequisites available before constructing a driver.
#[derive(Debug)]
pub struct Needs {
    /// All of them, not any of them.
    pub caps: &'static [Capability],
    /// Required read/write device access. A trailing * matches within one directory.
    pub devices: &'static [&'static str],
    /// Description included in a missing-prerequisite message.
    pub what: &'static str,
    /// Optional explanation of the features unavailable without this prerequisite.
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
                // Distinguish a missing device from denied access; external tools may
                // otherwise collapse both into an unhelpful failure.
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

/// No driver-wide capability or device prerequisites. Per-profile and runtime
/// checks may still fail, such as an inaccessible input evdev path.
pub static NOTHING: Needs = Needs {
    caps: &[],
    devices: &[],
    what: "",
    then: None,
};

/// KVM requires read/write access to `/dev/kvm`.
pub static KVM: Needs = Needs {
    caps: &[],
    devices: &["/dev/kvm"],
    what: "/dev/kvm",
    then: None,
};

/// Tap, bridge, VXLAN and nftables setup requires network administration.
pub static TAPS: Needs = Needs {
    caps: &[Capability::NetAdmin],
    devices: &["/dev/net/tun"],
    what: "CAP_NET_ADMIN for taps, bridges, vxlan and the nftables tap guard",
    then: Some("tap guard off: guests on this node are not filtered"),
};

/// Router namespace setup has additional requirements beyond tap creation.
pub static ROUTER: Needs = Needs {
    caps: &[Capability::SysAdmin],
    devices: &[],
    what: "CAP_SYS_ADMIN for ip netns (unshare(CLONE_NEWNET) and the bind mount under /run/netns)",
    then: Some("no tenant router can run here, though this node claims network/gateway"),
};

/// Device-mapper requires administrative ioctls and access to LVM control paths.
pub static DEVICE_MAPPER: Needs = Needs {
    caps: &[Capability::SysAdmin, Capability::DacOverride],
    devices: &[],
    what: "CAP_SYS_ADMIN and CAP_DAC_OVERRIDE for device-mapper (lvs, lvcreate, lvremove)",
    then: None,
};

/// Managed mounts require CAP_SYS_ADMIN.
pub static MOUNT: Needs = Needs {
    caps: &[Capability::SysAdmin],
    devices: &[],
    what: "CAP_SYS_ADMIN for mount(2), which mount.nfs needs",
    then: None,
};

/// NVMe-oF connection setup requires administrative rights and fabrics-device access.
pub static NVME_FABRICS: Needs = Needs {
    caps: &[Capability::SysAdmin, Capability::DacOverride],
    devices: &["/dev/nvme-fabrics"],
    what: "CAP_SYS_ADMIN and CAP_DAC_OVERRIDE for nvme connect",
    then: None,
};

/// VFIO binding also needs write access to PCI sysfs control paths.
pub static VFIO_BIND: Needs = Needs {
    caps: &[Capability::SysAdmin, Capability::DacOverride],
    devices: &["/dev/vfio/vfio"],
    what: "CAP_SYS_ADMIN and CAP_DAC_OVERRIDE to bind a device to vfio-pci through sysfs",
    then: None,
};

/// Require access to a DRM render node and KVM.
pub static RENDER_NODE: Needs = Needs {
    caps: &[],
    devices: &["/dev/dri/renderD*", "/dev/kvm"],
    what: "a DRM render node",
    then: None,
};

/// Probe NVIDIA control-device access. This does not verify mdev sysfs rights.
pub static NVIDIA: Needs = Needs {
    caps: &[],
    devices: &["/dev/nvidiactl"],
    what: "the nvidia device nodes",
    then: None,
};

/// Host prerequisite probes, replaceable in tests.
pub trait Probe: Send + Sync {
    /// Effective UID for diagnostics; capability checks do not special-case root.
    fn euid(&self) -> u32;

    /// Count effective or ambient capabilities; ambient capabilities survive into tool subprocesses.
    fn holds(&self, cap: Capability) -> bool;

    fn opens(&self, device: &str) -> Result<(), Denial>;

    /// Render measured capabilities, groups and cgroup access for diagnostics.
    fn primitives(&self, cgroup_root: &Path) -> String;
}

/// Probes of the running agent process.
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
        // An empty `cgroup.controllers` means this subtree cannot enforce the
        // resource limits, even if it permits directory creation.
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

/// Read effective and ambient capability masks from `/proc/self/status`.
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

/// Resolve a trailing `*` to the first sorted directory entry with that prefix.
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
    // Choose deterministically when several device paths match.
    matches.sort();
    matches.into_iter().next()
}

/// Configured driver prerequisites retained for heartbeat rechecks.
pub struct Watched {
    pub driver: &'static str,
    pub needs: &'static Needs,
}

/// Refresh Unprivileged against current prerequisites. This does not construct
/// a driver omitted during startup; restarting is required to register it.
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
            // Combine all missing prerequisites into one condition of this type.
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

    /// Missing network privileges report the unavailable tap guard.
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

    /// Hypervisor prerequisites require KVM device access without extra capabilities.
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

        // Clear the condition after all prerequisites recover.
        Watch::new(Arc::new(Fake::root()), watched()).refresh(&conditions);
        assert!(conditions.report().is_empty());
    }
}
