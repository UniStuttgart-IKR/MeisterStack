// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Current node faults reported with heartbeats. Conditions are keyed by type;
//! a change replaces the message and recovery removes the entry. Event history
//! belongs to the controller.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;

use tracing::{debug, info, warn};

/// The filesystem containing the agent store returned ENOSPC.
pub const DISK_PRESSURE: &str = "DiskPressure";

/// The store could not complete an operation after I/O recovery.
pub const STORE_UNHEALTHY: &str = "StoreUnhealthy";

/// `cgroup_root` is not a cgroup2 filesystem, so no VM on this node can be
/// killed or torn down through its slice. See [`check_cgroup_root`].
pub const CGROUP_UNUSABLE: &str = "CgroupUnusable";

/// Configured driver requirements are currently unmet. Refreshed on reports;
/// driver registration itself happens at startup.
pub const UNPRIVILEGED: &str = "Unprivileged";

/// A configured device driver could not be built at startup, so its
/// capability is missing. Driver construction happens once, so only a restart
/// with a corrected configuration clears it.
pub const DRIVER_UNAVAILABLE: &str = "DriverUnavailable";

/// A VMM has no matching persisted VM row. The reconciler reports it before
/// cleanup after a grace period; see `sweep_unmanaged_vmms`.
pub const VMM_UNMANAGED: &str = "VmmUnmanaged";

/// Latest message per condition type, ordered for stable reports.
#[derive(Default)]
pub struct Conditions {
    held: Mutex<BTreeMap<&'static str, String>>,
}

impl Conditions {
    /// Raise or update a condition; log only changes.
    pub fn raise(&self, kind: &'static str, message: impl Into<String>) {
        let message = message.into();
        let mut held = self.held.lock().expect("conditions");
        let unchanged = held.get(kind).is_some_and(|said| *said == message);
        if !unchanged {
            // `detail` and not `message`: the latter is tracing's own field
            // for the event text, and a condition that set it would render
            // its sentence where the log line's name belongs.
            warn!(condition = kind, detail = %message, "node condition raised");
            held.insert(kind, message);
        }
    }

    /// Clear a condition; log only when it was present.
    pub fn clear(&self, kind: &'static str) {
        let gone = self.held.lock().expect("conditions").remove(kind);
        if gone.is_some() {
            info!(condition = kind, "node condition cleared");
        }
    }

    /// What the heartbeat carries. Empty on a healthy node.
    pub fn report(&self) -> Vec<proto::NodeCondition> {
        self.held
            .lock()
            .expect("conditions")
            .iter()
            .map(|(kind, message)| proto::NodeCondition {
                r#type: (*kind).to_string(),
                message: message.clone(),
            })
            .collect()
    }

    /// The sentence this node is saying about `kind`, if it is saying one.
    pub fn message(&self, kind: &str) -> Option<String> {
        self.held.lock().expect("conditions").get(kind).cloned()
    }
}

/// Check that the nearest existing ancestor of `cgroup_root` is on cgroup2.
/// Startup and reconciliation refresh the condition without refusing startup.
/// This tests the filesystem type, not delegation permissions or controllers.
pub fn check_cgroup_root(root: &Path, conditions: &Conditions) -> bool {
    let mut measured = root;
    let stat = loop {
        match nix::sys::statfs::statfs(measured) {
            Ok(stat) => break Ok(stat),
            Err(nix::errno::Errno::ENOENT) => match measured.parent() {
                Some(parent) => measured = parent,
                None => break Err(nix::errno::Errno::ENOENT),
            },
            Err(e) => break Err(e),
        }
    };
    // Condition changes are logged by `raise` and `clear`.
    let unusable = |message: String| {
        conditions.raise(CGROUP_UNUSABLE, message);
        false
    };
    match stat {
        Ok(stat) if stat.filesystem_type() == nix::sys::statfs::CGROUP2_SUPER_MAGIC => {
            debug!(cgroup_root = %root.display(), "cgroup2 confirmed at the configured root");
            conditions.clear(CGROUP_UNUSABLE);
            true
        }
        Ok(stat) => unusable(format!(
            "cgroup_root {} is not a cgroup2 filesystem ({} is 0x{:x}, not 0x{:x}); \
             cgroup.kill goes into an ordinary file and rmdir fails with ENOTEMPTY, so no vm \
             on this node can be torn down",
            root.display(),
            measured.display(),
            stat.filesystem_type().0,
            nix::sys::statfs::CGROUP2_SUPER_MAGIC.0,
        )),
        Err(e) => unusable(format!(
            "cgroup_root {} cannot be measured ({e}); whether a vm on this node can be torn \
             down is unknown",
            root.display()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A condition holds while the trouble does, says itself once, and goes
    /// away when it goes away.
    #[test]
    fn a_condition_is_what_is_true_now_and_not_a_history() {
        let c = Conditions::default();
        assert!(c.report().is_empty(), "a healthy node says nothing");

        c.raise(DISK_PRESSURE, "no room in /var/lib/meisterstack");
        c.raise(DISK_PRESSURE, "no room in /var/lib/meisterstack");
        assert_eq!(c.report().len(), 1, "the same trouble twice is one line");
        assert_eq!(c.report()[0].r#type, "DiskPressure");
        assert!(c.report()[0].message.contains("/var/lib/meisterstack"));

        // A second, different fault is a second line, and the order is stable.
        c.raise(STORE_UNHEALTHY, "begin write: Previous I/O error");
        let types: Vec<String> = c.report().into_iter().map(|c| c.r#type).collect();
        assert_eq!(types, vec!["DiskPressure", "StoreUnhealthy"]);

        // Cleared means gone, not "false": what is not said is not true.
        c.clear(DISK_PRESSURE);
        let types: Vec<String> = c.report().into_iter().map(|c| c.r#type).collect();
        assert_eq!(types, vec!["StoreUnhealthy"]);
        assert_eq!(c.message(DISK_PRESSURE), None);

        // Clearing what was never raised is the ordinary healthy pass.
        c.clear(CGROUP_UNUSABLE);
        c.clear(STORE_UNHEALTHY);
        assert!(c.report().is_empty());
    }

    /// An ordinary directory raises CgroupUnusable; a cgroup2 ancestor clears it.
    #[test]
    fn a_cgroup_root_that_is_not_cgroupfs_says_so_at_start_up() {
        let temp = tempfile::tempdir().expect("a temp dir");
        let dir = temp.path().to_path_buf();

        let c = Conditions::default();
        check_cgroup_root(&dir, &c);
        let said = c.message(CGROUP_UNUSABLE).expect("the node says it");
        assert!(
            said.contains("not a cgroup2 filesystem") && said.contains("ENOTEMPTY"),
            "the sentence says what will go wrong: {said}"
        );

        // Check the parent filesystem when the configured directory does not yet exist.
        let c = Conditions::default();
        check_cgroup_root(&dir.join("meisterstack"), &c);
        assert!(c.message(CGROUP_UNUSABLE).is_some());

        // Check the host mount only when it is available as cgroup2.
        let host = Path::new("/sys/fs/cgroup");
        let cgroup2 = nix::sys::statfs::statfs(host)
            .map(|s| s.filesystem_type() == nix::sys::statfs::CGROUP2_SUPER_MAGIC)
            .unwrap_or(false);
        if cgroup2 {
            let c = Conditions::default();
            c.raise(CGROUP_UNUSABLE, "left over from a previous look");
            check_cgroup_root(&host.join("meisterstack-that-is-not-there"), &c);
            assert!(
                c.report().is_empty(),
                "a cgroup2 mount is what this node needs, and saying nothing is how it says so"
            );
        }
    }
}
