// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! What is wrong with this node, said out loud on the heartbeat.
//!
//! The heartbeat used to carry a liveness signal and nothing else: the
//! controller learned that the agent's process was up, and read that as "this
//! node can do things". A chaos run showed what the gap costs. A full root
//! disk wedged the agent's redb handle, every command failed for hours, and
//! `node ls`, the session and `check.sh` all said the same word — READY —
//! while the scheduler kept placing VMs on a machine that could not write a
//! byte.
//!
//! A condition is the node's own statement about a fault it can see and the
//! tier above cannot. Presence IS the statement: it is raised while the
//! trouble holds and dropped when it stops, so nothing here keeps a history —
//! the events one tier up are the history, and a second copy of them would be
//! the worse one.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;

use tracing::{debug, info, warn};

/// The root filesystem this node writes volumes and its own database into has
/// no room. Raised by the store when a write fails with `ENOSPC`.
pub const DISK_PRESSURE: &str = "DiskPressure";

/// The agent's database cannot be written to. Everything this node is asked
/// to do ends in a record, so this is "no commands can be served here",
/// whatever the heartbeat says.
pub const STORE_UNHEALTHY: &str = "StoreUnhealthy";

/// `cgroup_root` is not a cgroup2 filesystem, so no VM on this node can be
/// killed or torn down through its slice. See [`check_cgroup_root`].
pub const CGROUP_UNUSABLE: &str = "CgroupUnusable";

/// A VMM is running here that no record of this agent names.
///
/// D18. "The agent adopts what it has a record of" was only half a rule, and
/// nothing said what became of the other half: a guest whose record went
/// while its process did not is running on a machine nobody manages — it
/// answers no command, appears in no report, and holds its disks and its
/// taps. The lab produced one, a destination whose agent was killed
/// mid-migration and whose VMM finished the transfer into a process nothing
/// was watching.
///
/// It is a condition and not a silent tidy-up because the tier above is the
/// party that can act on it: a node with an unmanaged guest is a node whose
/// free memory is a fiction, and whether to place there is a scheduling
/// decision. The agent ends the process too, but only after a grace and only
/// after having said so — see `reconcile::Reconciler::sweep_unmanaged_vmms`.
pub const VMM_UNMANAGED: &str = "VmmUnmanaged";

/// The conditions this node currently holds, by type.
///
/// One per type and the newest sentence wins: two ENOSPC failures in a row are
/// one `DiskPressure`, not two, and the report is a statement about now rather
/// than a log. A `BTreeMap` and not a `HashMap` so that the reported order is
/// the same on every heartbeat — a controller diffing two reports should see a
/// difference only when something actually changed.
#[derive(Default)]
pub struct Conditions {
    held: Mutex<BTreeMap<&'static str, String>>,
}

impl Conditions {
    /// Raise a condition, or update the sentence of one already raised.
    ///
    /// Logged once per change and not per call: a level-triggered agent says
    /// the same true thing every few seconds, and a WARN on every repetition
    /// would bury the run it belongs to.
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

    /// Drop a condition. Idempotent, and silent when it was not held —
    /// clearing what was never raised is the ordinary case on a healthy node,
    /// which is every pass of every loop that calls this.
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

/// Is `cgroup_root` a cgroup2 filesystem? Asked at start-up and in every
/// reconcile pass afterwards. Answers whether it is.
///
/// D17, found by the migration E2E and true of any misconfigured agent: on a
/// plain directory `kill_slice` writes `cgroup.kill` into a file nothing
/// reads and `destroy_slice` fails with `ENOTEMPTY`, so every teardown hangs,
/// the record stays, and the VM's way back is refused with "this node already
/// has a record of that vm". On real cgroupfs those are kernel pseudo-files
/// and `rmdir` takes them with it — so the difference is invisible until the
/// first delete, and nobody says it at start-up.
///
/// **Not a refusal to start**, deliberately. The local E2E runs exactly like
/// this, on purpose, and an agent that would not come up over it would trade
/// a known limitation for an outage. It is a WARN and a condition: the
/// cluster gets to see that this node cannot tear a VM down, which is what
/// makes it a scheduling decision one tier up (C1) rather than a surprise
/// three commands later.
///
/// **And it is asked again, every pass.** Once at start-up made it a
/// statement about the second the agent came up, and a `/sys/fs/cgroup` that
/// was unmounted, remounted or shadowed while the agent ran was something
/// nobody said a word about until the first delete hung — the exact shape of
/// the original defect, with a start-up check in front of it. It is a level
/// condition like every other one here: raised while the trouble holds,
/// dropped when it stops, and `Conditions` says either only when it changes,
/// so a pass every thirty seconds writes no log line at all on a healthy
/// node. One `statfs` per pass is nothing next to the probe of every VM the
/// same pass already makes.
///
/// The nearest EXISTING ancestor is what gets measured. `cgroup_root` is
/// created on demand by the first `create_slice`, so on a healthy node it
/// frequently does not exist yet at start-up — and a filesystem is a property
/// of the mount, so a directory that will be made under a cgroup2 parent is
/// cgroup2 too.
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
    // The raise is the WARN — see `Conditions::raise`, which says it once
    // per change rather than once per look. The healthy branch is DEBUG for
    // the same reason, now that this runs every pass: `clear` already says
    // "node condition cleared" at INFO on the pass that recovers, which is
    // the only healthy look worth a line.
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

    /// A `cgroup_root` that is not cgroupfs is a node that cannot tear a VM
    /// down, and the cluster gets told.
    ///
    /// D17: on an ordinary directory `cgroup.kill` is a file nobody reads and
    /// `rmdir` fails with ENOTEMPTY, so every teardown hangs and the record
    /// stays behind — and the first anybody hears of it is a VM that cannot
    /// come back. The agent still starts: the local E2E is configured exactly
    /// this way on purpose.
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

        // A directory that does not exist YET is measured by its parent: the
        // first `create_slice` makes it, and a filesystem is a property of the
        // mount rather than of the directory.
        let c = Conditions::default();
        check_cgroup_root(&dir.join("meisterstack"), &c);
        assert!(c.message(CGROUP_UNUSABLE).is_some());

        // And on this machine's real cgroup2 mount, nothing is said. Guarded,
        // because a test that assumed the host's mounts would be a test about
        // the host.
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
