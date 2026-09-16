// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

use agent_api::{CgroupHandle, ConfinerResult, ResourceConfiner, ResourceLimits};
use std::path::{Path, PathBuf};
use tracing::{debug, instrument, warn};

/// The subgroup this process moves itself into when `cgroup_root` is its own
/// delegated subtree. systemd's own name for it — `CGROUP_DELEGATION.md`
/// names the pair `supervisor/` and `payload-xyz/` — and the same string
/// `nix/agent.nix` passes to `DelegateSubgroup=`, so that the two ways of
/// getting there end in one directory and not in two.
pub const SUPERVISOR: &str = "supervisor";

/// This driver only supports Linux cgroups_v2
pub struct CgroupV2 {
    root: PathBuf,
    /// This process's OWN cgroup, absolute, or `None` when it could not be
    /// read.
    ///
    /// It is what tells a delegated subtree from the mount root: an agent
    /// whose own cgroup IS `root`, or lies under it, was handed that subtree
    /// by `Delegate=` in its unit, and everything above it belongs to
    /// systemd. An agent running as root with
    /// `cgroup_root = /sys/fs/cgroup/meisterstack` sits in
    /// `system.slice/meister-agent.service`, which is neither — and for it
    /// nothing in this file changes.
    own: Option<PathBuf>,
}

impl CgroupV2 {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            own: own_cgroup(),
        }
    }

    /// Pretend this process sits in `own`. For the tests, which stand a
    /// cgroupfs up in a temp directory and cannot move themselves into it.
    pub fn with_own_cgroup(mut self, own: Option<PathBuf>) -> Self {
        self.own = own;
        self
    }

    /// Is `dir` at or above this process's own cgroup — a delegation root
    /// whose parent is not ours to write?
    ///
    /// Asked of `dir` and not of `self.root`, because `create_slice` climbs
    /// from whatever parent it was handed: a nested slice UNDER the root is
    /// inside the delegated subtree and the climb out of it lands inside it
    /// too. The one climb that crosses the boundary is the one out of the
    /// root itself.
    fn hands_off_above(&self, dir: &Path) -> bool {
        self.own
            .as_ref()
            .is_some_and(|own| own == dir || own.starts_with(dir))
    }

    /// Move this process into `<root>/supervisor`, so that the root's own
    /// `cgroup.subtree_control` can be written at all.
    ///
    /// cgroup v2 forbids processes in an inner node, and the price is not a
    /// formality. Measured on this machine (2026-09-16, kernel 7.2.4, in a
    /// `systemd-run --user -p Delegate=yes --scope`): `+memory` on the
    /// scope's own `cgroup.subtree_control` while the scope still holds
    /// processes is **EBUSY**, and until that write succeeds a child has no
    /// `memory.max` FILE at all — whereupon cgroupfs answers the write with
    /// **EACCES**, not ENOENT, because a name it does not know cannot be
    /// created. That is the whole of the report's unexplained finding 5: not
    /// a permission that was missing, a file that was not there.
    ///
    /// Three cases, and only the first one does anything:
    ///
    /// * own cgroup IS the root — an agent under `Delegate=` without
    ///   `DelegateSubgroup=`. It moves, and the caller says so.
    /// * own cgroup is already BELOW the root — `DelegateSubgroup=supervisor`
    ///   (systemd 254+) did it, or a test rig did. Nothing to do, and a
    ///   second subgroup would only be a second place to look.
    /// * own cgroup is somewhere else entirely — the agent as root with
    ///   `cgroup_root = /sys/fs/cgroup/meisterstack`. Not its subtree and
    ///   not its business.
    pub fn join_supervisor_subgroup(&mut self) -> std::io::Result<Option<PathBuf>> {
        let Some(own) = self.own.clone() else {
            return Ok(None);
        };
        if own != self.root {
            return Ok(None);
        }
        let sup = self.root.join(SUPERVISOR);
        std::fs::create_dir_all(&sup)?;
        // The whole process and not one thread: writing a pid into
        // `cgroup.procs` migrates every thread of it, which is what makes
        // this safe to do after the runtime has started.
        std::fs::write(sup.join("cgroup.procs"), std::process::id().to_string())?;
        self.own = Some(sup.clone());
        Ok(Some(sup))
    }
}

/// This process's cgroup as an absolute path, from `/proc/self/cgroup` and
/// the cgroup2 mount it is relative to.
///
/// `None` on anything unexpected — no unified line, no cgroup2 mount — and
/// `None` means "claim no delegated subtree", so an unreadable `/proc`
/// leaves the behaviour this driver has always had rather than guessing at a
/// new one.
fn own_cgroup() -> Option<PathBuf> {
    let relative = std::fs::read_to_string("/proc/self/cgroup")
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("0::").map(str::to_string))?;
    let mount = cgroup2_mount()?;
    Some(mount.join(relative.trim().trim_start_matches('/')))
}

/// Where cgroup2 is mounted. Read and not assumed: `/sys/fs/cgroup` is a
/// convention, and libvirt says the same thing of itself ("Libvirt will
/// never attempt to mount any controllers itself, merely detect where they
/// are mounted").
fn cgroup2_mount() -> Option<PathBuf> {
    let mounts = std::fs::read_to_string("/proc/self/mounts").ok()?;
    mounts.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let _device = fields.next()?;
        let point = fields.next()?;
        (fields.next()? == "cgroup2").then(|| PathBuf::from(point))
    })
}

impl ResourceConfiner for CgroupV2 {
    #[instrument(skip_all, fields(slice = %name, ?limits))]
    fn create_slice(
        &self,
        name: &str,
        parent: Option<&CgroupHandle>,
        limits: &ResourceLimits,
    ) -> ConfinerResult<CgroupHandle> {
        use agent_api::ConfinerError;
        let at = |path: std::path::PathBuf| move |source| ConfinerError::IoAt { path, source };

        let parent_dir = parent
            .map(|p| p.path.clone())
            .unwrap_or_else(|| self.root.clone());
        std::fs::create_dir_all(&parent_dir).map_err(at(parent_dir.clone()))?;

        // Enabling a controller that the PARENT does not delegate is ENOENT
        // in cgroup v2 — and right after boot systemd has not filled the
        // mount root's subtree_control yet (hit on the lab's NixOS agent
        // VMs: the first create per boot failed, later ones worked). Make
        // the delegation explicit instead of racing systemd.
        //
        // NOT above a delegation root. This one write is the whole of what
        // an unprivileged agent cannot do: `/sys/fs/cgroup` is not writable
        // for anybody but root, and the parent of a `Delegate=` unit's
        // cgroup belongs to systemd — so the climb is EACCES there, and an
        // EACCES here would mean no VM on such a node could be confined at
        // all. Inside the handed subtree nothing is missing that this write
        // could add: what `Delegate=` did not hand over cannot be taken.
        let controllers = parent_dir.join("cgroup.controllers");
        let have = std::fs::read_to_string(&controllers).unwrap_or_default();
        let missing = !have.contains("cpu") || !have.contains("memory");
        if missing && !self.hands_off_above(&parent_dir) {
            if let Some(grandparent) = parent_dir.parent() {
                let gp_subtree = grandparent.join("cgroup.subtree_control");
                std::fs::write(&gp_subtree, "+cpu +memory").map_err(at(gp_subtree.clone()))?;
            }
        } else if missing {
            debug!(root = %parent_dir.display(), controllers = %have.trim(),
                   "a delegated subtree is not climbed out of");
        }

        let subtree = parent_dir.join("cgroup.subtree_control");
        std::fs::write(&subtree, "+cpu +memory").map_err(|source| {
            // The same ENOENT, two causes, and only one of them is something
            // an operator can act on (the reference study asked for the
            // distinction, and the measurement of finding 5 is where the
            // second sentence comes from). Said HERE rather than left to a
            // bare errno, because this is the one call that knows which of
            // the two it is looking at.
            if missing && self.hands_off_above(&parent_dir) {
                ConfinerError::Io(std::io::Error::other(format!(
                    "{}: the cpu and memory controllers were never delegated to this agent \
                     (its subtree offers {:?}), so no vm here can be given a limit: add them \
                     to Delegate= in the unit. This is not the boot-time race the same errno \
                     means for a root agent — {source}",
                    subtree.display(),
                    have.trim(),
                )))
            } else {
                at(subtree.clone())(source)
            }
        })?;

        // The CPU pinning is a property of this AGENT, not of one VM, so it
        // goes on the parent slice: in cgroup v2 a child whose `cpuset.cpus`
        // is empty runs on whatever its parent's effective set is, which is
        // exactly the inheritance wanted here. Written on every create rather
        // than once at start-up because create is the only call that knows
        // the parent directory exists — and writing the same value again is
        // what "level-triggered" means everywhere else in this stack.
        //
        // `cpuset` has to be delegated from a tier further up before it can
        // be set here, and it is delegated separately from cpu and memory
        // (systemd hands out what it was asked for). Best effort in both
        // places: a host whose root cgroup does not offer cpuset at all is a
        // host where the pinning cannot work, and refusing to start a VM over
        // it would turn a lost optimisation into an outage.
        if let Some(cpus) = &limits.cpuset {
            // And the same boundary as above: a delegated subtree is not
            // climbed out of. A `user@.service` never carries cpuset at all
            // (measured: `user.slice` offers it, `user@1000.service` does
            // not), which is why the agent's unit is a SYSTEM unit — and
            // there `Delegate=cpuset` is what puts it in reach, not a write
            // one tier up.
            if !self.hands_off_above(&parent_dir)
                && let Some(grandparent) = parent_dir.parent()
            {
                let gp_subtree = grandparent.join("cgroup.subtree_control");
                if let Err(e) = std::fs::write(&gp_subtree, "+cpuset") {
                    warn!(path = %gp_subtree.display(), error = %format!("{e:#}"),
                          "could not delegate the cpuset controller");
                }
            }
            let p = parent_dir.join("cpuset.cpus");
            match std::fs::write(&p, cpus) {
                Ok(()) => debug!(path = %p.display(), cpus = %cpus, "parent slice pinned"),
                Err(e) => warn!(path = %p.display(), cpus = %cpus, error = %format!("{e:#}"),
                                "could not pin the parent slice, vms run unpinned"),
            }
        }

        let dir = parent_dir.join(name);
        std::fs::create_dir_all(&dir).map_err(at(dir.clone()))?;

        if let Some(bytes) = limits.memory_max {
            let p = dir.join("memory.max");
            std::fs::write(&p, bytes.to_string()).map_err(at(p))?;
        }

        if let Some(pct) = limits.cpu_quota {
            let period = 100_000u64; // µs
            let quota = period * pct as u64 / 100; // 200% -> "200000 100000"
            let p = dir.join("cpu.max");
            std::fs::write(&p, format!("{quota} {period}")).map_err(at(p))?;
        }
        Ok(CgroupHandle { path: dir })
    }

    fn open_slice(&self, name: &str) -> CgroupHandle {
        CgroupHandle {
            path: self.root.join(name),
        }
    }

    #[instrument(skip_all, fields(slice = %cg.path.display()))]
    fn destroy_slice(&self, cg: &CgroupHandle) -> ConfinerResult<()> {
        use std::io::ErrorKind;
        for attempt in 0..10 {
            match std::fs::remove_dir(&cg.path) {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
                Err(e) if e.raw_os_error() == Some(libc::EBUSY) && attempt < 9 => {
                    warn!(path = %cg.path.display(), attempt, "cgroup busy, retrying");
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
                Err(e) => return Err(e.into()),
            }
        }
        unreachable!()
    }

    #[instrument(level = "trace", skip_all, fields(slice = %name))]
    fn pids_in_slice(&self, name: &str) -> ConfinerResult<Vec<u32>> {
        match std::fs::read_to_string(self.root.join(name).join("cgroup.procs")) {
            Ok(s) => Ok(s.lines().filter_map(|l| l.trim().parse().ok()).collect()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e.into()),
        }
    }

    #[instrument(skip_all, fields(slice = %name))]
    fn kill_slice(&self, name: &str) -> ConfinerResult<()> {
        match std::fs::write(self.root.join(name).join("cgroup.kill"), "1") {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// The configured `cgroup_root`. This driver is the one that writes
    /// `cgroup.subtree_control` and `cgroup.kill` into it, so it is the one
    /// that can say where "it" is.
    fn root(&self) -> Option<&std::path::Path> {
        Some(&self.root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_api::ResourceLimits;

    /// A directory tree that stands in for cgroupfs: the two pseudo-files
    /// this driver reads and writes, and a parent above the root so that a
    /// climb over the boundary would leave a trace.
    ///
    /// An ordinary filesystem cannot reproduce the KERNEL's answers (a write
    /// to `cgroup.subtree_control` here always succeeds, where the real one
    /// is EBUSY while processes sit in the cgroup). What it reproduces is the
    /// only thing these tests are about: WHICH file this driver writes.
    fn fake_cgroupfs(controllers: &str) -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().expect("a temp dir");
        let above = temp.path().join("above");
        let root = above.join("meister-agent.service");
        std::fs::create_dir_all(&root).expect("the tree");
        std::fs::write(above.join("cgroup.subtree_control"), "").expect("the parent's file");
        std::fs::write(root.join("cgroup.controllers"), controllers).expect("the root's file");
        std::fs::write(root.join("cgroup.subtree_control"), "").expect("the root's file");
        (temp, root)
    }

    fn said_above(root: &Path) -> String {
        std::fs::read_to_string(root.parent().unwrap().join("cgroup.subtree_control"))
            .expect("the parent's file")
    }

    /// The one write that crosses a delegation boundary does not happen when
    /// the root IS the delegation root.
    #[test]
    fn a_delegated_root_is_not_climbed_out_of() {
        // `memory pids`, which is what a user session's own cgroup offers —
        // no cpu, so the old code would climb.
        let (_temp, root) = fake_cgroupfs("memory pids");
        let cg = CgroupV2::new(&root).with_own_cgroup(Some(root.clone()));

        let limits = ResourceLimits {
            memory_max: Some(1 << 20),
            cpu_quota: Some(200),
            cpuset: Some("0-3".to_string()),
        };
        let handle = cg.create_slice("vm-1", None, &limits).expect("a slice");

        assert_eq!(
            said_above(&root),
            "",
            "nothing may be written above a delegated root"
        );
        assert_eq!(
            std::fs::read_to_string(root.join("cgroup.subtree_control")).unwrap(),
            "+cpu +memory",
            "the root's OWN subtree_control is inside the subtree and still written"
        );
        assert_eq!(
            std::fs::read_to_string(handle.path.join("memory.max")).unwrap(),
            (1u64 << 20).to_string()
        );
        assert_eq!(
            std::fs::read_to_string(handle.path.join("cpu.max")).unwrap(),
            "200000 100000"
        );
    }

    /// And with no delegated subtree — the agent as root, `cgroup_root`
    /// somewhere under the mount root — the climb is exactly what it was.
    #[test]
    fn a_root_agent_still_climbs_to_the_grandparent() {
        let (_temp, root) = fake_cgroupfs("memory pids");
        // Its own cgroup is `system.slice/meister-agent.service`, which is
        // neither the configured root nor under it.
        let elsewhere = root.parent().unwrap().join("system.slice").join("other");
        let cg = CgroupV2::new(&root).with_own_cgroup(Some(elsewhere));

        cg.create_slice("vm-1", None, &ResourceLimits::default())
            .expect("a slice");

        assert_eq!(
            said_above(&root),
            "+cpu +memory",
            "the boot-time race is still raced for a root agent"
        );
    }

    /// A slice UNDER the root is inside the subtree, and the climb out of it
    /// lands inside it too — so it happens.
    #[test]
    fn a_nested_slice_may_be_climbed_out_of() {
        let (_temp, root) = fake_cgroupfs("memory pids");
        let cg = CgroupV2::new(&root).with_own_cgroup(Some(root.clone()));
        let vm = CgroupHandle {
            path: root.join("vm-1"),
        };
        std::fs::create_dir_all(&vm.path).expect("the slice");
        std::fs::write(vm.path.join("cgroup.controllers"), "memory pids").expect("its file");

        cg.create_slice("inner", Some(&vm), &ResourceLimits::default())
            .expect("a slice");

        assert_eq!(said_above(&root), "", "still nothing above the root");
        assert_eq!(
            std::fs::read_to_string(root.join("cgroup.subtree_control")).unwrap(),
            "+cpu +memory",
            "the root is the nested slice's parent and is written"
        );
    }

    /// The `supervisor` move: once, only when the agent sits IN the root, and
    /// idempotent afterwards.
    #[test]
    fn the_agent_hangs_itself_below_the_delegation_root() {
        let (_temp, root) = fake_cgroupfs("cpu memory pids");
        let mut cg = CgroupV2::new(&root).with_own_cgroup(Some(root.clone()));

        let moved = cg
            .join_supervisor_subgroup()
            .expect("the move")
            .expect("it moved");
        assert_eq!(moved, root.join(SUPERVISOR));
        assert_eq!(
            std::fs::read_to_string(moved.join("cgroup.procs")).unwrap(),
            std::process::id().to_string(),
            "the whole process, by pid"
        );

        // Second call: the agent is already below the root — which is also
        // what `DelegateSubgroup=supervisor` leaves behind — so there is
        // nothing to do and no second subgroup.
        assert_eq!(cg.join_supervisor_subgroup().expect("the move"), None);
        // And the boundary still holds from down there.
        assert!(cg.hands_off_above(&root));
        cg.create_slice("vm-1", None, &ResourceLimits::default())
            .expect("a slice");
        assert_eq!(said_above(&root), "");
    }

    /// An agent whose `cgroup_root` is not its own subtree does not move.
    #[test]
    fn a_root_agent_does_not_move_itself() {
        let (_temp, root) = fake_cgroupfs("cpu memory pids");
        let elsewhere = root.parent().unwrap().join("system.slice").join("other");
        let mut cg = CgroupV2::new(&root).with_own_cgroup(Some(elsewhere));
        assert_eq!(cg.join_supervisor_subgroup().expect("the move"), None);
        assert!(!root.join(SUPERVISOR).exists());
    }

    /// The two causes of one errno, told apart.
    ///
    /// The failing write is forced by putting a DIRECTORY where
    /// `cgroup.subtree_control` belongs, because an ordinary filesystem has
    /// no way to answer a write the way the kernel does. What is under test
    /// is the sentence, and the sentence is the whole point of the branch:
    /// "never delegated" is something an operator fixes in the unit, the
    /// boot-time race is something that fixes itself.
    #[test]
    fn a_controller_that_was_never_delegated_says_so() {
        let (_temp, root) = fake_cgroupfs("memory pids");
        std::fs::remove_file(root.join("cgroup.subtree_control")).expect("the file goes");
        std::fs::create_dir(root.join("cgroup.subtree_control")).expect("a directory instead");

        let cg = CgroupV2::new(&root).with_own_cgroup(Some(root.clone()));
        let err = cg
            .create_slice("vm-1", None, &ResourceLimits::default())
            .expect_err("the write fails");
        let said = format!("{err}");
        assert!(
            said.contains("never delegated") && said.contains("Delegate="),
            "the sentence names the fix: {said}"
        );
        assert!(
            said.contains("not the boot-time race"),
            "and says which of the two causes it is not: {said}"
        );
    }
}
