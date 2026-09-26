// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

use agent_api::{CgroupHandle, ConfinerResult, ResourceConfiner, ResourceLimits};
use std::path::{Path, PathBuf};
use tracing::{debug, instrument, warn};

/// Supervisor subgroup for an agent located at its delegated root.
/// The name matches `DelegateSubgroup=` in `nix/agent.nix`.
pub const SUPERVISOR: &str = "supervisor";

/// This driver only supports Linux cgroups_v2
pub struct CgroupV2 {
    root: PathBuf,
    /// This process's absolute cgroup, if readable. It defines the delegation
    /// boundary above which controller setup must not write.
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

    /// Whether climbing above `dir` would leave this process's delegated subtree.
    /// Check the current parent, since nested slices may still climb within it.
    fn hands_off_above(&self, dir: &Path) -> bool {
        self.own
            .as_ref()
            .is_some_and(|own| own == dir || own.starts_with(dir))
    }

    /// Move the agent into `<root>/supervisor` when it occupies the root itself.
    /// This leaves the parent free of processes so cgroup v2 can enable controllers.
    /// Do nothing when the agent is already below the root or outside it.
    pub fn join_supervisor_subgroup(&mut self) -> std::io::Result<Option<PathBuf>> {
        let Some(own) = self.own.clone() else {
            return Ok(None);
        };
        if own != self.root {
            return Ok(None);
        }
        let sup = self.root.join(SUPERVISOR);
        std::fs::create_dir_all(&sup)?;
        // Writing cgroup.procs moves the whole process, including runtime threads.
        std::fs::write(sup.join("cgroup.procs"), std::process::id().to_string())?;
        self.own = Some(sup.clone());
        Ok(Some(sup))
    }
}

/// Resolve this process's cgroup using procfs and the cgroup2 mount.
/// Return None on unreadable or unexpected input, claiming no delegation boundary.
fn own_cgroup() -> Option<PathBuf> {
    let relative = std::fs::read_to_string("/proc/self/cgroup")
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("0::").map(str::to_string))?;
    let mount = cgroup2_mount()?;
    Some(mount.join(relative.trim().trim_start_matches('/')))
}

/// Discover the existing cgroup2 mount rather than assuming `/sys/fs/cgroup`.
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

        // Enable missing CPU and memory controllers in the parent when permitted.
        // Never write above the agent's own delegated subtree.
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
            // Report missing delegated controllers separately from a missing cgroup root.
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

        // Apply the configured CPU set to the parent so VM slices inherit it.
        // Pinning is best effort: missing cpuset delegation is logged and does not
        // prevent VM creation. Repeat the write whenever the parent is prepared.
        if let Some(cpus) = &limits.cpuset {
            // Respect the same delegation boundary when enabling cpuset.
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

    /// Configured root for controller enablement and slice creation.
    fn root(&self) -> Option<&std::path::Path> {
        Some(&self.root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_api::ResourceLimits;

    /// Directory fixture with pseudo-file stand-ins and a parent above the root.
    /// It checks which paths receive writes, not kernel cgroup semantics such as
    /// EBUSY when enabling controllers in an occupied cgroup.
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

    /// Force a failed subtree-control write and verify that missing delegation
    /// is reported separately from the root-agent controller setup path.
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
