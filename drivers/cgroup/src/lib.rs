// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

use agent_api::{CgroupHandle, ConfinerResult, ResourceConfiner, ResourceLimits};
use std::path::PathBuf;
use tracing::{debug, instrument, warn};

/// This driver only supports Linux cgroups_v2
pub struct CgroupV2 {
    root: PathBuf,
}

impl CgroupV2 {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
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
        let controllers = parent_dir.join("cgroup.controllers");
        let have = std::fs::read_to_string(&controllers).unwrap_or_default();
        if (!have.contains("cpu") || !have.contains("memory"))
            && let Some(grandparent) = parent_dir.parent()
        {
            let gp_subtree = grandparent.join("cgroup.subtree_control");
            std::fs::write(&gp_subtree, "+cpu +memory").map_err(at(gp_subtree.clone()))?;
        }

        let subtree = parent_dir.join("cgroup.subtree_control");
        std::fs::write(&subtree, "+cpu +memory").map_err(at(subtree.clone()))?;

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
            if let Some(grandparent) = parent_dir.parent() {
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
}
