// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

use std::path::PathBuf;

/// Set resource limits for the host process. This is different from Hypervisors InstanceSpec. The
/// InstanceSpec is what is visible to the VM for example 4GiB RAM, this resource limit is the true
/// limit for the hypervisor that means the guests memory + vmm-overhead
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct ResourceLimits {
    pub memory_max: Option<u64>,
    pub cpu_quota: Option<u32>, // in percent: like OpenNebula 100 = 1 vCore, 200 = 2vCores...
    /// Allowed CPUs for all VM slices, e.g. `0-15,32-47`. Applied to the
    /// parent cgroup and inherited by children. This enforces host partitioning;
    /// `capacity_vcpus` separately controls advertised scheduler capacity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpuset: Option<String>,
}

/// Existing cgroup handle, for example `/sys/fs/cgroup/meisterstack/<id>`.
#[derive(Clone, Debug)]
pub struct CgroupHandle {
    pub path: PathBuf,
}

impl CgroupHandle {
    pub fn attach_pid(&self, pid: u32) -> std::io::Result<()> {
        std::fs::write(self.path.join("cgroup.procs"), pid.to_string())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfinerError {
    #[error("cgroup io error: {0}")]
    Io(#[from] std::io::Error),
    /// Same as Io, but naming the path — a bare ENOENT out of a cgroup write
    /// cost a live debugging session to locate once.
    #[error("cgroup io error at {path}: {source}")]
    IoAt {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
}
pub type ConfinerResult<T> = std::result::Result<T, ConfinerError>;

pub trait ResourceConfiner: Send + Sync {
    /// create cgroup.
    /// If nested croups are necessary use the @parent attribute, if the cgroup has no parents leave
    /// it empty.
    fn create_slice(
        &self,
        name: &str,
        parent: Option<&CgroupHandle>,
        limits: &ResourceLimits,
    ) -> ConfinerResult<CgroupHandle>;

    /// destroy cgroup.
    /// cgroup must be empty, ergo no processes and childs.
    fn destroy_slice(&self, cg: &CgroupHandle) -> ConfinerResult<()>;

    /// Handle for an existing Cgroup, by name.
    fn open_slice(&self, name: &str) -> CgroupHandle;

    // Reconcile requirements
    fn pids_in_slice(&self, name: &str) -> ConfinerResult<Vec<u32>>;
    fn kill_slice(&self, name: &str) -> ConfinerResult<()>;

    /// Confiner root used for periodic cgroup2 prerequisite checks. None
    /// means this driver has no filesystem root to inspect.
    fn root(&self) -> Option<&std::path::Path> {
        None
    }
}
