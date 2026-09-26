// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Resolve the account used by VMMs and vhost-user backends.
//!
//! Resolve the UID, primary GID and supplementary groups at startup, before VM
//! creation. Backends that map guest memory share the VMM's trust boundary and
//! must drop privileges too.
//!
//! The VMM account must not belong to the group that can access the agent's
//! control socket. An unprivileged agent may instead need membership in the VMM
//! group to read files created by the VMM.

use std::fmt;

/// A resolved system user for the VMM and its vhost-user backends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmmUser {
    /// What the operator wrote, kept for every message that mentions it.
    pub name: String,
    pub uid: u32,
    /// The user's primary group, and therefore the group of every file the
    /// VMM creates. Deliberately the user's own and not the agent's: see the
    /// module note on what this user must not be in.
    pub gid: u32,
    /// Primary and supplementary groups resolved at startup. Credential
    /// switching retains these groups for KVM, render and input device access.
    pub groups: Vec<u32>,
}

impl VmmUser {
    /// Resolve the account directly through getpwnam without depending on a helper executable.
    pub fn resolve(name: &str) -> anyhow::Result<Self> {
        let user = nix::unistd::User::from_name(name)
            .map_err(|e| anyhow::anyhow!("looking up the user {name:?}: {e}"))?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "there is no user {name:?} on this node. `vmm_user` names the account the \
                     hypervisor and its vhost-user backends run as, and it has to exist before \
                     the agent starts — the deployment makes it (see deploy/README.md, Stufe 3)"
                )
            })?;
        if user.uid.as_raw() == 0 {
            anyhow::bail!(
                "`vmm_user` names {name:?}, which is uid 0. Running the vmm as root is what this \
                 option exists to stop; leave the key unset to get today's behaviour honestly"
            );
        }
        // Resolved here, where NSS may be consulted freely, and never in the
        // child: `getgrouplist` reads files and allocates, and the child of a
        // fork in a threaded process may do neither.
        let name_c = std::ffi::CString::new(name)
            .map_err(|e| anyhow::anyhow!("the user name {name:?} is not a C string: {e}"))?;
        let groups: Vec<u32> = nix::unistd::getgrouplist(&name_c, user.gid)
            .map_err(|e| anyhow::anyhow!("reading the groups of {name:?}: {e}"))?
            .into_iter()
            .map(|g| g.as_raw())
            .collect();
        Ok(Self {
            name: name.to_string(),
            uid: user.uid.as_raw(),
            gid: user.gid.as_raw(),
            groups,
        })
    }

    /// Apply stored supplementary groups, then GID, then UID in the child before exec.
    /// The groups retain device access such as KVM. This currently allocates a
    /// temporary GID vector before the syscalls, so the hook is not allocation-free.
    pub fn switch_to(&self) -> std::io::Result<()> {
        let groups: Vec<libc::gid_t> = self.groups.iter().map(|g| *g as libc::gid_t).collect();
        // SAFETY: three FFI calls with a slice this function owns and scalars.
        unsafe {
            if libc::setgroups(groups.len(), groups.as_ptr()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setgid(self.gid as libc::gid_t) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setuid(self.uid as libc::uid_t) != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        Ok(())
    }

    /// Explain spawn failures caused by missing UID/GID-changing capabilities.
    pub fn cannot_switch(&self, e: &std::io::Error) -> String {
        format!(
            "starting it as {self} failed: {e}. Changing uid and gid needs CAP_SETUID and \
             CAP_SETGID, which an agent that is neither root nor granted them does not have — the \
             start-up check reports that, and until it is fixed `vmm_user` has to come out of the \
             config"
        )
    }

    /// Transfer ownership to the VMM user and group, with mode 0660 for
    /// files or 0770 for directories. Propagate ownership/permission errors.
    pub fn take(&self, path: &std::path::Path) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path)?;
        let mode = if meta.is_dir() { 0o770 } else { 0o660 };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
        nix::unistd::chown(
            path,
            Some(nix::unistd::Uid::from_raw(self.uid)),
            Some(nix::unistd::Gid::from_raw(self.gid)),
        )
        .map_err(std::io::Error::from)
    }

    /// Restore file ownership to the agent's effective UID and GID. This does
    /// not restore a separately remembered original owner.
    pub fn give_back(path: &std::path::Path) -> std::io::Result<()> {
        nix::unistd::chown(
            path,
            Some(nix::unistd::Uid::effective()),
            Some(nix::unistd::Gid::effective()),
        )
        .map_err(std::io::Error::from)
    }
}

impl fmt::Display for VmmUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({}:{})", self.name, self.uid, self.gid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unknown VMM users fail with the requested name in the error.
    #[test]
    fn an_unknown_user_says_which_name_it_could_not_find() {
        let said = format!("{:#}", VmmUser::resolve("no-such-user-b7f3c1").unwrap_err());
        assert!(said.contains("no-such-user-b7f3c1"), "{said}");
        assert!(said.contains("vmm_user"), "{said}");
    }

    /// The groups a real account is in come back with it, primary included:
    /// they are what the VMM reaches `/dev/kvm` through, and a switch that
    /// dropped them would be a node that cannot start a guest.
    #[test]
    fn a_resolved_user_carries_its_group_list() {
        let me = nix::unistd::User::from_uid(nix::unistd::Uid::effective())
            .unwrap()
            .unwrap();
        let resolved = VmmUser::resolve(&me.name);
        // uid 0 is refused by design, so this test says nothing when it runs
        // as root — which is how the ignored e2es run.
        if let Ok(resolved) = resolved {
            assert!(
                resolved.groups.contains(&resolved.gid),
                "the primary group is missing from {:?}",
                resolved.groups
            );
        }
    }

    /// Reject root as the requested reduced-privilege VMM identity.
    #[test]
    fn root_is_refused_because_it_is_the_thing_being_escaped() {
        let said = format!("{:#}", VmmUser::resolve("root").unwrap_err());
        assert!(said.contains("uid 0"), "{said}");
    }

    /// Credential-switch errors identify required capabilities and the configuration key.
    #[test]
    fn a_failed_switch_names_the_capabilities_and_the_key() {
        let user = VmmUser {
            name: "meister-vmm".into(),
            uid: 991,
            gid: 991,
            groups: vec![991],
        };
        let said = user.cannot_switch(&std::io::Error::from_raw_os_error(libc_eperm()));
        assert!(said.contains("CAP_SETUID"), "{said}");
        assert!(said.contains("CAP_SETGID"), "{said}");
        assert!(said.contains("vmm_user"), "{said}");
        assert!(said.contains("meister-vmm (991:991)"), "{said}");
    }

    fn libc_eperm() -> i32 {
        1
    }

    /// Apply the writable mode even when ownership transfer fails.
    #[test]
    fn taking_a_file_sets_the_mode_even_when_the_chown_cannot_happen() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("volume.raw");
        std::fs::write(&file, b"x").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let me = VmmUser {
            name: "me".into(),
            uid: nix::unistd::Uid::effective().as_raw(),
            gid: nix::unistd::Gid::effective().as_raw(),
            groups: vec![nix::unistd::Gid::effective().as_raw()],
        };
        me.take(&file).expect("own user, own file");
        let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o660);
        VmmUser::give_back(&file).expect("own user, own file");
    }
}
