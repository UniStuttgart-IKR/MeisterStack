// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Who the VMM and its backends run as, when that is not the agent.
//!
//! Stufe 3 of `design/privilege-separation.md`, and the shape every stack
//! that does this has: one privileged process prepares — taps, cgroups,
//! device nodes, volumes — and the process that runs guest code has nothing.
//! libvirt changes uid "immediately before executing the QEMU binary", Incus
//! hands QEMU `-run-with user=`, Firecracker's jailer `setuid`s before
//! `exec`, Kata gives the VMM a `kata-<n>` user. This type is the value all
//! four of those need: a resolved uid and gid, resolved ONCE at start-up
//! rather than at every spawn.
//!
//! **Resolved once on purpose.** A name is looked up in `/etc/passwd` (or
//! wherever NSS points), and a node whose `vmm_user` does not exist must fail
//! at start-up with a sentence naming the user — not at the first VM, with an
//! errno, in front of somebody trying to boot a guest.
//!
//! # The backends are not outside this
//!
//! `nvrm`, `input` and `crosvm-gpu` run as this user too, and that is not
//! thoroughness. A vhost-user backend has the guest's memory mapped and CH
//! says so itself ("Cloud Hypervisor gives vhost-user devices complete
//! control over the guest"); QEMU's own security document is blunter: "There
//! is not considered to be security boundary between QEMU and the vhost-user
//! & vfio-user backends." An unprivileged VMM beside a root backend is a root
//! VMM with extra steps.
//!
//! # What this user must NOT be in
//!
//! The agent's own group. The agent's socket is `0660` with
//! `[paths] socket_group`, and whoever can reach that socket can name image
//! paths, virtiofs shares and devices — on a node whose agent is privileged
//! that is the whole machine. Stufe 3 only buys anything if the VMM cannot
//! open it, so `meister-vmm` stays out of `meister`.
//!
//! The consequence runs the other way instead: the files the VMM makes belong
//! to the VMM, so an agent that is NOT root has to be in the VMM's group to
//! read them. That direction is safe — group membership is not symmetric —
//! and it is the no-root lane's business to arrange.

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
}

impl VmmUser {
    /// Look the name up, or say why not.
    ///
    /// `getpwnam`, through `nix`, rather than shelling out to `id` — a unit's
    /// `PATH` is not something a privilege decision should depend on.
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
        Ok(Self {
            name: name.to_string(),
            uid: user.uid.as_raw(),
            gid: user.gid.as_raw(),
        })
    }

    /// The one sentence a failed uid change needs.
    ///
    /// `Command::uid`/`gid` do their work in the child, between `fork` and
    /// `exec`, so a missing capability surfaces as `EPERM` on the spawn with
    /// nothing said about which of the two calls failed or why. An agent that
    /// is root has both capabilities; an agent that is not needs them
    /// granted, and that is a line in a unit file rather than anything code
    /// can fix.
    pub fn cannot_switch(&self, e: &std::io::Error) -> String {
        format!(
            "starting it as {self} failed: {e}. Changing uid and gid needs CAP_SETUID and \
             CAP_SETGID, which an agent that is neither root nor granted them does not have — the \
             start-up check reports that, and until it is fixed `vmm_user` has to come out of the \
             config"
        )
    }

    /// Give a file to this user, and let its group at it.
    ///
    /// `0660` for a file and `0770` for a directory, which is what the VMM's
    /// own umask produces for everything it makes itself (see the spawn
    /// paths) — this is the same rule applied to the things the AGENT made
    /// and then handed over: the per-VM run directory, the VMM's log, a file
    /// volume.
    ///
    /// Best effort is not acceptable here and it does not pretend to be: a
    /// console file the VMM cannot open is a VM that does not boot, and the
    /// caller gets to decide that with the error in hand.
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

    /// Give a file back to whoever is running this agent.
    ///
    /// The other half of libvirt's `dynamic_ownership`, and the same shape:
    /// what was handed over on attach is handed back on detach, so a volume
    /// does not stay readable by the VMM user after the VM that used it is
    /// gone. The agent's own euid rather than a remembered original, which is
    /// the same thing for every file in this tree — the agent is what created
    /// all of them — and is the one answer that cannot go stale in a record.
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

    /// A name nobody has is a start-up failure with the name in it, because
    /// the alternative is a node that starts and cannot boot a VM.
    #[test]
    fn an_unknown_user_says_which_name_it_could_not_find() {
        let said = format!("{:#}", VmmUser::resolve("no-such-user-b7f3c1").unwrap_err());
        assert!(said.contains("no-such-user-b7f3c1"), "{said}");
        assert!(said.contains("vmm_user"), "{said}");
    }

    /// `root` is refused rather than accepted as a no-op: an operator who
    /// wrote it meant to change something, and silently doing nothing is the
    /// worst of the three possible answers.
    #[test]
    fn root_is_refused_because_it_is_the_thing_being_escaped() {
        let said = format!("{:#}", VmmUser::resolve("root").unwrap_err());
        assert!(said.contains("uid 0"), "{said}");
    }

    /// The sentence a missing capability produces names both capabilities and
    /// the key, because those are the two things an operator acts on.
    #[test]
    fn a_failed_switch_names_the_capabilities_and_the_key() {
        let user = VmmUser {
            name: "meister-vmm".into(),
            uid: 991,
            gid: 991,
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

    /// Handing a file over and taking it back are one pair, and the mode is
    /// part of the handover: a file the VMM owns but cannot write is the same
    /// failure as one it does not own.
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
        };
        me.take(&file).expect("own user, own file");
        let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o660);
        VmmUser::give_back(&file).expect("own user, own file");
    }
}
