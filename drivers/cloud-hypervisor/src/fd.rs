// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Handing the VMM a descriptor instead of a right.
//!
//! This is the whole of Stufe 3's network half: the agent opens the tap it
//! made and passes the OPEN FILE to cloud hypervisor over the API socket as
//! ancillary data, so the VMM never needs `/dev/net/tun` and never needs
//! `CAP_NET_ADMIN`. It is the mechanism every comparable stack uses —
//! libvirt inherits `tapfd` into QEMU, `qemu-bridge-helper` sends one back
//! over its own socket, Incus opens the tap and QEMU drops to a user
//! afterwards — and cloud hypervisor v53 accepts it on exactly two verbs,
//! `vm.add-net` and `vm.add-device` (`vmm/src/api/http/http_endpoint.rs`,
//! module note: "passes file descriptors (FDs) via _ancillary_ messages -
//! specifically using the `SCM_RIGHTS` mechanism").
//!
//! It does NOT accept them on `vm.create`: the same file says so twice
//! (`// For the VmCreate call, we do not accept FDs from the socket
//! currently.`) and nulls every fd in `net` and `devices`. So a VM with a
//! NIC is three calls and not one — create without `net`, one `add-net` per
//! NIC, then boot — and that ordering is why this module exists rather than
//! a flag on the existing client.
//!
//! # Why the request is written by hand here
//!
//! `ch_api` speaks HTTP through hyper, and hyper owns the socket: there is no
//! seam at which a `sendmsg` with a control message can be put on the first
//! write. The request that carries an fd is one line, three headers and a
//! small JSON body, sent once and answered once, so writing those bytes
//! directly is less machinery than teaching hyper to pass descriptors — and
//! it is the only place in this driver that needs it.
//!
//! One `sendmsg` for the whole request is enough, and that is a property of
//! the SERVER: `micro_http` accumulates the descriptors it has received on a
//! connection and attaches them to the request that completes next
//! (`connection.rs`, `pending_request.files = self.files.drain(..)`). The
//! descriptors therefore have to arrive no later than the last byte of the
//! request, which one `sendmsg` guarantees.

use std::io::Read;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use super::*;

/// The flags cloud hypervisor's own `Tap::from_tap_fd` sets on a descriptor
/// it is handed.
///
/// It re-issues `TUNSETIFF` on the fd it receives and forgives only `EEXIST`
/// (`net_util/src/tap.rs`), so a tap opened with different flags would take
/// the VMM down at boot. `IFF_VNET_HDR` is the one that is easy to miss:
/// `linux-network` creates the persistent device without it, because a
/// device's flags and a descriptor's flags are not the same thing, and it is
/// the descriptor that must match.
const TAP_FLAGS: libc::c_short =
    (libc::IFF_TAP | libc::IFF_NO_PI | libc::IFF_VNET_HDR) as libc::c_short;

nix::ioctl_write_ptr_bad!(
    tunsetiff,
    nix::request_code_write!(b'T', 202, std::mem::size_of::<libc::c_int>()),
    libc::ifreq
);

/// Open the tap the network driver already made, by name.
///
/// Opening is all this does. The device exists, it is in its bridge, it is UP
/// and it carries its MTU — `linux-network`'s `create` did all of that with
/// the agent's own rights, before this is called — and none of it can be done
/// through this descriptor by an unprivileged VMM. That division is the whole
/// design: the privileged side configures, the unprivileged side gets a
/// descriptor.
///
/// Needs no capability of its own when the tap belongs to the caller or to
/// the caller's group (`drivers/net/tun.c`, `tun_not_capable`: owner OR group
/// match is enough, otherwise `CAP_NET_ADMIN`), which is why the same code
/// works for an agent that is root and for one that is not.
pub(crate) fn open_tap(name: &str) -> anyhow::Result<OwnedFd> {
    if name.len() >= libc::IFNAMSIZ {
        bail!("tap name too long: {name}");
    }
    let tun = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")
        .context("opening /dev/net/tun to hand the tap to the vmm")?;

    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    for (dst, src) in ifr.ifr_name.iter_mut().zip(name.as_bytes()) {
        *dst = *src as libc::c_char;
    }
    ifr.ifr_ifru.ifru_flags = TAP_FLAGS;
    // SAFETY: `ifr` is a zeroed `ifreq` with a NUL-terminated name, which is
    // what TUNSETIFF reads.
    unsafe { tunsetiff(tun.as_raw_fd(), &ifr) }
        .with_context(|| format!("TUNSETIFF on the existing tap {name}"))?;
    Ok(OwnedFd::from(tun))
}

/// One request that carries descriptors: connect, `sendmsg` with
/// `SCM_RIGHTS`, read the answer, drop.
///
/// Blocking, and run on a blocking thread by the caller. The alternative is
/// an async `sendmsg` with ancillary data, which tokio's `UnixStream` does
/// not offer without reaching for the raw fd anyway — and the call is one
/// round trip on a local socket.
///
/// The descriptors are borrowed, never consumed: the kernel `dup`s them into
/// the VMM (`cmsg(3)`), and CH `dup`s again in `from_tap_fds` ("Duplicate so
/// that it can survive reboots"). What this side holds afterwards is its own
/// copy, and closing it is the caller's business — see `create_vm`, which
/// closes it as soon as the VMM has its own.
fn request_with_fds(
    socket: &Path,
    method: &str,
    endpoint: &str,
    body: &serde_json::Value,
    fds: &[BorrowedFd<'_>],
    timeout: Duration,
) -> anyhow::Result<Vec<u8>> {
    use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};

    let stream =
        UnixStream::connect(socket).with_context(|| format!("connect {}", socket.display()))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let payload = serde_json::to_vec(body)?;
    let head = format!(
        "{method} /api/v1/{endpoint} HTTP/1.1\r\nHost: localhost\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        payload.len()
    );
    let mut request = head.into_bytes();
    request.extend_from_slice(&payload);

    let raw: Vec<std::os::fd::RawFd> = fds.iter().map(|f| f.as_raw_fd()).collect();
    let cmsg = [ControlMessage::ScmRights(&raw)];
    let iov = [std::io::IoSlice::new(&request)];
    let sent = sendmsg::<()>(stream.as_raw_fd(), &iov, &cmsg, MsgFlags::empty(), None)
        .with_context(|| format!("sendmsg {endpoint} with {} fd(s)", raw.len()))?;
    // A short write would leave the request half-sent and the descriptors
    // already across, which the server would attach to whatever request
    // completes next. A request of this size does not short-write on a unix
    // stream socket; saying so out loud is cheaper than the bug it prevents.
    if sent != request.len() {
        bail!(
            "ch {endpoint}: only {sent} of {} bytes went out",
            request.len()
        );
    }

    let (status, body) = read_answer(&stream)?;
    if !(200..300).contains(&status) {
        bail!(
            "ch {endpoint} -> {status}: {}",
            String::from_utf8_lossy(&body)
        );
    }
    Ok(body)
}

/// The status line and the body of one HTTP/1.1 answer.
///
/// Reads headers up to the blank line, then exactly `Content-Length` bytes.
/// Cloud hypervisor answers 204 with no body for a call that only changes
/// configuration and 200 with a small JSON document for one that returns
/// something, and it never chunks — so this is the whole parser this needs.
fn read_answer(stream: &UnixStream) -> anyhow::Result<(u16, Vec<u8>)> {
    let mut stream = stream;
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 512];
    let split = loop {
        if let Some(at) = find_headers_end(&buf) {
            break at;
        }
        let read = stream
            .read(&mut chunk)
            .context("reading the vmm's answer")?;
        if read == 0 {
            bail!("the vmm closed the connection without answering");
        }
        buf.extend_from_slice(&chunk[..read]);
    };

    let head = String::from_utf8_lossy(&buf[..split]).to_string();
    let status: u16 = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| anyhow::anyhow!("the vmm's answer has no status line: {head:?}"))?;
    let length: usize = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })
        .unwrap_or(0);

    let mut body = buf[split + 4..].to_vec();
    while body.len() < length {
        let read = stream.read(&mut chunk).context("reading the answer body")?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(length.min(body.len()));
    Ok((status, body))
}

/// Where the headers stop, as the offset of the `\r\n\r\n`.
fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

impl CloudHypervisorDriver {
    /// `vm.add-net` for one NIC, with the tap as a descriptor.
    ///
    /// The same call before and after boot, which is what makes hot-plug free:
    /// v53 routes it by whether it owns a VM yet — `VmOwnership::None` only
    /// updates the config it will boot from (`vmm/src/lib.rs`, `vm_add_net`),
    /// `Owned` builds the device and answers with its PCI address. Both
    /// validate first, so a wrong `num_queues` is refused at create time and
    /// not at boot time.
    pub(crate) async fn add_net_with_fd(
        &self,
        id: &VmId,
        nic: &agent_api::NicAttachment,
    ) -> hypervisor::Result<()> {
        let socket = self.vm_socket_path(id);
        let body = net_config(nic);
        let tap = nic.tap_name.clone();
        let timeout = self.ch_timeout;
        tokio::task::spawn_blocking(move || {
            let fd = open_tap(&tap)?;
            // Dropped at the end of this closure, which is the moment the VMM
            // has its own copy: the descriptor this side holds is not the one
            // the guest's NIC is built on, and keeping it would only mean an
            // fd per NIC in the agent for the life of the VM.
            request_with_fds(&socket, "PUT", "vm.add-net", &body, &[fd.as_fd()], timeout)
                .map(|_| ())
        })
        .await
        .map_err(|e| HypervisorError::Backend(anyhow::anyhow!("blocking task failed: {e}")))?
        .map_err(HypervisorError::Backend)
    }
}

/// Every file this VM's VMM will open for writing, out of its own spec.
///
/// The disks and the cloud-init seed, and deliberately not the kernel, the
/// initramfs or the firmware: those are shared, read-only and live in the
/// image directory, so handing one to the VMM user would change a file
/// several VMs read. Read access to them is an ordinary `0644` and a Landlock
/// rule, not an ownership question.
///
/// A vhost-user disk is a socket and not a file, and the socket belongs to
/// the backend — which already runs as the same user. A share is virtiofsd's
/// and virtiofsd stays the agent. So both are absent, and `disk_config` is
/// where the same split is made for the VMM's config document.
pub(crate) fn writable_files(spec: &InstanceSpec) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = spec
        .volumes
        .iter()
        .filter_map(|v| match &v.attachment {
            VolumeAttachment::Path(path) => Some(path.clone()),
            VolumeAttachment::VhostUserBlk { .. } | VolumeAttachment::FsShare { .. } => None,
        })
        .collect();
    if let Some(seed) = &spec.cloud_init_seed {
        files.push(seed.clone());
    }
    files
}

impl CloudHypervisorDriver {
    /// Hand this VM's writable files to the VMM user, libvirt's
    /// `dynamic_ownership` in one call.
    ///
    /// Before `vm.create` and not after: the VMM opens its disks while it is
    /// building the VM, and a disk it cannot open is a create that fails with
    /// CH's own errno rather than with a sentence about ownership.
    ///
    /// An error here is fatal on purpose. The alternative — carry on and let
    /// the VMM fail — turns one clear message into two unclear ones.
    pub(crate) fn hand_over_files(&self, spec: &InstanceSpec) -> hypervisor::Result<()> {
        let Some(user) = &self.vmm_user else {
            return Ok(());
        };
        for path in writable_files(spec) {
            user.take(&path).map_err(|e| {
                HypervisorError::Backend(anyhow::anyhow!(
                    "giving {} to {user} so the vmm can open it: {e}",
                    path.display()
                ))
            })?;
        }
        Ok(())
    }

    /// Take the files back, which is the other half of the same idea.
    ///
    /// The paths come off `vm.info` rather than off a record, and that is
    /// what makes this work for a VMM this agent did not start: an adopted
    /// VM has no spec here, and the VMM lists what it holds. Asked BEFORE the
    /// shutdown, because a VMM that has exited answers nothing.
    ///
    /// Best effort, unlike the handover. A teardown that failed over a chown
    /// would leave the VM in the records for ever; a volume left owned by the
    /// VMM user is untidy and is corrected the next time it is attached.
    pub(crate) async fn take_files_back(&self, id: &VmId) {
        if self.vmm_user.is_none() {
            return;
        }
        let Ok(bytes) = self.api(id, Method::GET, "vm.info", None).await else {
            return;
        };
        let Ok(info) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            return;
        };
        let disks = info
            .get("config")
            .and_then(|c| c.get("disks"))
            .and_then(serde_json::Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        for path in disks
            .iter()
            .filter_map(|d| d.get("path").and_then(serde_json::Value::as_str))
        {
            if let Err(e) = agent_api::VmmUser::give_back(Path::new(path)) {
                debug!(path, error = %e, "a volume could not be handed back");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers_end_is_the_blank_line() {
        assert_eq!(find_headers_end(b"HTTP/1.1 204 \r\n\r\n"), Some(13));
        assert_eq!(find_headers_end(b"HTTP/1.1 204 \r\n"), None);
    }

    /// The answer parser against the two shapes v53 actually sends: a 204
    /// with no body, and a 200 with a JSON document whose length is stated.
    #[test]
    fn an_answer_is_a_status_and_exactly_content_length_bytes() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        let doc = br#"{"id":"_net1","bdf":"0000:00:03.0"}"#;
        let answer = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}trailing-garbage",
            doc.len(),
            String::from_utf8_lossy(doc)
        );
        std::io::Write::write_all(&mut { theirs }, answer.as_bytes()).unwrap();
        let (status, body) = read_answer(&ours).unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, doc);
    }

    #[test]
    fn a_204_has_no_body() {
        let (ours, theirs) = UnixStream::pair().unwrap();
        std::io::Write::write_all(&mut { theirs }, b"HTTP/1.1 204 \r\n\r\n").unwrap();
        let (status, body) = read_answer(&ours).unwrap();
        assert_eq!(status, 204);
        assert!(body.is_empty());
    }

    /// A tap name that cannot exist is refused before `/dev/net/tun` is
    /// touched, so the error names the name and not the device.
    #[test]
    fn a_name_the_kernel_cannot_hold_is_refused_by_name() {
        let said = format!("{:#}", open_tap("far-too-long-a-tap-name").unwrap_err());
        assert!(said.contains("too long"), "{said}");
    }
}
