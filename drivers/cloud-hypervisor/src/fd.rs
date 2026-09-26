// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Transfer open tap descriptors over the VMM API with SCM_RIGHTS.
//!
//! Create the guest without NICs, add each NIC with its descriptor, then boot.
//! The supported VMM accepts descriptors on `vm.add-net`, not `vm.create`.
//!
//! This path writes a small HTTP request directly because it must attach
//! ancillary data to the send. The blocking socket work runs on a blocking task.

use std::io::Read;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use super::*;

/// Match Cloud Hypervisor's `Tap::from_tap_fd` flags, including IFF_VNET_HDR.
/// It repeats TUNSETIFF and tolerates only EEXIST; descriptor flags must match
/// even when the persistent tap was created with different flags.
const TAP_FLAGS: libc::c_short =
    (libc::IFF_TAP | libc::IFF_NO_PI | libc::IFF_VNET_HDR) as libc::c_short;

nix::ioctl_write_ptr_bad!(
    tunsetiff,
    nix::request_code_write!(b'T', 202, std::mem::size_of::<libc::c_int>()),
    libc::ifreq
);

/// Open an existing, configured tap without changing its bridge, state or MTU.
/// The caller needs tap owner/group access or CAP_NET_ADMIN; the descriptor
/// then lets an unprivileged VMM use the device.
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

/// Send one blocking HTTP request with SCM_RIGHTS and read the response.
/// The caller runs this on a blocking thread. Descriptors are borrowed: the
/// kernel duplicates them for the receiver, leaving local closure to the caller.
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
    // Reject a short send because the peer may already hold the descriptors
    // without a complete request. Closing this connection ends that exchange.
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

/// Read an HTTP status and a Content-Length body; chunked encoding is not
/// supported. The current parser returns partial bytes if EOF precedes the
/// declared body length.
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
    /// Add one NIC through descriptor handoff. Cloud Hypervisor v53 accepts
    /// vm.add-net before boot and during hotplug, validating the request in both cases.
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
            // Drop the local descriptor after the VMM receives its own copy.
            request_with_fds(&socket, "PUT", "vm.add-net", &body, &[fd.as_fd()], timeout)
                .map(|_| ())
        })
        .await
        .map_err(|e| HypervisorError::Backend(anyhow::anyhow!("blocking task failed: {e}")))?
        .map_err(HypervisorError::Backend)
    }
}

/// Writable disk paths and the cloud-init seed requiring VMM-user ownership.
/// Exclude shared read-only boot images and socket-backed storage; backend
/// processes own their sockets.
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
    /// Transfer writable files before vm.create opens them. Ownership errors abort creation.
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

    /// Best-effort ownership restoration before VMM shutdown. Discover paths
    /// through vm.info so adopted VMMs work without an in-memory creation spec.
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

    /// Parse v53 empty 204 responses and length-delimited JSON 200 responses.
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
