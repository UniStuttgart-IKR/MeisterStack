// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Sockets in the run directory that neither a vm record nor a start of
//! this driver accounts for.
//!
//! Such a socket is left behind by a backend that is gone, or it belongs to
//! a backend still running for a device no record names any more (a record
//! deleted by hand, a teardown that lost track of it). The first holds
//! nothing and is removed. The second holds an unknown share of the card,
//! so admission waits for an operator; it is not killed, because the agent
//! cannot tell what it serves.

use std::collections::HashSet;
use std::path::Path;

use agent_api::device::DeviceId;
use backend::BackendKind;
use tracing::{info, warn};

use crate::paths;

/// A running backend whose device nothing accounts for.
#[derive(Debug, PartialEq)]
pub(crate) struct Stray {
    pub(crate) device: DeviceId,
    pub(crate) pid: u32,
}

/// The backends in `run_dir` serving devices outside `accounted`. Sockets of
/// such devices that nothing serves are removed on the way.
pub(crate) fn strays(
    run_dir: &Path,
    accounted: &HashSet<DeviceId>,
    process: &BackendKind,
) -> std::io::Result<Vec<Stray>> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(run_dir)? {
        let socket = entry?.path();
        let Some(device) = paths::socket_device(&socket) else {
            continue;
        };
        if accounted.contains(&device) {
            continue;
        }
        match process.find_serving(&socket)? {
            Some(pid) => {
                warn!(device_id = %device, pid, socket = %socket.display(),
                      "an nvrm backend runs for a device no vm record names; it holds an \
                       unknown share of the card and admission waits until an operator stops it");
                found.push(Stray { device, pid });
            }
            None => remove_stale(&socket, &device),
        }
    }
    Ok(found)
}

/// A socket no process serves holds nothing on the card.
fn remove_stale(socket: &Path, device: &DeviceId) {
    match std::fs::remove_file(socket) {
        Ok(()) => info!(device_id = %device, socket = %socket.display(),
                        "removed a socket whose backend is gone"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        // It counts for nothing either way; only the directory stays untidy.
        Err(e) => warn!(device_id = %device, error = %e, "could not remove a stale socket"),
    }
}
