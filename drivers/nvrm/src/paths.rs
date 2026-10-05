// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Where a device's files live in the driver's run directory.

use std::path::{Path, PathBuf};

use agent_api::device::DeviceId;

pub(crate) const SOCKET: &str = "sock";
pub(crate) const LOG: &str = "log";
pub(crate) const CLAIM: &str = "claim";

/// `<run_dir>/<id>.<extension>`: every file the driver keeps for a device.
pub(crate) fn device_file(run_dir: &Path, id: &DeviceId, extension: &str) -> PathBuf {
    run_dir.join(format!("{id}.{extension}"))
}

/// The backend derives the vGPU identity from the socket path, so it must
/// be unique and stable per device for its whole lifetime.
pub(crate) fn socket_file(run_dir: &Path, id: &DeviceId) -> PathBuf {
    device_file(run_dir, id, SOCKET)
}

pub(crate) fn log_file(run_dir: &Path, id: &DeviceId) -> PathBuf {
    device_file(run_dir, id, LOG)
}

pub(crate) fn claim_file(run_dir: &Path, id: &DeviceId) -> PathBuf {
    device_file(run_dir, id, CLAIM)
}

/// The device a file in the run directory belongs to, if its name is
/// `<id>.<extension>`.
pub(crate) fn device_of(path: &Path, extension: &str) -> Option<DeviceId> {
    if path.extension().and_then(|e| e.to_str()) != Some(extension) {
        return None;
    }
    path.file_stem()?.to_str()?.parse().ok()
}
