// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Deployment contracts, planning, execution and recovery evidence.
//! Nix, SSH and the CA are external commands admitted through the runner's effect policy.
//! Read-only command classification and observed outcomes still require validation.

pub mod activate;
pub mod build;
pub mod canonical;
pub mod checks;
pub mod effects;
pub mod execute;
#[cfg(test)]
pub mod fixtures;
pub mod ids;
pub mod install;
pub mod inventory;
pub mod manifest;
pub mod nix;
pub mod observation;
pub mod observe;
pub mod pki;
pub mod plan;
pub mod readiness;
pub mod receipt;
pub mod release;
pub mod run;
pub mod source;
pub mod state;
pub mod template;
pub mod transport;
pub mod verify;
