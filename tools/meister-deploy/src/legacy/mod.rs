// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The tool as it was, kept whole, behind one word.
//!
//! These five modules are the pre-v1 `meister-deploy`: one `fleet.toml`
//! schema that Rust and Nix both derived addresses from, an rsync push to the
//! context fleet, `nixos-rebuild --target-host` for metal, and a renderer that
//! wrote a node back out as a Nix module. Nothing in here was changed except
//! the module paths — the point is that the twelve OpenNebula VMs keep a
//! working verb while the new pipeline is built beside them, and that the 52
//! tests that pin the old command lines keep running.
//!
//! They are reachable only as `meister-deploy legacy <verb>`, because `plan`
//! means something else from v1 on: a `DeploymentPlan` on disk, not a table on
//! a terminal. They go away with L3, when the context fleet is migrated and
//! the parity evidence is written down — not before.
//!
//! Nothing new may be built on this. In particular [`run::Fake`] is not the
//! test contract any more; `crate::run::StrictFake` is.

pub mod fleet;
pub mod ops;
pub mod remote;
pub mod render;
pub mod run;
