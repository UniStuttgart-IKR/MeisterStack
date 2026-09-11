// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! `meister-deploy` — the plan, the order, and the table.
//!
//! The tools that do the work are the ones an operator already trusts: `nix`
//! builds, `ssh` and `rsync` carry, `nixos-rebuild` switches, `tools/meister-ca`
//! signs. What is here is the part none of them can know — which box is what,
//! which addresses follow from that, in which order a fleet is allowed to be
//! taken forward, and what the fleet looks like right now.
//!
//! So: no Nix evaluation in Rust, and no ssh library. Every outside command
//! goes through one narrow door (`run::Runner`), which is also what lets the
//! tests read the command lines instead of a lab.

pub mod fleet;
pub mod ops;
pub mod remote;
pub mod render;
pub mod run;
