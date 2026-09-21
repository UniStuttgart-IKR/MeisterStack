// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! `meister-deploy` — the plan, the order, and the evidence.
//!
//! The tools that do the work are the ones an operator already trusts: `nix`
//! builds, `ssh` carries, `tools/meister-ca` signs. What is here is the part
//! none of them can know — which box is what, in which order a fleet is
//! allowed to be taken forward, whether that is safe right now, and what
//! actually happened afterwards.
//!
//! So: no Nix evaluation in Rust, and no ssh library. Every outside command
//! goes through one narrow door, and the door knows the effect class of what
//! passes it — which is what makes `--dry-run` and `--offline` a property of
//! the program rather than a promise in its documentation.
//!
//! The pre-v1 tool is whole under [`legacy`] and reachable as
//! `meister-deploy legacy <verb>`; it carries the context fleet until L3.

pub mod effects;
pub mod legacy;
pub mod run;
