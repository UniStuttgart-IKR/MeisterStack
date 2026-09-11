// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The `Counter` kind: the one object nobody creates by hand.
//! Moved out of `resources.rs` unchanged.

use super::*;

/// A number the server hands out, kept in the store so that handing it out is
/// a compare-and-swap rather than a hope.
///
/// It is an ordinary object with an ordinary `resourceVersion`, which is the
/// entire point: the store's CAS on that field is the allocator. Nothing else
/// had to be built, and nothing about it is specific to VNIs — the next
/// counter this stack needs takes another name under the same resource.
///
/// No REST route serves it. It is not something anybody creates, lists or
/// edits, and a counter an operator could PUT is a counter two tenants can be
/// given the same value from.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CounterSpec {
    /// The value the next allocation hands out, before the floor is applied.
    pub next: u32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct CounterStatus {}

pub type Counter = Object<CounterSpec, CounterStatus>;
