// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Persisted allocation counters.

use super::*;

/// Internal monotonic allocator stored as a resource. resourceVersion CAS serializes updates.
/// No REST route exposes the counter, preventing clients from resetting allocation state.
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CounterSpec {
    /// The value the next allocation hands out, before the floor is applied.
    pub next: u32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct CounterStatus {}

pub type Counter = Object<CounterSpec, CounterStatus>;
