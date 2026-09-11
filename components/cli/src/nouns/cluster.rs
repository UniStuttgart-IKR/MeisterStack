// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! `Cluster` as the cloud sees it, and its row.

use super::*;

#[derive(Deserialize)]
pub(super) struct Cluster {
    metadata: Meta,
    #[serde(default)]
    spec: ClusterSpec,
    #[serde(default)]
    status: ClusterStatus,
}

#[derive(Deserialize)]
pub(super) struct ClusterSpec {
    #[serde(default = "yes")]
    schedulable: bool,
    #[serde(default)]
    drain: bool,
}

pub(super) fn yes() -> bool {
    true
}

impl Default for ClusterSpec {
    fn default() -> Self {
        Self {
            schedulable: true,
            drain: false,
        }
    }
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(super) struct ClusterStatus {
    #[serde(default)]
    connected: bool,
    #[serde(default)]
    last_heartbeat: Option<DateTime<Utc>>,
    #[serde(default)]
    nodes_ready: u32,
    #[serde(default)]
    nodes_total: u32,
    #[serde(default)]
    capacity: Capacity,
    #[serde(default)]
    vms: u32,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(super) struct Capacity {
    #[serde(default)]
    vcpus: u32,
    #[serde(default)]
    mem_mib: u64,
    // The alias is the mixed-version case, not tidiness: a controller that
    // predates the rename still sends `gpuProfiles`, and without this the
    // column would come out empty against every node in a fleet that has not
    // been rolled out yet.
    #[serde(default, alias = "gpuProfiles")]
    capabilities: Vec<String>,
}

pub(super) fn cluster_row(c: Cluster, now: DateTime<Utc>) -> Vec<String> {
    let cap = c.status.capacity;
    vec![
        c.metadata.name,
        readiness(c.status.connected, c.spec.schedulable, c.spec.drain, &[]),
        age(c.status.last_heartbeat, now),
        format!("{}/{}", c.status.nodes_ready, c.status.nodes_total),
        cap.vcpus.to_string(),
        mem(cap.mem_mib),
        joined(&cap.capabilities),
        c.status.vms.to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A cluster the cloud has only ever heard Hello from carries no capacity
    /// at all; the table must still render it.
    #[test]
    fn a_bare_cluster_object_parses() {
        let c: Cluster =
            serde_json::from_str(r#"{"metadata":{"name":"cluster-1"},"spec":{},"status":{}}"#)
                .unwrap();
        assert_eq!(c.metadata.name, "cluster-1");
        assert!(c.spec.schedulable);
        assert_eq!(
            readiness(c.status.connected, c.spec.schedulable, c.spec.drain, &[]),
            "no"
        );

        let row = cluster_row(c, Utc::now());
        assert_eq!(row[1], "no");
        assert_eq!(row[3], "0/0");
    }
}
