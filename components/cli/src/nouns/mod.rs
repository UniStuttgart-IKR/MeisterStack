// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Resource-specific table rows and convenience commands.
//! Generic discovery and CRUD live in crate::generic; VM and node commands have separate modules.

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::json;

use crate::generic::Ctx;
use crate::output::{self, View, age, age_until, joined, mem, or_dash, readiness, size};
use crate::{
    CsrCmd, FloatingIpCmd, FloatingPoolCmd, ImageCmd, ProviderNetworkCmd, RoutedSubnetCmd,
    RouterCmd, SecretCmd, StoragePoolCmd, TenantCmd, UserCmd, VolumeCmd, VolumeSnapshotCmd,
};

mod cluster;
mod csr;
mod floating_ip;
mod floating_pool;
mod image;
mod network;
mod routed_subnet;
mod secret;
mod storage_pool;
mod tenant;
mod user;
mod vm_migration;
mod volume;
mod volume_snapshot;

use cluster::*;
pub(crate) use csr::*;
pub(crate) use floating_ip::*;
pub(crate) use floating_pool::*;
pub(crate) use image::*;
pub(crate) use network::*;
pub(crate) use routed_subnet::*;
pub(crate) use secret::*;
pub(crate) use storage_pool::*;
pub(crate) use tenant::*;
pub(crate) use user::*;
use vm_migration::*;
pub(crate) use volume::*;
pub(crate) use volume_snapshot::*;

#[derive(Deserialize)]
struct Meta {
    name: String,
}

/// One field out of `metadata`, because one field is what this table asks
/// about. The rest of the envelope stays undeserialised, as it does for every
/// other row builder here.
#[derive(Deserialize, Default)]
struct Generation {
    #[serde(default)]
    generation: u64,
}

/// And its counterpart out of `status`.
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct Observed {
    #[serde(default)]
    observed_generation: u64,
}

/// Show whether the controller has observed the resource generation.
/// This compares reported metadata; it is not an independent dataplane check.
fn applied(generation: u64, observed: u64) -> String {
    if observed >= generation {
        "yes"
    } else {
        "pending"
    }
    .to_string()
}

/// The two fields every object in this API carries, for a kind this CLI has
/// never heard of.
#[derive(Deserialize)]
struct Bare {
    metadata: BareMeta,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BareMeta {
    name: String,
    #[serde(default)]
    creation_timestamp: Option<DateTime<Utc>>,
}

// --- the table for a kind ---------------------------------------------------

/// Select a row renderer by discovery kind. Unknown kinds use metadata columns.
pub(crate) fn table_of_kind(
    kind: &str,
    body: &Bytes,
    placement: crate::vm::Placement,
) -> Result<View> {
    let now = Utc::now();
    match kind {
        "Vm" => crate::vm::table(body, placement),
        "Node" => crate::cluster::node_table(body, now),
        "Event" => crate::vm::event_table(body),
        "Cluster" => output::table_of(
            body,
            "parsing cluster list",
            &[
                "cluster",
                "ready",
                "heartbeat",
                "nodes",
                "vcpus",
                "mem",
                "capabilities",
                "vms",
            ],
            "no clusters known to this cloud",
            |c: Cluster| cluster_row(c, now),
        ),
        "Image" => output::table_of(
            body,
            "parsing image list",
            // `source` is last because it is the one cell here an operator
            // can put a space in: it is a path they chose. Everything before
            // it stays one token, so `awk` can cut this table up.
            &[
                "name", "tenant", "scope", "format", "size", "phase", "nodes", "source",
            ],
            "no images in this catalogue",
            image_row,
        ),
        "Tenant" => output::table_of(
            body,
            "parsing tenant list",
            &["tenant", "vni", "vms", "vcpus", "mem", "description"],
            "no tenants",
            tenant_row,
        ),
        "User" => output::table_of(
            body,
            "parsing user list",
            &[
                "user",
                "role",
                "tenant",
                "certs",
                "next-expiry",
                "description",
            ],
            "no users in this directory",
            |u: User| user_row(u, now),
        ),
        "CertificateSigningRequest" => output::table_of(
            body,
            "parsing request list",
            &["request", "user", "phase", "by"],
            "no certificate requests",
            csr_row,
        ),
        "FloatingPool" => output::table_of(
            body,
            "parsing pool list",
            &["pool", "cidrs", "scope", "default", "quota", "description"],
            "no floating pools; an admin creates one with `meister floatingpool create`",
            floating_pool_row,
        ),
        "FloatingIp" => output::table_of(
            body,
            "parsing reservation list",
            // "points at" and not "vm": a reservation points at a vm that
            // holds it or at a router that translates it, and one column for
            // both is what keeps the two roads readable side by side.
            &["address", "tenant", "pool", "points at", "applied"],
            "no floating addresses reserved",
            floating_ip_row,
        ),
        "RoutedSubnet" => output::table_of(
            body,
            "parsing subnet list",
            &["subnet", "tenant", "cidr", "description"],
            "no routed subnets",
            routed_subnet_row,
        ),
        "ProviderNetwork" => output::table_of(
            body,
            "parsing provider network list",
            &[
                "network",
                "physnet",
                "cidr",
                "gateway",
                "allocation",
                "description",
            ],
            "no provider networks; an admin declares one with \
             `meister providernetwork create`",
            provider_network_row,
        ),
        "Router" => output::table_of(
            body,
            "parsing router list",
            // `nat` is snat/dnat/routed, counted — see `router_row`.
            &[
                "router", "tenant", "network", "phase", "external", "internal", "cluster",
                "active", "nat",
            ],
            "no routers",
            router_row,
        ),
        "StoragePool" => output::table_of(
            body,
            "parsing pool list",
            &[
                "pool",
                "driver",
                // Expose pool readiness independently of its driver and locality.
                "phase",
                // Where this pool's bytes are, which is what decides whether
                // a VM using one of its disks is pinned to one machine.
                // Reported by the nodes, never set by an admin.
                "locality",
                "cluster",
                "default",
                "nodes",
                "quota",
                "description",
            ],
            "no storage pools; an admin creates one with `meister storagepool create`",
            storage_pool_row,
        ),
        // `Volume` is not here, and that is the one exception in this match:
        // its listing needs a second request (the snapshots that stand on
        // each disk), so it has a function of its own. See `list_volumes`.
        "VolumeSnapshot" => output::table_of(
            body,
            "parsing snapshot list",
            &[
                "snapshot",
                "tenant",
                // What it is a copy OF. It keeps meaning something after that
                // volume is gone, which is the whole point of the object.
                "volume",
                "phase",
                // Show measured snapshot size and the node retaining its bytes.
                "size",
                "node",
                "age",
                "description",
            ],
            "no volume snapshots",
            volume_snapshot_row,
        ),
        "VmMigration" => output::table_of(
            body,
            "parsing migration list",
            &[
                "migration",
                "tenant",
                "vm",
                "phase",
                "from",
                "to",
                "age",
                // Last, because it is the one cell here that carries a server
                // sentence — and on a Failed migration it is the whole reason
                // the object is worth keeping.
                "note",
            ],
            "no live migrations recorded here",
            move |m: VmMigration| vm_migration_row(m, now),
        ),
        // Listable on the day it exists, with the two things every object in
        // this API has. The sentence for it is in the report.
        other => output::table_of(
            body,
            "parsing the listing",
            &["name", "age"],
            "nothing here",
            move |o: Bare| vec![o.metadata.name, age(o.metadata.creation_timestamp, now)],
        )
        .map_err(|e| e.context(format!("this cli has no table for kind {other}"))),
    }
}

/// The volume's own envelope: the name and when it was made. `age` is what
/// tells "reserved a moment ago" from "has been Pending all afternoon", which
/// is the difference between waiting and looking into it.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VolumeMeta {
    name: String,
    #[serde(default)]
    creation_timestamp: Option<DateTime<Utc>>,
}
