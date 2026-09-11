// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The nouns that are only a cloud's, and how each of them is rendered.
//!
//! Two things live here and they are two halves of one job. The `*_row`
//! functions are how a listing becomes a table, one per kind, chosen by the
//! kind out of the discovery document — `ls` itself is in [`crate::generic`]
//! and knows nothing about any of them. The verbs below them are the sugar: a
//! create, and the handful of "set one field" verbs, every one of which is
//! now a single merge patch rather than the read-edit-write it used to be.
//!
//! The VM verbs are in [`crate::vm`] and the machine verbs in
//! [`crate::cluster`], for the same reason: they are the same act against a
//! different inventory.

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

/// `yes` or `pending`, from the generation pair.
///
/// The column exists because `floatingip assign` says "takes effect at the
/// next recreate" in its help and nothing afterwards ever said whether it
/// had. `pending` here is not an error and not a warning: it is the true
/// answer to "is this address on the wire yet", and for an address assigned
/// to a running VM it stays `pending` until that VM is created again.
///
/// A VM list gets no such column on purpose — a VM's own drift lasts one
/// reconcile pass and is not something an operator runs a business on.
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

/// The listing of one kind, chosen by the kind the discovery document named.
///
/// This is the whole of what `ls` knows about resources, and it is a lookup
/// rather than a command tree: `meister <anything> ls` reaches the same
/// function, and what differs is one row builder. A kind nothing here knows
/// still lists — `NAME` and `AGE` come off metadata, which every object in
/// this API has — so a resource added to the control plane is listable the
/// day it exists and gets a table when somebody decides what its columns are.
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
                // The one field that says "this pool is unusable", and the
                // only kind in this table that did not show it — `Image`,
                // `VolumeSnapshot` and `VmMigration` all do. A pool whose
                // driver no node offers is created without complaint and read
                // `Pending` in the API while this table showed it beside the
                // healthy ones (D14).
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
                // How big the copy came out, as the node measured it, and
                // which machine has it. A snapshot outlives its volume, so
                // after the volume goes this column is the only thing that
                // says where the bytes are.
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
