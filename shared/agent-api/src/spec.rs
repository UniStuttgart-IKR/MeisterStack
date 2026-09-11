// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The document a VM is created from — `spec.vm` at both REST edges and the
//! body of the node's own create route, one type.
//!
//! It lives HERE rather than in `components/agent` for a single reason: the
//! refusal it makes has to be made where the client can still read it. A
//! controller that takes `spec.vm` as an opaque `Value` answers 201 and lets
//! the node say "unknown field `base_image`" three tiers down, asynchronously,
//! into a status field nobody was waiting on. Both controllers now
//! deserialise into these types at the edge and hand the serde sentence back
//! as a 422 with the field in `details.field`.
//!
//! What did NOT move is everything that needs a node to be true: sizing,
//! images on disk, a bridge, a driver. `into_spec` — the step that turns this
//! document into the node's own record — stays in the agent, and so the tier
//! boundary stays where it was. This module is the SHAPE, and the shape is
//! not a secret: `/schemas` publishes it (schemars is derived here), so a
//! form can list the fields without knowing a single rule.
//!
//! Note the case: everything outside `spec.vm` is camelCase, everything
//! inside it is snake_case. That is this boundary, made visible.

use serde::{Deserialize, Serialize};

// reconcile alibi-state-machine
/// Intention of the owner of the VM.
/// Owner is here the http-api or the controller.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Default,
    serde::Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
pub enum Desired {
    #[default]
    Running,
    /// VMM stopped, memory freed, volumes and nics stay existend.
    Stopped,
    Paused,
    Absent,
    /// Reserved for guest shutdown. VMM stays in RAM;
    /// Reconciler knows there is a state transition.
    Halted,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
// `deny_unknown_fields` here as everywhere else in this document. It was the
// one part that took a stray field in silence, which the first foreign client
// found and wrote down: a boot block is the shortest thing anybody types by
// hand and therefore the one they most often misspell.
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BootSourceSpec {
    DirectKernel {
        kernel: String,
        cmdline: String,
        initramfs: Option<String>,
    },
    Firmware {
        firmware: String,
    },
}

/// What the guest is configured with. Absent from a spec entirely means the
/// VM gets no seed and its configuration is byte for byte what it was — which
/// is the most important property this feature has.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CloudInit {
    /// The `#cloud-config` document, or a script, or whatever else cloud-init
    /// accepts. Passed through untouched: what is valid user-data is
    /// cloud-init's question and not this control plane's, and a stack that
    /// validated it would be a stack that rejects next year's syntax.
    pub user_data: String,
    /// Derived when absent — see `meta_data_for`. Given, it is used verbatim.
    #[serde(default)]
    pub meta_data: Option<String>,
    /// The optional third file. Only written when it is there: an empty
    /// `network-config` is not the same thing as none, and cloud-init treats
    /// the two differently.
    #[serde(default)]
    pub network_config: Option<String>,
    /// What the guest should call itself. Filled in by the cluster tier from
    /// the VM object's name, because that is the only tier that knows it —
    /// the agent has a uid and nothing else. Absent falls back to the uid,
    /// which is an ugly hostname and an honest one.
    #[serde(default)]
    pub local_hostname: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NewVmSpec {
    pub vcpus: u32,
    pub memory_mib: u64,
    pub boot: BootSourceSpec,
    #[serde(default)]
    pub desired: Desired,
    #[serde(default)]
    pub volumes: Vec<NewVolume>,
    #[serde(default)]
    pub nics: Vec<NewNic>,
    #[serde(default)]
    pub devices: Vec<NewDevice>,
    /// The NoCloud seed this VM boots with, if it has one. Absent — which is
    /// every spec ever written before this — means no second disk is built
    /// and no line of the VM's configuration changes.
    #[serde(default)]
    pub cloud_init: Option<CloudInit>,
}

/// The volume half of a NewVmSpec. `driver` and `params` mirror `NewDevice`:
/// both default, so every spec written before storage had more than one
/// backend is still exactly the spec it was.
///
/// # Ephemeral, and why that needs no field
///
/// An entry here is an EPHEMERAL disk: it is made when the VM is made and it
/// goes when the VM goes, like an instance store. Nothing on it says so
/// because nothing has to — the axis is structural. A disk described INSIDE a
/// VM's spec has no existence outside that VM, and a disk that is a `Volume`
/// object was there before the VM and is there after it. Those are the two
/// cases, they are told apart by WHERE the disk is written down, and a
/// `ephemeral: true` anywhere would be a second way of saying the same thing
/// — with the usual consequence that the two can disagree.
///
/// So there is deliberately no `ephemeral` on the `Volume` object either:
/// somebody who wants scratch space writes it inline, here, and gets it.
/// What the distinction costs elsewhere is one sentence in the placement
/// rules: a VM whose local disks are all ephemeral may be moved to another
/// node and have them made again there, and a VM holding one persistent
/// node-local volume may not.
#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NewVolume {
    /// The `Volume` this entry REFERS to rather than describes.
    ///
    /// At the API edge it is the object's NAME, inside the tenant, the way
    /// `FloatingIp.spec.vm` names a VM. What reaches this node is the object's
    /// UID — the controller resolves it on the way down, because a name is
    /// what people call a volume and a node has no directory to look one up
    /// in.
    ///
    /// Set: this node ATTACHES a volume it already owns a record of (see
    /// `crate::volumes`) and provisions nothing; the disk was there before
    /// this VM and stays after it. Every other field except `params` is then
    /// refused — a referenced volume has its size and its image already, and
    /// a second statement about them is one that can disagree.
    ///
    /// Unset: everything below describes a disk to be MADE for this VM and
    /// unmade with it. That is the ephemeral case and the only one that
    /// existed before this field.
    #[serde(default)]
    pub volume: Option<String>,
    #[serde(default)]
    pub base_image: Option<String>,
    /// Where `base_image` can be fetched from if this node does not have it,
    /// and what the bytes must hash to. Both control-plane-owned: the cloud
    /// resolves them from the Image object and writes them into the spec, and
    /// the create edge refuses them from a client — a URL somebody else chose
    /// is a base image somebody else chose.
    ///
    /// Both default, so every spec ever written is still exactly the spec it
    /// was: a `base_image` with no url beside it is looked up under the
    /// node's image_dir exactly as it always has been.
    #[serde(default)]
    pub base_image_url: Option<String>,
    #[serde(default)]
    pub base_image_sha256: Option<String>,
    /// How big, for a disk this node is to MAKE. Defaults so that a
    /// referenced entry need not name it — the size belongs to the volume
    /// that already exists — and an INLINE entry that names none is refused
    /// by `into_spec` with a sentence rather than by serde with a field path.
    #[serde(default)]
    pub size_bytes: u64,
    /// None = the node's default, `filesystem`.
    #[serde(default)]
    pub driver: Option<String>,
    #[serde(default)]
    pub params: Option<serde_json::Value>,
}

#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NewNic {
    #[serde(default)]
    pub bridge: Option<String>,
    #[serde(default)]
    pub mac: Option<String>,
    /// The tenant overlay this NIC belongs on. Defaults, so every spec ever
    /// written is still exactly the spec it was.
    ///
    /// Normally injected by the controller out of the VM's tenant (see
    /// `controller_api::vni`); set by hand on a standalone cluster with no
    /// cloud above it, which has no Tenant object to resolve.
    #[serde(default)]
    pub vxlan_id: Option<u32>,
    /// Floating addresses this VM holds, and the tenant's routed subnets.
    /// Both default to empty and both travel the road `vxlan_id` travels —
    /// injected by the controller out of the cloud's objects, or written by
    /// hand on a standalone cluster. See `agent_api::networking::NicSpec`.
    #[serde(default)]
    pub floating_ips: Vec<String>,
    #[serde(default)]
    pub routed_subnets: Vec<String>,
    /// Put this NIC on a PROVIDER network rather than on an overlay: the
    /// name of one of the node's physnets. See
    /// `agent_api::networking::NicSpec::physnet`; naming both this and
    /// `vxlan_id` is refused.
    #[serde(default)]
    pub physnet: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NewDevice {
    #[serde(default, alias = "driver_name")]
    pub driver: Option<String>,
    pub partition: String,
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub params: Option<serde_json::Value>,
}
