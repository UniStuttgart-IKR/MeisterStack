// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Shared VM request types for controller `spec.vm` and the agent create API.
//!
//! Controllers validate this shape before accepting a request. Conversion into
//! node records and checks that require local drivers remain in the agent.
//! `spec.vm` uses snake_case; the surrounding controller object uses camelCase.
//! These same types supply the published JSON Schema.

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
// Reject unknown boot-source fields, including misspelled variant parameters.
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
    /// Cloud-init user-data, passed through without interpreting its format.
    pub user_data: String,
    /// Derived when absent — see `meta_data_for`. Given, it is used verbatim.
    #[serde(default)]
    pub meta_data: Option<String>,
    /// Optional network-config file. Absence omits it; an empty supplied value creates an empty file.
    #[serde(default)]
    pub network_config: Option<String>,
    /// Guest hostname, normally supplied from the VM object name by the controller.
    /// The agent falls back to the VM UID when absent.
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
    /// Optional NoCloud seed. Absence adds no seed disk to the VM.
    #[serde(default)]
    pub cloud_init: Option<CloudInit>,
}

/// A VM disk request: either an inline ephemeral disk or a reference to a
/// persistent Volume. Inline disks share the VM lifecycle; referenced volumes
/// outlive it. Persistent node-local volumes constrain placement even when
/// ephemeral local disks can be recreated elsewhere. `driver` and `params`
/// default for compatibility with older requests.
#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NewVolume {
    /// Reference to an independently managed Volume. The API accepts its
    /// name; controllers resolve it to a UID before agent dispatch. The agent
    /// attaches existing storage and does not provision inline data. Only
    /// `params` may accompany the reference. None selects VM-owned inline storage.
    #[serde(default)]
    pub volume: Option<String>,
    #[serde(default)]
    pub base_image: Option<String>,
    /// Control-plane-resolved image URL and digest. Cloud admission rejects
    /// client overrides; absent download metadata selects the node image directory.
    #[serde(default)]
    pub base_image_url: Option<String>,
    #[serde(default)]
    pub base_image_sha256: Option<String>,
    /// Control-plane-owned image incarnation, combined with its digest in
    /// cache identity. Standalone and legacy specs without a UID use the digest.
    #[serde(default)]
    pub base_image_uid: Option<String>,
    /// Inline disk size. Zero defaults permit referenced entries to omit it;
    /// agent conversion rejects inline entries without a positive size.
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
    /// Optional tenant VNI, injected by the controller or supplied directly
    /// in standalone specs.
    #[serde(default)]
    pub vxlan_id: Option<u32>,
    /// Floating addresses and routed tenant subnets, defaulting to empty.
    /// Controllers may inject them; standalone specs may supply them directly.
    #[serde(default)]
    pub floating_ips: Vec<String>,
    #[serde(default)]
    pub routed_subnets: Vec<String>,
    /// Direct provider-network name, mutually exclusive with vxlan_id.
    /// See `crate::networking::NicSpec::physnet`.
    #[serde(default)]
    pub physnet: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NewDevice {
    #[serde(default, alias = "driver_name")]
    pub driver: Option<String>,
    pub partition: String,
    /// Named device profile defined by the node operator.
    #[serde(default)]
    pub profile: Option<String>,
    /// Driver-specific request parameters. The agent rejects keys that the
    /// driver has not declared tenant-configurable; operator process settings
    /// such as environment and privileges cannot be supplied through this map.
    #[serde(default)]
    pub params: Option<serde_json::Value>,
}
