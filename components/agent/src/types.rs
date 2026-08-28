// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

use agent_api::{
    Device, Nic,
    device::{DeviceId, DeviceSpec, PartitionSpec, default_device_driver},
    hypervisor::VmId,
    networking::{NicId, NicSpec},
    storage::{Volume, VolumeId, VolumeSpec},
    types::mac_addr::MacAddr,
};
use anyhow::{Context, bail};
use macros::generated;
use uuid::Uuid;

// reconcile alibi-state-machine
/// Intention of the owner of the VM.
/// Owner is here the http-api or the controller.
#[derive(Clone, Copy, Debug, PartialEq, Default, serde::Serialize, serde::Deserialize)]
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

/// Process that requires ownership of the VM.
/// This is required to let the reconciler know to not start/stop the VM while its in one of these
/// states.
/// If one of those actions is found on startup the VM is considered orphaned.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum Operation {
    Snapshotting { target: String },
    Restoring { source: String },
    MigratingOut { peer: String },
    MigratingIn { peer: String },
}

/// Process of the resource creation. Only for journaling.
/// For decision-making its only relevant `Provisioned` (finished) or else (not finished).
/// This is to track the creation phase of a VM.
#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum Phase {
    Provisioning,
    VolumesDone,
    NetworkDone,
    DevicesDone,
    Provisioned,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
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

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AgentVmSpec {
    pub vcpus: u32,
    pub memory_mib: u64,
    pub boot: BootSourceSpec,
    pub volumes: Vec<VolumeWithId>,
    pub nics: Vec<NicWithId>,
    pub devices: Vec<DeviceWithId>,
    /// Where the base images this VM names can be fetched from, if this node
    /// does not have them yet. Beside the volumes rather than inside their
    /// specs, and that is the point: a `VolumeSpec` is the contract three
    /// storage drivers implement, all three resolve `base_image` by joining
    /// the name onto their own image_dir, and none of them has to learn what
    /// a URL is for this to work. The agent puts the bytes there first.
    ///
    /// Empty for every spec written before this existed, and empty for every
    /// path-based image afterwards — so a record written yesterday loads
    /// unchanged and behaves unchanged.
    #[serde(default)]
    pub images: Vec<crate::images::Source>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct VolumeWithId {
    pub id: VolumeId,
    pub spec: VolumeSpec,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct NicWithId {
    pub id: NicId,
    pub spec: NicSpec,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DeviceWithId {
    pub id: DeviceId,
    pub spec: DeviceSpec,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct VmRecord {
    pub spec: AgentVmSpec,
    #[serde(default)]
    pub desired: Desired,
    pub phase: Phase,
    #[serde(default)]
    pub operation: Option<Operation>,
    /// `time::SystemTime` to make the deadline surrive an agent restart.
    #[serde(default)]
    pub stop_deadline: Option<std::time::SystemTime>,
    /// Set by the reconciler when it detects a condition it must not repair
    /// automatically (e.g. a dead device backend under a live VMM). While set,
    /// the reconciler quarantines the VM: no automatic Provision/Start.
    /// Cleared by explicit lifecycle actions (start/stop/destroy via API) or
    /// by a successful re-provision.
    #[serde(default)]
    pub unhealthy: Option<String>,
    /// True when this record came into being over the controller session.
    /// Only these may be torn down by a desired-state snapshot: a VM created
    /// straight on the agent's unix socket belongs to whoever is at that
    /// socket, is invisible to the controller, and is not the controller's
    /// to reap. Records written before the marker existed default to false
    /// and are claimed the first time the controller names one.
    #[serde(default)]
    pub managed_by_controller: bool,
    pub volumes: Vec<Volume>,
    pub nics: Vec<Nic>,
    pub devices: Vec<Device>,
    #[serde(default)]
    pub vmm_pid: Option<u32>,
}

#[derive(Debug, Clone, serde::Deserialize)]
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
}

/// The volume half of a NewVmSpec. `driver` and `params` mirror `NewDevice`:
/// both default, so every spec written before storage had more than one
/// backend is still exactly the spec it was.
#[generated(model = ClaudeOpus, version = "5")]
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewVolume {
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
    pub size_bytes: u64,
    /// None = the node's default, `filesystem`.
    #[serde(default)]
    pub driver: Option<String>,
    #[serde(default)]
    pub params: Option<serde_json::Value>,
}

#[derive(Debug, Clone, serde::Deserialize)]
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
}

#[generated(model = ClaudeFable, version = "5")]
#[derive(Debug, Clone, serde::Deserialize)]
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

#[generated(model = ClaudeFable, version = "5")]
impl TryFrom<proto::VmSpec> for AgentVmSpec {
    type Error = anyhow::Error;
    fn try_from(p: proto::VmSpec) -> Result<Self, Self::Error> {
        let boot = match p.boot {
            Some(proto::vm_spec::Boot::DirectKernel(dk)) => BootSourceSpec::DirectKernel {
                kernel: non_empty(dk.kernel).context("kernel must be set")?,
                cmdline: dk.cmdline,
                initramfs: non_empty(dk.initramfs),
            },
            Some(proto::vm_spec::Boot::Firmware(fw)) => BootSourceSpec::Firmware {
                firmware: non_empty(fw.firmware).context("firmware must be set")?,
            },
            None => bail!("vm spec has no boot source"),
        };

        Ok(Self {
            vcpus: p.vcpus,
            memory_mib: p.memory_mib,
            boot,
            volumes: p
                .volumes
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()
                .context("invalid volume spec")?,
            nics: p
                .nics
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()
                .context("invalid nic spec")?,
            // The proto path carries no fetchable image, the same way it
            // carries neither driver nor params: the controller sends
            // spec_json (control-plane.md §6), and that is where anything
            // beyond the four original fields travels.
            images: Vec::new(),
            devices: p
                .devices
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()
                .context("invalid device spec")?,
        })
    }
}

#[generated(model = ClaudeFable, version = "5")]
impl TryFrom<proto::VolumeSpec> for VolumeWithId {
    type Error = anyhow::Error;
    fn try_from(p: proto::VolumeSpec) -> Result<Self, Self::Error> {
        Ok(Self {
            id: parse_uuid(&p.id).context("volume id")?,
            // The proto path carries neither driver nor params; the
            // controller sends spec_json (see control-plane.md §6), and that
            // is where a routed volume travels. Same TODO the device
            // conversion below carries, and it will be closed the same way.
            spec: VolumeSpec {
                base_image: non_empty(p.base_image),
                size_bytes: p.size_bytes,
                driver: None,
                params: None,
            },
        })
    }
}

#[generated(model = ClaudeFable, version = "5")]
impl TryFrom<proto::NicSpec> for NicWithId {
    type Error = anyhow::Error;
    fn try_from(p: proto::NicSpec) -> Result<Self, Self::Error> {
        Ok(Self {
            id: parse_uuid(&p.id).context("nic id")?,
            spec: NicSpec {
                bridge: non_empty(p.bridge).context("bridge must be set")?, // controller
                // sends explicit
                // bridges
                mac: p
                    .mac
                    .parse::<MacAddr>()
                    .map_err(|e| anyhow::anyhow!("invalid mac {:?}: {e}", p.mac))?,
                // The proto NicSpec carries neither the overlay nor the
                // addresses: the controller sends spec_json (control-plane.md
                // §6) and that is where a tenant-bound NIC travels. Same
                // reason the volume conversion above carries no driver.
                vxlan_id: None,
                floating_ips: Vec::new(),
                routed_subnets: Vec::new(),
            },
        })
    }
}

#[generated(model = ClaudeFable, version = "5")]
impl TryFrom<proto::DeviceSpec> for DeviceWithId {
    type Error = anyhow::Error;
    fn try_from(p: proto::DeviceSpec) -> Result<Self, Self::Error> {
        let partition = match p.partition.as_str() {
            "exclusive" => PartitionSpec::Exclusive,
            "mediated" => PartitionSpec::Mediated,
            other => bail!("unknown partition type {other:?}"),
        };
        let params = non_empty(p.params_json)
            .map(|s| serde_json::from_str(&s))
            .transpose()
            .context("device params_json")?;
        Ok(Self {
            id: parse_uuid(&p.id).context("device id")?,
            // `driver_name` IS in the proto and is honoured here: routing a
            // device to the driver the controller named is the whole point of
            // the field, and silently sending every device to the node's
            // default was a lie the record then remembered forever.
            // An empty string is proto3's "unset" and keeps the old meaning,
            // so a controller that does not fill the field changes nothing.
            //
            // TODO(proto): `profile` still has no field; extend control.proto
            // when the controller learns to pick one.
            spec: DeviceSpec {
                driver: non_empty(p.driver_name).unwrap_or_else(default_device_driver),
                partition,
                profile: None,
                params,
            },
        })
    }
}

impl NewVmSpec {
    #[generated(model = ClaudeFable, version = "5")]
    pub fn into_spec(self, default_bridge: &str) -> anyhow::Result<(VmId, AgentVmSpec, Desired)> {
        if self.vcpus == 0 {
            bail!("vcpus must be greater than zero");
        }
        if matches!(self.desired, Desired::Absent | Desired::Halted) {
            bail!("desired {:?} is not a valid creation target", self.desired);
        }
        if self.volumes.is_empty() {
            bail!("a vm needs at least one volume as boot disk");
        }
        let vm_id = Uuid::new_v4();

        // The fetchable half, lifted out of the volumes and deduplicated:
        // two volumes off one base image are one download.
        let mut images: Vec<crate::images::Source> = Vec::new();
        for v in &self.volumes {
            let (Some(name), Some(url), Some(sha256)) = (
                v.base_image.as_deref(),
                v.base_image_url.as_deref(),
                v.base_image_sha256.as_deref(),
            ) else {
                // A url without a checksum, or either without a base_image,
                // asks for nothing: the create edge refuses that shape, and
                // here it simply means "look this name up locally", which is
                // what a path-based image has always meant.
                continue;
            };
            if !images.iter().any(|s| s.name == name) {
                images.push(crate::images::Source {
                    name: name.to_string(),
                    url: url.to_string(),
                    sha256: sha256.to_string(),
                });
            }
        }

        let volumes = self
            .volumes
            .into_iter()
            .map(|v| VolumeWithId {
                id: Uuid::new_v4(),
                spec: VolumeSpec {
                    base_image: v.base_image,
                    size_bytes: v.size_bytes,
                    driver: v.driver,
                    params: v.params,
                },
            })
            .collect();

        let nics = self
            .nics
            .into_iter()
            .map(|n| {
                let id = Uuid::new_v4();
                let mac = n.mac.unwrap_or_else(|| {
                    let b = id.as_bytes();
                    format!("52:54:00:{:02x}:{:02x}:{:02x}", b[0], b[1], b[2])
                });
                let mac: MacAddr = mac
                    .parse()
                    .map_err(|e| anyhow::anyhow!("invalid mac {mac:?}: {e}"))?;
                let bridge = match n.bridge {
                    Some(b) if !b.is_empty() => b,
                    _ => default_bridge.to_string(),
                };
                Ok(NicWithId {
                    id,
                    spec: NicSpec {
                        bridge,
                        mac,
                        vxlan_id: n.vxlan_id,
                        floating_ips: n.floating_ips,
                        routed_subnets: n.routed_subnets,
                    },
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        let devices = self
            .devices
            .into_iter()
            .map(|d| {
                let partition = match d.partition.as_str() {
                    "exclusive" => PartitionSpec::Exclusive,
                    "mediated" => PartitionSpec::Mediated,
                    other => anyhow::bail!("unknown partition type {other:?}"),
                };
                Ok(DeviceWithId {
                    id: Uuid::new_v4(),
                    spec: DeviceSpec {
                        driver: d.driver.unwrap_or_else(default_device_driver),
                        partition,
                        profile: d.profile,
                        params: d.params,
                    },
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        Ok((
            vm_id,
            AgentVmSpec {
                vcpus: self.vcpus,
                memory_mib: self.memory_mib,
                boot: self.boot,
                volumes,
                nics,
                devices,
                images,
            },
            self.desired,
        ))
    }
}

fn parse_uuid(s: &str) -> anyhow::Result<uuid::Uuid> {
    s.parse().with_context(|| format!("invalid uuid: {s:?}"))
}

fn non_empty(s: String) -> Option<String> {
    (!s.is_empty()).then_some(s)
}

#[cfg(test)]
#[generated(model = ClaudeOpus, version = "5")]
mod tests {
    use super::*;

    /// `DeviceSpec.driver_name` is a real proto field, so a device the
    /// controller routed to `nvrm` must not land on the node's default
    /// driver. Unset stays unset: proto3 has no absent string, and an empty
    /// one still means "whatever this node defaults to".
    #[test]
    #[generated(model = ClaudeOpus, version = "5")]
    fn a_device_is_routed_to_the_driver_the_controller_named() {
        let named = DeviceWithId::try_from(proto::DeviceSpec {
            id: uuid::Uuid::nil().to_string(),
            driver_name: "nvrm".into(),
            partition: "mediated".into(),
            params_json: String::new(),
        })
        .expect("a named driver parses");
        assert_eq!(named.spec.driver, "nvrm");

        let unset = DeviceWithId::try_from(proto::DeviceSpec {
            id: uuid::Uuid::nil().to_string(),
            driver_name: String::new(),
            partition: "mediated".into(),
            params_json: String::new(),
        })
        .expect("an unset driver parses");
        assert_eq!(unset.spec.driver, default_device_driver());
    }

    /// The controller has no Desired type of its own: it writes the variant
    /// name into `spec_json` and this serde is what has to accept it. Both
    /// halves of that contract are spelled by hand, so guard this one here
    /// and the other in the controller's `build_spec_json` test.
    #[test]
    fn the_run_strategy_spellings_arrive_as_desired_states() {
        for (spelling, expected) in [
            ("Running", Desired::Running),
            ("Stopped", Desired::Stopped),
            ("Paused", Desired::Paused),
        ] {
            let doc = format!(
                r#"{{"vcpus":1,"memory_mib":256,
                     "boot":{{"kind":"firmware","firmware":"fw"}},
                     "desired":"{spelling}",
                     "volumes":[{{"size_bytes":1}}]}}"#
            );
            let spec: NewVmSpec = serde_json::from_str(&doc).expect("spec parses");
            let (_, _, desired) = spec.into_spec("br0").expect("spec is valid");
            assert_eq!(desired, expected);
        }
    }

    /// A create carrying runStrategy=Stopped provisions the VM without it
    /// ending up Running: the intent travels in the spec and the reconciler
    /// takes it from there (see `plan`).
    #[test]
    fn a_spec_without_a_desired_state_defaults_to_running() {
        let doc = r#"{"vcpus":1,"memory_mib":256,
                      "boot":{"kind":"firmware","firmware":"fw"},
                      "volumes":[{"size_bytes":1}]}"#;
        let spec: NewVmSpec = serde_json::from_str(doc).unwrap();
        assert_eq!(spec.into_spec("br0").unwrap().2, Desired::Running);
    }

    /// The repo's own spec files, parsed as they are on disk. `NewVmSpec` is
    /// `deny_unknown_fields`, so this catches a field renamed as well as one
    /// added — and it is the promise the volume driver/params fields were
    /// added under: every spec written before them means exactly what it did.
    #[test]
    fn every_spec_in_the_repo_still_parses() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config/json");
        let mut seen = 0;
        for entry in std::fs::read_dir(&dir).expect("config/json is where the specs live") {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let raw = std::fs::read_to_string(&path).unwrap();
            let spec: NewVmSpec = serde_json::from_str(&raw)
                .unwrap_or_else(|e| panic!("{} no longer parses: {e}", path.display()));
            spec.into_spec("br0")
                .unwrap_or_else(|e| panic!("{} is no longer valid: {e:#}", path.display()));
            seen += 1;
        }
        assert!(seen >= 3, "only {seen} specs found in {}", dir.display());
    }

    /// A volume that names no driver stays what it was: the default, which
    /// `Drivers::from_config` always registers.
    #[test]
    fn a_volume_without_a_driver_stays_the_default_one() {
        let doc = r#"{"vcpus":1,"memory_mib":256,
                      "boot":{"kind":"firmware","firmware":"fw"},
                      "volumes":[{"base_image":"n.raw","size_bytes":10}]}"#;
        let spec: NewVmSpec = serde_json::from_str(doc).unwrap();
        let (_, spec, _) = spec.into_spec("br0").unwrap();
        assert_eq!(spec.volumes[0].spec.driver, None);
        assert_eq!(spec.volumes[0].spec.params, None);
    }

    /// And one that does names it, with params the agent hands through
    /// untouched — the same shape a device request has, so a storage backend
    /// takes its options the way a gpu backend already does.
    #[test]
    fn a_volume_may_name_a_driver_and_carry_params_through() {
        let doc = r#"{"vcpus":1,"memory_mib":256,
                      "boot":{"kind":"firmware","firmware":"fw"},
                      "volumes":[{"size_bytes":10,"driver":"lvm-thin",
                                  "params":{"pool":"vg0/thin","snapshot_of":"base"}}]}"#;
        let spec: NewVmSpec = serde_json::from_str(doc).unwrap();
        let (_, spec, _) = spec.into_spec("br0").unwrap();
        assert_eq!(spec.volumes[0].spec.driver.as_deref(), Some("lvm-thin"));
        assert_eq!(
            spec.volumes[0].spec.params.as_ref().unwrap()["pool"],
            "vg0/thin"
        );
    }

    /// The compatibility invariant of this milestone at the tier that reads
    /// it: a NIC that says nothing about addresses means what it has always
    /// meant, and the two new lists come out empty. `deny_unknown_fields` is
    /// what makes the other direction hold too — a field renamed here fails
    /// this test and every spec in the repo along with it.
    #[test]
    fn a_nic_that_names_no_addresses_gets_none() {
        let doc = r#"{"vcpus":1,"memory_mib":256,
                      "boot":{"kind":"firmware","firmware":"fw"},
                      "volumes":[{"size_bytes":1}],
                      "nics":[{}]}"#;
        let spec: NewVmSpec = serde_json::from_str(doc).unwrap();
        let (_, spec, _) = spec.into_spec("br0").unwrap();
        assert_eq!(spec.nics[0].spec.bridge, "br0");
        assert_eq!(spec.nics[0].spec.vxlan_id, None);
        assert!(spec.nics[0].spec.floating_ips.is_empty());
        assert!(spec.nics[0].spec.routed_subnets.is_empty());

        // ... and the record that goes to disk carries neither key, so an
        // agent from before this milestone reads it back unchanged.
        let json = serde_json::to_value(&spec.nics[0].spec).unwrap();
        assert!(json.get("floating_ips").is_none(), "{json}");
        assert!(json.get("routed_subnets").is_none(), "{json}");
    }

    /// The standalone road: a cluster with no cloud above it has no FloatingIp
    /// objects to resolve, so the addresses go straight in the spec — and the
    /// same file is what the controller's injection produces, which is why
    /// there is only one shape to test.
    #[test]
    fn a_nic_may_name_its_own_addresses() {
        let doc = r#"{"vcpus":1,"memory_mib":256,
                      "boot":{"kind":"firmware","firmware":"fw"},
                      "volumes":[{"size_bytes":1}],
                      "nics":[{"vxlan_id":10007,
                               "floating_ips":["10.255.0.7"],
                               "routed_subnets":["10.7.1.0/24"]}]}"#;
        let spec: NewVmSpec = serde_json::from_str(doc).unwrap();
        let (_, spec, _) = spec.into_spec("br0").unwrap();
        assert_eq!(spec.nics[0].spec.vxlan_id, Some(10_007));
        assert_eq!(spec.nics[0].spec.floating_ips, ["10.255.0.7"]);
        assert_eq!(spec.nics[0].spec.routed_subnets, ["10.7.1.0/24"]);
    }

    #[test]
    fn absent_and_halted_are_not_creation_targets() {
        for spelling in ["Absent", "Halted"] {
            let doc = format!(
                r#"{{"vcpus":1,"memory_mib":256,
                     "boot":{{"kind":"firmware","firmware":"fw"}},
                     "desired":"{spelling}",
                     "volumes":[{{"size_bytes":1}}]}}"#
            );
            let spec: NewVmSpec = serde_json::from_str(&doc).unwrap();
            assert!(spec.into_spec("br0").is_err());
        }
    }
}
