// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Provisioner tests grouped by resource family. Shared fixtures and the
//! `limits_for` test live here.

use super::*;
use crate::types::{AgentVmSpec, BootSourceSpec, DeviceWithId};
use agent_api::device::DeviceSpec;
use agent_api::storage::VolumeAttachment;

mod devices;
mod migrate;
mod network;
mod seed;
mod teardown;
mod volumes;

fn spec(vcpus: u32, memory_mib: u64, devices: Vec<DeviceWithId>) -> AgentVmSpec {
    AgentVmSpec {
        vcpus,
        memory_mib,
        boot: BootSourceSpec::Firmware {
            firmware: "fw".into(),
        },
        volumes: vec![],
        nics: vec![],
        devices,
        images: Vec::new(),
        cloud_init: None,
    }
}

fn device(driver: &str, partition: PartitionSpec) -> DeviceWithId {
    DeviceWithId {
        id: uuid::Uuid::nil(),
        spec: DeviceSpec {
            driver: driver.into(),
            partition,
            profile: None,
            params: None,
        },
    }
}

fn volume(attachment: VolumeAttachment) -> Volume {
    Volume {
        handle: agent_api::VolumeHandle {
            id: uuid::Uuid::nil(),
            backend: "/vol/a.raw".into(),
            size_bytes: 0,
            params: None,
        },
        attachment,
        detached: false,
    }
}

/// Hypervisor fixture with successful no-op destruction so teardown can remove records.
struct EmptyHypervisor;

#[async_trait::async_trait]
impl agent_api::hypervisor::Hypervisor for EmptyHypervisor {
    async fn create(
        &self,
        _: &VmId,
        _: &InstanceSpec,
        _: Option<&agent_api::CgroupHandle>,
    ) -> agent_api::hypervisor::Result<u32> {
        Ok(1)
    }
    async fn destroy(&self, id: &VmId) -> agent_api::hypervisor::Result<()> {
        Err(HypervisorError::NotFound(*id))
    }
    async fn start(&self, _: &VmId) -> agent_api::hypervisor::Result<()> {
        Ok(())
    }
    async fn shutdown(&self, _: &VmId) -> agent_api::hypervisor::Result<()> {
        Ok(())
    }
    async fn power_button(&self, _: &VmId) -> agent_api::hypervisor::Result<()> {
        Ok(())
    }
    async fn get_state(
        &self,
        id: &VmId,
    ) -> agent_api::hypervisor::Result<agent_api::hypervisor::VmState> {
        Err(HypervisorError::NotFound(*id))
    }
    async fn adopt(&self, _: &VmId, _: u32) -> agent_api::hypervisor::Result<()> {
        Ok(())
    }
    async fn probe(&self, _: &VmId) -> bool {
        false
    }
    fn is_tracked(&self, _: &VmId) -> bool {
        false
    }
}

/// Path-backed disk fixture: both migration endpoints resolve its path, and a boot finds a
/// block disk in it.
#[derive(Default)]
struct PlainDisk {
    /// Every id a provision named, in order, so a test can tell a fresh disk from a held one.
    provisioned: std::sync::Mutex<Vec<VolumeId>>,
    /// Record forget calls separately from destructive deprovision calls.
    forgotten: std::sync::Mutex<Vec<VolumeId>>,
    /// Record destructive deprovision requests.
    deprovisioned: std::sync::Mutex<Vec<VolumeId>>,
}

#[async_trait::async_trait]
impl agent_api::storage::VolumeProvider for PlainDisk {
    fn locality(&self) -> agent_api::storage::Locality {
        agent_api::storage::Locality::Shared
    }
    async fn provision(
        &self,
        id: &VolumeId,
        spec: &agent_api::storage::VolumeSpec,
    ) -> agent_api::storage::Result<agent_api::storage::VolumeHandle> {
        self.provisioned.lock().unwrap().push(*id);
        Ok(agent_api::storage::VolumeHandle {
            id: *id,
            backend: format!("/fake/{id}.raw"),
            size_bytes: spec.size_bytes,
            params: None,
        })
    }
    async fn deprovision(
        &self,
        h: &agent_api::storage::VolumeHandle,
    ) -> agent_api::storage::Result<()> {
        self.deprovisioned.lock().unwrap().push(h.id);
        Ok(())
    }
    /// A fake that keeps no bytes holds none under any id.
    async fn probe(
        &self,
        _: &VolumeId,
        _: &agent_api::storage::VolumeSpec,
    ) -> agent_api::storage::Result<Option<agent_api::storage::VolumeHandle>> {
        Ok(None)
    }
    async fn forget(&self, h: &agent_api::storage::VolumeHandle) -> agent_api::storage::Result<()> {
        self.forgotten.lock().unwrap().push(h.id);
        Ok(())
    }
    async fn describe(
        &self,
        h: &agent_api::storage::VolumeHandle,
    ) -> agent_api::storage::Result<agent_api::storage::VolumeState> {
        Ok(agent_api::storage::VolumeState {
            size_bytes: h.size_bytes,
        })
    }
}

#[async_trait::async_trait]
impl agent_api::storage::VolumeAttacher for PlainDisk {
    async fn attach(
        &self,
        handle: &agent_api::storage::VolumeHandle,
        _: Option<&agent_api::CgroupHandle>,
    ) -> agent_api::storage::Result<VolumeAttachment> {
        Ok(VolumeAttachment::Path(handle.path()))
    }
    async fn detach(
        &self,
        _: &agent_api::storage::VolumeHandle,
        _: &VolumeAttachment,
    ) -> agent_api::storage::Result<()> {
        Ok(())
    }
    async fn stat(
        &self,
        h: &agent_api::storage::VolumeHandle,
        _: &VolumeAttachment,
    ) -> agent_api::storage::Result<agent_api::storage::VolumeState> {
        Ok(agent_api::storage::VolumeState {
            size_bytes: h.size_bytes,
        })
    }
}

/// A volume this node owns already, as a `Volume` object's provisioning leaves one.
fn a_volume_held_here(store: &crate::store::Store) -> VolumeId {
    let id = VolumeId::new_v4();
    let spec = agent_api::storage::VolumeSpec {
        base_image: None,
        size_bytes: 4096,
        driver: Some("filesystem".into()),
        params: None,
    };
    let handle = agent_api::storage::VolumeHandle {
        id,
        backend: format!("/fake/{id}.raw"),
        size_bytes: 4096,
        params: None,
    };
    let record = crate::types::VolumeRecord {
        spec,
        handle: Some(handle),
        phase: crate::types::VolumeRecordPhase::Ready,
        reason: None,
        message: None,
        gone_at: None,
    };
    store.put_volume(&id, &record).expect("a volume record");
    id
}

fn overlay_vm(vni: u32) -> (VmId, VmRecord) {
    let nic_id = agent_api::networking::NicId::new_v4();
    let nic_spec = agent_api::networking::NicSpec {
        bridge: "br0".into(),
        mac: "52:54:00:00:00:01".parse().expect("a mac"),
        vxlan_id: Some(vni),
        physnet: None,
        floating_ips: Vec::new(),
        routed_subnets: Vec::new(),
        address_space_known: false,
    };
    let mut spec = spec(1, 256, vec![]);
    spec.nics = vec![crate::types::NicWithId {
        id: nic_id,
        spec: nic_spec,
    }];
    (
        VmId::new_v4(),
        VmRecord {
            spec,
            desired: Desired::Running,
            phase: Phase::Provisioned,
            operation: None,
            stop_deadline: None,
            receive_deadline: None,
            send_failed: None,
            migration: None,
            unhealthy: None,
            managed_by_controller: true,
            unattached_volumes: Vec::new(),
            volumes: Vec::new(),
            nics: vec![agent_api::networking::Nic {
                id: nic_id,
                tap_name: format!("tap{nic_id}"),
                mtu: None,
                mac: Some("52:54:00:00:00:01".parse().expect("a mac")),
            }],
            devices: Vec::new(),
            vmm_pid: None,
            overlay_bridges: Default::default(),
        },
    )
}

/// Minimal record for teardown identity and route-announcement tests.
fn spec_record() -> VmRecord {
    VmRecord {
        spec: spec(1, 256, vec![]),
        desired: Desired::Stopped,
        phase: Phase::Provisioned,
        operation: None,
        stop_deadline: None,
        receive_deadline: None,
        send_failed: None,
        migration: None,
        unhealthy: None,
        managed_by_controller: true,
        unattached_volumes: Vec::new(),
        volumes: Vec::new(),
        nics: Vec::new(),
        devices: Vec::new(),
        vmm_pid: None,
        overlay_bridges: Default::default(),
    }
}

#[test]
fn plain_vm_gets_vmm_overhead_only() {
    let l = Provisioner::limits_for(&spec(2, 2048, vec![]));
    // 64 + 8*2 + 32 = 112 MiB on top of guest RAM
    assert_eq!(l.memory_max, Some((2048 + 112) * 1024 * 1024));
    assert_eq!(l.cpu_quota, Some(250));
}

/// An unreadable row is occupied. Both entry points must refuse it without replacing its bytes.
#[tokio::test]
async fn a_corrupt_vm_record_refuses_a_create_and_a_receive() {
    let temp = tempfile::Builder::new()
        .prefix("meister-admit-")
        .tempdir()
        .expect("a temp dir");
    let root = temp.path().to_path_buf();
    let store = Arc::new(crate::store::Store::open(&root.join("a.redb")).expect("a store"));
    let provisioner = Provisioner::new(
        store.clone(),
        Drivers {
            confiner: Arc::new(cgroup_driver::CgroupV2::new(root.join("cgroup"))),
            hypervisor: None,
            hypervisor_name: None,
            storage: HashMap::new(),
            networking: None,
            bridge: None,
            announcer: None,
            devices: HashMap::new(),
        },
        Arc::new(crate::images::Cache::new(root.join("images"))),
        root.join("images"),
        root.join("run"),
        "br0".to_string(),
        None,
        None,
    );

    let id = VmId::new_v4();
    let bytes = b"not a record at all";
    store.put_raw(&id.to_string(), bytes).expect("a raw row");

    let created = provisioner
        .provision(id, spec(1, 256, vec![]), Desired::Running, true)
        .await
        .expect_err("a create may not land on a row nobody can read");
    assert!(
        format!("{created:#}").contains("cannot read"),
        "the refusal says what is wrong with the row: {created:#}"
    );

    let received = provisioner
        .prepare_migration(id, spec(1, 256, vec![]), "127.0.0.1:0", true, "attempt-1")
        .await
        .expect_err("and neither may a reception");
    assert!(
        format!("{received:#}").contains("cannot read"),
        "{received:#}"
    );

    // Refused operations preserve the unreadable row byte for byte.
    assert_eq!(
        store.get_raw(&id).expect("a read").as_deref(),
        Some(&bytes[..])
    );
}
