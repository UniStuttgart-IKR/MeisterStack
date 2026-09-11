// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The provisioner's tests, cut along the links of the chain. This file
//! holds what more than one link needs — the three builders, the empty
//! hypervisor, an overlay VM, a bare record — and the one test of
//! `limits_for`, which lives in `provision/mod.rs` beside it.

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

/// A hypervisor that has nothing to destroy and says so, so that a
/// teardown in a test reaches its end and deletes the record — which is
/// the state the NEXT teardown counts against.
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

fn overlay_vm(vni: u32) -> (VmId, VmRecord) {
    let nic_id = agent_api::networking::NicId::new_v4();
    let nic_spec = agent_api::networking::NicSpec {
        bridge: "br0".into(),
        mac: "52:54:00:00:00:01".parse().expect("a mac"),
        vxlan_id: Some(vni),
        physnet: None,
        floating_ips: Vec::new(),
        routed_subnets: Vec::new(),
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
            unhealthy: None,
            managed_by_controller: true,
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

/// A record with nothing in it but what the two tests that ask for one
/// need — the teardown's kill and the route announcement.
fn spec_record() -> VmRecord {
    VmRecord {
        spec: spec(1, 256, vec![]),
        desired: Desired::Stopped,
        phase: Phase::Provisioned,
        operation: None,
        stop_deadline: None,
        receive_deadline: None,
        send_failed: None,
        unhealthy: None,
        managed_by_controller: true,
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
