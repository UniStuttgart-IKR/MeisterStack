// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The reconciler's tests, verbatim out of `reconcile.rs`. The module path is
//! unchanged (`reconcile::tests`), so every test still answers to the name it
//! had before.

use super::*;
use crate::types::VmRecord;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

fn record(desired: Desired, phase: Phase) -> VmRecord {
    VmRecord {
        desired,
        phase,
        ..VmRecord::blank()
    }
}

fn obs(vmm: bool, sock: bool, dev: bool, guest: Option<VmState>) -> Observed {
    Observed {
        tracked: true,
        vmm_alive: vmm,
        socket_responsive: sock,
        backends_alive: dev,
        guest,
        receive_failed: false,
    }
}

fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000)
}

/// The one line that decides whether a dead virtiofsd quarantines a VM.
/// A share's backend has to be counted exactly as a gpu backend is, and
/// the things with no process behind them must not be counted at all —
/// a passthrough device or a plain disk contributing a phantom pid would
/// quarantine every VM that has one.
#[test]
fn every_backend_process_counts_and_nothing_else_does() {
    use agent_api::device::Device;
    use agent_api::storage::{Volume, VolumeAttachment, VolumeHandle};

    fn volume(attachment: VolumeAttachment) -> Volume {
        Volume::attached(
            VolumeHandle {
                id: uuid::Uuid::nil(),
                backend: "/vol/a.raw".into(),
                size_bytes: 1,
                params: None,
            },
            attachment,
        )
    }

    let mut r = record(Desired::Running, Phase::Provisioned);
    r.devices = vec![
        Device {
            id: uuid::Uuid::nil(),
            attachment: DeviceAttachment::VhostUser {
                socket: "/run/gpu.sock".into(),
                pid: 100,
                device_type: 16,
                queue_sizes: vec![256],
            },
        },
        Device {
            id: uuid::Uuid::nil(),
            attachment: DeviceAttachment::VfioPci {
                sysfs_path: "/sys/x".into(),
            },
        },
    ];
    r.volumes = vec![
        volume(VolumeAttachment::Path("/vol/a.raw".into())),
        volume(VolumeAttachment::FsShare {
            socket: "/run/fs.sock".into(),
            tag: "share".into(),
            pid: 200,
        }),
    ];
    assert_eq!(backend_pids(&r).collect::<Vec<_>>(), vec![100, 200]);

    // A VM with nothing but a plain disk has no backend to lose.
    let mut plain = record(Desired::Running, Phase::Provisioned);
    plain.volumes = vec![volume(VolumeAttachment::Path("/vol/a.raw".into()))];
    assert_eq!(backend_pids(&plain).count(), 0);
}

#[test]
fn running_and_healthy_converges() {
    let r = record(Desired::Running, Phase::Provisioned);
    assert_eq!(
        plan(&r, &obs(true, true, true, Some(VmState::Running)), now()),
        Action::None
    );
}

#[test]
fn dead_vmm_reprovisions_when_running_desired() {
    let r = record(Desired::Running, Phase::Provisioned);
    assert_eq!(
        plan(&r, &obs(false, false, false, None), now()),
        Action::Provision
    );
}

/// The decision the chaos run put a question mark over, nailed down so it
/// cannot drift into a quarantine by accident.
///
/// The observed behaviour was `Running -> Provisioning -> Running` in
/// fifteen seconds where the expectation said `Quarantined`, and the code
/// is the half that is right: a dead VMM takes its backends with it, so
/// nothing is left standing to diagnose and rebuilding is strictly better
/// than waiting for a person. What the quarantine is FOR is the other
/// shape, and both halves are asserted here — the same VM, the same
/// record, and only `vmm_alive` between them.
#[test]
fn a_killed_vmm_recovers_and_a_backend_that_dies_under_a_live_one_does_not() {
    use agent_api::storage::{Volume, VolumeAttachment, VolumeHandle};

    // A VM with a real backend process behind one of its disks: without
    // one there is no quarantine to argue about in either direction.
    let mut r = record(Desired::Running, Phase::Provisioned);
    r.vmm_pid = Some(4242);
    r.volumes = vec![Volume::attached(
        VolumeHandle {
            id: uuid::Uuid::nil(),
            backend: "/vol/a.raw".into(),
            size_bytes: 1,
            params: None,
        },
        VolumeAttachment::FsShare {
            socket: "/run/fake/a.sock".into(),
            tag: "data".into(),
            pid: 4243,
        },
    )];
    assert_eq!(backend_pids(&r).count(), 1, "there is a backend to lose");

    // `kill -9` on the VMM. The backend hangs up with it, so BOTH are
    // gone by the next pass — which is exactly the shape that must not
    // read as "a backend died".
    let killed = obs(false, false, false, None);
    assert!(
        !backend_died_under_vmm(&r, &killed),
        "a dead vmm is not a backend dying under a live one"
    );
    assert_eq!(
        plan(&r, &killed, now()),
        Action::Provision,
        "the vm is rebuilt rather than left for a person"
    );
    assert_eq!(
        report_status(&r, &killed, 0).0,
        ReportedPhase::Provisioning,
        "and it says so: Provisioning on the way back, never Quarantined"
    );

    // The one this mechanism exists for: the VMM is still running, still
    // serving a guest, and its backend is gone.
    let orphaned = obs(true, true, false, Some(VmState::Running));
    assert!(
        backend_died_under_vmm(&r, &orphaned),
        "this, and only this, is the condition"
    );
    r.unhealthy = Some(BACKEND_DIED_REASON.to_string());
    assert_eq!(
        plan(&r, &orphaned, now()),
        Action::Quarantined,
        "no automatic repair of a live vm with half its hardware gone"
    );

    // And a VM without the marker in the same world is not quarantined by
    // the observation alone: the record is what the gate reads, so the
    // marking and the gate cannot disagree.
    r.unhealthy = None;
    assert_eq!(plan(&r, &orphaned, now()), Action::None);
}

#[test]
fn stopping_signals_within_grace_then_forces() {
    let mut r = record(Desired::Stopped, Phase::Provisioned);
    r.stop_deadline = Some(now() + Duration::from_secs(30));
    let o = obs(true, true, true, Some(VmState::Running));
    assert_eq!(plan(&r, &o, now()), Action::SignalShutdown);
    // Deadline expired: escalate to a hard stop.
    assert_eq!(plan(&r, &o, now() + Duration::from_secs(31)), Action::Stop);
    // No deadline recorded at all: hard stop immediately.
    r.stop_deadline = None;
    assert_eq!(plan(&r, &o, now()), Action::Stop);
}

#[test]
fn stopping_runs_stop_posthumously_exactly_once() {
    // The VMM exits by itself when the guest powers off; device backends
    // and record state still need the Stop path once.
    let mut r = record(Desired::Stopped, Phase::Provisioned);
    r.vmm_pid = Some(4242);
    let dead = obs(false, false, false, None);
    assert_eq!(plan(&r, &dead, now()), Action::Stop);

    // And exactly once. stop() keeps volumes and taps, so it leaves the
    // phase at Provisioned; clearing vmm_pid is what marks it done, and
    // without that this VM would be stopped again on every pass forever.
    r.vmm_pid = None;
    assert_eq!(plan(&r, &dead, now()), Action::None);

    // A VM that never got as far as a VMM has nothing to tear down.
    let r = record(Desired::Stopped, Phase::Provisioning);
    assert_eq!(plan(&r, &dead, now()), Action::None);
}

#[test]
fn stopping_a_paused_guest_does_not_wait_out_the_grace() {
    // A paused guest cannot act on a power button, so the deadline would
    // only ever expire unused.
    let mut r = record(Desired::Stopped, Phase::Provisioned);
    r.stop_deadline = Some(now() + Duration::from_secs(30));
    assert_eq!(
        plan(&r, &obs(true, true, true, Some(VmState::Paused)), now()),
        Action::Stop
    );
}

#[test]
fn the_stop_deadline_is_armed_on_the_way_in_and_never_re_armed() {
    let first = now() + Duration::from_secs(30);
    let later = now() + Duration::from_secs(300);
    // Running -> Stopped arms what the caller proposed.
    assert_eq!(
        next_stop_deadline(Desired::Running, None, Desired::Stopped, Some(first)),
        Some(first)
    );
    // A repeated Stop keeps the running deadline: the controller derives
    // its command level-triggered and repeats it until the phase moves,
    // and each repeat would otherwise postpone the hard stop.
    assert_eq!(
        next_stop_deadline(Desired::Stopped, Some(first), Desired::Stopped, Some(later)),
        Some(first)
    );
    // Any other intent disarms.
    for to in [Desired::Running, Desired::Paused, Desired::Absent] {
        assert_eq!(
            next_stop_deadline(Desired::Stopped, Some(first), to, None),
            None
        );
    }
}

#[test]
fn dead_device_backend_quarantines_running_vm() {
    let mut r = record(Desired::Running, Phase::Provisioned);
    r.unhealthy = Some("backend died".into());
    assert_eq!(
        plan(&r, &obs(true, true, false, Some(VmState::Running)), now()),
        Action::Quarantined
    );
}

#[test]
fn quarantine_still_allows_stop_and_teardown() {
    let mut r = record(Desired::Stopped, Phase::Provisioned);
    r.unhealthy = Some("backend died".into());
    assert_eq!(
        plan(&r, &obs(true, true, false, Some(VmState::Running)), now()),
        Action::Stop
    );
    r.desired = Desired::Absent;
    assert_eq!(
        plan(&r, &obs(true, true, false, Some(VmState::Running)), now()),
        Action::Teardown
    );
}

#[test]
fn pending_operation_blocks_everything() {
    let mut r = record(Desired::Running, Phase::Provisioned);
    r.operation = Some(crate::types::Operation::Snapshotting { target: "t".into() });
    assert_eq!(
        plan(&r, &obs(true, true, true, Some(VmState::Running)), now()),
        Action::Blocked
    );
}

#[test]
fn untracked_vmm_with_pid_is_adopted() {
    let mut r = record(Desired::Running, Phase::Provisioned);
    r.vmm_pid = Some(4242);
    let mut o = obs(true, true, true, Some(VmState::Running));
    o.tracked = false;
    assert_eq!(plan(&r, &o, now()), Action::Adopt { vmm_pid: 4242 });
}

fn phase_of(r: &VmRecord, o: &Observed, failures: u32) -> &'static str {
    report_status(r, o, failures).0.as_str()
}

#[test]
fn reported_phase_follows_the_observed_guest() {
    let r = record(Desired::Running, Phase::Provisioned);
    assert_eq!(
        phase_of(&r, &obs(true, true, true, Some(VmState::Running)), 0),
        "Running"
    );
    assert_eq!(
        phase_of(&r, &obs(true, true, true, Some(VmState::Paused)), 0),
        "Paused"
    );
    assert_eq!(
        phase_of(&r, &obs(true, true, true, Some(VmState::Stopped)), 0),
        "Stopped"
    );
    assert_eq!(
        phase_of(&r, &obs(true, true, true, Some(VmState::Defined)), 0),
        "Stopped"
    );
}

#[test]
fn reported_phase_is_provisioning_while_resources_are_built() {
    let r = record(Desired::Running, Phase::VolumesDone);
    assert_eq!(
        phase_of(&r, &obs(false, false, true, None), 0),
        "Provisioning"
    );
    // Provisioned but the vmm is gone: the next pass re-provisions, and a
    // first attempt is in flight, not failed.
    let r = record(Desired::Running, Phase::Provisioned);
    assert_eq!(
        phase_of(&r, &obs(false, false, false, None), 0),
        "Provisioning"
    );
    // A live vmm whose state cannot be read is the same situation.
    assert_eq!(
        phase_of(&r, &obs(true, false, true, None), 0),
        "Provisioning"
    );
}

#[test]
fn repeated_reconcile_failures_report_failed_with_a_count() {
    let r = record(Desired::Running, Phase::Provisioned);
    let (phase, message) = report_status(&r, &obs(false, false, false, None), 3);
    assert_eq!(phase.as_str(), "Failed");
    assert!(message.unwrap().contains('3'));
}

#[test]
fn unhealthy_reports_quarantined_with_its_reason() {
    let mut r = record(Desired::Running, Phase::Provisioned);
    r.unhealthy = Some("backend died".into());
    let (phase, message) = report_status(&r, &obs(true, true, false, Some(VmState::Running)), 0);
    assert_eq!(phase.as_str(), "Quarantined");
    assert_eq!(message.as_deref(), Some("backend died"));
}

#[test]
fn stopped_stays_stopped_although_stop_leaves_the_phase_provisioned() {
    // stop() keeps volumes and taps, so phase is still Provisioned; only
    // desired tells this apart from a vm that never came up.
    let r = record(Desired::Stopped, Phase::Provisioned);
    assert_eq!(phase_of(&r, &obs(false, false, false, None), 0), "Stopped");
    // Still shutting down: the guest is what the controller should see.
    assert_eq!(
        phase_of(&r, &obs(true, true, true, Some(VmState::Running)), 0),
        "Running"
    );
}

fn managed(desired: Desired) -> VmRecord {
    let mut r = record(desired, Phase::Provisioned);
    r.managed_by_controller = true;
    r
}

/// The failover, asserted at the only place it is decided: an address is
/// announced because its VM is running HERE. Stop it, tear it down or move
/// it, and the same mechanism withdraws — the record stops contributing to
/// this set.
#[test]
fn only_the_addresses_of_running_vms_are_announced_and_only_as_host_routes() {
    let mut holder = record(Desired::Running, Phase::Provisioned);
    holder.spec.nics.push(crate::types::NicWithId {
        id: uuid::Uuid::nil(),
        spec: agent_api::networking::NicSpec {
            bridge: "meister_br0".into(),
            mac: "52:54:00:00:00:01".parse().unwrap(),
            vxlan_id: Some(10_007),
            physnet: None,
            floating_ips: vec!["10.255.0.7".into(), "203.0.113.9".into()],
            routed_subnets: vec!["10.7.1.0/24".into()],
        },
    });
    let plain = record(Desired::Running, Phase::Provisioned);

    let announced = floating_prefixes([&holder, &plain].into_iter());
    assert_eq!(
        announced,
        ["10.255.0.7/32".to_string(), "203.0.113.9/32".to_string()].into()
    );
    // The routed subnet is NOT in there. A subnet spans hosts, so a
    // per-host announcement would be every node claiming the whole prefix.
    assert!(
        !announced.iter().any(|p| p.contains("10.7.1")),
        "{announced:?}"
    );

    // Nobody running is nothing announced, which is the withdraw.
    assert!(floating_prefixes(std::iter::empty()).is_empty());
}

#[test]
fn a_snapshot_reaps_managed_records_it_does_not_list() {
    let gone = uuid::Uuid::from_u128(1);
    let kept = uuid::Uuid::from_u128(2);
    let listed = managed(Desired::Running);
    let dropped = managed(Desired::Running);
    let snapshot = HashSet::from([kept]);
    assert_eq!(
        sync_orphans(&snapshot, [(kept, &listed), (gone, &dropped)]),
        vec![gone]
    );
}

#[test]
fn a_snapshot_never_touches_a_locally_created_vm() {
    // The managed boundary: a VM born on the agent's unix socket is not
    // in any snapshot and is not the controller's to reap.
    let local = uuid::Uuid::from_u128(3);
    let r = record(Desired::Running, Phase::Provisioned);
    assert!(sync_orphans(&HashSet::new(), [(local, &r)]).is_empty());
}

/// A migration in flight survives a snapshot, and the reason is the one
/// the E2E paid for: the snapshot lists the vms BOUND to this node, and
/// for the whole of a live migration the destination is not one of them.
///
/// Only the DESTINATION, though: a migrated record holds no guest, and
/// the reap is the second way out it needs when its explicit destroy was
/// lost.
#[test]
fn a_snapshot_does_not_reap_a_migration_in_flight() {
    let arriving = uuid::Uuid::from_u128(5);
    let mut receiving = managed(Desired::Running);
    receiving.phase = Phase::Receiving;
    assert!(sync_orphans(&HashSet::new(), [(arriving, &receiving)]).is_empty());

    // A MIGRATED record IS reaped, which is the other half of the rule:
    // its guest is on another machine and its vmm is gone, so the reap
    // detaches disks that outlive it and destroys nothing. Left in the
    // exception it would sit there for ever after one lost destroy,
    // refusing the guest's way back.
    let left = uuid::Uuid::from_u128(6);
    let mut migrated = managed(Desired::Running);
    migrated.phase = Phase::Migrated;

    // And an ordinary managed record beside them is reaped too, so the
    // exception is an exception and not a hole.
    let ordinary = uuid::Uuid::from_u128(7);
    let plain = managed(Desired::Running);
    assert_eq!(
        sync_orphans(
            &HashSet::new(),
            [
                (arriving, &receiving),
                (ordinary, &plain),
                (left, &migrated)
            ]
        ),
        vec![ordinary, left]
    );
}

#[test]
fn a_record_already_being_torn_down_is_left_alone() {
    // Its teardown is already in flight; naming it again would only
    // restart a pass that is running.
    let leaving = uuid::Uuid::from_u128(4);
    let r = managed(Desired::Absent);
    assert!(sync_orphans(&HashSet::new(), [(leaving, &r)]).is_empty());
}

#[test]
fn lifecycle_transitions() {
    let r = record(Desired::Running, Phase::Provisioned);
    assert_eq!(
        plan(&r, &obs(true, true, true, Some(VmState::Stopped)), now()),
        Action::Start
    );
    assert_eq!(
        plan(&r, &obs(true, true, true, Some(VmState::Paused)), now()),
        Action::Resume
    );
    let r = record(Desired::Paused, Phase::Provisioned);
    assert_eq!(
        plan(&r, &obs(true, true, true, Some(VmState::Running)), now()),
        Action::Pause
    );
    assert_eq!(
        plan(&r, &obs(true, true, true, Some(VmState::Paused)), now()),
        Action::None
    );
}

/// A resume the guest never obeys says so, and stops being repeated.
///
/// D7, from the chaos run: a snapshot failed after the quiesce pause, the
/// resume behind it was issued and did not work, and the agent went on
/// issuing it every five seconds — no WARN, no event, no escalation —
/// while `spec.runStrategy` said Running and the guest stayed Paused. The
/// fake here is that hypervisor: it accepts every resume and its guest
/// never comes back.
#[tokio::test]
async fn a_resume_that_does_not_take_is_not_repeated_in_silence() {
    use agent_api::hypervisor::InstanceSpec;
    use std::path::PathBuf;
    use std::sync::Mutex as StdMutex;

    /// A hypervisor that takes the request and leaves the guest where it
    /// was — until somebody sets `guest`, which is the repair.
    struct Deaf {
        guest: StdMutex<VmState>,
        resumes: StdMutex<u32>,
    }

    #[async_trait::async_trait]
    impl agent_api::Hypervisor for Deaf {
        async fn create(
            &self,
            _: &VmId,
            _: &InstanceSpec,
            _: Option<&agent_api::CgroupHandle>,
        ) -> agent_api::hypervisor::Result<u32> {
            Ok(1)
        }
        async fn destroy(&self, _: &VmId) -> agent_api::hypervisor::Result<()> {
            Ok(())
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
        async fn get_state(&self, _: &VmId) -> agent_api::hypervisor::Result<VmState> {
            Ok(*self.guest.lock().unwrap())
        }
        fn console_paths(&self, _: &VmId) -> Vec<(ConsoleStream, PathBuf)> {
            Vec::new()
        }
        async fn adopt(&self, _: &VmId, _: u32) -> agent_api::hypervisor::Result<()> {
            Ok(())
        }
        async fn probe(&self, _: &VmId) -> bool {
            true
        }
        fn is_tracked(&self, _: &VmId) -> bool {
            true
        }
        fn as_pausable(&self) -> Option<&dyn agent_api::Pausable> {
            Some(self)
        }
    }

    #[async_trait::async_trait]
    impl agent_api::Pausable for Deaf {
        async fn pause(&self, _: &VmId) -> agent_api::hypervisor::Result<()> {
            Ok(())
        }
        /// Answered, and that is all it ever was: the API says it took the
        /// request, not that the guest is running.
        async fn resume(&self, _: &VmId) -> agent_api::hypervisor::Result<()> {
            *self.resumes.lock().unwrap() += 1;
            Ok(())
        }
    }

    let temp = tempfile::tempdir().expect("a temp dir");
    let root = temp.path().to_path_buf();
    let store = Arc::new(Store::open(&root.join("a.redb")).expect("a store"));
    let id = VmId::new_v4();
    let mut r = record(Desired::Running, Phase::Provisioned);
    r.vmm_pid = Some(1);
    store.put(&id, &r).expect("a record");

    let vmm = Arc::new(Deaf {
        guest: StdMutex::new(VmState::Paused),
        resumes: StdMutex::new(0),
    });
    let drivers = Drivers {
        confiner: Arc::new(cgroup_driver::CgroupV2::new(root.join("cgroup"))),
        hypervisor: Some(vmm.clone()),
        hypervisor_name: Some("fake".into()),
        storage: HashMap::new(),
        networking: None,
        bridge: None,
        announcer: None,
        devices: HashMap::new(),
    };
    let ops = Arc::new(tokio::sync::Mutex::new(()));
    let provisioner = Arc::new(Provisioner::new(
        store.clone(),
        drivers.clone(),
        Arc::new(crate::images::Cache::new(root.join("images"))),
        root.join("images"),
        root.join("run"),
        "br0".to_string(),
        None,
        None,
    ));
    let reconciler = Reconciler::new(store.clone(), drivers, provisioner, ops);
    let planned = (Phase::Provisioned, Desired::Running);

    for attempt in 1..RESUME_ATTEMPTS {
        let failed = reconciler
            .execute(&id, planned, Action::Resume)
            .await
            .expect_err("the guest is still paused");
        assert!(
            format!("{failed:#}").contains("Paused"),
            "the failure names what the guest actually is: {failed:#}"
        );
        assert!(
            store
                .get(&id)
                .expect("the record")
                .unwrap()
                .unhealthy
                .is_none(),
            "attempt {attempt} is not yet a quarantine"
        );
    }

    // The third one is. Not a race any more, and the marker is what stops
    // the pass from issuing a fourth, a fifth and a five-hundredth.
    reconciler
        .execute(&id, planned, Action::Resume)
        .await
        .expect_err("still paused");
    let marked = store.get(&id).expect("the record").unwrap();
    assert_eq!(marked.unhealthy.as_deref(), Some(RESUME_INEFFECTIVE_REASON));
    assert_eq!(
        plan(
            &marked,
            &obs(true, true, true, Some(VmState::Paused)),
            now()
        ),
        Action::Quarantined,
        "and no pass resumes a quarantined vm"
    );
    // What the tier above reads: the phase and the sentence that becomes
    // the event.
    let (phase, message) = report_status(&marked, &obs(true, true, true, Some(VmState::Paused)), 0);
    assert_eq!(phase, ReportedPhase::Quarantined);
    assert_eq!(message.as_deref(), Some(RESUME_INEFFECTIVE_REASON));

    // A resume that DOES take is silent and clears the count.
    *vmm.guest.lock().unwrap() = VmState::Running;
    store
        .mutate(&id, |r| r.unhealthy = None)
        .expect("the operator's repair");
    reconciler
        .execute(&id, planned, Action::Resume)
        .await
        .expect("the guest is running");
    assert_eq!(*vmm.resumes.lock().unwrap(), RESUME_ATTEMPTS + 1);
    assert!(
        reconciler.resume_failures.lock().unwrap().is_empty(),
        "and the count is gone with it"
    );
}

/// The MAC half of `Vm.status.addresses[]` starts here, and this is the line
/// that decides what "the node HAS" means: the record, not the spec.
///
/// A NIC the controller asked for and whose tap was never made has no entry
/// in `record.nics`, so it has no entry in the report either — and one whose
/// driver does not know an address (a liveness-only `get`, a record from
/// before the field) is left out rather than reported with an empty one.
#[test]
fn a_node_reports_the_taps_it_made_and_the_addresses_it_put_on_them() {
    let nic = |mac: Option<&str>| agent_api::networking::Nic {
        id: agent_api::networking::NicId::new_v4(),
        tap_name: "tap0".into(),
        mtu: None,
        mac: mac.map(|m| m.parse().expect("a mac")),
    };

    // Nothing made, nothing said — which is every VM with no NICs at all.
    assert!(reported_nics(&VmRecord::blank()).is_empty());

    let mut record = VmRecord::blank();
    record.nics = vec![
        nic(Some("52:54:00:11:22:33")),
        nic(Some("52:54:00:AA:BB:CC")),
    ];
    let out = reported_nics(&record);
    assert_eq!(
        out.iter().map(|n| n.name.as_str()).collect::<Vec<_>>(),
        ["nics[0]", "nics[1]"],
        "the position is the name, because a spec's nics have none of their own"
    );
    assert_eq!(
        out.iter().map(|n| n.mac.as_str()).collect::<Vec<_>>(),
        ["52:54:00:11:22:33", "52:54:00:aa:bb:cc"],
        "lower case with colons, whatever the spec was written in"
    );

    // A driver that does not know an address contributes no line, and the
    // ones beside it keep the position they have in the record.
    record.nics = vec![nic(None), nic(Some("52:54:00:11:22:33"))];
    let out = reported_nics(&record);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].name, "nics[1]");
}

/// Every pass asks whether this node can still tear a guest down.
///
/// `check_cgroup_root` ran exactly once, at start-up, which made it a
/// statement about the second the agent came up: `/sys/fs/cgroup` unmounted,
/// remounted or shadowed while the agent ran was something nobody said a word
/// about until the first delete hung — the original defect with a start-up
/// check in front of it.
///
/// The pass is where it belongs, because the pass is the one loop that runs
/// whether anybody asks or not. The condition is level like every other one:
/// raised while the trouble holds, and gone the pass after it stops.
#[tokio::test]
async fn a_cgroup_root_that_stops_being_one_is_noticed_by_the_next_pass() {
    let temp = tempfile::tempdir().expect("a temp dir");
    let root = temp.path().to_path_buf();
    let store = Arc::new(Store::open(&root.join("a.redb")).expect("a store"));

    // An ordinary directory, which is exactly what a wrong `cgroup_root` is:
    // `cgroup.kill` becomes a file nothing reads and `rmdir` fails with
    // ENOTEMPTY, so no VM here can ever be torn down.
    let ordinary = root.join("not-a-cgroup");
    std::fs::create_dir_all(&ordinary).expect("a plain directory");
    let drivers = |confiner: Arc<dyn agent_api::ResourceConfiner>| Drivers {
        confiner,
        hypervisor: None,
        hypervisor_name: None,
        storage: HashMap::new(),
        networking: None,
        bridge: None,
        announcer: None,
        devices: HashMap::new(),
    };
    let build = |d: Drivers| {
        let provisioner = Arc::new(Provisioner::new(
            store.clone(),
            d.clone(),
            Arc::new(crate::images::Cache::new(root.join("images"))),
            root.join("images"),
            root.join("run"),
            "br0".to_string(),
            None,
            None,
        ));
        Reconciler::new(
            store.clone(),
            d,
            provisioner,
            Arc::new(tokio::sync::Mutex::new(())),
        )
    };

    // Nothing is wrong until a pass looks — which is the half that was
    // missing: the store came up healthy and stayed that way on paper.
    assert!(store.conditions().report().is_empty());

    let bad = build(drivers(Arc::new(cgroup_driver::CgroupV2::new(
        ordinary.clone(),
    ))));
    bad.reconcile_all(Trigger::Periodic)
        .await
        .expect("a pass over no vms");
    let said = store
        .conditions()
        .message(crate::conditions::CGROUP_UNUSABLE)
        .expect("the pass found it");
    assert!(
        said.contains("not a cgroup2 filesystem") && said.contains("torn down"),
        "and says what it costs: {said}"
    );

    // A confiner with no directory of its own is asked nothing and claims
    // nothing. `ResourceConfiner::root` defaults to `None` precisely so that a
    // driver which is not cgroupfs cannot be made to answer for one.
    struct Nowhere;
    impl agent_api::ResourceConfiner for Nowhere {
        fn create_slice(
            &self,
            _: &str,
            _: Option<&agent_api::CgroupHandle>,
            _: &agent_api::ResourceLimits,
        ) -> agent_api::ConfinerResult<agent_api::CgroupHandle> {
            unreachable!("no vm in this test")
        }
        fn destroy_slice(&self, _: &agent_api::CgroupHandle) -> agent_api::ConfinerResult<()> {
            unreachable!("no vm in this test")
        }
        fn open_slice(&self, name: &str) -> agent_api::CgroupHandle {
            agent_api::CgroupHandle {
                path: PathBuf::from(name),
            }
        }
        fn pids_in_slice(&self, _: &str) -> agent_api::ConfinerResult<Vec<u32>> {
            Ok(Vec::new())
        }
        fn kill_slice(&self, _: &str) -> agent_api::ConfinerResult<()> {
            Ok(())
        }
    }
    store.conditions().clear(crate::conditions::CGROUP_UNUSABLE);
    build(drivers(Arc::new(Nowhere)))
        .reconcile_all(Trigger::Periodic)
        .await
        .expect("a pass");
    assert!(
        store.conditions().report().is_empty(),
        "a confiner with no directory is not a node with a broken one"
    );

    // And the other direction, on this machine's real mount: a condition that
    // was raised goes away the pass after the trouble does. Guarded, because a
    // test that assumed the host's mounts would be a test about the host.
    let host = Path::new("/sys/fs/cgroup");
    let cgroup2 = nix::sys::statfs::statfs(host)
        .map(|s| s.filesystem_type() == nix::sys::statfs::CGROUP2_SUPER_MAGIC)
        .unwrap_or(false);
    if cgroup2 {
        store
            .conditions()
            .raise(crate::conditions::CGROUP_UNUSABLE, "from the pass above");
        build(drivers(Arc::new(cgroup_driver::CgroupV2::new(
            host.join("meisterstack-that-is-not-there"),
        ))))
        .reconcile_all(Trigger::Periodic)
        .await
        .expect("a pass");
        assert!(
            store.conditions().report().is_empty(),
            "the condition is what is true now, not a history"
        );
    }
}

/// Which base images in a spec nobody is going to fetch.
///
/// The complement of `spec.images` and not a second derivation of it: an
/// image cannot be both stated by a fetch and re-stated by a `stat`, and two
/// disks off one base image are one image.
#[test]
fn a_path_image_is_the_one_no_source_entry_names() {
    let volume = |base: Option<&str>| crate::types::VolumeWithId {
        id: agent_api::storage::VolumeId::new_v4(),
        spec: agent_api::storage::VolumeSpec {
            base_image: base.map(str::to_string),
            size_bytes: 1024,
            driver: None,
            params: None,
        },
        referenced: false,
    };
    let mut spec = VmRecord::blank().spec;
    spec.volumes = vec![
        volume(Some("nixos.raw")),
        volume(Some("nixos.raw")),
        volume(Some("ubuntu.raw")),
        volume(None),
    ];
    spec.images = vec![crate::images::Source {
        name: "ubuntu.raw".into(),
        url: "https://example.invalid/ubuntu.raw".into(),
        sha256: "a".repeat(64),
    }];
    assert_eq!(
        crate::provision::path_images(&spec),
        vec!["nixos.raw".to_string()],
        "the fetched one is not restated, the duplicate is not doubled, \
         and a disk with no base image contributes nothing"
    );
}

/// Every pass says again whether the base images this node's records name are
/// still on its disk.
///
/// The level half of D-P7. A provision states it once, and once is not
/// something a control plane can rely on: an image that vanished from shared
/// storage after the VM was made would be reported `Ready` for ever, and one
/// RESTORED after somebody fixed it would be reported `Failed` until the next
/// create. The chain above this — `ImageStateReport`, `ImageView`,
/// `Image.status.nodes[]`, `Image.status.phase` — was complete; this is the
/// first line of it.
#[tokio::test]
async fn a_pass_says_again_whether_the_path_images_of_its_records_are_here() {
    let temp = tempfile::tempdir().expect("a temp dir");
    let root = temp.path().to_path_buf();
    let store = Arc::new(Store::open(&root.join("a.redb")).expect("a store"));
    let image_dir = root.join("images");
    std::fs::create_dir_all(&image_dir).expect("an image dir");

    // One record, one disk, one base image with no url — the catalogue entry
    // over storage somebody else filled, and the shape no node ever spoke
    // about.
    let mut r = record(Desired::Running, Phase::Provisioned);
    r.spec.volumes = vec![crate::types::VolumeWithId {
        id: agent_api::storage::VolumeId::new_v4(),
        spec: agent_api::storage::VolumeSpec {
            base_image: Some("nixos.raw".into()),
            size_bytes: 1024,
            driver: None,
            params: None,
        },
        referenced: false,
    }];
    store.put(&VmId::new_v4(), &r).expect("a record");

    let drivers = Drivers {
        confiner: Arc::new(cgroup_driver::CgroupV2::new(root.join("cgroup"))),
        hypervisor: None,
        hypervisor_name: None,
        storage: HashMap::new(),
        networking: None,
        bridge: None,
        announcer: None,
        devices: HashMap::new(),
    };
    let images = Arc::new(crate::images::Cache::new(image_dir.clone()));
    let provisioner = Arc::new(Provisioner::new(
        store.clone(),
        drivers.clone(),
        images.clone(),
        image_dir.clone(),
        root.join("run"),
        "br0".to_string(),
        None,
        None,
    ));
    let reconciler = Reconciler::new(
        store.clone(),
        drivers,
        provisioner,
        Arc::new(tokio::sync::Mutex::new(())),
    );

    reconciler
        .reconcile_all(Trigger::Periodic)
        .await
        .expect("a pass");
    let (name, state) = images.report().pop().expect("the pass has an opinion");
    assert_eq!(name, "nixos.raw");
    assert_eq!(state.phase(), "Failed", "the file is not there");
    assert!(
        state.message().contains("nixos.raw"),
        "and the sentence names it: {}",
        state.message()
    );

    // Somebody puts the bytes on shared storage. No create, no restart: the
    // next pass says so, and the cloud's `Image` follows it back to Ready.
    std::fs::write(image_dir.join("nixos.raw"), b"an image").expect("the bytes");
    reconciler
        .reconcile_all(Trigger::Periodic)
        .await
        .expect("a pass");
    assert_eq!(images.report()[0].1.phase(), "Ready");
}

/// A VMM this node has no record of is said out loud, every pass, until it is
/// not one any more.
///
/// The other half of D18. The condition is what the tier above acts on: a node
/// with an unmanaged guest is a node whose free memory is a fiction, and
/// whether to place there is a scheduling decision rather than a surprise
/// three commands later. Ending the process is the agent's own half and comes
/// only after `STRAY_GRACE` — what that grace buys is the difference between a
/// race this agent lost and a mistake it is about to make.
#[tokio::test]
async fn a_vmm_nobody_has_a_record_of_is_reported_every_pass_and_not_killed_at_once() {
    struct Ghost {
        live: std::sync::Mutex<Vec<VmId>>,
        ended: std::sync::Mutex<Vec<VmId>>,
    }
    #[async_trait::async_trait]
    impl agent_api::hypervisor::Hypervisor for Ghost {
        async fn create(
            &self,
            _: &VmId,
            _: &agent_api::InstanceSpec,
            _: Option<&agent_api::CgroupHandle>,
        ) -> agent_api::hypervisor::Result<u32> {
            unreachable!("no vm is made in this test")
        }
        async fn destroy(&self, _: &VmId) -> agent_api::hypervisor::Result<()> {
            Ok(())
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
        async fn get_state(&self, _: &VmId) -> agent_api::hypervisor::Result<VmState> {
            Ok(VmState::Running)
        }
        async fn adopt(&self, _: &VmId, _: u32) -> agent_api::hypervisor::Result<()> {
            Ok(())
        }
        async fn probe(&self, _: &VmId) -> bool {
            true
        }
        fn is_tracked(&self, _: &VmId) -> bool {
            true
        }
        async fn strays(&self, known: &[VmId]) -> Vec<VmId> {
            self.live
                .lock()
                .unwrap()
                .iter()
                .filter(|id| !known.contains(id))
                .copied()
                .collect()
        }
        async fn end_stray(&self, id: &VmId) -> agent_api::hypervisor::Result<()> {
            self.ended.lock().unwrap().push(*id);
            self.live.lock().unwrap().retain(|l| l != id);
            Ok(())
        }
    }

    let temp = tempfile::tempdir().expect("a temp dir");
    let root = temp.path().to_path_buf();
    let store = Arc::new(Store::open(&root.join("a.redb")).expect("a store"));
    let ghost_id = VmId::new_v4();
    let vmm = Arc::new(Ghost {
        live: std::sync::Mutex::new(vec![ghost_id]),
        ended: std::sync::Mutex::new(Vec::new()),
    });
    let drivers = Drivers {
        confiner: Arc::new(cgroup_driver::CgroupV2::new(root.join("cgroup"))),
        hypervisor: Some(vmm.clone()),
        hypervisor_name: Some("fake".into()),
        storage: HashMap::new(),
        networking: None,
        bridge: None,
        announcer: None,
        devices: HashMap::new(),
    };
    let provisioner = Arc::new(Provisioner::new(
        store.clone(),
        drivers.clone(),
        Arc::new(crate::images::Cache::new(root.join("images"))),
        root.join("images"),
        root.join("run"),
        "br0".to_string(),
        None,
        None,
    ));
    let reconciler = Reconciler::new(
        store.clone(),
        drivers,
        provisioner,
        Arc::new(tokio::sync::Mutex::new(())),
    );

    reconciler
        .reconcile_all(Trigger::Startup)
        .await
        .expect("a pass");
    let said = store
        .conditions()
        .message(crate::conditions::VMM_UNMANAGED)
        .expect("the node says so");
    assert!(said.contains(&ghost_id.to_string()), "by name: {said}");
    assert!(
        said.contains("no record of") && said.contains("free memory"),
        "and says what it costs the tier above: {said}"
    );
    assert!(
        vmm.ended.lock().unwrap().is_empty(),
        "and nothing was killed on the first sight of it"
    );

    // Give it a record — an adoption, an operator, a row that came back —
    // and the condition goes with the next pass. Level, like every other
    // statement this node makes about itself.
    store
        .put(&ghost_id, &record(Desired::Running, Phase::Provisioned))
        .expect("a record");
    reconciler
        .reconcile_all(Trigger::Periodic)
        .await
        .expect("a pass");
    assert!(
        store
            .conditions()
            .message(crate::conditions::VMM_UNMANAGED)
            .is_none(),
        "a vm with a record is not an unmanaged vmm"
    );
    assert!(vmm.ended.lock().unwrap().is_empty());
}
