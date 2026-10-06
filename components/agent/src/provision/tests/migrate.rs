// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The chain's second exit: a VM that arrives on this node.

use super::*;

#[tokio::test]
async fn restart_keeps_an_unresolved_source_protected() {
    let (_temp, root) = migration_root("restart-send");
    let store = Arc::new(crate::store::Store::open(&root.join("src.redb")).unwrap());
    let hv = Arc::new(MigratingVmm::that_fails_mid_send());
    let drivers = migrating_drivers(&root, hv.clone());
    let provisioner = Arc::new(provisioner_over(&root, store.clone(), drivers.clone()));
    let ops = Arc::new(tokio::sync::Mutex::new(()));
    let id = VmId::new_v4();
    let mut record = VmRecord::blank();
    record.vmm_pid = Some(std::process::id());
    record.operation = Some(crate::types::Operation::MigratingOut {
        peer: "tcp:target:49000".into(),
    });
    store.put(&id, &record).unwrap();
    let restarted = crate::reconcile::Reconciler::new(store.clone(), drivers, provisioner, ops);
    assert_eq!(
        restarted
            .reconcile(id, crate::reconcile::Trigger::Startup)
            .await
            .unwrap(),
        crate::reconcile::Action::Blocked
    );
    let record = store.get(&id).unwrap().unwrap();
    for guest in [
        None,
        Some(agent_api::VmState::Paused),
        Some(agent_api::VmState::Running),
    ] {
        let mut observed = sending_observation();
        observed.guest = guest;
        observed.vmm_alive = guest.is_some();
        assert_eq!(
            crate::reconcile::plan(&record, &observed, std::time::SystemTime::now()),
            crate::reconcile::Action::Blocked
        );
    }
}

/// Fake hypervisor recording boot and receive calls through the same provisioning chain.
#[derive(Default)]
struct MigratingVmm {
    log: std::sync::Mutex<Vec<String>>,
    /// What `migrate_out` answers. `false` = the send was refused, which
    /// is the case where the guest never leaves.
    can_send: bool,
    /// Whether the fake source VMM remains tracked after a send.
    still_here_after_send: std::sync::atomic::AtomicBool,
    /// Explicit receiver-failure evidence while the VMM remains responsive.
    receive_broke: std::sync::Mutex<Option<String>>,
    /// A receiving fixture reports Defined until the stream supplies a guest.
    receiving: std::sync::atomic::AtomicBool,
    /// Live fake VMMs, tracked independently of persisted records for stray-process tests.
    live: std::sync::Mutex<std::collections::BTreeSet<VmId>>,
    /// Whether an accepted send removes the source process or leaves it serving the guest.
    send_leaves: bool,
    /// What `send_failed` answers: `Some` is the VMM serving its guest
    /// again, which after a send has started can only mean it failed.
    send_broke: std::sync::Mutex<Option<String>>,
    /// Created PID override. By default use this test process, which does not
    /// match VM command-line identity checks.
    vmm_pid: std::sync::Mutex<Option<u32>>,
    /// How many times the api socket has been asked, for the tests that have
    /// to know the watch has gone round without looking at a clock.
    probes: std::sync::atomic::AtomicUsize,
    guest_override: std::sync::Mutex<Option<agent_api::VmState>>,
}

impl MigratingVmm {
    fn new(can_send: bool) -> Self {
        Self {
            log: std::sync::Mutex::new(Vec::new()),
            can_send,
            still_here_after_send: std::sync::atomic::AtomicBool::new(true),
            receive_broke: std::sync::Mutex::new(None),
            receiving: std::sync::atomic::AtomicBool::new(false),
            live: std::sync::Mutex::new(std::collections::BTreeSet::new()),
            send_leaves: true,
            send_broke: std::sync::Mutex::new(None),
            vmm_pid: std::sync::Mutex::new(None),
            probes: std::sync::atomic::AtomicUsize::new(0),
            guest_override: std::sync::Mutex::new(None),
        }
    }
    /// Accept submission while retaining the source process until the test
    /// supplies an explicit abort observation.
    fn that_fails_mid_send() -> Self {
        let mut vmm = Self::new(true);
        vmm.send_leaves = false;
        vmm
    }
    fn the_send_broke(&self, why: &str) {
        *self.send_broke.lock().unwrap() = Some(why.to_string());
    }
    fn said(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }
    /// The transfer died: cloud-hypervisor writes the line and goes on
    /// serving its api, holding a VM that never arrived.
    fn the_stream_broke(&self, why: &str) {
        *self.receive_broke.lock().unwrap() = Some(why.to_string());
    }
}

#[async_trait::async_trait]
impl agent_api::hypervisor::Hypervisor for MigratingVmm {
    async fn create(
        &self,
        id: &VmId,
        _: &InstanceSpec,
        _: Option<&agent_api::CgroupHandle>,
    ) -> agent_api::hypervisor::Result<u32> {
        self.log.lock().unwrap().push("create".into());
        self.live.lock().unwrap().insert(*id);
        Ok(self.vmm_pid.lock().unwrap().unwrap_or(std::process::id()))
    }
    async fn destroy(&self, id: &VmId) -> agent_api::hypervisor::Result<()> {
        self.log.lock().unwrap().push("destroy".into());
        self.live.lock().unwrap().remove(id);
        // The process goes, and with it everything that could still be
        // asked about it — which is what the give-back has to achieve and
        // what the test asserts afterwards.
        self.still_here_after_send
            .store(false, std::sync::atomic::Ordering::SeqCst);
        *self.receive_broke.lock().unwrap() = None;
        self.receiving
            .store(false, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
    async fn start(&self, _: &VmId) -> agent_api::hypervisor::Result<()> {
        self.log.lock().unwrap().push("start".into());
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
        _: &VmId,
    ) -> agent_api::hypervisor::Result<agent_api::hypervisor::VmState> {
        if self.receive_broke.lock().unwrap().is_some() {
            // The real driver's answer too: the event file said the
            // transfer failed, so this VMM does not speak for any guest.
            return Err(HypervisorError::Backend(anyhow!(
                "receiving the migration failed"
            )));
        }
        if self.receiving.load(std::sync::atomic::Ordering::SeqCst) {
            return Ok(agent_api::hypervisor::VmState::Defined);
        }
        Ok(self
            .guest_override
            .lock()
            .unwrap()
            .unwrap_or(agent_api::hypervisor::VmState::Running))
    }
    async fn adopt(&self, _: &VmId, _: u32) -> agent_api::hypervisor::Result<()> {
        Ok(())
    }
    /// Simulate source API responsiveness independently of the send acknowledgement.
    async fn probe(&self, _: &VmId) -> bool {
        self.probes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.still_here_after_send
            .load(std::sync::atomic::Ordering::SeqCst)
    }
    fn is_tracked(&self, _: &VmId) -> bool {
        self.still_here_after_send
            .load(std::sync::atomic::Ordering::SeqCst)
    }
    fn as_migratable(&self) -> Option<&dyn agent_api::Migratable> {
        Some(self)
    }
    /// Return fake live processes with no corresponding record.
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
        self.log.lock().unwrap().push(format!("end_stray {id}"));
        self.live.lock().unwrap().remove(id);
        Ok(())
    }
}

#[async_trait::async_trait]
impl agent_api::Migratable for MigratingVmm {
    async fn migrate_in(&self, id: &VmId, peer: &str) -> agent_api::hypervisor::Result<u32> {
        self.log.lock().unwrap().push(format!("migrate_in {peer}"));
        self.receiving
            .store(true, std::sync::atomic::Ordering::SeqCst);
        self.live.lock().unwrap().insert(*id);
        Ok(std::process::id())
    }
    async fn migrate_out(&self, _: &VmId, peer: &str) -> agent_api::hypervisor::Result<()> {
        self.log.lock().unwrap().push(format!("migrate_out {peer}"));
        if !self.can_send {
            return Err(HypervisorError::Backend(anyhow!("the peer refused")));
        }
        // Optionally simulate the source process exiting after transfer.
        if self.send_leaves {
            self.still_here_after_send
                .store(false, std::sync::atomic::Ordering::SeqCst);
        }
        Ok(())
    }
    fn receive_failed(&self, _: &VmId) -> Option<String> {
        self.receive_broke.lock().unwrap().clone()
    }
    async fn send_failed(&self, _: &VmId) -> Option<String> {
        self.send_broke.lock().unwrap().clone()
    }
}

/// Migratable fixture with one referenced volume and its independent store record.
fn migratable_spec(store: &crate::store::Store) -> AgentVmSpec {
    let id = VolumeId::new_v4();
    store
        .put_volume(
            &id,
            &crate::types::VolumeRecord {
                spec: agent_api::storage::VolumeSpec {
                    base_image: None,
                    size_bytes: 4096,
                    driver: Some("filesystem".into()),
                    params: None,
                },
                handle: Some(agent_api::storage::VolumeHandle {
                    id,
                    backend: format!("/fake/{id}.raw"),
                    size_bytes: 4096,
                    params: None,
                }),
                phase: crate::types::VolumeRecordPhase::Ready,
                reason: None,
                message: None,
                gone_at: None,
            },
        )
        .expect("a volume record");
    let mut spec = spec(1, 256, vec![]);
    spec.volumes = vec![crate::types::VolumeWithId {
        id,
        spec: agent_api::storage::VolumeSpec {
            base_image: None,
            size_bytes: 4096,
            driver: Some("filesystem".into()),
            params: None,
        },
        referenced: true,
    }];
    spec
}

/// Provisioner and reconciler sharing one node's store and drivers.
/// Failed-receive cleanup is driven by reconciliation.
fn migrating_node(
    root: &std::path::Path,
    store: Arc<crate::store::Store>,
    hv: Arc<MigratingVmm>,
) -> (Arc<Provisioner>, crate::reconcile::Reconciler) {
    let drivers = migrating_drivers(root, hv);
    let provisioner = Arc::new(provisioner_over(root, store.clone(), drivers.clone()));
    let ops = Arc::new(tokio::sync::Mutex::new(()));
    let reconciler =
        crate::reconcile::Reconciler::new(store, drivers, provisioner.clone(), ops.clone());
    (provisioner, reconciler)
}

/// Cgroup fixture backed by ordinary directories. Remove the whole directory
/// tree because files created for limit writes are not cgroup pseudo-files.
struct LooseSlices(cgroup_driver::CgroupV2);

impl agent_api::ResourceConfiner for LooseSlices {
    fn create_slice(
        &self,
        name: &str,
        parent: Option<&agent_api::CgroupHandle>,
        limits: &agent_api::ResourceLimits,
    ) -> agent_api::ConfinerResult<agent_api::CgroupHandle> {
        self.0.create_slice(name, parent, limits)
    }
    fn destroy_slice(&self, cg: &agent_api::CgroupHandle) -> agent_api::ConfinerResult<()> {
        let _ = std::fs::remove_dir_all(&cg.path);
        Ok(())
    }
    fn open_slice(&self, name: &str) -> agent_api::CgroupHandle {
        self.0.open_slice(name)
    }
    fn pids_in_slice(&self, name: &str) -> agent_api::ConfinerResult<Vec<u32>> {
        self.0.pids_in_slice(name)
    }
    fn kill_slice(&self, name: &str) -> agent_api::ConfinerResult<()> {
        self.0.kill_slice(name)
    }
}

/// Observe and plan without executing, as the local observe endpoint does.
async fn preview(reconciler: &crate::reconcile::Reconciler, id: &VmId) -> crate::reconcile::DryRun {
    reconciler
        .dry_run(id)
        .await
        .expect("a look")
        .expect("a record")
}

fn migrating_drivers(root: &std::path::Path, hv: Arc<MigratingVmm>) -> Drivers {
    let mut storage: std::collections::HashMap<String, Arc<dyn agent_api::storage::VolumeDriver>> =
        std::collections::HashMap::new();
    storage.insert("filesystem".to_string(), Arc::new(PlainDisk::default()));
    Drivers {
        confiner: Arc::new(LooseSlices(cgroup_driver::CgroupV2::new(
            root.join("cgroup"),
        ))),
        hypervisor: Some(hv),
        hypervisor_name: Some("fake".into()),
        storage,
        networking: None,
        bridge: None,
        announcer: None,
        devices: std::collections::HashMap::new(),
    }
}

fn provisioner_over(
    root: &std::path::Path,
    store: Arc<crate::store::Store>,
    drivers: Drivers,
) -> Provisioner {
    Provisioner::new(
        store,
        drivers,
        Arc::new(crate::images::Cache::new(root.join("images"))),
        root.join("images"),
        root.join("run"),
        "br0".to_string(),
        None,
        None,
    )
}

fn migrating_provisioner(
    root: &std::path::Path,
    store: Arc<crate::store::Store>,
    hv: Arc<MigratingVmm>,
) -> Provisioner {
    migrating_provisioner_over(root, store, hv, Arc::new(PlainDisk::default()))
}

/// Build a provisioner with a supplied disk fixture for operation assertions.
fn migrating_provisioner_over(
    root: &std::path::Path,
    store: Arc<crate::store::Store>,
    hv: Arc<MigratingVmm>,
    disk: Arc<PlainDisk>,
) -> Provisioner {
    let mut storage: std::collections::HashMap<String, Arc<dyn agent_api::storage::VolumeDriver>> =
        std::collections::HashMap::new();
    storage.insert("filesystem".to_string(), disk);
    Provisioner::new(
        store,
        Drivers {
            confiner: Arc::new(cgroup_driver::CgroupV2::new(root.join("cgroup"))),
            hypervisor: Some(hv),
            hypervisor_name: Some("fake".into()),
            storage,
            networking: None,
            bridge: None,
            announcer: None,
            devices: std::collections::HashMap::new(),
        },
        Arc::new(crate::images::Cache::new(root.join("images"))),
        root.join("images"),
        root.join("run"),
        "br0".to_string(),
        None,
        None,
    )
}

/// Return nonexistent slice paths so `attach_pid` fails with ENOENT,
/// modeling a lost or shadowed cgroup root.
struct SlicelessConfiner(std::path::PathBuf);

impl agent_api::ResourceConfiner for SlicelessConfiner {
    fn create_slice(
        &self,
        name: &str,
        _: Option<&agent_api::CgroupHandle>,
        _: &agent_api::ResourceLimits,
    ) -> agent_api::ConfinerResult<agent_api::CgroupHandle> {
        Ok(self.open_slice(name))
    }
    fn destroy_slice(&self, _: &agent_api::CgroupHandle) -> agent_api::ConfinerResult<()> {
        Ok(())
    }
    fn open_slice(&self, name: &str) -> agent_api::CgroupHandle {
        agent_api::CgroupHandle {
            path: self.0.join("no-such-cgroup-root").join(name),
        }
    }
    fn pids_in_slice(&self, _: &str) -> agent_api::ConfinerResult<Vec<u32>> {
        Ok(Vec::new())
    }
    fn kill_slice(&self, _: &str) -> agent_api::ConfinerResult<()> {
        Ok(())
    }
}

/// Failure to attach a receiving VMM to its cgroup must stop preparation and end that VMM.
#[tokio::test]
async fn a_receiver_that_cannot_enter_its_slice_is_not_stored_as_ready() {
    let (_temp, root) = migration_root("mig-no-slice");
    let store = Arc::new(crate::store::Store::open(&root.join("a.redb")).expect("a store"));
    let hv = Arc::new(MigratingVmm::new(true));
    let mut drivers = migrating_drivers(&root, hv.clone());
    drivers.confiner = Arc::new(SlicelessConfiner(root.clone()));
    let p = provisioner_over(&root, store.clone(), drivers);

    let id = VmId::new_v4();
    let err = p
        .prepare_migration(
            id,
            migratable_spec(&store),
            "127.0.0.1:9000",
            true,
            "attempt-1",
        )
        .await
        .expect_err("a vmm that cannot enter its slice is not a reception");
    assert!(
        format!("{err:#}").contains("in its slice"),
        "the error names what could not be done: {err:#}"
    );

    // The VMM was ended, not left listening.
    assert!(
        hv.said().iter().any(|l| l == "destroy"),
        "the receiving vmm has to be ended: {:?}",
        hv.said()
    );
    use agent_api::hypervisor::Hypervisor as _;
    assert!(
        hv.strays(&[]).await.is_empty(),
        "and nothing of it is left running"
    );

    // Failed preparation must leave no active receiving marker or PID.
    if let Some(record) = store.get(&id).expect("a read") {
        assert_ne!(record.phase, Phase::Receiving, "{record:?}");
        assert_eq!(record.vmm_pid, None, "{record:?}");
        assert_eq!(record.receive_deadline, None, "{record:?}");
    }
}

/// Return a temporary resource root and its lifetime guard; callers must retain both.
fn migration_root(name: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let temp = tempfile::Builder::new()
        .prefix(&format!("meister-{name}-"))
        .tempdir()
        .expect("a temp dir");
    let root = temp.path().to_path_buf();
    (temp, root)
}

/// Boot and receive share resource preparation; only boot calls create/start.
/// Receive waits for an observed Running guest before advancing the phase.
#[tokio::test]
async fn the_chain_ends_two_ways_and_is_the_same_chain_until_it_does() {
    let (_temp, root) = migration_root("mig-chain");
    let boot_store = Arc::new(crate::store::Store::open(&root.join("boot.redb")).expect("a store"));
    let boot_hv = Arc::new(MigratingVmm::new(true));
    let booting = migrating_provisioner(&root, boot_store.clone(), boot_hv.clone());
    let booted = VmId::new_v4();
    let boot_spec = migratable_spec(&boot_store);
    booting
        .provision(booted, boot_spec, Desired::Running, true)
        .await
        .expect("the ordinary exit");
    assert_eq!(boot_hv.said(), vec!["create", "start"]);
    assert_eq!(
        boot_store
            .get(&booted)
            .expect("a record")
            .expect("one")
            .phase,
        Phase::Provisioned
    );

    let recv_store = Arc::new(crate::store::Store::open(&root.join("recv.redb")).expect("a store"));
    let recv_hv = Arc::new(MigratingVmm::new(true));
    let receiving = migrating_provisioner(&root, recv_store.clone(), recv_hv.clone());
    let arriving = VmId::new_v4();
    let recv_spec = migratable_spec(&recv_store);
    receiving
        .prepare_migration(
            arriving,
            recv_spec,
            "tcp:127.0.0.1:49000",
            true,
            "attempt-1",
        )
        .await
        .expect("the migration exit");
    // No create and no start: v53 refuses to receive into a vm that has
    // been created and builds the destination's from the stream.
    assert_eq!(recv_hv.said(), vec!["migrate_in tcp:127.0.0.1:49000"]);
    let record = recv_store.get(&arriving).expect("a record").expect("one");
    assert_eq!(record.phase, Phase::Receiving);
    assert!(record.vmm_pid.is_some(), "a vmm is listening");
    assert!(record.operation.is_none(), "the marker came off");

    // Without arrival or failure evidence, migration phases do not trigger ordinary repair.
    let waiting = crate::reconcile::Observed {
        vmm_alive: true,
        socket_responsive: true,
        tracked: true,
        guest: Some(agent_api::hypervisor::VmState::Defined),
        backends_alive: true,
        receive_failed: false,
    };
    assert_eq!(
        crate::reconcile::plan(&record, &waiting, std::time::SystemTime::now()),
        crate::reconcile::Action::None,
        "a receiving vm is nobody's to rebuild"
    );
    let arrived = crate::reconcile::Observed {
        guest: Some(agent_api::hypervisor::VmState::Running),
        ..waiting
    };
    assert_eq!(
        crate::reconcile::plan(&record, &arrived, std::time::SystemTime::now()),
        crate::reconcile::Action::Arrived
    );
    receiving
        .migration_arrived(&arriving)
        .await
        .expect("the guest is here");
    assert_eq!(
        recv_store
            .get(&arriving)
            .expect("a record")
            .expect("one")
            .phase,
        Phase::Provisioned
    );
}

/// Migration requires referenced disks whose ownership outlives the source VM.
#[tokio::test]
async fn a_vm_with_an_inline_disk_is_not_received_and_the_refusal_names_the_disk() {
    let (_temp, root) = migration_root("mig-inline");
    let store = Arc::new(crate::store::Store::open(&root.join("a.redb")).expect("a store"));
    let hv = Arc::new(MigratingVmm::new(true));
    let p = migrating_provisioner(&root, store.clone(), hv.clone());

    let inline = VolumeId::new_v4();
    let mut with_disk = spec(1, 256, vec![]);
    with_disk.volumes = vec![crate::types::VolumeWithId {
        id: inline,
        spec: agent_api::storage::VolumeSpec {
            base_image: None,
            size_bytes: 4096,
            driver: Some("filesystem".into()),
            params: None,
        },
        referenced: false,
    }];

    let id = VmId::new_v4();
    let refused = p
        .prepare_migration(id, with_disk, "tcp:127.0.0.1:49000", true, "attempt-1")
        .await
        .expect_err("an inline disk does not migrate");
    let said = format!("{refused:#}");
    assert!(said.contains(&inline.to_string()), "{said}");
    assert!(said.contains("instance store"), "{said}");
    assert!(hv.said().is_empty(), "nothing was built: {:?}", hv.said());
    assert!(store.get(&id).expect("a lookup").is_none(), "no record");
}

/// IKR-B17: a destination refuses a guest with a GPU before it prepares
/// anything, rather than starting a backend the stream will never fill.
#[tokio::test]
async fn a_vm_with_a_device_is_not_received() {
    let (_temp, root) = migration_root("mig-device-in");
    let store = Arc::new(crate::store::Store::open(&root.join("a.redb")).expect("a store"));
    let hv = Arc::new(MigratingVmm::new(true));
    let p = migrating_provisioner(&root, store.clone(), hv.clone());

    let id = VmId::new_v4();
    let gpu = spec(1, 256, vec![device("nvrm", PartitionSpec::Mediated)]);
    let refused = p
        .prepare_migration(id, gpu, "tcp:127.0.0.1:49000", true, "attempt-1")
        .await
        .expect_err("a device does not migrate");
    let said = format!("{refused:#}");
    assert!(said.contains("nvrm"), "{said}");
    assert!(said.contains("by reboot"), "{said}");
    assert!(hv.said().is_empty(), "nothing was built: {:?}", hv.said());
    assert!(store.get(&id).expect("a lookup").is_none(), "no record");
}

/// IKR-B17: a source refuses to send a guest with a device before it claims
/// the attempt or opens a stream.
#[tokio::test]
async fn a_vm_with_a_device_is_not_sent() {
    let (_temp, root) = migration_root("mig-device-out");
    let store = Arc::new(crate::store::Store::open(&root.join("a.redb")).expect("a store"));
    let hv = Arc::new(MigratingVmm::new(true));
    let p = migrating_provisioner(&root, store.clone(), hv.clone());
    let id = VmId::new_v4();
    p.provision(id, migratable_spec(&store), Desired::Running, true)
        .await
        .expect("a running vm");
    // The same guest as if it had been given a GPU when it was made.
    let mut record = store.get(&id).expect("a lookup").expect("a record");
    record.spec.devices = vec![device("crosvm-gpu", PartitionSpec::Mediated)];
    store.put(&id, &record).expect("stored");

    let refused = p
        .begin_migrate_out(
            &id,
            "tcp:10.0.0.9:49000",
            "attempt-1",
            &tokio::sync::Mutex::new(()),
        )
        .await
        .expect_err("a device does not migrate");
    assert!(format!("{refused:#}").contains("crosvm-gpu"), "{refused:#}");
    let record = store.get(&id).expect("a lookup").expect("still a record");
    assert!(record.operation.is_none(), "no send was begun");
    assert!(record.migration.is_none(), "no attempt was claimed");
    assert!(
        !hv.said().iter().any(|line| line.starts_with("migrate_out")),
        "{:?}",
        hv.said()
    );
}

/// The NICs the conversion of a create document naming two NICs gives the VM `id`.
fn derived_nics(id: VmId) -> Vec<crate::types::NicWithId> {
    use crate::types::NewVmSpecExt;
    let document: crate::types::NewVmSpec = serde_json::from_value(serde_json::json!({
        "vcpus": 1,
        "memory_mib": 256,
        "boot": {"kind": "firmware", "firmware": "fw"},
        "volumes": [{"size_bytes": 1}],
        "nics": [{}, {}],
    }))
    .expect("a create document");
    document
        .into_spec(id, "br0")
        .expect("a valid document")
        .0
        .nics
}

/// A running guest whose record names `nics`, as an agent of that time wrote them.
async fn running_with_nics(
    p: &Provisioner,
    store: &crate::store::Store,
    id: VmId,
    nics: Vec<crate::types::NicWithId>,
) {
    p.provision(id, migratable_spec(store), Desired::Running, true)
        .await
        .expect("a running vm");
    let mut record = store.get(&id).expect("a lookup").expect("a record");
    record.spec.nics = nics;
    store.put(&id, &record).expect("stored");
}

/// IKR-B66: a guest whose NIC ids an older agent rolled at random is not sent, since the
/// destination would name its taps after ids it derives; nothing is claimed or opened.
#[tokio::test]
async fn a_vm_whose_nic_ids_were_rolled_at_random_is_not_sent() {
    let (_temp, root) = migration_root("mig-rolled-nic");
    let store = Arc::new(crate::store::Store::open(&root.join("a.redb")).expect("a store"));
    let hv = Arc::new(MigratingVmm::new(true));
    let p = migrating_provisioner(&root, store.clone(), hv.clone());
    let id = VmId::new_v4();
    let mut legacy = derived_nics(id);
    legacy[1].id = agent_api::networking::NicId::new_v4();
    let rolled = legacy[1].id;
    running_with_nics(&p, &store, id, legacy).await;

    let refused = p
        .begin_migrate_out(
            &id,
            "tcp:10.0.0.9:49000",
            "attempt-1",
            &tokio::sync::Mutex::new(()),
        )
        .await
        .expect_err("a guest on rolled NIC ids does not migrate");
    let said = format!("{refused:#}");
    assert!(said.contains(&rolled.to_string()), "{said}");
    assert!(said.contains("by reboot"), "{said}");
    let record = store.get(&id).expect("a lookup").expect("still a record");
    assert!(record.operation.is_none(), "no send was begun");
    assert!(record.migration.is_none(), "no attempt was claimed");
    assert!(
        !hv.said().iter().any(|line| line.starts_with("migrate_out")),
        "{:?}",
        hv.said()
    );
}

/// A guest whose NIC ids are the ones every conversion of its document derives is sent.
#[tokio::test]
async fn a_vm_whose_nic_ids_are_derived_is_sent() {
    let (_temp, root) = migration_root("mig-derived-nic");
    let store = Arc::new(crate::store::Store::open(&root.join("a.redb")).expect("a store"));
    let hv = Arc::new(MigratingVmm::new(true));
    let p = migrating_provisioner(&root, store.clone(), hv.clone());
    let id = VmId::new_v4();
    running_with_nics(&p, &store, id, derived_nics(id)).await;

    p.begin_migrate_out(
        &id,
        "tcp:10.0.0.9:49000",
        "attempt-1",
        &tokio::sync::Mutex::new(()),
    )
    .await
    .expect("the stream is open");
    assert!(
        hv.said()
            .contains(&"migrate_out tcp:10.0.0.9:49000".to_string()),
        "{:?}",
        hv.said()
    );
}

/// Successful departure retains a Migrated record. An untyped send error
/// retains the operation barrier because it does not prove an abort.
#[tokio::test]
async fn a_successful_send_leaves_a_record_and_a_failed_one_leaves_the_guest() {
    let (_temp, root) = migration_root("mig-out");

    // The good end.
    let store = Arc::new(crate::store::Store::open(&root.join("ok.redb")).expect("a store"));
    let hv = Arc::new(MigratingVmm::new(true));
    let p = migrating_provisioner(&root, store.clone(), hv.clone());
    let id = VmId::new_v4();
    let running = migratable_spec(&store);
    p.provision(id, running, Desired::Running, true)
        .await
        .expect("a running vm");
    let ops = tokio::sync::Mutex::new(());
    p.begin_migrate_out(&id, "tcp:10.0.0.9:49000", "attempt-1", &ops)
        .await
        .expect("the stream is open");
    // Persist the operation marker before acknowledging submission so reconciliation cannot interfere.
    let sending = store.get(&id).expect("a lookup").expect("a record");
    assert!(matches!(
        sending.operation,
        Some(crate::types::Operation::MigratingOut { .. })
    ));
    assert_eq!(
        crate::reconcile::departure(&sending)
            .expect("a line")
            .outcome,
        crate::reconcile::DepartureOutcome::Sending,
        "and that is what the heartbeat says while it runs"
    );

    p.finish_migrate_out(
        &id,
        "tcp:10.0.0.9:49000",
        "attempt-1",
        std::time::Instant::now(),
        &ops,
    )
    .await;
    let record = store.get(&id).expect("a lookup").expect("still a record");
    assert_eq!(record.phase, Phase::Migrated, "the record is not deleted");
    assert!(record.vmm_pid.is_none());
    assert!(record.operation.is_none());
    assert!(record.send_failed.is_none());
    assert_eq!(
        crate::reconcile::departure(&record)
            .expect("a line")
            .outcome,
        crate::reconcile::DepartureOutcome::Gone,
        "and the tier above reads that instead of waiting for an ack"
    );
    assert!(
        hv.said()
            .contains(&"migrate_out tcp:10.0.0.9:49000".to_string())
    );
    // And nothing touches it from here on: the cluster's DestroyInstance
    // is what takes it away.
    let gone = crate::reconcile::Observed {
        vmm_alive: false,
        socket_responsive: false,
        tracked: false,
        guest: None,
        backends_alive: true,
        receive_failed: false,
    };
    assert_eq!(
        crate::reconcile::plan(&record, &gone, std::time::SystemTime::now()),
        crate::reconcile::Action::None,
        "a migrated record is not a vm to start"
    );

    // An untyped submission error does not establish abort. The source guest
    // and disk remain recorded, with Unknown outcome and an operation barrier.
    let store = Arc::new(crate::store::Store::open(&root.join("no.redb")).expect("a store"));
    let hv = Arc::new(MigratingVmm::new(false));
    let p = migrating_provisioner(&root, store.clone(), hv.clone());
    let id = VmId::new_v4();
    let running = migratable_spec(&store);
    p.provision(id, running, Desired::Running, true)
        .await
        .expect("a running vm");
    let refused = p
        .begin_migrate_out(
            &id,
            "tcp:10.0.0.9:49000",
            "attempt-1",
            &tokio::sync::Mutex::new(()),
        )
        .await
        .expect_err("the peer refused");
    assert!(
        format!("{refused:#}").contains("tcp:10.0.0.9:49000"),
        "the refusal names where it was going: {refused:#}"
    );
    let record = store.get(&id).expect("a lookup").expect("still a record");
    assert_eq!(record.phase, Phase::Provisioned, "the guest is still ours");
    assert!(record.vmm_pid.is_some());
    assert!(
        record.operation.is_some(),
        "an untyped driver error is not an abort proof"
    );
    assert_eq!(
        crate::reconcile::departure(&record).unwrap().outcome,
        crate::reconcile::DepartureOutcome::Unknown
    );
}

/// Receiving and migrated records retain overlay ownership until their rows are removed.
#[test]
fn a_migration_carries_the_overlay_count_without_anybody_keeping_it() {
    let (_temp, root) = migration_root("mig-overlay");
    let store = crate::store::Store::open(&root.join("a.redb")).expect("a store");

    let vni = 10_042;
    let (source_id, mut source) = overlay_vm(vni);
    let (target_id, mut target) = overlay_vm(vni);
    // Use one fixture store to test per-node reference counting across both migration records.
    source.phase = Phase::Provisioned;
    store.put(&source_id, &source).expect("the source");
    assert_eq!(
        overlay_users(&store, vni, &source_id).expect("a count"),
        0,
        "one vm on the wire, and it is the one asking"
    );

    // The destination's record exists from PrepareMigration on, with no
    // tap and no guest — and it still counts, or a teardown of the source
    // could take the bridge with it.
    target.phase = Phase::Receiving;
    target.nics.clear();
    store.put(&target_id, &target).expect("the destination");
    assert_eq!(
        overlay_users(&store, vni, &source_id).expect("a count"),
        1,
        "a record that is still receiving is a user of the wire"
    );

    // The guest arrives; the source's record becomes Migrated and is
    // still a user until the cluster takes it away.
    target.phase = Phase::Provisioned;
    store.put(&target_id, &target).expect("arrived");
    source.phase = Phase::Migrated;
    store.put(&source_id, &source).expect("left");
    assert_eq!(
        overlay_users(&store, vni, &target_id).expect("a count"),
        1,
        "and the source is a user of it until its record goes"
    );

    // After source-record removal, only the destination reference remains.
    store.delete(&source_id).expect("the source lets go");
    assert_eq!(overlay_users(&store, vni, &target_id).expect("a count"), 0);
}

/// Receiving records contribute a running phase only after observing Running;
/// a migrated record cannot contribute one even if its observation is stale.
#[test]
fn the_route_announcement_follows_the_guest_and_never_leads_it() {
    let obs = crate::reconcile::Observed {
        vmm_alive: true,
        socket_responsive: true,
        tracked: true,
        guest: Some(agent_api::hypervisor::VmState::Running),
        backends_alive: true,
        receive_failed: false,
    };
    let announced = |phase: Phase| {
        let mut record = spec_record();
        record.desired = Desired::Running;
        record.phase = phase;
        crate::reconcile::report_status(&record, &obs, 0, None).phase
    };
    // Guest observation determines arrival, independently of the persisted phase.
    // A Defined receiver has no running guest to announce.
    let waiting = crate::reconcile::Observed {
        guest: Some(agent_api::hypervisor::VmState::Defined),
        ..obs
    };
    let mut record = spec_record();
    record.desired = Desired::Running;
    record.phase = Phase::Receiving;
    assert_eq!(
        crate::reconcile::report_status(&record, &waiting, 0, None).phase,
        crate::reconcile::ReportedPhase::Provisioning
    );
    assert_eq!(
        announced(Phase::Receiving),
        crate::reconcile::ReportedPhase::Running,
        "the guest is here, whatever the bookkeeping still says"
    );
    // The guest has left: the same, from the other end.
    assert_eq!(
        announced(Phase::Migrated),
        crate::reconcile::ReportedPhase::Provisioning
    );
    // And once it is here, it is an ordinary running vm and its addresses
    // are announced like anybody's.
    assert_eq!(
        announced(Phase::Provisioned),
        crate::reconcile::ReportedPhase::Running
    );

    // Both in-flight phases include a diagnostic message.
    record.phase = Phase::Receiving;
    assert!(
        crate::reconcile::report_status(&record, &waiting, 0, None)
            .message
            .is_some(),
        "a receiving vm with no guest yet says nothing"
    );
    record.phase = Phase::Migrated;
    assert!(
        crate::reconcile::report_status(&record, &obs, 0, None)
            .message
            .is_some(),
        "a migrated vm says nothing"
    );
}

/// An explicit receive failure releases the receiver without deleting referenced data.
/// A later attempt can reuse the VM ID.
#[tokio::test]
async fn a_reception_that_fails_gives_everything_back_and_the_next_one_works() {
    let (_temp, root) = migration_root("mig-abort");
    let store = Arc::new(crate::store::Store::open(&root.join("dest.redb")).expect("a store"));
    let hv = Arc::new(MigratingVmm::new(true));
    let (dest, reconciler) = migrating_node(&root, store.clone(), hv.clone());

    let id = VmId::new_v4();
    dest.prepare_migration(
        id,
        migratable_spec(&store),
        "tcp:127.0.0.1:49000",
        true,
        "attempt-1",
    )
    .await
    .expect("a listening vmm");
    let standing = store.get(&id).expect("a record").expect("one");
    assert_eq!(standing.phase, Phase::Receiving);
    assert!(standing.vmm_pid.is_some(), "a vmm is listening");
    assert_eq!(standing.volumes.len(), 1, "and the disk is attached to it");
    assert!(
        standing.receive_deadline.is_some(),
        "and this node knows when to stop waiting"
    );

    // Nothing has happened yet, so nothing is given back: a pass here
    // must not touch a reception that is simply still in flight.
    let waiting = preview(&reconciler, &id).await;
    assert!(!waiting.observed.receive_failed);
    assert_eq!(
        waiting.action,
        crate::reconcile::Action::None,
        "a guest still on its way is nobody's to tear down"
    );

    // Record explicit receive failure while keeping the VMM responsive.
    hv.the_stream_broke("Failed to receive migratable component snapshot");
    let broken = preview(&reconciler, &id).await;
    assert!(broken.observed.receive_failed, "the node can see it now");
    assert_eq!(broken.action, crate::reconcile::Action::Teardown);
    // And the report says it, rather than "in flight" forever.
    let reported = crate::reconcile::report_status(&standing, &broken.observed, 0, None);
    assert_eq!(reported.phase, crate::reconcile::ReportedPhase::Failed);
    assert_eq!(
        reported.reason,
        Some(crate::reconcile::VmReason::ReceiveFailed),
        "and names the class of failure, not just that there was one"
    );
    assert!(
        reported
            .message
            .expect("a sentence")
            .contains("still running where it was"),
        "the report names the machine to look at"
    );

    // One ordinary pass, and the node is empty again.
    assert_eq!(
        reconciler
            .reconcile(id, crate::reconcile::Trigger::Periodic)
            .await
            .expect("a pass"),
        crate::reconcile::Action::Teardown
    );
    assert!(
        hv.said().contains(&"destroy".to_string()),
        "the vmm was ended: {:?}",
        hv.said()
    );
    assert!(
        store.get(&id).expect("a lookup").is_none(),
        "and the record went with it"
    );
    // Failed-receive cleanup detaches referenced storage without deleting its data.
    let volumes = store.list_volumes().expect("the volume table");
    assert_eq!(volumes.len(), 1, "the volume object outlived the reception");
    assert_eq!(
        volumes[0].1.phase,
        crate::types::VolumeRecordPhase::Ready,
        "and it is untouched"
    );

    // A second attempt can receive the same VM ID after the failed one is cleaned up.
    let again = Arc::new(MigratingVmm::new(true));
    let (dest, _) = migrating_node(&root, store.clone(), again.clone());
    dest.prepare_migration(
        id,
        migratable_spec(&store),
        "tcp:127.0.0.1:49001",
        true,
        "attempt-2",
    )
    .await
    .expect("the second attempt is an ordinary one");
    assert_eq!(
        store.get(&id).expect("a record").expect("one").phase,
        Phase::Receiving
    );
}

/// A receive deadline is not proof of failure. Preserve the attempt across startup
/// and accept a later observed arrival without destroying the receiver.
#[tokio::test]
async fn a_receive_deadline_does_not_authorize_cleanup() {
    let (_temp, root) = migration_root("mig-nobody");
    let store = Arc::new(crate::store::Store::open(&root.join("dest.redb")).expect("a store"));
    let hv = Arc::new(MigratingVmm::new(true));
    let (dest, reconciler) = migrating_node(&root, store.clone(), hv.clone());

    let id = VmId::new_v4();
    dest.prepare_migration(
        id,
        migratable_spec(&store),
        "tcp:127.0.0.1:49000",
        true,
        "attempt-1",
    )
    .await
    .expect("a listening vmm");

    // Repeated passes must not disrupt an active receiver before the advisory deadline.
    let mut record = store.get(&id).expect("a record").expect("one");
    assert!(!preview(&reconciler, &id).await.observed.receive_failed);
    assert_eq!(
        reconciler
            .reconcile(id, crate::reconcile::Trigger::Periodic)
            .await
            .expect("a pass"),
        crate::reconcile::Action::None
    );

    // The deadline passes — written into the record, which is how it
    // survives the agent that armed it.
    record.receive_deadline =
        Some(std::time::SystemTime::now() - std::time::Duration::from_secs(1));
    store.put(&id, &record).expect("the record");
    assert!(
        !preview(&reconciler, &id).await.observed.receive_failed,
        "silence is not evidence of an aborted transfer"
    );
    assert_eq!(
        reconciler
            .reconcile(id, crate::reconcile::Trigger::Periodic)
            .await
            .expect("a pass"),
        crate::reconcile::Action::None
    );
    assert!(store.get(&id).expect("a lookup").is_some());
    assert_eq!(
        reconciler
            .reconcile(id, crate::reconcile::Trigger::Startup)
            .await
            .unwrap(),
        crate::reconcile::Action::None
    );
    hv.receiving
        .store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        reconciler
            .reconcile(id, crate::reconcile::Trigger::Periodic)
            .await
            .unwrap(),
        crate::reconcile::Action::Arrived
    );
    assert!(!hv.said().contains(&"destroy".to_string()));
}

/// The send watcher releases the global operations lock while awaiting an outcome.
/// Explicit abort evidence clears the per-VM barrier and reports StillHere.
#[tokio::test]
async fn a_failed_send_answers_and_leaves_the_command_path_free() {
    let (_temp, root) = migration_root("mig-blocked");
    let store = Arc::new(crate::store::Store::open(&root.join("src.redb")).expect("a store"));
    let hv = Arc::new(MigratingVmm::that_fails_mid_send());
    let source = Arc::new(migrating_provisioner(&root, store.clone(), hv.clone()));
    let id = VmId::new_v4();
    source
        .provision(id, migratable_spec(&store), Desired::Running, true)
        .await
        .expect("a running vm");

    let ops = Arc::new(tokio::sync::Mutex::new(()));
    source
        .begin_migrate_out(&id, "tcp:10.0.0.9:49000", "attempt-1", &ops)
        .await
        .expect("the stream is open, which is now the whole of the answer");
    let sending = tokio::spawn({
        let source = source.clone();
        let ops = ops.clone();
        async move {
            source
                .finish_migrate_out(
                    &id,
                    "tcp:10.0.0.9:49000",
                    "attempt-1",
                    std::time::Instant::now(),
                    &ops,
                )
                .await
        }
    });

    // Verify that other commands can acquire the operations lock during the send.
    let mut free = false;
    for _ in 0..200 {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        if hv.said().iter().any(|l| l.starts_with("migrate_out")) && ops.try_lock().is_ok() {
            free = true;
            break;
        }
    }
    assert!(
        free,
        "the node's operation lock was held for the length of the transfer"
    );
    // The persisted operation marker excludes this VM from reconciliation.
    let inflight = store.get(&id).expect("a lookup").expect("a record");
    assert!(
        matches!(
            inflight.operation,
            Some(crate::types::Operation::MigratingOut { .. })
        ),
        "the vm is spoken for while it is being sent"
    );

    // Now cloud-hypervisor gives the guest back, which is what a failed send
    // does. Nothing exits, so nothing that watches for an exit would ever
    // learn of it.
    hv.the_send_broke("cloud-hypervisor is serving the guest here again");
    tokio::time::timeout(std::time::Duration::from_secs(10), sending)
        .await
        .expect("the watch ended instead of running to its ceiling")
        .expect("the task");

    // And the source is exactly what it was: the guest, its vmm, its disks.
    let record = store.get(&id).expect("a lookup").expect("still a record");
    assert_eq!(record.phase, Phase::Provisioned, "the guest is still ours");
    assert!(record.vmm_pid.is_some());
    assert!(record.operation.is_none(), "the marker came off");
    assert_eq!(record.volumes.len(), 1, "and it kept its disk");

    // The outcome is persisted for the next heartbeat.
    let line = crate::reconcile::departure(&record).expect("this node says so");
    assert_eq!(line.outcome, crate::reconcile::DepartureOutcome::StillHere);
    let said = line.message.expect("with a reason");
    assert!(
        said.contains("cloud-hypervisor is serving the guest here again"),
        "and it is v53's own sentence, not a summary of one: {said}"
    );

    // The next command on this node is served, which is the sentence the
    // defect was reported as: `vm create` on agent-1a went Failed.
    assert!(ops.try_lock().is_ok(), "the lock outlived the send");
}

/// Persist the per-VM migration barrier before returning acceptance;
/// transfer completion is reported later.
#[tokio::test]
async fn the_send_is_accepted_while_the_transfer_is_still_running() {
    let (_temp, root) = migration_root("mig-accepted");
    let store = Arc::new(crate::store::Store::open(&root.join("src.redb")).expect("a store"));
    // Accepts the send and never lets the process go, so nothing about this
    // transfer is over when the answer arrives.
    let hv = Arc::new(MigratingVmm::that_fails_mid_send());
    let p = Arc::new(migrating_provisioner(&root, store.clone(), hv.clone()));
    let id = VmId::new_v4();
    p.provision(id, migratable_spec(&store), Desired::Running, true)
        .await
        .expect("a running vm");

    let ops = Arc::new(tokio::sync::Mutex::new(()));
    let accepted = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        p.begin_migrate_out(&id, "tcp:10.0.0.9:49000", "attempt-1", &ops),
    )
    .await
    .expect("the answer did not wait for the transfer");
    accepted.expect("accepted");

    // The source remains alive with no terminal failure evidence.
    use agent_api::Migratable as _;
    use agent_api::hypervisor::Hypervisor as _;
    assert!(hv.probe(&id).await, "the source vmm is still running");
    assert!(
        hv.send_failed(&id).await.is_none(),
        "and it has not given the guest back either"
    );

    // Report the in-flight send and its destination peer.
    let record = store.get(&id).expect("a lookup").expect("a record");
    let line = crate::reconcile::departure(&record).expect("a line");
    assert_eq!(line.outcome, crate::reconcile::DepartureOutcome::Sending);
    assert_eq!(line.peer, "tcp:10.0.0.9:49000");
    assert!(line.message.is_none());

    // Persist the repair barrier before returning so reconciliation cannot
    // resume a source paused during transfer.
    assert!(matches!(
        record.operation,
        Some(crate::types::Operation::MigratingOut { .. })
    ));
    assert_eq!(
        crate::reconcile::plan(
            &record,
            &sending_observation(),
            std::time::SystemTime::now()
        ),
        crate::reconcile::Action::Blocked,
        "a vm that is being sent is nobody else's to touch"
    );
}

/// A source in the middle of a send: VMM alive, socket answering, guest
/// paused — which is what the last seconds of a transfer look like.
fn sending_observation() -> crate::reconcile::Observed {
    crate::reconcile::Observed {
        vmm_alive: true,
        socket_responsive: true,
        tracked: true,
        guest: Some(agent_api::VmState::Paused),
        backends_alive: true,
        receive_failed: false,
    }
}

/// A second send must neither replace the first peer nor call the VMM again.
#[tokio::test]
async fn a_second_migrate_out_for_a_vm_already_sending_is_refused() {
    let (_temp, root) = migration_root("mig-twice");
    let store = Arc::new(crate::store::Store::open(&root.join("src.redb")).expect("a store"));
    // Accepts the send and never lets the process go, so the transfer is
    // still under way when the second command arrives.
    let hv = Arc::new(MigratingVmm::that_fails_mid_send());
    let p = Arc::new(migrating_provisioner(&root, store.clone(), hv.clone()));
    let id = VmId::new_v4();
    p.provision(id, migratable_spec(&store), Desired::Running, true)
        .await
        .expect("a running vm");

    let ops = tokio::sync::Mutex::new(());
    p.begin_migrate_out(&id, "tcp:10.0.0.9:49000", "attempt-1", &ops)
        .await
        .expect("the stream is open");

    let refused = p
        .begin_migrate_out(&id, "tcp:10.0.0.11:49000", "attempt-1", &ops)
        .await
        .expect_err("a guest is sent to one machine at a time");
    let why = format!("{refused:#}");
    assert!(
        why.contains("tcp:10.0.0.9:49000"),
        "and the refusal names the transfer that is running: {why}"
    );

    // Retain the first attempt's peer for its watcher and status reports.
    let record = store.get(&id).expect("a lookup").expect("a record");
    assert!(
        matches!(
            &record.operation,
            Some(crate::types::Operation::MigratingOut { peer }) if peer == "tcp:10.0.0.9:49000"
        ),
        "{:?}",
        record.operation
    );

    // And the VMM was asked to send exactly once.
    assert_eq!(
        hv.said()
            .iter()
            .filter(|said| said.starts_with("migrate_out"))
            .count(),
        1,
        "{:?}",
        hv.said()
    );
}

/// Raw row keys protect guests whose records cannot be decoded from stray-process cleanup.
#[tokio::test]
async fn a_vmm_with_no_record_is_named_and_a_corrupt_row_still_counts_as_one() {
    let (_temp, root) = migration_root("mig-stray");
    let store = Arc::new(crate::store::Store::open(&root.join("a.redb")).expect("a store"));
    let hv = Arc::new(MigratingVmm::new(true));
    let p = Arc::new(migrating_provisioner(&root, store.clone(), hv.clone()));

    let managed = VmId::new_v4();
    p.provision(managed, migratable_spec(&store), Desired::Running, true)
        .await
        .expect("a running vm");
    // Create a live guest, then corrupt its row. Admission would correctly
    // refuse creating a guest over an already unreadable row.
    let unreadable = VmId::new_v4();
    p.provision(unreadable, migratable_spec(&store), Desired::Running, true)
        .await
        .expect("a second running vm");
    store
        .put_raw(&unreadable.to_string(), b"{\"not\":\"a record\"}")
        .expect("and its row is broken");

    // Every row this table has, readable or not — which is what the sweep
    // uses and the point of the test.
    let known: Vec<VmId> = store
        .list_raw()
        .expect("the rows")
        .iter()
        .filter_map(|(key, _)| key.parse().ok())
        .collect();
    assert_eq!(known.len(), 2, "a corrupt row is still a row");

    use agent_api::hypervisor::Hypervisor as _;
    let strays = hv.strays(&known).await;
    assert!(
        strays.is_empty(),
        "neither vm is unmanaged, and the unreadable one least of all: {strays:?}"
    );

    // Now take one of them off the books, which is exactly what a `destroy`
    // that removed the record and failed at the process leaves behind.
    store.delete(&managed).expect("the record goes");
    let known: Vec<VmId> = store
        .list_raw()
        .expect("the rows")
        .iter()
        .filter_map(|(key, _)| key.parse().ok())
        .collect();
    let strays = hv.strays(&known).await;
    assert_eq!(strays, vec![managed], "and now it is nobody's");

    // End strays through their socket because no persisted PID identity is available.
    hv.end_stray(&managed).await.expect("it goes");
    assert!(
        hv.said().iter().any(|l| l.contains("end_stray")),
        "the driver was asked, and by the narrow verb: {:?}",
        hv.said()
    );
}

/// Failed-receiver cleanup forgets local import claims while preserving shared data.
#[tokio::test]
async fn a_reception_that_is_given_back_lets_go_of_the_claim_and_not_the_bytes() {
    let (_temp, root) = migration_root("mig-claim");
    let store = Arc::new(crate::store::Store::open(&root.join("a.redb")).expect("a store"));
    let hv = Arc::new(MigratingVmm::new(true));
    let disk = Arc::new(PlainDisk::default());
    let p = migrating_provisioner_over(&root, store.clone(), hv.clone(), disk.clone());

    let arriving = VmId::new_v4();
    p.prepare_migration(
        arriving,
        migratable_spec(&store),
        "tcp:127.0.0.1:49000",
        true,
        "attempt-1",
    )
    .await
    .expect("a vmm that is listening");
    let opened = store
        .get(&arriving)
        .expect("a lookup")
        .expect("a record")
        .volumes
        .iter()
        .map(agent_api::storage::Volume::id)
        .collect::<Vec<_>>();
    assert_eq!(opened.len(), 1, "the reception opened the guest's disk");

    // The guest never came, and this node gives everything back.
    let _ = p.teardown(&arriving).await;

    assert_eq!(
        *disk.forgotten.lock().unwrap(),
        opened,
        "the note over the namespace goes with the reception"
    );
    assert!(
        disk.deprovisioned.lock().unwrap().is_empty(),
        "and the bytes do not: they belong to a guest running on another machine"
    );
}

/// Ordinary VM teardown detaches referenced volumes and retains local provider ownership.
#[tokio::test]
async fn tearing_down_a_guest_that_ran_here_keeps_the_volume_this_node_owns() {
    let (_temp, root) = migration_root("mig-noclaim");
    let store = Arc::new(crate::store::Store::open(&root.join("a.redb")).expect("a store"));
    let hv = Arc::new(MigratingVmm::new(true));
    let disk = Arc::new(PlainDisk::default());
    let p = migrating_provisioner_over(&root, store.clone(), hv.clone(), disk.clone());

    let running = VmId::new_v4();
    p.provision(running, migratable_spec(&store), Desired::Running, true)
        .await
        .expect("a running vm");
    let _ = p.teardown(&running).await;

    assert!(
        disk.forgotten.lock().unwrap().is_empty(),
        "an ordinary teardown detaches and says nothing else about the volume"
    );
    assert!(
        disk.deprovisioned.lock().unwrap().is_empty(),
        "and certainly does not delete a referenced volume's bytes"
    );
}

/// Live process carrying the VM UUID in its argv for identity checks. Killed on drop.
struct StandInVmm(std::process::Child);

impl StandInVmm {
    fn for_vm(id: &VmId) -> Self {
        use std::os::unix::process::CommandExt as _;
        // Spawn one process with the VM ID in argv and no inherited streams.
        // Avoid a shell child that could survive cleanup and hold stdout open.
        let child = std::process::Command::new("sleep")
            .arg0(format!("stand-in-vmm --api-socket=/run/meister/{id}.sock"))
            .arg("600")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("a process");
        Self(child)
    }
    fn pid(&self) -> u32 {
        self.0.id()
    }
    /// The VMM exits, which is what v53 does when a send took.
    fn exit(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Drop for StandInVmm {
    fn drop(&mut self) {
        self.exit();
    }
}

/// An unresponsive API socket does not prove process exit.
/// Keep the source record and attachments until the process is confirmed gone.
#[tokio::test]
async fn a_vmm_that_stops_answering_has_not_left() {
    let (_temp, root) = migration_root("mig-unreachable");
    let store = Arc::new(crate::store::Store::open(&root.join("src.redb")).expect("a store"));
    let id = VmId::new_v4();
    let mut vmm = StandInVmm::for_vm(&id);
    // Accepts the send and goes quiet on its socket at once — which is also
    // what a successful send looks like from here, until the process is asked.
    let hv = Arc::new(MigratingVmm::new(true));
    *hv.vmm_pid.lock().unwrap() = Some(vmm.pid());
    let disk = Arc::new(PlainDisk::default());
    let source = Arc::new(migrating_provisioner_over(
        &root,
        store.clone(),
        hv.clone(),
        disk.clone(),
    ));
    source
        .provision(id, migratable_spec(&store), Desired::Running, true)
        .await
        .expect("a running vm");
    use agent_api::hypervisor::Hypervisor as _;
    assert!(hv.owns_pid(&id, vmm.pid()), "the stand-in IS this vm's vmm");

    let ops = Arc::new(tokio::sync::Mutex::new(()));
    source
        .begin_migrate_out(&id, "tcp:10.0.0.9:49000", "attempt-1", &ops)
        .await
        .expect("the stream is open");
    let asked_before = hv.probes.load(std::sync::atomic::Ordering::SeqCst);
    let watching = tokio::spawn({
        let source = source.clone();
        let ops = ops.clone();
        async move {
            source
                .finish_migrate_out(
                    &id,
                    "tcp:10.0.0.9:49000",
                    "attempt-1",
                    std::time::Instant::now(),
                    &ops,
                )
                .await
        }
    });

    // Let the watch go round five times against a silent socket and a live
    // process. Counted, not timed.
    while hv.probes.load(std::sync::atomic::Ordering::SeqCst) < asked_before + 5 {
        assert!(
            !watching.is_finished(),
            "the watch ended on a socket that did not answer"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let record = store.get(&id).expect("a lookup").expect("a record");
    assert_eq!(record.phase, Phase::Provisioned, "not Migrated");
    assert_eq!(record.vmm_pid, Some(vmm.pid()), "the pid is not forgotten");
    assert_eq!(record.volumes.len(), 1, "and the disk is not let go of");
    assert!(
        disk.forgotten.lock().unwrap().is_empty(),
        "nothing was detached at the backend"
    );
    assert!(matches!(
        record.operation,
        Some(crate::types::Operation::MigratingOut { .. })
    ));

    // Now the process goes, which is the evidence v53 gives of a send that
    // took — and the watch reads it as that.
    vmm.exit();
    tokio::time::timeout(std::time::Duration::from_secs(10), watching)
        .await
        .expect("the watch ended once the process had")
        .expect("the task");
    let record = store.get(&id).expect("a lookup").expect("a record");
    assert_eq!(record.phase, Phase::Migrated);
    assert!(record.vmm_pid.is_none());
}

/// An unresponsive source that remains alive has an unknown outcome at the ceiling;
/// retain its PID, guest ownership and disks.
#[tokio::test]
async fn a_vmm_that_never_answers_again_is_unknown_at_the_ceiling() {
    let (_temp, root) = migration_root("mig-unreachable-ceiling");
    let store = Arc::new(crate::store::Store::open(&root.join("src.redb")).expect("a store"));
    let id = VmId::new_v4();
    let vmm = StandInVmm::for_vm(&id);
    let hv = Arc::new(MigratingVmm::new(true));
    *hv.vmm_pid.lock().unwrap() = Some(vmm.pid());
    let source = migrating_provisioner(&root, store.clone(), hv.clone()).with_ceilings(
        crate::provision::Ceilings {
            migrate_out: std::time::Duration::ZERO,
            receive: std::time::Duration::from_secs(600),
        },
    );
    source
        .provision(id, migratable_spec(&store), Desired::Running, true)
        .await
        .expect("a running vm");
    let ops = tokio::sync::Mutex::new(());
    source
        .begin_migrate_out(&id, "tcp:10.0.0.9:49000", "attempt-1", &ops)
        .await
        .expect("the stream is open");
    source
        .finish_migrate_out(
            &id,
            "tcp:10.0.0.9:49000",
            "attempt-1",
            std::time::Instant::now(),
            &ops,
        )
        .await;

    let record = store.get(&id).expect("a lookup").expect("a record");
    assert_eq!(record.phase, Phase::Provisioned, "the guest is still ours");
    assert_eq!(record.vmm_pid, Some(vmm.pid()));
    assert_eq!(record.volumes.len(), 1);
    let line = crate::reconcile::departure(&record).expect("this node says so");
    assert_eq!(line.outcome, crate::reconcile::DepartureOutcome::Unknown);
    let said = line.message.expect("with a reason");
    assert!(said.contains("unknown"), "{said}");
    assert!(record.operation.is_some());
    assert_eq!(
        crate::reconcile::plan(
            &record,
            &sending_observation(),
            std::time::SystemTime::now()
        ),
        crate::reconcile::Action::Blocked
    );
}

/// Force a plan-before-lock interleaving: the operation barrier written while
/// the pass waits must prevent execution of its stale Stop action.
#[tokio::test]
async fn a_plan_made_before_a_migration_began_is_not_carried_out_during_it() {
    let (_temp, root) = migration_root("stale-plan");
    let store = Arc::new(crate::store::Store::open(&root.join("src.redb")).expect("a store"));
    let hv = Arc::new(MigratingVmm::new(true));
    let drivers = migrating_drivers(&root, hv.clone());
    let provisioner = Arc::new(provisioner_over(&root, store.clone(), drivers.clone()));
    let ops = Arc::new(tokio::sync::Mutex::new(()));
    let reconciler = Arc::new(crate::reconcile::Reconciler::new(
        store.clone(),
        drivers,
        provisioner.clone(),
        ops.clone(),
    ));
    let id = VmId::new_v4();
    provisioner
        .provision(id, migratable_spec(&store), Desired::Running, true)
        .await
        .expect("a running vm");
    // Set stop intent without running reconciliation; the following pass is under test.
    store
        .mutate(&id, |r| r.desired = Desired::Stopped)
        .expect("the intent");

    // The node's lock, held the way `begin_migrate_out` holds it.
    let lock = ops.lock().await;
    let asked = hv.probes.load(std::sync::atomic::Ordering::SeqCst);
    let pass = tokio::spawn({
        let reconciler = reconciler.clone();
        async move {
            reconciler
                .reconcile(id, crate::reconcile::Trigger::Manual)
                .await
        }
    });
    // Wait until observation has read the record without an operation marker.
    // Execution must then revalidate after acquiring the lock.
    while hv.probes.load(std::sync::atomic::Ordering::SeqCst) == asked {
        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
    }
    // What the send writes under the lock before it answers.
    store
        .mutate(&id, |r| {
            r.operation = Some(crate::types::Operation::MigratingOut {
                peer: "tcp:10.0.0.9:49000".into(),
            })
        })
        .expect("the marker");
    drop(lock);

    let decided = pass.await.expect("the task").expect("a pass");
    assert_eq!(
        decided,
        crate::reconcile::Action::Stop,
        "the plan WAS a stop, made from the record as it was before the send"
    );
    assert!(
        !hv.said().iter().any(|l| l == "destroy"),
        "and it was not carried out into the send: {:?}",
        hv.said()
    );
    let record = store.get(&id).expect("a lookup").expect("a record");
    assert!(
        record.vmm_pid.is_some(),
        "the sending vmm is still recorded"
    );
    assert!(
        matches!(
            record.operation,
            Some(crate::types::Operation::MigratingOut { .. })
        ),
        "and the send still owns the vm"
    );
}

/// Redb, not a task, owns the repair barrier across process lifetimes.
#[tokio::test]
async fn persisted_send_recovery_never_provisions_or_resumes_a_second_guest() {
    use std::sync::atomic::Ordering::SeqCst;
    for state in [
        None,
        Some(agent_api::VmState::Running),
        Some(agent_api::VmState::Paused),
    ] {
        let (_temp, root) = migration_root("restart-contract");
        let id = VmId::new_v4();
        let db = root.join("agent.redb");
        {
            let store = crate::store::Store::open(&db).unwrap();
            let mut record = VmRecord::blank();
            record.vmm_pid = Some(std::process::id());
            record.operation = Some(crate::types::Operation::MigratingOut {
                peer: "tcp:target:49000".into(),
            });
            record.migration = Some(crate::types::MigrationAttempt {
                id: "M1".into(),
                peer: "tcp:target:49000".into(),
                incoming: false,
                accepted: true,
                unknown: Some("agent stopped watching".into()),
            });
            store.put(&id, &record).unwrap();
        }
        let store = Arc::new(crate::store::Store::open(&db).unwrap());
        let hv = Arc::new(MigratingVmm::that_fails_mid_send());
        hv.still_here_after_send.store(state.is_some(), SeqCst);
        *hv.guest_override.lock().unwrap() = state;
        let (_, restarted) = migrating_node(&root, store.clone(), hv.clone());
        let action = restarted
            .reconcile(id, crate::reconcile::Trigger::Startup)
            .await
            .unwrap();
        assert!(matches!(
            action,
            crate::reconcile::Action::Blocked | crate::reconcile::Action::None
        ));
        assert!(
            hv.said().is_empty(),
            "recovery must not create, start, resume or destroy: {:?}",
            hv.said()
        );
        let record = store.get(&id).unwrap().unwrap();
        let report = crate::reconcile::departure(&record).unwrap();
        assert_eq!(report.migration_id, "M1");
        assert_eq!(
            report.outcome,
            if state.is_none() {
                crate::reconcile::DepartureOutcome::Gone
            } else {
                crate::reconcile::DepartureOutcome::Unknown
            }
        );
    }
}

#[tokio::test]
async fn deadline_keeps_ownership_and_later_evidence_resolves_the_same_attempt() {
    let (_temp, root) = migration_root("late-send-report");
    let store = Arc::new(crate::store::Store::open(&root.join("a.redb")).unwrap());
    let hv = Arc::new(MigratingVmm::that_fails_mid_send());
    let p = migrating_provisioner(&root, store.clone(), hv.clone()).with_ceilings(
        crate::provision::Ceilings {
            migrate_out: std::time::Duration::ZERO,
            receive: std::time::Duration::ZERO,
        },
    );
    let id = VmId::new_v4();
    p.provision(id, migratable_spec(&store), Desired::Running, true)
        .await
        .unwrap();
    let ops = tokio::sync::Mutex::new(());
    p.begin_migrate_out(&id, "tcp:target:49000", "M1", &ops)
        .await
        .unwrap();
    p.finish_migrate_out(
        &id,
        "tcp:target:49000",
        "M1",
        std::time::Instant::now(),
        &ops,
    )
    .await;
    let unknown = store.get(&id).unwrap().unwrap();
    assert!(unknown.operation.is_some());
    assert_eq!(
        crate::reconcile::departure(&unknown).unwrap().outcome,
        crate::reconcile::DepartureOutcome::Unknown
    );
    hv.the_send_broke("explicit abort observed");
    assert!(p.observe_send(&id, "M1", &ops).await.unwrap());
    let ended = store.get(&id).unwrap().unwrap();
    assert!(ended.operation.is_none());
    assert_eq!(
        crate::reconcile::departure(&ended).unwrap().outcome,
        crate::reconcile::DepartureOutcome::StillHere
    );
    hv.send_broke.lock().unwrap().take();
    p.begin_migrate_out(&id, "tcp:target:49000", "M2", &ops)
        .await
        .unwrap();
    // The old watcher completes after M2 was dispatched.
    assert!(p.observe_send(&id, "M1", &ops).await.unwrap());
    let current = store.get(&id).unwrap().unwrap();
    assert!(current.operation.is_some());
    assert_eq!(
        crate::reconcile::departure(&current).unwrap().migration_id,
        "M2"
    );
    hv.the_send_broke("M2 aborted");
    p.observe_send(&id, "M2", &ops).await.unwrap();
    assert!(
        p.begin_migrate_out(&id, "tcp:target:49000", "M1", &ops)
            .await
            .is_err(),
        "an old command cannot replay after a newer attempt ended"
    );
}

#[tokio::test]
async fn cleanup_is_attempt_bound_and_cancel_before_prepare_survives_restart() {
    let (_temp, root) = migration_root("cleanup-contract");
    let db = root.join("a.redb");
    let id = VmId::new_v4();
    {
        let store = Arc::new(crate::store::Store::open(&db).unwrap());
        let p = migrating_provisioner(&root, store, Arc::new(MigratingVmm::new(true)));
        p.cleanup_migration(&id, "cancelled", false).await.unwrap();
    }
    let store = Arc::new(crate::store::Store::open(&db).unwrap());
    let hv = Arc::new(MigratingVmm::new(true));
    let p = migrating_provisioner(&root, store.clone(), hv.clone());
    assert!(
        p.prepare_migration(
            id,
            migratable_spec(&store),
            "tcp:target:49000",
            true,
            "cancelled"
        )
        .await
        .is_err()
    );
    assert!(hv.said().is_empty());
    p.prepare_migration(id, migratable_spec(&store), "tcp:target:49000", true, "M2")
        .await
        .unwrap();
    let before = hv.said();
    assert!(p.cleanup_migration(&id, "M1", false).await.is_err());
    assert!(p.cleanup_migration(&id, "M2", true).await.is_err());
    assert_eq!(hv.said(), before);
    // The guest arrived, but the agent's phase has not caught up yet.
    hv.receiving
        .store(false, std::sync::atomic::Ordering::SeqCst);
    assert!(p.cleanup_migration(&id, "M2", false).await.is_err());
    assert_eq!(hv.said(), before);
    p.migration_arrived(&id).await.unwrap();
    let record = store.get(&id).unwrap().unwrap();
    let report = crate::reconcile::departure(&record).unwrap();
    assert_eq!(report.outcome, crate::reconcile::DepartureOutcome::Arrived);
    assert_eq!(report.migration_id, "M2");
    assert!(
        crate::reconcile::sync_orphans(&Default::default(), [(id, &record)]).is_empty(),
        "a reconnect before binding commits must not delete the arrived guest"
    );
}

#[test]
fn legacy_records_load_without_inventing_attempt_evidence() {
    let mut record = VmRecord::blank();
    record.operation = Some(crate::types::Operation::MigratingOut {
        peer: "tcp:target:49000".into(),
    });
    let mut json = serde_json::to_value(&record).unwrap();
    json.as_object_mut().unwrap().remove("migration");
    json.as_object_mut().unwrap().remove("unattached_volumes");
    let loaded: VmRecord = serde_json::from_value(json).unwrap();
    assert!(loaded.unattached_volumes.is_empty());
    assert!(crate::reconcile::departure(&loaded).is_none());
    assert_eq!(
        crate::reconcile::plan(
            &loaded,
            &sending_observation(),
            std::time::SystemTime::now()
        ),
        crate::reconcile::Action::Blocked
    );
}
