// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! The chain's second exit: a VM that arrives on this node.

use super::*;

/// A hypervisor that can migrate, and records which of the two ends it
/// was asked for. `create`/`start` are here too so that the SAME driver
/// serves both exits of `run_chain` — which is what the first test
/// compares.
#[derive(Default)]
struct MigratingVmm {
    log: std::sync::Mutex<Vec<String>>,
    /// What `migrate_out` answers. `false` = the send was refused, which
    /// is the case where the guest never leaves.
    can_send: bool,
    /// Whether `is_tracked` says the VMM is still there after a send.
    /// The source VMM exits on a successful send, and that is how the
    /// agent finds out it worked.
    still_here_after_send: std::sync::atomic::AtomicBool,
    /// What the event file of a receiving VMM would say. `Some` is
    /// `migration-receive-failed` and its reason; the VMM goes on
    /// answering, which is exactly what makes the case hard to see.
    receive_broke: std::sync::Mutex<Option<String>>,
    /// Whether this VMM was started to receive rather than to boot. v53
    /// has no VM in it until the stream builds one, so `vm.info` says
    /// `Created` — `Defined` here — for the whole of a reception.
    receiving: std::sync::atomic::AtomicBool,
    /// The VMM processes this fake is serving, by vm id — what a real
    /// driver discovers by walking its run directory and pinging each
    /// socket. A process outlives the RECORD of it, which is the whole
    /// subject of `strays`.
    live: std::sync::Mutex<std::collections::BTreeSet<VmId>>,
    /// Whether an accepted send lets the process go. v53 exits the source
    /// VMM only when the transfer TOOK; one that starts and then fails
    /// resumes the guest and goes on serving it, which is the case that
    /// used to hold this node's command path for ten minutes.
    send_leaves: bool,
    /// What `send_failed` answers: `Some` is the VMM serving its guest
    /// again, which after a send has started can only mean it failed.
    send_broke: std::sync::Mutex<Option<String>>,
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
        }
    }
    /// A hypervisor that ACCEPTS the send and then fails it, which is the
    /// only shape D-P4 has: 204 on the call, a worker that breaks, and a
    /// process that stays and serves.
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
        Ok(std::process::id())
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
        Ok(agent_api::hypervisor::VmState::Running)
    }
    async fn adopt(&self, _: &VmId, _: u32) -> agent_api::hypervisor::Result<()> {
        Ok(())
    }
    /// The api socket, which is what `migrate_out` waits on: v53 exits
    /// the source VMM when a send succeeds, and the socket going quiet is
    /// how that is knowable from the outside.
    async fn probe(&self, _: &VmId) -> bool {
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
    /// What the real driver reads off its run directory: the processes that
    /// are here, minus the ones somebody has a row for.
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
        // v53 shuts the guest down and the source VMM exits. This is that,
        // and `send_leaves` is the other case: a send that started and has
        // not ended yet.
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

/// A disk that is a path, which is what every live-migratable volume in
/// this tree is: the config that travels in the migration stream names
/// files, and a file is what both nodes have to be able to open.
#[derive(Default)]
struct PlainDisk {
    /// The volumes this node was told to LET GO of — record and per-node
    /// claim, bytes untouched. Recorded because the difference between this
    /// and `deprovision` is somebody's data, and a test that could not tell
    /// the two apart would be no test at all.
    forgotten: std::sync::Mutex<Vec<VolumeId>>,
    /// And the ones it was told to destroy, for the same reason from the
    /// other side.
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

/// A spec with one REFERENCED disk, which is the only shape a live
/// migration accepts — and the record for it, in the store the node
/// would already have.
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

/// The provisioner and a reconciler over the same store and the same
/// drivers — one node, both halves.
///
/// The give-back of a failed reception is a decision the RECONCILER makes,
/// so a test of it that only held a provisioner would be testing the wrong
/// object: the whole defect was that no pass ever looked.
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

/// A cgroup driver over an ordinary directory tree.
///
/// `CgroupV2` writes `memory.max` and `cpu.max` into the slice, which on a
/// real cgroupfs are files that were already there and on a temp directory
/// are files it just made — so its `destroy_slice`, which is a bare
/// `remove_dir`, cannot take the slice away again and the teardown ends
/// with a failure and keeps the record. Everything this test is about is
/// on the other side of that line, so the tree goes as a tree.
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

/// What a pass would see and decide, without doing it — the same view an
/// operator gets from the node's `observe` endpoint.
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

/// The same, with the disk handed in, for the one test that has to ask the
/// backend afterwards what it was told.
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

/// A directory of this test's own, and the guard that removes it again.
///
/// The guard comes back with the path and every caller binds it: it owns the
/// directory for as long as the binding lives, and a caller that dropped it
/// would be provisioning into a directory that is already gone.
fn migration_root(name: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let temp = tempfile::Builder::new()
        .prefix(&format!("meister-{name}-"))
        .tempdir()
        .expect("a temp dir");
    let root = temp.path().to_path_buf();
    (temp, root)
}

/// The same chain, twice, and the only difference is the last step.
///
/// This is the whole claim of the second exit: a vm that ARRIVES on a
/// node is built here exactly as one that boots here, right up to the
/// point where one calls `create` + `start` and the other calls
/// `migrate_in` — because the configuration of a migrating guest travels
/// inside the stream and names this node's things.
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
        .prepare_migration(arriving, recv_spec, "tcp:127.0.0.1:49000", true)
        .await
        .expect("the migration exit");
    // No create and no start: v53 refuses to receive into a vm that has
    // been created and builds the destination's from the stream.
    assert_eq!(recv_hv.said(), vec!["migrate_in tcp:127.0.0.1:49000"]);
    let record = recv_store.get(&arriving).expect("a record").expect("one");
    assert_eq!(record.phase, Phase::Receiving);
    assert!(record.vmm_pid.is_some(), "a vmm is listening");
    assert!(record.operation.is_none(), "the marker came off");

    // And the reconciler does nothing to either of the two migration
    // phases until the guest is actually here.
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

/// An inline disk is refused, by name, and nothing is built.
///
/// The refusal the first migration report asked for (D6): a disk written
/// straight into the vm's spec has no `Volume` object behind it and is
/// node-local by definition, so the config that would arrive in the
/// stream names a file this node would have to invent.
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
        .prepare_migration(id, with_disk, "tcp:127.0.0.1:49000", true)
        .await
        .expect_err("an inline disk does not migrate");
    let said = format!("{refused:#}");
    assert!(said.contains(&inline.to_string()), "{said}");
    assert!(said.contains("instance store"), "{said}");
    assert!(hv.said().is_empty(), "nothing was built: {:?}", hv.said());
    assert!(store.get(&id).expect("a lookup").is_none(), "no record");
}

/// The source gives the guest up only when the guest is gone — and the
/// record stays behind, because until the destination says it is Running
/// the source is the only description of it there is.
///
/// Both halves are now written down rather than answered: `begin_migrate_out`
/// opens the stream and returns, and `finish_migrate_out` records the outcome
/// on the record, where `departure` reads it into the heartbeat. That is D16
/// — the tier above no longer holds a reconcile pass open for the length of a
/// guest's memory — and it is why the failing half below is not an `Err` any
/// more but a sentence on `send_failed`.
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
    p.begin_migrate_out(&id, "tcp:10.0.0.9:49000", &ops)
        .await
        .expect("the stream is open");
    // Answering means the stream is open, and the marker is on the record
    // BEFORE the answer — a pass one millisecond later must not touch a vm
    // whose guest is being paused.
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

    p.finish_migrate_out(&id, "tcp:10.0.0.9:49000", std::time::Instant::now(), &ops)
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

    // The bad end, and it is the invariant: a send that did not happen
    // leaves the source exactly as it was.
    //
    // This is the half that is still SYNCHRONOUS after D16, and deliberately:
    // v53 refusing `vm.send-migration` outright is a fault in the request,
    // not an outcome of a transfer. Nothing has been done to the guest, the
    // answer costs a unix socket round trip, and the tier above should hear
    // it as a rejection rather than have to read it off a heartbeat.
    let store = Arc::new(crate::store::Store::open(&root.join("no.redb")).expect("a store"));
    let hv = Arc::new(MigratingVmm::new(false));
    let p = migrating_provisioner(&root, store.clone(), hv.clone());
    let id = VmId::new_v4();
    let running = migratable_spec(&store);
    p.provision(id, running, Desired::Running, true)
        .await
        .expect("a running vm");
    let refused = p
        .begin_migrate_out(&id, "tcp:10.0.0.9:49000", &tokio::sync::Mutex::new(()))
        .await
        .expect_err("the peer refused");
    assert!(
        format!("{refused:#}").contains("tcp:10.0.0.9:49000"),
        "the refusal names where it was going: {refused:#}"
    );
    let record = store.get(&id).expect("a lookup").expect("still a record");
    assert_eq!(record.phase, Phase::Provisioned, "the guest is still ours");
    assert!(record.vmm_pid.is_some());
    assert!(record.operation.is_none(), "the marker came off");
    assert!(
        crate::reconcile::departure(&record).is_none(),
        "and nothing is reported about a send that never started"
    );
}

/// The overlay's user count carries a migration by itself, and the reason
/// is that it is COUNTED off the records rather than kept.
///
/// A destination gets a record — with its NIC's vni on the spec — at
/// `PrepareMigration`, before there is a guest and before there is a tap,
/// so from that moment the wire has one more user. The source's record
/// goes when the cluster destroys it, and the wire has one fewer. Neither
/// end has to remember anything, and an agent that restarted in the
/// middle counts the same numbers afterwards.
///
/// The window that matters is the middle one: while both ends have a
/// record, neither can take the tenant's bridge down under the other.
#[test]
fn a_migration_carries_the_overlay_count_without_anybody_keeping_it() {
    let (_temp, root) = migration_root("mig-overlay");
    let store = crate::store::Store::open(&root.join("a.redb")).expect("a store");

    let vni = 10_042;
    let (source_id, mut source) = overlay_vm(vni);
    let (target_id, mut target) = overlay_vm(vni);
    // The same guest, arriving on the other machine. In a real migration
    // these are two agents with two stores; one store here is what lets
    // the counting rule be exercised at all, and the rule is per node.
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

    // The cluster destroys the source's record. Now the destination is
    // alone on the wire, which is what it was before the migration — one
    // machine, one user.
    store.delete(&source_id).expect("the source lets go");
    assert_eq!(overlay_users(&store, vni, &target_id).expect("a count"), 0);
}

/// FRR follows the guest without a line of migration code, because what
/// is announced is derived from the vms that are RUNNING here — and
/// neither end of a migration is running one until it is.
///
/// The destination announces nothing while it is only listening; the
/// source stops announcing the moment its guest has left; and the
/// announcement moves in the one direction that is safe if the two
/// overlap, because the destination only starts once the source has
/// already stopped.
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
    // Listening for a guest that is not here: nothing to announce, and
    // the sentence says which of the two machines to look at. The guest
    // and not the phase decides — a receiving record whose VMM says
    // Running IS running one, and the tier above reads this line to
    // decide what it may tear down.
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

    // Both in-flight states carry a sentence, because "in flight"
    // without one is the state an operator cannot act on.
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

/// D-P5 and D-P3, which are one defect: a reception that fails gives
/// everything back, and the next attempt therefore works.
///
/// What the lab found, on the first run of the invariant checker:
///
/// ```text
/// FAIL I1  vmm for 3d4a0f5b-… alive on ['agent-1a', 'agent-1b']
/// ```
///
/// Two cloud-hypervisor processes for one VM uid and two `live` NVMe/TCP
/// sessions to one 100-GiB block — the source running the guest, the
/// destination holding a VMM that had been told a guest was coming and
/// never learned that it was not. It survived every pass (the reconciler
/// read "still waiting"), it survived a restart (the marker was cleared
/// and the phase was not), and it survived `vm rm` (that reached the
/// source). Only `systemctl stop`, `pkill`, `nvme disconnect` and deleting
/// the database got rid of it.
///
/// The whole of the fix is that the reception has an end. The
/// hypervisor's own `migration-receive-failed` is one way to reach it and
/// the record's deadline is the other, and both arrive here as the same
/// observation.
#[tokio::test]
async fn a_reception_that_fails_gives_everything_back_and_the_next_one_works() {
    let (_temp, root) = migration_root("mig-abort");
    let store = Arc::new(crate::store::Store::open(&root.join("dest.redb")).expect("a store"));
    let hv = Arc::new(MigratingVmm::new(true));
    let (dest, reconciler) = migrating_node(&root, store.clone(), hv.clone());

    let id = VmId::new_v4();
    dest.prepare_migration(id, migratable_spec(&store), "tcp:127.0.0.1:49000", true)
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

    // And now the transfer dies. The VMM goes on answering — that is the
    // whole difficulty of the case — and the event file is the only place
    // that says the guest is not coming.
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
    // The volume it was holding is DETACHED and not deprovisioned: a
    // migration's disk belongs to a `Volume` object the source is still
    // using, and the destination giving back a connection must never be
    // the destination deleting somebody's data.
    let volumes = store.list_volumes().expect("the volume table");
    assert_eq!(volumes.len(), 1, "the volume object outlived the reception");
    assert_eq!(
        volumes[0].1.phase,
        crate::types::VolumeRecordPhase::Ready,
        "and it is untouched"
    );

    // D-P3: the same vm, the same node, a second time — and this is the
    // one that used to answer "this node already has a record of vm …; it
    // cannot receive it as well" until somebody restarted the agent.
    let again = Arc::new(MigratingVmm::new(true));
    let (dest, _) = migrating_node(&root, store.clone(), again.clone());
    dest.prepare_migration(id, migratable_spec(&store), "tcp:127.0.0.1:49001", true)
        .await
        .expect("the second attempt is an ordinary one");
    assert_eq!(
        store.get(&id).expect("a record").expect("one").phase,
        Phase::Receiving
    );
}

/// The other way a reception ends badly, and the only one no hypervisor
/// can report: nobody dials at all.
///
/// A source that is killed between `PrepareMigration` and `MigrateOut`, or
/// told to send to a port that does not answer, leaves the destination in
/// `accept` with an event file that says `migration-receive-ready` and
/// nothing more. The deadline is what turns that into an answer, and it is
/// on the RECORD rather than in the task that started the reception —
/// because the ghost of the lab outlived the process that made it.
#[tokio::test]
async fn a_source_that_never_comes_is_a_deadline_and_not_a_wait_forever() {
    let (_temp, root) = migration_root("mig-nobody");
    let store = Arc::new(crate::store::Store::open(&root.join("dest.redb")).expect("a store"));
    let hv = Arc::new(MigratingVmm::new(true));
    let (dest, reconciler) = migrating_node(&root, store.clone(), hv.clone());

    let id = VmId::new_v4();
    dest.prepare_migration(id, migratable_spec(&store), "tcp:127.0.0.1:49000", true)
        .await
        .expect("a listening vmm");

    // Before the deadline nothing happens, however many passes run: a
    // transfer may legitimately take longer than a pass, and a
    // destination that gave up first would tear down the VMM a guest is
    // arriving into.
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
        preview(&reconciler, &id).await.observed.receive_failed,
        "nothing came, and this node stops waiting"
    );
    assert_eq!(
        reconciler
            .reconcile(id, crate::reconcile::Trigger::Periodic)
            .await
            .expect("a pass"),
        crate::reconcile::Action::Teardown
    );
    assert!(store.get(&id).expect("a lookup").is_none());
}

/// D-P4: a send that cloud-hypervisor fails answers, and never holds this
/// node's command path while it waits.
///
/// What the lab saw was not a migration problem at all:
///
/// ```text
/// $ meister vm create plain-probe -f ...
/// status: {"phase":"Failed","message":"agent agent-1a did not answer within 60s"}
/// ```
///
/// EVERY command to agent-1a ran into the sixty-second timeout, while the
/// agent reconciled happily and `node ls` showed it `ready` with a five-
/// second heartbeat. That is the expensive kind of fault — the session looks
/// healthy — and the cause was one lock: the send held the operation mutex
/// that every other command needs, waiting ten minutes for a process that
/// had gone back to serving its guest and was never going to exit.
///
/// Two claims, and they are the two halves of the fix: the lock is free
/// while the transfer runs, and the transfer's failure is knowable before
/// the ceiling.
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
        .begin_migrate_out(&id, "tcp:10.0.0.9:49000", &ops)
        .await
        .expect("the stream is open, which is now the whole of the answer");
    let sending = tokio::spawn({
        let source = source.clone();
        let ops = ops.clone();
        async move {
            source
                .finish_migrate_out(&id, "tcp:10.0.0.9:49000", std::time::Instant::now(), &ops)
                .await
        }
    });

    // The send has started, and the guest's memory is going over a wire.
    // This is the whole window D-P4 lived in — and in it, every other
    // command on this node has to be servable.
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
    // And the record says who owns the vm meanwhile, which is the exclusion
    // that DOES belong to a migration: per vm, on the record, read by the
    // reconciler.
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

    // The news is on the record and therefore on the next heartbeat. It used
    // to be the error of a command the cluster was still awaiting, which is
    // what made that command's duration the pass's duration (D16).
    let line = crate::reconcile::departure(&record).expect("this node says so");
    assert_eq!(line.outcome, crate::reconcile::DepartureOutcome::StillHere);
    let said = line.message.expect("with a reason");
    assert!(said.contains("still running here"), "{said}");
    assert!(said.contains("was not given up"), "{said}");
    assert!(
        said.contains("cloud-hypervisor is serving the guest here again"),
        "and it is v53's own sentence, not a summary of one: {said}"
    );

    // The next command on this node is served, which is the sentence the
    // defect was reported as: `vm create` on agent-1a went Failed.
    assert!(ops.try_lock().is_ok(), "the lock outlived the send");
}

/// D16: the command answers while the guest's memory is still on the wire.
///
/// `MigrateOut` used to answer with the OUTCOME, and the cluster's reconcile
/// pass awaited it: 300 ms of pass time on a small guest, up to 45 s on a
/// large one, and for all of that no other VM in that cluster was placed or
/// repaired. An operation measured in a network's throughput has no business
/// being a command's answer.
///
/// Two claims, and together they are the fix. The answer comes back while the
/// transfer is still running — measured against a VMM that has neither exited
/// nor given the guest back, which is exactly "still sending". And the marker
/// is already on the record when it does, so a reconcile pass one millisecond
/// later does not touch a VM whose guest is being paused.
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
        p.begin_migrate_out(&id, "tcp:10.0.0.9:49000", &ops),
    )
    .await
    .expect("the answer did not wait for the transfer");
    accepted.expect("accepted");

    // The transfer has NOT ended: the VMM is still there and has said nothing
    // about failing. This is the whole of what the old answer was waiting for.
    use agent_api::Migratable as _;
    use agent_api::hypervisor::Hypervisor as _;
    assert!(hv.probe(&id).await, "the source vmm is still running");
    assert!(
        hv.send_failed(&id).await.is_none(),
        "and it has not given the guest back either"
    );

    // What the tier above sees meanwhile: a line that says a send is under
    // way, and the peer it is going to.
    let record = store.get(&id).expect("a lookup").expect("a record");
    let line = crate::reconcile::departure(&record).expect("a line");
    assert_eq!(line.outcome, crate::reconcile::DepartureOutcome::Sending);
    assert_eq!(line.peer, "tcp:10.0.0.9:49000");
    assert!(line.message.is_none());

    // And the exclusion that keeps a pass off this VM is on the record BEFORE
    // the answer, not after it: a guest is paused near the end of a transfer,
    // and a pass that saw a paused guest under a Running record would resume
    // it into a copy of itself.
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

/// D18, the shutdown half: a stopping agent gives back a VMM that is waiting
/// for a guest — and keeps the ones that are running one.
///
/// Running guests survive an agent restart, and that is not negotiable: a
/// record on disk, a pid in it, an adoption on the way back up. An agent that
/// killed its guests on SIGTERM would make `systemctl restart meister-agent`
/// an outage.
///
/// A RECEIVING VMM is the exception. It has no guest — it is a process
/// listening on a port for one — and it holds a cgroup, a set of taps and, on
/// a fabric, a live NVMe/TCP session to somebody's disk. Nothing will finish
/// that reception once this agent is gone: the task watching it dies with the
/// process, the cluster's migration times out, and what is left is the ghost
/// the lab found.
#[tokio::test]
async fn a_stopping_agent_gives_back_a_vmm_that_is_waiting_and_keeps_the_ones_serving() {
    let (_temp, root) = migration_root("mig-goodbye");
    let store = Arc::new(crate::store::Store::open(&root.join("a.redb")).expect("a store"));
    let hv = Arc::new(MigratingVmm::new(true));
    let p = migrating_provisioner(&root, store.clone(), hv.clone());

    // One guest running here, one VMM listening for a guest that is on its
    // way. The two are the whole of the decision.
    let serving = VmId::new_v4();
    p.provision(serving, migratable_spec(&store), Desired::Running, true)
        .await
        .expect("a running vm");
    let arriving = VmId::new_v4();
    p.prepare_migration(
        arriving,
        migratable_spec(&store),
        "tcp:127.0.0.1:49000",
        true,
    )
    .await
    .expect("a vmm that is listening");
    assert_eq!(
        store
            .get(&arriving)
            .expect("a lookup")
            .expect("a record")
            .phase,
        Phase::Receiving
    );

    // What the stop path selects, which is the whole of the decision: the
    // reception, and never the guest that is being served.
    let records = store.list().expect("the records");
    assert_eq!(
        crate::half_built(&records),
        vec![arriving],
        "a running guest is not something a stopping agent takes with it"
    );

    // And what it then does to it. The teardown is best effort — this test's
    // cgroup_root is an ordinary directory, which is D17 and exactly the
    // configuration the local E2E runs — so what is asserted is that the VMM
    // was asked to go, which is the part that matters: a process listening on
    // a port for a guest nobody will hand it.
    let _ = p.teardown(&arriving).await;
    assert!(
        hv.said().contains(&"destroy".to_string()),
        "the listening vmm was given back: {:?}",
        hv.said()
    );
    let kept = store
        .get(&serving)
        .expect("a lookup")
        .expect("the running guest is still this node's");
    assert_eq!(kept.phase, Phase::Provisioned);
    assert!(
        kept.vmm_pid.is_some(),
        "and its vmm is untouched: a restart is not an outage"
    );
}

/// D18, the start-up half: a VMM this node has no record of is named, and
/// ended once it has been unmanaged for long enough.
///
/// "The agent adopts what it has a record of" was only half a rule. A guest
/// whose record went while its process did not answers no command, appears in
/// no report, and holds its disks and its taps — and the first anybody hears
/// of it is a second guest dying on a write lock over the same volume.
///
/// The known set is every ROW, readable or not: a record this build cannot
/// deserialise is a VM this agent cannot manage, and killing its guest over
/// that would be the worst possible reading of a bad row.
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
    // A second guest whose record cannot be read. The row exists, so this vm
    // is somebody's — this build simply cannot say whose.
    let unreadable = VmId::new_v4();
    store
        .put_raw(&unreadable.to_string(), b"{\"not\":\"a record\"}")
        .expect("a raw row");
    p.provision(unreadable, migratable_spec(&store), Desired::Running, true)
        .await
        .expect("a second running vm");
    store
        .put_raw(&unreadable.to_string(), b"{\"not\":\"a record\"}")
        .expect("and its row is broken again");

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

    // Ended over the socket and not by a signal: there is no pid to check,
    // and the act at the end of a wrong answer would be a SIGKILL at a
    // stranger.
    hv.end_stray(&managed).await.expect("it goes");
    assert!(
        hv.said().iter().any(|l| l.contains("end_stray")),
        "the driver was asked, and by the narrow verb: {:?}",
        hv.said()
    );
}

/// D-P20: a reception that is given back gives the node-local note back too,
/// and never the bytes.
///
/// A guest that never arrived left this node holding a claim over a namespace
/// somebody else owns: `teardown` detaches a referenced volume and nothing
/// more, which is right for the DATA — the disk belongs to a guest that is
/// running elsewhere — and wrong for the note, which is per node and which
/// `detach` does not touch. agent-1b carried two of them after the lab run,
/// for volumes it never held.
///
/// `forget` is the narrow verb: everything this node holds ABOUT the volume
/// goes, everything the volume IS stays. For every backend but
/// `nvmeof-import` it does nothing at all.
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

/// And the ordinary teardown does NOT: a guest that really ran here has a
/// disk this node is still the home of.
///
/// The counter-proof to the one above, and the line the fix must not cross.
/// A `forget` here would take a live volume's record off the node that owns
/// it, and the cluster would then hear nothing at all about a disk it is
/// still using.
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
