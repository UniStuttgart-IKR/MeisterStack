// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Volume cgroup allowances, persisted ownership, hotplug order and detach accounting.

use super::*;

/// Storage backend processes need cgroup headroom; plain paths do not.
#[test]
fn a_volume_backend_widens_the_slice_and_a_plain_path_does_not() {
    let base = Provisioner::limits_for(&spec(2, 2048, vec![]));
    assert_eq!(base.memory_max, Some((2048 + 112) * 1024 * 1024));

    // Plain paths are not processes: byte for byte the old limits.
    assert!(
        widen_for_storage_backends(&base, &[volume(VolumeAttachment::Path("/a.raw".into()))])
            .is_none()
    );
    assert!(widen_for_storage_backends(&base, &[]).is_none());

    // A virtiofsd share is, and so is a vhost-user-blk backend.
    let widened = widen_for_storage_backends(
        &base,
        &[
            volume(VolumeAttachment::Path("/a.raw".into())),
            volume(VolumeAttachment::FsShare {
                socket: "/s".into(),
                tag: "share".into(),
                pid: 7,
            }),
        ],
    )
    .expect("a share is a backend process");
    assert_eq!(widened.memory_max, Some((2048 + 112 + 512) * 1024 * 1024));

    let two = widen_for_storage_backends(
        &base,
        &[
            volume(VolumeAttachment::FsShare {
                socket: "/s".into(),
                tag: "share".into(),
                pid: 7,
            }),
            volume(VolumeAttachment::VhostUserBlk {
                socket: "/b".into(),
                pid: 8,
            }),
        ],
    )
    .expect("two backends");
    assert_eq!(two.memory_max, Some((2048 + 112 + 1024) * 1024 * 1024));
}

/// The pinning is the agent's, not the VM's, and the widening must not
/// quietly drop it: it goes back through `create_slice`, which writes the
/// parent's cpuset from exactly this field.
#[test]
fn widening_keeps_every_limit_it_is_not_about() {
    let mut base = Provisioner::limits_for(&spec(4, 1024, vec![]));
    base.cpuset = Some("0-7".into());
    let widened = widen_for_storage_backends(
        &base,
        &[volume(VolumeAttachment::VhostUserBlk {
            socket: "/b".into(),
            pid: 3,
        })],
    )
    .expect("one backend");
    assert_eq!(widened.cpuset.as_deref(), Some("0-7"));
    assert_eq!(widened.cpu_quota, base.cpu_quota);
}

/// Resolve a referenced volume without provisioning. The fake counts calls that a
/// filesystem backend's idempotence could otherwise hide.
#[tokio::test]
async fn a_referenced_volume_is_attached_and_never_provisioned() {
    use agent_api::storage::{
        StorageError, VolumeAttachment, VolumeDriver, VolumeHandle, VolumeState,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct Counting {
        provisions: AtomicUsize,
        attaches: AtomicUsize,
        detaches: AtomicUsize,
        deprovisions: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl agent_api::storage::VolumeProvider for Counting {
        fn locality(&self) -> agent_api::storage::Locality {
            agent_api::storage::Locality::NodeLocal
        }
        async fn provision(
            &self,
            id: &VolumeId,
            spec: &agent_api::storage::VolumeSpec,
        ) -> agent_api::storage::Result<VolumeHandle> {
            self.provisions.fetch_add(1, Ordering::SeqCst);
            Ok(VolumeHandle {
                id: *id,
                backend: format!("/fake/{id}.raw"),
                size_bytes: spec.size_bytes,
                params: spec.params.clone(),
            })
        }
        async fn deprovision(&self, _: &VolumeHandle) -> agent_api::storage::Result<()> {
            self.deprovisions.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn describe(&self, h: &VolumeHandle) -> agent_api::storage::Result<VolumeState> {
            Ok(VolumeState {
                size_bytes: h.size_bytes,
            })
        }
        /// A fake that keeps no bytes holds none under any id.
        async fn probe(
            &self,
            _: &VolumeId,
            _: &agent_api::storage::VolumeSpec,
        ) -> agent_api::storage::Result<Option<VolumeHandle>> {
            Ok(None)
        }
    }

    #[async_trait::async_trait]
    impl agent_api::storage::VolumeAttacher for Counting {
        async fn attach(
            &self,
            handle: &VolumeHandle,
            _: Option<&agent_api::CgroupHandle>,
        ) -> agent_api::storage::Result<VolumeAttachment> {
            self.attaches.fetch_add(1, Ordering::SeqCst);
            Ok(VolumeAttachment::Path(handle.path()))
        }
        async fn detach(
            &self,
            _: &VolumeHandle,
            _: &VolumeAttachment,
        ) -> agent_api::storage::Result<()> {
            self.detaches.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn stat(
            &self,
            h: &VolumeHandle,
            _: &VolumeAttachment,
        ) -> agent_api::storage::Result<VolumeState> {
            let _ = h;
            Err(StorageError::NotFound(h.id))
        }
    }

    let temp = tempfile::tempdir().expect("a temp dir");
    let root = temp.path().to_path_buf();
    let store = Arc::new(crate::store::Store::open(&root.join("a.redb")).expect("a store"));
    let counting = Arc::new(Counting::default());
    let mut storage: std::collections::HashMap<String, Arc<dyn VolumeDriver>> =
        std::collections::HashMap::new();
    storage.insert("filesystem".to_string(), counting.clone());

    // A volume this node already owns, exactly as position 2 leaves one.
    let volume_id = VolumeId::new_v4();
    let handle = VolumeHandle {
        id: volume_id,
        backend: format!("/fake/{volume_id}.raw"),
        size_bytes: 4096,
        params: None,
    };
    store
        .put_volume(
            &volume_id,
            &crate::types::VolumeRecord {
                spec: agent_api::storage::VolumeSpec {
                    base_image: None,
                    size_bytes: 4096,
                    driver: Some("filesystem".into()),
                    params: None,
                },
                handle: Some(handle.clone()),
                phase: crate::types::VolumeRecordPhase::Ready,
                reason: None,
                message: None,
                gone_at: None,
            },
        )
        .expect("a volume record");

    let provisioner = Provisioner::new(
        store.clone(),
        Drivers {
            confiner: Arc::new(cgroup_driver::CgroupV2::new(root.join("cgroup"))),
            hypervisor: None,
            hypervisor_name: None,
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
    );

    // Resolve references without provisioning new data.
    let (driver, resolved) = provisioner.reference(&volume_id, None).expect("resolved");
    assert_eq!(driver, "filesystem");
    assert_eq!(resolved.backend, handle.backend);
    assert_eq!(counting.provisions.load(Ordering::SeqCst), 0);

    // Attach options travel with the VM and override what the volume was
    // made with; a reference that names none leaves it alone.
    let (_, tagged) = provisioner
        .reference(&volume_id, Some(serde_json::json!({"tag": "data"})))
        .expect("resolved");
    assert_eq!(tagged.params.unwrap()["tag"], "data");

    // Missing referenced volumes fail instead of creating replacement disks.
    let err = provisioner
        .reference(&VolumeId::new_v4(), None)
        .expect_err("no record here");
    assert!(
        format!("{err:#}").contains("no record of volume"),
        "{err:#}"
    );
    assert_eq!(counting.provisions.load(Ordering::SeqCst), 0);
}

/// Attach before add-disk; confirm guest unplug before backend detach.
/// Referenced-volume changes must never provision or delete their data.
#[tokio::test]
async fn a_hot_plug_attaches_before_it_tells_the_guest_and_detaches_after() {
    use agent_api::hypervisor::{ConsoleStream, InstanceSpec, VmState};
    use agent_api::storage::{
        StorageError, VolumeAttachment, VolumeDriver, VolumeHandle, VolumeState,
    };
    use std::sync::Mutex as StdMutex;

    /// Every call both fakes take, in the order they took it.
    type Log = Arc<StdMutex<Vec<String>>>;

    struct Storage(Log);

    #[async_trait::async_trait]
    impl agent_api::storage::VolumeProvider for Storage {
        fn locality(&self) -> agent_api::storage::Locality {
            agent_api::storage::Locality::NodeLocal
        }
        async fn provision(
            &self,
            id: &VolumeId,
            spec: &agent_api::storage::VolumeSpec,
        ) -> agent_api::storage::Result<VolumeHandle> {
            self.0.lock().unwrap().push(format!("provision {id}"));
            Ok(VolumeHandle {
                id: *id,
                backend: format!("/fake/{id}.raw"),
                size_bytes: spec.size_bytes,
                params: None,
            })
        }
        async fn deprovision(&self, h: &VolumeHandle) -> agent_api::storage::Result<()> {
            self.0.lock().unwrap().push(format!("deprovision {}", h.id));
            Ok(())
        }
        async fn describe(&self, h: &VolumeHandle) -> agent_api::storage::Result<VolumeState> {
            Ok(VolumeState {
                size_bytes: h.size_bytes,
            })
        }
        /// A fake that keeps no bytes holds none under any id.
        async fn probe(
            &self,
            _: &VolumeId,
            _: &agent_api::storage::VolumeSpec,
        ) -> agent_api::storage::Result<Option<VolumeHandle>> {
            Ok(None)
        }
    }

    #[async_trait::async_trait]
    impl agent_api::storage::VolumeAttacher for Storage {
        async fn attach(
            &self,
            handle: &VolumeHandle,
            _: Option<&agent_api::CgroupHandle>,
        ) -> agent_api::storage::Result<VolumeAttachment> {
            self.0.lock().unwrap().push(format!("attach {}", handle.id));
            Ok(VolumeAttachment::Path(handle.path()))
        }
        async fn detach(
            &self,
            handle: &VolumeHandle,
            _: &VolumeAttachment,
        ) -> agent_api::storage::Result<()> {
            self.0.lock().unwrap().push(format!("detach {}", handle.id));
            Ok(())
        }
        async fn stat(
            &self,
            h: &VolumeHandle,
            _: &VolumeAttachment,
        ) -> agent_api::storage::Result<VolumeState> {
            Err(StorageError::NotFound(h.id))
        }
    }

    /// Fake running hypervisor with disk hotplug. The flag simulates a guest
    /// that never completes unplug, causing removal to fail.
    struct Vmm(Log, Arc<std::sync::atomic::AtomicBool>);

    #[async_trait::async_trait]
    impl agent_api::Hypervisor for Vmm {
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
            Ok(VmState::Running)
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
        fn as_hotpluggable(&self) -> Option<&dyn agent_api::HotPluggable> {
            Some(self)
        }
    }

    #[async_trait::async_trait]
    impl agent_api::HotPluggable for Vmm {
        async fn add_disk(
            &self,
            _: &VmId,
            volume: &agent_api::AttachedVolume,
        ) -> agent_api::hypervisor::Result<()> {
            self.0
                .lock()
                .unwrap()
                .push(format!("add-disk {}", volume.disk_id()));
            Ok(())
        }
        async fn resize_disk(
            &self,
            _: &VmId,
            disk_id: &str,
            size_bytes: u64,
        ) -> agent_api::hypervisor::Result<()> {
            self.0
                .lock()
                .unwrap()
                .push(format!("resize-disk {disk_id} {size_bytes}"));
            Ok(())
        }
        async fn remove_disk(&self, _: &VmId, disk_id: &str) -> agent_api::hypervisor::Result<()> {
            self.0
                .lock()
                .unwrap()
                .push(format!("remove-device {disk_id}"));
            match self.1.load(std::sync::atomic::Ordering::Relaxed) {
                false => Ok(()),
                true => Err(agent_api::HypervisorError::Backend(anyhow!(
                    "the guest has not let go of {disk_id}: the vmm still has it open"
                ))),
            }
        }
    }

    let temp = tempfile::tempdir().expect("a temp dir");
    let root = temp.path().to_path_buf();
    let store = Arc::new(crate::store::Store::open(&root.join("a.redb")).expect("a store"));
    let log: Log = Arc::new(StdMutex::new(Vec::new()));
    let deaf_guest = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Prepare boot, currently attached and replacement volume records.
    let mut ids = Vec::new();
    for _ in 0..3 {
        let id = VolumeId::new_v4();
        let handle = VolumeHandle {
            id,
            backend: format!("/fake/{id}.raw"),
            size_bytes: 4096,
            params: None,
        };
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
                    handle: Some(handle),
                    phase: crate::types::VolumeRecordPhase::Ready,
                    reason: None,
                    message: None,
                    gone_at: None,
                },
            )
            .expect("a volume record");
        ids.push(id);
    }
    let (boot, going, arriving) = (ids[0], ids[1], ids[2]);

    let mut storage: std::collections::HashMap<String, Arc<dyn VolumeDriver>> =
        std::collections::HashMap::new();
    storage.insert("filesystem".to_string(), Arc::new(Storage(log.clone())));
    let provisioner = Provisioner::new(
        store.clone(),
        Drivers {
            confiner: Arc::new(cgroup_driver::CgroupV2::new(root.join("cgroup"))),
            hypervisor: Some(Arc::new(Vmm(log.clone(), deaf_guest.clone()))),
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
    );

    let referenced = |id: VolumeId| crate::types::VolumeWithId {
        id,
        spec: agent_api::storage::VolumeSpec {
            base_image: None,
            size_bytes: 4096,
            driver: Some("filesystem".into()),
            params: None,
        },
        referenced: true,
    };
    let with = |volumes: Vec<VolumeId>| {
        let mut s = spec(1, 256, vec![]);
        s.volumes = volumes.into_iter().map(referenced).collect();
        s
    };

    let vm = VmId::new_v4();
    let mut record = crate::types::VmRecord {
        spec: with(vec![boot, going]),
        desired: Desired::Running,
        phase: crate::types::Phase::Provisioned,
        operation: None,
        stop_deadline: None,
        receive_deadline: None,
        send_failed: None,
        migration: None,
        unhealthy: None,
        managed_by_controller: true,
        unattached_volumes: Vec::new(),
        volumes: vec![boot, going]
            .into_iter()
            .map(|id| {
                Volume::attached(
                    VolumeHandle {
                        id,
                        backend: format!("/fake/{id}.raw"),
                        size_bytes: 4096,
                        params: None,
                    },
                    VolumeAttachment::Path(format!("/fake/{id}.raw").into()),
                )
            })
            .collect(),
        nics: vec![],
        devices: vec![],
        vmm_pid: Some(1),
        overlay_bridges: Default::default(),
    };

    // The edit: `going` leaves, `arriving` comes.
    provisioner
        .apply_volume_diff(&vm, &mut record, &with(vec![boot, arriving]))
        .await
        .expect("the diff applies");

    let calls = log.lock().unwrap().clone();
    assert_eq!(
        calls,
        vec![
            format!("remove-device {}", agent_api::disk_id(&going)),
            format!("detach {going}"),
            format!("attach {arriving}"),
            format!("add-disk {}", agent_api::disk_id(&arriving)),
        ],
        "the guest is told before the attachment goes, and after it comes"
    );

    // The record is what it holds, and the spec is what it was asked for.
    let held: Vec<VolumeId> = record.volumes.iter().map(|v| v.id()).collect();
    assert_eq!(held, vec![boot, arriving]);
    assert_eq!(
        record.spec.volumes.iter().map(|v| v.id).collect::<Vec<_>>(),
        vec![boot, arriving]
    );
    // Changing referenced attachments must not provision or delete their data.
    assert!(!calls.iter().any(|c| c.starts_with("deprovision")));
    assert!(!calls.iter().any(|c| c.starts_with("provision")));

    // The record has to be readable for the resize below: it addresses a
    // VM by id, the way a command from the controller does.
    store.put(&vm, &record).expect("stored");

    // Notify resize by stable disk ID after detach changes attachment ordering.
    log.lock().unwrap().clear();
    provisioner
        .resize_attachment(&vm, &arriving, 2 << 30)
        .await
        .expect("the guest is told");
    assert_eq!(
        *log.lock().unwrap(),
        vec![format!(
            "resize-disk {} {}",
            agent_api::disk_id(&arriving),
            2u64 << 30
        )]
    );
    // Refuse resize notification for a disk no longer attached to this VM.
    let err = provisioner
        .resize_attachment(&vm, &going, 2 << 30)
        .await
        .expect_err("not attached here any more");
    assert!(
        format!("{err:#}").contains("does not have volume"),
        "{err:#}"
    );

    // Reapplying an unchanged volume list makes no driver calls.
    log.lock().unwrap().clear();
    provisioner
        .apply_volume_diff(&vm, &mut record, &with(vec![boot, arriving]))
        .await
        .expect("idempotent");
    assert!(log.lock().unwrap().is_empty(), "nothing drifted");

    // Failed guest unplug stops before backend detach and retains the attachment.
    deaf_guest.store(true, std::sync::atomic::Ordering::Relaxed);
    log.lock().unwrap().clear();
    let refused = provisioner
        .apply_volume_diff(&vm, &mut record, &with(vec![boot]))
        .await
        .expect_err("the guest kept the disk");
    assert!(
        format!("{refused:#}").contains("unplugging volume"),
        "the failure says which half did not happen: {refused:#}"
    );
    let calls = log.lock().unwrap().clone();
    assert_eq!(
        calls,
        vec![format!("remove-device {}", agent_api::disk_id(&arriving))],
        "the attacher was never asked to let go"
    );
    assert_eq!(
        record.volumes.iter().map(|v| v.id()).collect::<Vec<_>>(),
        vec![boot, arriving],
        "and the record still holds what the vmm still holds"
    );
    deaf_guest.store(false, std::sync::atomic::Ordering::Relaxed);
}

/// The agent diff excludes the boot position and inline disks.
/// Validation of an attempted boot-disk replacement belongs to the API boundary.
#[test]
fn the_diff_never_touches_the_boot_entry_or_an_inline_disk() {
    let entry = |referenced: bool| {
        let id = VolumeId::new_v4();
        (
            id,
            crate::types::VolumeWithId {
                id,
                spec: agent_api::storage::VolumeSpec {
                    base_image: None,
                    size_bytes: 4096,
                    driver: None,
                    params: None,
                },
                referenced,
            },
        )
    };
    let (_, boot) = entry(true);
    let (_, other_boot) = entry(true);
    let (_, inline) = entry(false);
    let (data_id, data) = entry(true);
    let with = |volumes: Vec<crate::types::VolumeWithId>| {
        let mut s = spec(1, 256, vec![]);
        s.volumes = volumes;
        s
    };

    // The diff excludes index zero; API validation must reject boot-disk replacement.
    let (attach, detach) = volume_diff(&with(vec![boot.clone()]), &with(vec![other_boot.clone()]));
    assert!(attach.is_empty() && detach.is_empty());

    // An inline disk that vanished from the spec is not detached either.
    let (attach, detach) = volume_diff(
        &with(vec![boot.clone(), inline.clone()]),
        &with(vec![boot.clone()]),
    );
    assert!(attach.is_empty() && detach.is_empty());

    // Adding a secondary reference requires attachment.
    let (attach, detach) = volume_diff(
        &with(vec![boot.clone(), inline.clone()]),
        &with(vec![boot, inline, data]),
    );
    assert_eq!(
        attach.iter().map(|v| v.id).collect::<Vec<_>>(),
        vec![data_id]
    );
    assert!(detach.is_empty());
}

/// Count driver operations to detect duplicate detach and cleanup calls.
#[derive(Default)]
struct CountingVolume {
    probe_has_bytes: std::sync::atomic::AtomicBool,
    fail_probe: std::sync::atomic::AtomicBool,
    fail_attach: std::sync::atomic::AtomicBool,
    fail_deprovision: std::sync::atomic::AtomicBool,
    provisions: std::sync::atomic::AtomicUsize,
    detaches: std::sync::atomic::AtomicUsize,
    deprovisions: std::sync::atomic::AtomicUsize,
}

#[async_trait::async_trait]
impl agent_api::storage::VolumeProvider for CountingVolume {
    fn locality(&self) -> agent_api::storage::Locality {
        agent_api::storage::Locality::NodeLocal
    }
    async fn provision(
        &self,
        id: &VolumeId,
        spec: &agent_api::storage::VolumeSpec,
    ) -> agent_api::storage::Result<agent_api::storage::VolumeHandle> {
        self.provisions
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(agent_api::storage::VolumeHandle {
            id: *id,
            backend: format!("/fake/{id}.raw"),
            size_bytes: spec.size_bytes,
            params: None,
        })
    }
    async fn deprovision(
        &self,
        _: &agent_api::storage::VolumeHandle,
    ) -> agent_api::storage::Result<()> {
        self.deprovisions
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self
            .fail_deprovision
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(agent_api::storage::StorageError::Backend(anyhow!(
                "injected delete error"
            )));
        }
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
    async fn probe(
        &self,
        id: &VolumeId,
        spec: &agent_api::storage::VolumeSpec,
    ) -> agent_api::storage::Result<Option<agent_api::storage::VolumeHandle>> {
        use std::sync::atomic::Ordering::SeqCst;
        if self.fail_probe.load(SeqCst) {
            return Err(agent_api::storage::StorageError::Backend(anyhow!(
                "injected probe error"
            )));
        }
        Ok(self
            .probe_has_bytes
            .load(SeqCst)
            .then(|| agent_api::storage::VolumeHandle {
                id: *id,
                backend: format!("/fake/{id}.raw"),
                size_bytes: spec.size_bytes,
                params: None,
            }))
    }
}

#[async_trait::async_trait]
impl agent_api::storage::VolumeAttacher for CountingVolume {
    async fn attach(
        &self,
        handle: &agent_api::storage::VolumeHandle,
        _: Option<&agent_api::CgroupHandle>,
    ) -> agent_api::storage::Result<VolumeAttachment> {
        if self.fail_attach.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(agent_api::storage::StorageError::Backend(anyhow!(
                "injected attach error"
            )));
        }
        Ok(VolumeAttachment::FsShare {
            socket: PathBuf::from(format!("/run/fake/{}.sock", handle.id)),
            tag: "data".into(),
            pid: 4242,
        })
    }
    async fn detach(
        &self,
        _: &agent_api::storage::VolumeHandle,
        _: &VolumeAttachment,
    ) -> agent_api::storage::Result<()> {
        self.detaches
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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

/// Persist completed detaches so teardown after a restart does not reuse stale backend PIDs.
#[tokio::test]
async fn a_stop_and_then_a_destroy_detach_the_volume_once() {
    let temp = tempfile::tempdir().expect("a temp dir");
    let root = temp.path().to_path_buf();
    let db = root.join("agent.redb");

    let counting = Arc::new(CountingVolume::default());
    let mut storage: HashMap<String, Arc<dyn agent_api::storage::VolumeDriver>> = HashMap::new();
    storage.insert("filesystem".to_string(), counting.clone());
    let build = |store: Arc<crate::store::Store>| {
        Provisioner::new(
            store,
            Drivers {
                confiner: Arc::new(cgroup_driver::CgroupV2::new(root.join("cgroup"))),
                hypervisor: Some(Arc::new(EmptyHypervisor)),
                hypervisor_name: Some("empty".into()),
                storage: storage.clone(),
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
        )
    };

    let vm = VmId::new_v4();
    let volume_id = VolumeId::new_v4();
    let handle = agent_api::storage::VolumeHandle {
        id: volume_id,
        backend: format!("/fake/{volume_id}.raw"),
        size_bytes: 4096,
        params: None,
    };
    // An inline disk: made with this VM, so the teardown deprovisions it
    // and the count of that is the control value.
    let mut vm_spec = spec(1, 256, vec![]);
    vm_spec.volumes = vec![crate::types::VolumeWithId {
        id: volume_id,
        spec: agent_api::storage::VolumeSpec {
            base_image: None,
            size_bytes: 4096,
            driver: Some("filesystem".into()),
            params: None,
        },
        referenced: false,
    }];
    let record = VmRecord {
        spec: vm_spec,
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
        volumes: vec![Volume::attached(
            handle,
            VolumeAttachment::FsShare {
                socket: PathBuf::from(format!("/run/fake/{volume_id}.sock")),
                tag: "data".into(),
                pid: 4242,
            },
        )],
        nics: Vec::new(),
        devices: Vec::new(),
        vmm_pid: None,
        overlay_bridges: Default::default(),
    };

    {
        let store = Arc::new(crate::store::Store::open(&db).expect("a store"));
        store.put(&vm, &record).expect("a record");
        build(store)
            .stop(&vm, record.clone())
            .await
            .expect("the vm stops");
    }
    assert_eq!(
        counting.detaches.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the stop gave the connection back"
    );

    // Reopen the store to model a restart with an empty driver process map.
    {
        let store = Arc::new(crate::store::Store::open(&db).expect("the store, reopened"));
        let held = store.get(&vm).expect("a read").expect("still there");
        assert!(
            held.volumes[0].detached,
            "the stop wrote down that it detached"
        );
        build(store).teardown(&vm).await.expect("the vm goes");
    }

    assert_eq!(
        counting.detaches.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "and the destroy after it did not detach a second time"
    );
    assert_eq!(
        counting
            .deprovisions
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the inline disk still went with the vm"
    );
}

/// Failed detach is not committed as closed and must be retried during teardown.
#[tokio::test]
async fn a_failed_detach_is_not_marked_and_is_tried_again() {
    #[derive(Default)]
    struct Refusing {
        attempts: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl agent_api::storage::VolumeProvider for Refusing {
        fn locality(&self) -> agent_api::storage::Locality {
            agent_api::storage::Locality::NodeLocal
        }
        async fn provision(
            &self,
            id: &VolumeId,
            _: &agent_api::storage::VolumeSpec,
        ) -> agent_api::storage::Result<agent_api::storage::VolumeHandle> {
            Ok(agent_api::storage::VolumeHandle {
                id: *id,
                backend: String::new(),
                size_bytes: 0,
                params: None,
            })
        }
        async fn deprovision(
            &self,
            _: &agent_api::storage::VolumeHandle,
        ) -> agent_api::storage::Result<()> {
            Ok(())
        }
        async fn describe(
            &self,
            _: &agent_api::storage::VolumeHandle,
        ) -> agent_api::storage::Result<agent_api::storage::VolumeState> {
            Ok(agent_api::storage::VolumeState { size_bytes: 0 })
        }
        /// A fake that keeps no bytes holds none under any id.
        async fn probe(
            &self,
            _: &VolumeId,
            _: &agent_api::storage::VolumeSpec,
        ) -> agent_api::storage::Result<Option<agent_api::storage::VolumeHandle>> {
            Ok(None)
        }
    }

    #[async_trait::async_trait]
    impl agent_api::storage::VolumeAttacher for Refusing {
        async fn attach(
            &self,
            _: &agent_api::storage::VolumeHandle,
            _: Option<&agent_api::CgroupHandle>,
        ) -> agent_api::storage::Result<VolumeAttachment> {
            Ok(VolumeAttachment::Path(PathBuf::from("/fake")))
        }
        async fn detach(
            &self,
            h: &agent_api::storage::VolumeHandle,
            _: &VolumeAttachment,
        ) -> agent_api::storage::Result<()> {
            self.attempts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(agent_api::storage::StorageError::Backend(anyhow!(
                "the backend will not let go of {}",
                h.id
            )))
        }
        async fn stat(
            &self,
            _: &agent_api::storage::VolumeHandle,
            _: &VolumeAttachment,
        ) -> agent_api::storage::Result<agent_api::storage::VolumeState> {
            Ok(agent_api::storage::VolumeState { size_bytes: 0 })
        }
    }

    let temp = tempfile::tempdir().expect("a temp dir");
    let root = temp.path().to_path_buf();
    let store = Arc::new(crate::store::Store::open(&root.join("a.redb")).expect("a store"));

    let refusing = Arc::new(Refusing::default());
    let mut storage: HashMap<String, Arc<dyn agent_api::storage::VolumeDriver>> = HashMap::new();
    storage.insert("filesystem".to_string(), refusing.clone());
    let provisioner = Provisioner::new(
        store.clone(),
        Drivers {
            confiner: Arc::new(cgroup_driver::CgroupV2::new(root.join("cgroup"))),
            hypervisor: Some(Arc::new(EmptyHypervisor)),
            hypervisor_name: Some("empty".into()),
            storage,
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

    let vm = VmId::new_v4();
    let volume_id = VolumeId::new_v4();
    let mut vm_spec = spec(1, 256, vec![]);
    vm_spec.volumes = vec![crate::types::VolumeWithId {
        id: volume_id,
        spec: agent_api::storage::VolumeSpec {
            base_image: None,
            size_bytes: 4096,
            driver: Some("filesystem".into()),
            params: None,
        },
        referenced: false,
    }];
    let record = VmRecord {
        spec: vm_spec,
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
        volumes: vec![Volume::attached(
            agent_api::storage::VolumeHandle {
                id: volume_id,
                backend: String::new(),
                size_bytes: 4096,
                params: None,
            },
            VolumeAttachment::Path(PathBuf::from("/fake")),
        )],
        nics: Vec::new(),
        devices: Vec::new(),
        vmm_pid: None,
        overlay_bridges: Default::default(),
    };
    store.put(&vm, &record).expect("a record");

    provisioner
        .stop(&vm, record)
        .await
        .expect("a stop reports its trouble in the log, not as an error");
    assert!(
        !store.get(&vm).expect("a read").expect("there").volumes[0].detached,
        "a detach that failed is not a detach"
    );
    let _ = provisioner.teardown(&vm).await;
    assert_eq!(
        refusing.attempts.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "so the teardown asked again"
    );
}

#[tokio::test]
async fn an_inline_attach_failure_remains_reclaimable_after_restart() {
    use std::sync::atomic::Ordering::SeqCst;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let db = root.join("agent.redb");
    let driver = Arc::new(CountingVolume::default());
    driver.fail_attach.store(true, SeqCst);
    driver.fail_deprovision.store(true, SeqCst);
    let build = |store| disk_provisioner(root, store, driver.clone());
    let vm = VmId::new_v4();
    let disk = VolumeId::new_v4();
    {
        let store = Arc::new(crate::store::Store::open(&db).unwrap());
        let provisioner = build(store.clone());
        let mut record = inline_record(disk);
        store.put(&vm, &record).unwrap();
        let spec = record.spec.clone();
        let cgroup = provisioner.drivers.confiner.open_slice(&vm.to_string());
        provisioner
            .attach_volumes(&vm, &mut record, &spec, &cgroup)
            .await
            .expect_err("attach failed");
        assert!(record.volumes.is_empty());
        // This is the error path in provision: preserve the latest record, then teardown.
        store.put(&vm, &record).unwrap();
    }
    {
        let store = Arc::new(crate::store::Store::open(&db).unwrap());
        build(store.clone())
            .teardown(&vm)
            .await
            .expect_err("failed deletion must retain its handle");
        assert!(store.get(&vm).unwrap().is_some());
        assert_eq!(driver.deprovisions.load(SeqCst), 1);
    }
    driver.fail_deprovision.store(false, SeqCst);
    {
        let store = Arc::new(crate::store::Store::open(&db).unwrap());
        build(store.clone()).teardown(&vm).await.unwrap();
        assert!(store.get(&vm).unwrap().is_none());
    }
    assert_eq!(driver.provisions.load(SeqCst), 1);
    assert_eq!(driver.deprovisions.load(SeqCst), 2);
    assert_eq!(
        driver.detaches.load(SeqCst),
        0,
        "no attachment was returned"
    );
}

/// A provisioner over `driver` as the node's `filesystem` backend, with a hypervisor that
/// tracks no VMM, so that every volume change is one for the next start.
fn disk_provisioner(
    root: &std::path::Path,
    store: Arc<crate::store::Store>,
    driver: Arc<dyn agent_api::storage::VolumeDriver>,
) -> Provisioner {
    let mut storage: HashMap<String, Arc<dyn agent_api::storage::VolumeDriver>> = HashMap::new();
    storage.insert("filesystem".into(), driver);
    Provisioner::new(
        store,
        Drivers {
            confiner: Arc::new(cgroup_driver::CgroupV2::new(root.join("cgroup"))),
            hypervisor: Some(Arc::new(EmptyHypervisor)),
            hypervisor_name: Some("empty".into()),
            storage,
            networking: None,
            bridge: None,
            announcer: None,
            devices: HashMap::new(),
        },
        Arc::new(crate::images::Cache::new(root.join("images"))),
        root.join("images"),
        root.join("run"),
        "br0".into(),
        None,
        None,
    )
}

fn inline_record(disk: VolumeId) -> VmRecord {
    let mut record = spec_record();
    record.spec.volumes.push(crate::types::VolumeWithId {
        id: disk,
        spec: agent_api::storage::VolumeSpec {
            base_image: None,
            size_bytes: 4096,
            driver: Some("filesystem".into()),
            params: None,
        },
        referenced: false,
    });
    record
}

#[tokio::test]
async fn a_crash_before_inline_handle_commit_is_recovered_by_probe() {
    use std::sync::atomic::Ordering::SeqCst;
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("agent.redb");
    let vm = VmId::new_v4();
    let disk = VolumeId::new_v4();
    let driver = Arc::new(CountingVolume::default());
    driver.probe_has_bytes.store(true, SeqCst);
    driver.fail_probe.store(true, SeqCst);
    driver.fail_deprovision.store(true, SeqCst);
    {
        let store = crate::store::Store::open(&db).unwrap();
        store.put(&vm, &inline_record(disk)).unwrap();
    }
    for probe_fails in [true, false] {
        driver.fail_probe.store(probe_fails, SeqCst);
        let store = Arc::new(crate::store::Store::open(&db).unwrap());
        let provisioner = disk_provisioner(temp.path(), store.clone(), driver.clone());
        provisioner
            .teardown(&vm)
            .await
            .expect_err("uncertain cleanup retains ownership");
        let record = store.get(&vm).unwrap().unwrap();
        assert_eq!(record.unattached_volumes.len(), usize::from(!probe_fails));
        assert_eq!(driver.deprovisions.load(SeqCst), usize::from(!probe_fails));
    }
    driver.fail_deprovision.store(false, SeqCst);
    {
        let store = Arc::new(crate::store::Store::open(&db).unwrap());
        disk_provisioner(temp.path(), store.clone(), driver.clone())
            .teardown(&vm)
            .await
            .unwrap();
        assert!(store.get(&vm).unwrap().is_none());
    }
    assert_eq!(driver.provisions.load(SeqCst), 0);
    assert_eq!(driver.deprovisions.load(SeqCst), 2);
}

#[tokio::test]
async fn a_restarted_attach_reuses_the_persisted_inline_handle() {
    use std::sync::atomic::Ordering::SeqCst;
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("agent.redb");
    let vm = VmId::new_v4();
    let disk = VolumeId::new_v4();
    let driver = Arc::new(CountingVolume::default());
    for attach_fails in [true, false] {
        driver.fail_attach.store(attach_fails, SeqCst);
        let store = Arc::new(crate::store::Store::open(&db).unwrap());
        let provisioner = disk_provisioner(temp.path(), store.clone(), driver.clone());
        let mut record = store
            .get(&vm)
            .unwrap()
            .unwrap_or_else(|| inline_record(disk));
        store.put(&vm, &record).unwrap();
        let spec = record.spec.clone();
        let cgroup = provisioner.drivers.confiner.open_slice(&vm.to_string());
        let result = provisioner
            .attach_volumes(&vm, &mut record, &spec, &cgroup)
            .await;
        assert_eq!(result.is_err(), attach_fails);
        let persisted = store.get(&vm).unwrap().unwrap();
        assert_eq!(
            persisted.unattached_volumes.len(),
            usize::from(attach_fails)
        );
        assert_eq!(persisted.volumes.len(), usize::from(!attach_fails));
    }
    assert_eq!(
        driver.provisions.load(SeqCst),
        1,
        "retry attaches the original disk"
    );
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

/// The node's spec for a create document with one inline boot disk and the `attached`
/// volumes, converted the way every create and every replay of it is.
fn converted(attached: &[VolumeId]) -> AgentVmSpec {
    use crate::types::NewVmSpecExt;
    let mut volumes = vec![serde_json::json!({"size_bytes": 4096, "driver": "filesystem"})];
    volumes.extend(
        attached
            .iter()
            .map(|id| serde_json::json!({"volume": id.to_string()})),
    );
    let document: crate::types::NewVmSpec = serde_json::from_value(serde_json::json!({
        "vcpus": 1,
        "memory_mib": 256,
        "boot": {"kind": "firmware", "firmware": "fw"},
        "volumes": volumes,
    }))
    .expect("a create document");
    document.into_spec("br0").expect("a valid document").1
}

/// IKR-B66: an attach and a detach replay the create document, whose conversion names the
/// inline boot disk anew each time. The record keeps the disk it holds, and a cold restart
/// boots from it instead of provisioning a fresh copy of the base image.
#[tokio::test]
async fn the_boot_disk_survives_an_attach_a_detach_and_a_cold_restart() {
    let temp = tempfile::tempdir().expect("a temp dir");
    let store = Arc::new(crate::store::Store::open(&temp.path().join("a.redb")).expect("a store"));
    let disk = Arc::new(PlainDisk::default());
    let provisioner = disk_provisioner(temp.path(), store.clone(), disk.clone());
    let data = a_volume_held_here(&store);
    let vm = VmId::new_v4();
    provisioner
        .provision(vm, converted(&[]), Desired::Running, true)
        .await
        .expect("the vm is made");
    let boot = store
        .get(&vm)
        .expect("a read")
        .expect("a record")
        .spec
        .volumes[0]
        .id;

    provisioner
        .sync_volumes(&vm, &converted(&[data]))
        .await
        .expect("the volume is attached");
    provisioner
        .sync_volumes(&vm, &converted(&[]))
        .await
        .expect("and detached again");
    let record = store.get(&vm).expect("a read").expect("a record");
    let named: Vec<VolumeId> = record.spec.volumes.iter().map(|v| v.id).collect();
    assert_eq!(
        named,
        vec![boot],
        "the record still names the disk it holds"
    );

    provisioner.stop(&vm, record).await.expect("the vm stops");
    let stopped = store.get(&vm).expect("a read").expect("a record");
    provisioner
        .resume(&vm, stopped)
        .await
        .expect("and starts again");

    assert_eq!(
        *disk.provisioned.lock().unwrap(),
        vec![boot, boot],
        "every provision named the disk the vm was made with"
    );
    let held: Vec<VolumeId> = store
        .get(&vm)
        .expect("a read")
        .expect("a record")
        .volumes
        .iter()
        .map(|v| v.id())
        .collect();
    assert_eq!(held, vec![boot], "and the restarted guest boots from it");
}

/// A spec whose fixed disks do not pair with the record's is refused before anything is
/// attached: the node cannot tell which of the disks the guest boots from.
#[tokio::test]
async fn a_spec_with_another_inline_disk_is_refused_before_anything_is_attached() {
    let temp = tempfile::tempdir().expect("a temp dir");
    let store = Arc::new(crate::store::Store::open(&temp.path().join("a.redb")).expect("a store"));
    let disk = Arc::new(PlainDisk::default());
    let provisioner = disk_provisioner(temp.path(), store.clone(), disk.clone());
    let data = a_volume_held_here(&store);
    let vm = VmId::new_v4();
    provisioner
        .provision(vm, converted(&[]), Desired::Running, true)
        .await
        .expect("the vm is made");
    let before = store.get(&vm).expect("a read").expect("a record");

    let mut grown = converted(&[data]);
    grown.volumes.push(converted(&[]).volumes.remove(0));
    let refused = provisioner
        .sync_volumes(&vm, &grown)
        .await
        .expect_err("a second inline disk is not an attach");

    assert!(
        format!("{refused:#}").contains("more fixed disks"),
        "{refused:#}"
    );
    let after = store.get(&vm).expect("a read").expect("a record");
    assert_eq!(
        after.volumes.iter().map(|v| v.id()).collect::<Vec<_>>(),
        before.volumes.iter().map(|v| v.id()).collect::<Vec<_>>(),
        "nothing was attached"
    );
    assert_eq!(
        after.spec.volumes.len(),
        1,
        "and the record names what it did"
    );
}

/// Fixed entries pair in order and keep the record's ids; pluggable ones come from the spec.
#[test]
fn fixed_disks_keep_the_records_ids_and_volumes_come_from_the_spec() {
    let inline = |id: VolumeId| crate::types::VolumeWithId {
        id,
        spec: agent_api::storage::VolumeSpec {
            base_image: Some("img".into()),
            size_bytes: 4096,
            driver: None,
            params: None,
        },
        referenced: false,
    };
    let referenced = |id: VolumeId| crate::types::VolumeWithId {
        referenced: true,
        ..inline(id)
    };
    let (boot, scratch, data) = (VolumeId::new_v4(), VolumeId::new_v4(), VolumeId::new_v4());
    let held = [inline(boot), inline(scratch)];
    let wanted = [
        inline(VolumeId::new_v4()),
        referenced(data),
        inline(VolumeId::new_v4()),
    ];

    let kept = volumes_keeping_fixed(&held, &wanted).expect("the lists pair");

    let ids: Vec<VolumeId> = kept.iter().map(|v| v.id).collect();
    assert_eq!(ids, vec![boot, data, scratch]);
    let swapped = [referenced(data)];
    assert!(
        volumes_keeping_fixed(&held[..1], &swapped).is_err(),
        "an inline boot disk is not a volume's"
    );
    assert!(
        volumes_keeping_fixed(&held, &wanted[..2]).is_err(),
        "an inline disk does not detach"
    );
}

/// A stopped VM made by `converted(&[])` whose record names a fresh inline id, as an attach
/// and a detach on an agent before IKR-B66 left one. Returns the id of the disk it held.
async fn drifted_vm(
    provisioner: &Provisioner,
    store: &crate::store::Store,
    vm: VmId,
    also_held: Option<VolumeId>,
) -> VolumeId {
    provisioner
        .provision(vm, converted(&[]), Desired::Running, true)
        .await
        .expect("the vm is made");
    let mut record = store.get(&vm).expect("a read").expect("a record");
    let held = record.spec.volumes[0].id;
    record.spec.volumes[0].id = VolumeId::new_v4();
    if let Some(other) = also_held {
        record.volumes.push(Volume::attached(
            agent_api::storage::VolumeHandle {
                id: other,
                backend: format!("/fake/{other}.raw"),
                size_bytes: 4096,
                params: None,
            },
            VolumeAttachment::Path(format!("/fake/{other}.raw").into()),
        ));
    }
    store.put(&vm, &record).expect("stored");
    provisioner.stop(&vm, record).await.expect("the vm stops");
    held
}

/// IKR-B66: a record an older agent left naming a fresh inline id names the disk its VM held
/// again, and the restart boots that disk instead of a fresh copy of the base image.
#[tokio::test]
async fn a_restart_boots_the_disk_a_drifted_record_held_and_not_a_fresh_one() {
    let temp = tempfile::tempdir().expect("a temp dir");
    let store = Arc::new(crate::store::Store::open(&temp.path().join("a.redb")).expect("a store"));
    let disk = Arc::new(PlainDisk::default());
    let provisioner = disk_provisioner(temp.path(), store.clone(), disk.clone());
    let vm = VmId::new_v4();
    let held = drifted_vm(&provisioner, &store, vm, None).await;

    let stopped = store.get(&vm).expect("a read").expect("a record");
    provisioner
        .resume(&vm, stopped)
        .await
        .expect("the vm starts again");

    assert_eq!(*disk.provisioned.lock().unwrap(), vec![held, held]);
    let record = store.get(&vm).expect("a read").expect("a record");
    assert_eq!(record.spec.volumes[0].id, held, "the record names it again");
}

/// A drifted record whose named and held disks do not pair is not started: which disk the
/// guest boots from cannot be told, and nothing is provisioned.
#[tokio::test]
async fn a_drifted_record_whose_disks_do_not_pair_is_not_started() {
    let temp = tempfile::tempdir().expect("a temp dir");
    let store = Arc::new(crate::store::Store::open(&temp.path().join("a.redb")).expect("a store"));
    let disk = Arc::new(PlainDisk::default());
    let provisioner = disk_provisioner(temp.path(), store.clone(), disk.clone());
    let vm = VmId::new_v4();
    let held = drifted_vm(&provisioner, &store, vm, Some(VolumeId::new_v4())).await;

    let stopped = store.get(&vm).expect("a read").expect("a record");
    let refused = provisioner
        .resume(&vm, stopped)
        .await
        .expect_err("two held disks, one named");

    assert!(
        format!("{refused:#}").contains("cannot be told"),
        "{refused:#}"
    );
    assert_eq!(
        *disk.provisioned.lock().unwrap(),
        vec![held],
        "only the create provisioned"
    );
}
