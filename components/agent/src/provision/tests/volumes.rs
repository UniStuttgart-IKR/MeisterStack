// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Volumes: the widening they ask of the slice, the fork between
//! referenced and inline, the hot-plug order, and the one detach per
//! attachment.

use super::*;

/// The gap this closes: an `[volume.nfs]` share is a virtiofsd in the
/// VM's own slice, and before the widening it had no allowance at all —
/// the slice was sized for the VMM and the devices only.
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

/// The rule the whole position exists for, counted rather than argued: a
/// referenced volume is ATTACHED and never provisioned, and a destroy
/// detaches it and leaves the data — and the record — standing.
///
/// A fake backend that counts its calls, because what is being proven is
/// which calls happened. The `filesystem` driver would make the same
/// bytes either way and the test would pass while the rule was broken.
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

    // The reference resolves to the stored handle, with no provision in
    // sight — which is the whole claim.
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

    // And a reference to a volume this node does not have is a refusal
    // rather than a fresh disk: the two pictures disagree, and making
    // bytes on the strength of that would be the wrong repair.
    let err = provisioner
        .reference(&VolumeId::new_v4(), None)
        .expect_err("no record here");
    assert!(
        format!("{err:#}").contains("no record of volume"),
        "{err:#}"
    );
    assert_eq!(counting.provisions.load(Ordering::SeqCst), 0);
}

/// The whole of the agent's half of hot-plug, counted and ordered.
///
/// What a fake buys here that a real driver cannot: `filesystem` would
/// make the same bytes whichever order the calls came in, and the test
/// would stay green while the rule was broken. What is being proven is
/// which calls happened and in what order —
///
///   * **attach before add-disk.** A VMM told about a path that does not
///     exist yet is an error the guest sees.
///   * **remove-device before detach.** Pulling a backend out from under
///     a live virtio device gives a guest I/O errors instead of an unplug.
///
/// And two things that must NOT happen: no provision (the volume was
/// already there) and no deprovision (it outlives this VM by definition —
/// a detach that took the bytes would be the whole reason the object
/// exists, undone).
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

    /// A hypervisor that is running the VM and can plug disks. Only the
    /// three methods this path touches do anything.
    ///
    /// The flag is the guest that will not let go: cloud hypervisor's own
    /// driver waits for `vm.info` to stop listing the disk and fails when
    /// it never does, and this is that failure without a VMM in the room.
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

    // Three volumes this node already owns: the boot disk, the one that
    // is attached now, and the one that will be plugged in.
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
        unhealthy: None,
        managed_by_controller: true,
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
    // The bytes of a detached volume are NOT touched, which is the whole
    // reason a `Volume` object exists.
    assert!(!calls.iter().any(|c| c.starts_with("deprovision")));
    assert!(!calls.iter().any(|c| c.starts_with("provision")));

    // The record has to be readable for the resize below: it addresses a
    // VM by id, the way a command from the controller does.
    store.put(&vm, &record).expect("stored");

    // And the second half of a resize, against the same fake: the guest
    // is told by the disk's NAME and with the size the backend already
    // grew to. What this proves is the name — a positional one would have
    // moved under the detach two lines up, and the guest would have been
    // told about somebody else's disk.
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
    // A disk this VM does not have is a refusal and not a quiet success:
    // the tier above has to be able to tell "the guest has the room" from
    // "the guest will have it after a restart".
    let err = provisioner
        .resize_attachment(&vm, &going, 2 << 30)
        .await
        .expect_err("not attached here any more");
    assert!(
        format!("{err:#}").contains("does not have volume"),
        "{err:#}"
    );

    // A second pass over the same spec is a no-op: the diff is by id, so
    // there is nothing left to differ.
    log.lock().unwrap().clear();
    provisioner
        .apply_volume_diff(&vm, &mut record, &with(vec![boot, arriving]))
        .await
        .expect("idempotent");
    assert!(log.lock().unwrap().is_empty(), "nothing drifted");

    // And the half D3 was missing: an unplug the guest never carried out
    // stops the sequence where it stands. The backend is NOT detached —
    // pulling it out from under a device the VMM still holds open is the
    // I/O error this order exists to prevent — and the record still says
    // the volume is here, because it is.
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

/// The boot entry and the inline entries are invisible to the diff, on
/// this side of the wire as well as at the API edge.
///
/// Said twice on purpose. The 422 is what a person meets; this is what a
/// second client at the agent's own unix socket meets, and a rule that
/// lived only at the edge would be a rule that socket does not have.
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

    // A different boot disk is not a plug and not an unplug: index 0 is
    // skipped on both sides, so the diff is empty and the API's 422 is
    // the only thing standing between a client and that edit.
    let (attach, detach) = volume_diff(&with(vec![boot.clone()]), &with(vec![other_boot.clone()]));
    assert!(attach.is_empty() && detach.is_empty());

    // An inline disk that vanished from the spec is not detached either.
    let (attach, detach) = volume_diff(
        &with(vec![boot.clone(), inline.clone()]),
        &with(vec![boot.clone()]),
    );
    assert!(attach.is_empty() && detach.is_empty());

    // And the one edit that IS a plug.
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

/// A volume driver that counts the calls it gets. What is being proven is
/// how MANY times each verb happens, so a real driver — whose second
/// detach looks exactly like its first from the outside — would let the
/// defect through.
#[derive(Default)]
struct CountingVolume {
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
impl agent_api::storage::VolumeAttacher for CountingVolume {
    async fn attach(
        &self,
        handle: &agent_api::storage::VolumeHandle,
        _: Option<&agent_api::CgroupHandle>,
    ) -> agent_api::storage::Result<VolumeAttachment> {
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

/// `stop` then `destroy` is the ordinary way a VM ends, and it used to
/// detach twice. The second call is the dangerous one: the driver's map
/// lost its entry with the first, so the fallback reaches for the pid on
/// the record — a number the kernel hands out again.
///
/// The mark travels through the store and not through a variable: the
/// agent may restart between the two commands, and a restart is exactly
/// when the driver's map is empty and the pid is all that is left.
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
        unhealthy: None,
        managed_by_controller: true,
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

    // The agent restarts between the two commands — the window in which
    // the driver's map is empty and the recorded pid is the only handle.
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

/// A detach that FAILED is not written down, so the teardown after it
/// tries again. The mark says "this connection was given back", not "we
/// asked once".
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
        unhealthy: None,
        managed_by_controller: true,
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
