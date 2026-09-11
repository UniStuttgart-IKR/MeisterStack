// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! What the hypervisor is told: `build_instance_spec`.

use super::*;

/// The claim this whole refactor is judged on: a VM gets the same
/// configuration it got before.
///
/// It goes through the real thing rather than a stub. A real filesystem
/// backend provisions a real file and attaches it, the attachment goes
/// into a real `VmRecord`, and `build_instance_spec` — the one function
/// that turns a record into what the hypervisor is told — produces the
/// list. What it must produce is exactly one `Path` volume, which is what
/// a single `create` produced before there were two calls.
///
/// The chain closes below this: `VolumeAttachment` did not change, and
/// the cloud-hypervisor driver's own tests pin the VMM config it builds
/// from a `Path`. So an unchanged attachment here IS an unchanged config
/// there, and the two halves together are the "byte for byte" claim.
#[tokio::test]
async fn a_vm_is_built_from_the_same_attachments_two_calls_now_produce() {
    let temp = tempfile::tempdir().expect("a temp dir");
    let dir = temp.path().to_path_buf();
    std::fs::create_dir_all(dir.join("images")).expect("a temp image dir");
    let d = dir.display();
    let cfg: crate::config::AgentConfig = toml::from_str(&format!(
        r#"node_id = "n1"
           [paths]
           db_path     = "{d}/a.redb"
           run_dir     = "{d}/run"
           image_dir   = "{d}/images"
           volume_dir  = "{d}/volumes"
           cgroup_root = "{d}/cgroup"
           [volume.filesystem]"#
    ))
    .expect("the test config parses");

    // A storage node's driver set: no hypervisor and no network, which is
    // exactly what `build_instance_spec` needs none of.
    let drivers = Drivers::from_config(&cfg).await.expect("drivers build");
    let provisioner = Provisioner::new(
        Arc::new(Store::open(&cfg.paths.db_path).expect("a store")),
        drivers.clone(),
        Arc::new(crate::images::Cache::new(cfg.paths.image_dir.clone())),
        cfg.paths.image_dir.clone(),
        cfg.paths.run_dir.clone(),
        String::new(),
        None,
        None,
    );

    let vol_id = uuid::Uuid::new_v4();
    let vspec = agent_api::storage::VolumeSpec {
        base_image: None,
        size_bytes: 4096,
        driver: None,
        params: None,
    };
    let backend = drivers
        .storage
        .get(&default_volume_driver())
        .expect("the default backend is always registered");

    // The two calls, in the order `run_chain` makes them.
    let handle = backend
        .provision(&vol_id, &vspec)
        .await
        .expect("provisioned");
    let attachment = backend.attach(&handle, None).await.expect("attached");

    let mut vm_spec = spec(2, 2048, vec![]);
    vm_spec.volumes = vec![crate::types::VolumeWithId {
        referenced: false,
        id: vol_id,
        spec: vspec,
    }];
    let mut record = crate::types::VmRecord {
        spec: vm_spec.clone(),
        desired: Desired::Running,
        phase: Phase::VolumesDone,
        operation: None,
        stop_deadline: None,
        receive_deadline: None,
        send_failed: None,
        unhealthy: None,
        managed_by_controller: false,
        volumes: vec![Volume::attached(handle.clone(), attachment.clone())],
        nics: vec![],
        devices: vec![],
        vmm_pid: None,
        overlay_bridges: Default::default(),
    };
    record.phase = Phase::VolumesDone;

    let ispec = provisioner
        .build_instance_spec(&uuid::Uuid::new_v4(), &vm_spec, &record)
        .expect("a vm with one block volume builds");

    assert_eq!(ispec.volumes.len(), 1);
    match &ispec.volumes[0].attachment {
        VolumeAttachment::Path(p) => {
            assert_eq!(p, &cfg.paths.volume_dir.join(format!("{vol_id}.raw")))
        }
        other => panic!("a plain disk is a path, not {other:?}"),
    }
    // The volume's id travels with its attachment, which is what lets the
    // VMM name the disk after the volume rather than after its position.
    assert_eq!(ispec.volumes[0].id, vol_id);
    // Nothing about the VM grew a backend process, so the slice is not
    // widened and the guest memory does not have to be shareable —
    // exactly the three answers a one-call `create` produced.
    assert!(
        widen_for_storage_backends(&Provisioner::limits_for(&vm_spec), &record.volumes).is_none()
    );
    assert!(!ispec.volumes[0].attachment.needs_shared_memory());
    assert!(ispec.volumes[0].attachment.is_block());
}
