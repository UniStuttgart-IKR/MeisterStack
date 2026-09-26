// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Cloud Hypervisor configuration, event parsing, unplug polling and file-lifecycle tests.

/// Use the v53 tcp: prefix and bracket IPv6 literals; tcp:// is a different input.
#[test]
fn the_migration_url_is_the_form_cloud_hypervisor_actually_parses() {
    assert_eq!(
        agent_api::migration_url("10.0.0.5", 49000),
        "tcp:10.0.0.5:49000"
    );
    assert_eq!(
        agent_api::migration_url("127.0.0.1", 49099),
        "tcp:127.0.0.1:49099"
    );
    // Bracketed, or the port would be part of the address.
    assert_eq!(
        agent_api::migration_url("2001:db8::1", 49000),
        "tcp:[2001:db8::1]:49000"
    );
    // Already bracketed stays that way rather than becoming doubly so.
    assert_eq!(
        agent_api::migration_url("[2001:db8::1]", 49000),
        "tcp:[2001:db8::1]:49000"
    );
    // And no scheme separator anywhere.
    assert!(!agent_api::migration_url("10.0.0.5", 1).contains("//"));
}

/// Readiness is distinct from receive completion or failure evidence.
#[test]
fn a_receive_says_nothing_until_it_has_finished_or_failed() {
    let temp = tempfile::tempdir().expect("a temp dir");
    let dir = temp.path().to_path_buf();
    let path = dir.join("events");

    // No file at all is the state between the spawn and the first event,
    // and it must read as "still going" rather than as an error.
    let _ = std::fs::remove_file(&path);
    assert!(receive_outcome(&path).is_none());
    assert!(!listening(&path));

    // Readiness permits migrate_in to return but is not a transfer outcome.
    std::fs::write(&path, "{\"event\":\"migration-receive-ready\"}\n\n").expect("write");
    assert!(listening(&path));
    assert!(receive_outcome(&path).is_none());

    // The stream started. Still no outcome.
    std::fs::write(
        &path,
        "{\"event\":\"migration-receive-ready\"}\n\n{\"event\":\"migration-receive-started\"}\n\n",
    )
    .expect("write");
    assert!(receive_outcome(&path).is_none());

    let done = format!(
        "{}{{\"event\":\"migration-receive-finished\"}}\n\n",
        std::fs::read_to_string(&path).unwrap()
    );
    std::fs::write(&path, &done).expect("write");
    assert_eq!(receive_outcome(&path), Some(Ok(())));

    // Explicit failure marks the receiver for cleanup.
    std::fs::write(&path, "{\"event\":\"migration-receive-failed\"}\n\n").expect("write");
    let said = receive_outcome(&path)
        .expect("an outcome")
        .expect_err("failed");
    assert!(said.contains("migration-receive-failed"), "{said}");
}
use super::fd::writable_files;
use super::*;
use agent_api::NicAttachment;

/// Enable verbose restore diagnostics for receivers and keep ordinary boot arguments quiet.
#[test]
fn the_vmm_that_receives_a_guest_is_the_one_that_is_asked_to_explain_itself() {
    let socket = Path::new("/run/meisterstack/agent/vms/a.sock");
    let booting = crate::process::vmm_args(socket, None);
    assert_eq!(
        booting,
        vec![
            "--api-socket".to_string(),
            "/run/meisterstack/agent/vms/a.sock".to_string(),
            // v53's own default, stated rather than relied on — see
            // `every_vmm_is_started_with_its_seccomp_filter_stated`.
            "--seccomp".to_string(),
            "true".to_string(),
        ],
        "a boot says nothing about itself beyond its socket and its filter"
    );

    let events = Path::new("/run/meisterstack/agent/vms/a.events");
    let receiving = crate::process::vmm_args(socket, Some(events));
    assert!(receiving.contains(&"-v".to_string()), "{receiving:?}");
    assert!(
        receiving.contains(&"path=/run/meisterstack/agent/vms/a.events".to_string()),
        "{receiving:?}"
    );
    // And the flag comes before the option it does not belong to, which is
    // the shape v53's own parser accepts.
    let dash_v = receiving.iter().position(|a| a == "-v").expect("-v");
    let monitor = receiving
        .iter()
        .position(|a| a == "--event-monitor")
        .expect("--event-monitor");
    assert!(dash_v < monitor, "{receiving:?}");
}

/// One volume id per position, so a test can name the disk it means
/// without carrying uuids around: `vol(0)` is the boot disk of every spec
/// below.
fn vol(index: u128) -> agent_api::VolumeId {
    agent_api::VolumeId::from_u128(index + 1)
}

fn spec(volumes: Vec<VolumeAttachment>, devices: Vec<DeviceAttachment>) -> InstanceSpec {
    InstanceSpec {
        boot: BootSource::Firmware {
            firmware: "/fw.fd".into(),
        },
        volumes: volumes
            .into_iter()
            .enumerate()
            .map(|(i, attachment)| AttachedVolume {
                id: vol(i as u128),
                attachment,
            })
            .collect(),
        vcpus: 2,
        memory_mib: 1024,
        nics: Vec::<NicAttachment>::new(),
        devices,
        cloud_init_seed: None,
    }
}

fn config(spec: &InstanceSpec) -> serde_json::Value {
    build_vm_config(
        spec,
        &PathBuf::from("/c"),
        &PathBuf::from("/s"),
        &VmForm {
            net: NetForm::TapName,
            landlock: None,
        },
    )
    .expect("config builds")
}

/// Build VM configuration for descriptor-based NIC handoff.
fn config_with_tap_fds(spec: &InstanceSpec) -> serde_json::Value {
    build_vm_config(
        spec,
        &PathBuf::from("/c"),
        &PathBuf::from("/s"),
        &VmForm {
            net: NetForm::TapFd,
            landlock: None,
        },
    )
    .expect("config builds")
}

/// Volume-derived disk IDs remain stable after hot-unplug changes list positions.
#[test]
fn every_disk_answers_to_a_name_derived_from_its_volume_and_not_to_its_position() {
    let mut s = spec(
        vec![
            VolumeAttachment::Path("/vol/root.raw".into()),
            VolumeAttachment::Path("/vol/data.raw".into()),
        ],
        vec![],
    );
    s.cloud_init_seed = Some("/run/vm.cidata.img".into());
    let disks = config(&s)["disks"].clone();

    assert_eq!(disks[0]["id"], agent_api::disk_id(&vol(0)));
    assert_eq!(disks[1]["id"], agent_api::disk_id(&vol(1)));
    // Two volumes are two names, and neither is a number.
    assert_ne!(disks[0]["id"], disks[1]["id"]);
    assert!(
        !disks[0]["id"].as_str().unwrap().starts_with('_'),
        "`_disk0` is CH's own namespace and its own counting"
    );
    // The seed has no volume ID because it does not support hotplug or resize.
    assert!(disks[2]["id"].is_null());

    // A share is not a disk, so it takes no disk id and no disk slot.
    let shared = spec(vec![share()], vec![]);
    assert_eq!(config(&shared)["disks"].as_array().map(Vec::len), Some(0));
}

/// Keep the seed read-only and after the boot disk so it does not change boot selection.
#[test]
fn the_cloud_init_seed_is_an_extra_read_only_disk_after_the_boot_volume() {
    let boot = VolumeAttachment::Path("/vol/root.raw".into());
    let mut with_seed = spec(vec![boot.clone()], vec![]);
    with_seed.cloud_init_seed = Some("/run/vm.cidata.img".into());
    let disks = config(&with_seed)["disks"].clone();

    assert_eq!(disks.as_array().map(Vec::len), Some(2));
    assert_eq!(
        disks[0]["path"], "/vol/root.raw",
        "the boot disk stays first"
    );
    assert!(disks[0].get("readonly").is_none(), "and stays writable");
    assert_eq!(disks[1]["path"], "/run/vm.cidata.img");
    assert_eq!(disks[1]["readonly"], true);
}

/// Omitting a seed preserves the ordinary VM configuration.
#[test]
fn a_vm_without_a_seed_gets_exactly_the_config_it_had_before() {
    let volumes = vec![VolumeAttachment::Path("/vol/root.raw".into())];
    let without = config(&spec(volumes.clone(), vec![]));

    let mut with_seed = spec(volumes, vec![]);
    with_seed.cloud_init_seed = Some("/run/vm.cidata.img".into());
    let with = config(&with_seed);

    // Everything except the disk list is the same document.
    for key in ["cpus", "memory", "payload", "console", "serial"] {
        assert_eq!(without[key], with[key], "{key}");
    }
    assert_eq!(without["disks"].as_array().map(Vec::len), Some(1));
    assert_ne!(without["disks"], with["disks"]);
    // And no key appeared or vanished.
    assert_eq!(
        without.as_object().map(|o| o.keys().collect::<Vec<_>>()),
        with.as_object().map(|o| o.keys().collect::<Vec<_>>())
    );
}

fn vhost_gpu() -> DeviceAttachment {
    DeviceAttachment::VhostUser {
        socket: "/run/gpu.sock".into(),
        pid: 1,
        device_type: 16,
        queue_sizes: vec![256],
    }
}

fn nic(mtu: Option<u32>) -> NicAttachment {
    NicAttachment {
        tap_name: "msk0000".into(),
        mac: "52:54:00:00:00:01".parse().unwrap(),
        mtu,
    }
}

/// Expose the configured overlay MTU to the guest; omit it when unspecified.
#[test]
fn an_overlay_nic_tells_the_guest_its_mtu_and_a_plain_one_says_nothing() {
    let mut overlay = spec(vec![VolumeAttachment::Path("/vol/a.raw".into())], vec![]);
    overlay.nics = vec![nic(Some(1450))];
    let cfg = config(&overlay);
    assert_eq!(cfg["net"][0]["tap"], "msk0000");
    assert_eq!(cfg["net"][0]["mtu"], 1450);

    // Unspecified MTU is omitted rather than serialized as null.
    let mut plain = spec(vec![VolumeAttachment::Path("/vol/a.raw".into())], vec![]);
    plain.nics = vec![nic(None)];
    let cfg = config(&plain);
    assert_eq!(cfg["net"][0]["mac"], "52:54:00:00:00:01");
    assert!(cfg["net"][0].get("mtu").is_none(), "no key, not a null");
}

/// Pass tap descriptors through SCM_RIGHTS. The add-net body omits tap, fds and
/// mtu so the unprivileged VMM need not open or reconfigure the tap.
#[test]
fn the_descriptor_form_names_no_tap_no_fd_and_no_mtu() {
    let mut overlay = spec(vec![VolumeAttachment::Path("/vol/a.raw".into())], vec![]);
    overlay.nics = vec![nic(Some(1450))];
    let cfg = config_with_tap_fds(&overlay);
    assert!(
        cfg.get("net").is_none(),
        "vm.create must carry no net at all: v53 nulls every fd in it"
    );

    let body = net_config(&nic(Some(1450)));
    assert_eq!(body["id"], "msk0000");
    assert_eq!(body["mac"], "52:54:00:00:00:01");
    // Exactly two: v53 refuses anything but `2 * fds.len()`.
    assert_eq!(body["num_queues"], 2);
    assert!(
        body.get("tap").is_none(),
        "the descriptor replaces the name"
    );
    assert!(body.get("fds").is_none(), "only SCM_RIGHTS fds count");
    assert!(
        body.get("mtu").is_none(),
        "set_mtu is SIOCSIFMTU and an unprivileged vmm may not; the tap already carries it"
    );
}

/// Tap-name and descriptor configurations differ only in how NICs are supplied.
#[test]
fn the_two_net_forms_differ_in_net_and_in_nothing_else() {
    let mut s = spec(
        vec![
            VolumeAttachment::Path("/vol/a.raw".into()),
            VolumeAttachment::VhostUserBlk {
                socket: "/run/blk.sock".into(),
                pid: 7,
            },
        ],
        vec![vhost_gpu()],
    );
    s.nics = vec![nic(Some(1450))];
    let mut named = config(&s);
    let with_fds = config_with_tap_fds(&s);
    assert!(named.get("net").is_some());
    named.as_object_mut().unwrap().remove("net");
    assert_eq!(named, with_fds);
}

/// CH reads the enum spelling Raw. Explicit typing avoids format autodetection
/// and its write restrictions; vhost-user disks have no file image type.
#[test]
fn a_file_backed_disk_states_its_image_type_and_states_it_the_way_ch_reads_it() {
    let cfg = config(&spec(
        vec![VolumeAttachment::Path("/vol/a.raw".into())],
        vec![],
    ));
    assert_eq!(cfg["disks"][0]["image_type"], "Raw");

    // The FAT12 seed also declares Raw format.
    let mut with_seed = spec(vec![VolumeAttachment::Path("/vol/a.raw".into())], vec![]);
    with_seed.cloud_init_seed = Some("/run/seed.img".into());
    let cfg = config(&with_seed);
    assert_eq!(cfg["disks"][1]["image_type"], "Raw");

    // A vhost-user disk is a backend CH connects to, not a file it opens,
    // so it has no image type to state.
    let cfg = config(&spec(
        vec![VolumeAttachment::VhostUserBlk {
            socket: "/run/blk.sock".into(),
            pid: 9,
        }],
        vec![],
    ));
    assert_eq!(cfg["disks"][0].get("image_type"), None);
}

/// Bound VMM diagnostic logs without including them in guest log output.
#[test]
fn the_vmm_log_is_bounded_but_never_part_of_the_guests_output() {
    let temp = tempfile::tempdir().expect("a temp dir");
    let dir = temp.path().to_path_buf();
    let d = CloudHypervisorDriver::new(
        "/nonexistent/cloud-hypervisor".into(),
        dir.clone(),
        Duration::from_secs(1),
        DEFAULT_UNPLUG_TIMEOUT,
    )
    .expect("the driver only needs its socket dir to exist");
    let id = VmId::new_v4();

    let diagnostics = d.diagnostic_paths(&id);
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0], d.vmm_log_path(&id));

    let served: Vec<_> = d.console_paths(&id).into_iter().map(|(_, p)| p).collect();
    assert!(
        !served.contains(&d.vmm_log_path(&id)),
        "the VMM's log must not reach vm logs"
    );
    assert!(
        !served.is_empty(),
        "the guest's own streams are still served"
    );
}

#[test]
fn a_path_volume_is_a_plain_disk_and_needs_nothing_shared() {
    let cfg = config(&spec(
        vec![VolumeAttachment::Path("/vol/a.raw".into())],
        vec![],
    ));
    assert_eq!(cfg["disks"][0]["path"], "/vol/a.raw");
    assert_eq!(cfg["disks"][0].get("vhost_user"), None);
    assert_eq!(cfg["memory"]["shared"], false);
}

/// Encode vhost-user block attachments using Cloud Hypervisor's disk fields.
#[test]
fn a_vhost_user_blk_volume_becomes_a_vhost_user_disk() {
    let cfg = config(&spec(
        vec![VolumeAttachment::VhostUserBlk {
            socket: "/run/blk.sock".into(),
            pid: 9,
        }],
        vec![],
    ));
    assert_eq!(cfg["disks"][0]["vhost_user"], true);
    assert_eq!(cfg["disks"][0]["vhost_socket"], "/run/blk.sock");
    assert_eq!(cfg["disks"][0].get("path"), None);
}

/// A vhost-user volume alone requires shared guest memory.
#[test]
fn a_vhost_user_volume_alone_turns_shared_memory_on() {
    let cfg = config(&spec(
        vec![VolumeAttachment::VhostUserBlk {
            socket: "/run/blk.sock".into(),
            pid: 9,
        }],
        vec![],
    ));
    assert_eq!(cfg["memory"]["shared"], true);
    assert_eq!(
        cfg.get("generic_vhost_user"),
        None,
        "a disk is not a generic device"
    );
}

#[test]
fn a_vhost_user_device_still_turns_it_on_by_itself() {
    let cfg = config(&spec(
        vec![VolumeAttachment::Path("/a.raw".into())],
        vec![vhost_gpu()],
    ));
    assert_eq!(cfg["memory"]["shared"], true);
    assert_eq!(cfg["generic_vhost_user"][0]["device_type"], 16);
}

/// Disks keep spec order — the first one is the boot disk, and mixing
/// attachment kinds must not reorder them.
#[test]
fn mixed_attachments_keep_their_spec_order() {
    let cfg = config(&spec(
        vec![
            VolumeAttachment::Path("/boot.raw".into()),
            VolumeAttachment::VhostUserBlk {
                socket: "/run/data.sock".into(),
                pid: 9,
            },
            VolumeAttachment::Path("/seed.raw".into()),
        ],
        vec![],
    ));
    assert_eq!(cfg["disks"][0]["path"], "/boot.raw");
    assert_eq!(cfg["disks"][1]["vhost_socket"], "/run/data.sock");
    assert_eq!(cfg["disks"][2]["path"], "/seed.raw");
    assert_eq!(cfg["memory"]["shared"], true);
}

fn share() -> VolumeAttachment {
    VolumeAttachment::FsShare {
        socket: "/run/fs.sock".into(),
        tag: "share".into(),
        pid: 12,
    }
}

/// Encode virtiofs shares as fs entries with tags and exclude them from disks.
#[test]
fn a_share_becomes_an_fs_entry_and_leaves_the_disks_alone() {
    let cfg = config(&spec(
        vec![VolumeAttachment::Path("/boot.raw".into()), share()],
        vec![],
    ));
    assert_eq!(cfg["disks"].as_array().unwrap().len(), 1);
    assert_eq!(cfg["disks"][0]["path"], "/boot.raw");
    assert_eq!(cfg["fs"][0]["socket"], "/run/fs.sock");
    assert_eq!(cfg["fs"][0]["tag"], "share");
    // num_queues/queue_size are CH's defaults, deliberately not ours
    assert_eq!(cfg["fs"][0].get("num_queues"), None);
}

/// A virtiofs share alone requires shared guest memory.
#[test]
fn a_share_alone_turns_shared_memory_on() {
    let cfg = config(&spec(
        vec![VolumeAttachment::Path("/a.raw".into()), share()],
        vec![],
    ));
    assert_eq!(cfg["memory"]["shared"], true);
    assert_eq!(
        cfg.get("generic_vhost_user"),
        None,
        "a share is not a generic device"
    );
}

/// Omit the optional fs field when no shares are present.
#[test]
fn a_vm_without_shares_has_no_fs_key() {
    let cfg = config(&spec(vec![VolumeAttachment::Path("/a.raw".into())], vec![]));
    assert_eq!(cfg.get("fs"), None);
}

/// VFIO pins memory without requiring vhost-user shared mappings.
#[test]
fn passthrough_does_not_ask_for_shared_memory() {
    let cfg = config(&spec(
        vec![VolumeAttachment::Path("/a.raw".into())],
        vec![DeviceAttachment::VfioPci {
            sysfs_path: "/sys/bus/pci/devices/0000:23:00.0".into(),
        }],
    ));
    assert_eq!(cfg["memory"]["shared"], false);
    assert_eq!(
        cfg["devices"][0]["path"],
        "/sys/bus/pci/devices/0000:23:00.0"
    );
}

/// An accepted removal is not completed unplug. Poll until absence is observed or time out.
#[tokio::test]
async fn a_disk_that_disappears_late_still_counts_as_unplugged() {
    use std::cell::Cell;

    let info = |disks: &[&str]| {
        serde_json::json!({
            "state": "Running",
            "config": { "disks": disks.iter().map(|id| serde_json::json!({
                "path": format!("/var/lib/meisterstack/volumes/{id}.raw"),
                "id": id,
            })).collect::<Vec<_>>() }
        })
    };

    let asked = Cell::new(0);
    super::until_the_disk_is_gone(
        "disk-5f8f99ec",
        || {
            asked.set(asked.get() + 1);
            let answer = match asked.get() {
                1 | 2 => info(&["disk-d282f561", "disk-5f8f99ec"]),
                _ => info(&["disk-d282f561"]),
            };
            async move { Ok(answer) }
        },
        || Ok(None),
        std::time::Duration::from_secs(5),
        std::time::Duration::from_millis(1),
    )
    .await
    .expect("the guest let go on the third look");
    assert_eq!(asked.get(), 3, "and it was asked until it did");

    // An unacknowledged unplug must return an error instead of authorizing detach.
    let refused = super::until_the_disk_is_gone(
        "disk-5f8f99ec",
        || async { Ok(info(&["disk-5f8f99ec"])) },
        || Ok(None),
        std::time::Duration::from_millis(5),
        std::time::Duration::from_millis(1),
    )
    .await
    .expect_err("the guest kept it");
    let said = format!("{refused}");
    assert!(
        said.contains("disk-5f8f99ec") && said.contains("still has it open"),
        "the failure names the disk and what is true: {said}"
    );
}

/// A removed config entry is insufficient while the VMM still holds the file descriptor.
#[tokio::test]
async fn a_disk_the_config_has_dropped_is_not_gone_while_the_vmm_holds_it() {
    use std::cell::Cell;

    let gone =
        || async { Ok(serde_json::json!({ "state": "Running", "config": { "disks": [] } })) };
    let looked = Cell::new(0);
    super::until_the_disk_is_gone(
        "disk-5f8f99ec",
        gone,
        || {
            looked.set(looked.get() + 1);
            Ok(Some(looked.get() < 3))
        },
        std::time::Duration::from_secs(5),
        std::time::Duration::from_millis(1),
    )
    .await
    .expect("the fd closed on the third look");
    assert_eq!(looked.get(), 3, "and the fd table was asked until it did");

    let refused = super::until_the_disk_is_gone(
        "disk-5f8f99ec",
        gone,
        || Ok(Some(true)),
        std::time::Duration::from_millis(5),
        std::time::Duration::from_millis(1),
    )
    .await
    .expect_err("a config that says gone is not the fd being closed");
    assert!(
        format!("{refused}").contains("still has it open"),
        "{refused}"
    );
}

/// The witness itself, against this very process: a file this test holds
/// open is in its fd table, and is not once it is closed. A pid that does
/// not exist holds nothing.
#[test]
fn the_fd_table_says_whether_a_file_is_still_held() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let path = dir.path().join("disk.raw");
    let file = std::fs::File::create(&path).expect("a file");
    let me = std::process::id();
    assert!(
        super::vmm_holds(me, &path).expect("readable"),
        "open, so held"
    );
    drop(file);
    assert!(
        !super::vmm_holds(me, &path).expect("readable"),
        "closed, so not held"
    );
    assert!(
        !super::vmm_holds(u32::MAX - 1, &path).expect("a missing process is not an error"),
        "a process that is gone holds nothing"
    );
}

/// An unreadable config is unknown; a readable config with no disks is an absence.
#[test]
fn a_vm_info_that_does_not_say_is_not_a_yes() {
    use serde_json::json;

    assert_eq!(
        super::disk_gone(&json!({"config": {"disks": [{"id": "disk-a"}]}}), "disk-a"),
        Some(false)
    );
    assert_eq!(
        super::disk_gone(&json!({"config": {"disks": [{"id": "disk-b"}]}}), "disk-a"),
        Some(true)
    );
    assert_eq!(
        super::disk_gone(&json!({"config": {"disks": []}}), "disk-a"),
        Some(true)
    );
    assert_eq!(
        super::disk_gone(&json!({"config": {"disks": null}}), "disk-a"),
        Some(true),
        "a vm with no disks says so by having none"
    );
    assert_eq!(
        super::disk_gone(&json!({"config": {}}), "disk-a"),
        Some(true)
    );
    assert_eq!(
        super::disk_gone(&json!({"state": "Running"}), "disk-a"),
        None,
        "no config at all is a document this driver cannot read"
    );
    assert_eq!(
        super::disk_gone(&json!({"config": {"disks": "one"}}), "disk-a"),
        None
    );
}

/// A UUID socket filename is only a candidate. Require a responding VMM before stray cleanup.
#[tokio::test]
async fn a_socket_nothing_answers_is_not_an_unmanaged_vmm() {
    let temp = tempfile::tempdir().expect("a temp dir");
    let dir = temp.path().to_path_buf();
    let d = CloudHypervisorDriver::new(
        "/nonexistent/cloud-hypervisor".into(),
        dir.clone(),
        Duration::from_millis(50),
        DEFAULT_UNPLUG_TIMEOUT,
    )
    .expect("the driver only needs its socket dir to exist");

    let dead = VmId::new_v4();
    let known = VmId::new_v4();
    std::fs::write(dir.join(format!("{dead}.sock")), b"").expect("a leftover socket");
    std::fs::write(dir.join(format!("{known}.sock")), b"").expect("a second one");
    // Ignore non-socket files and socket names without valid VM IDs.
    std::fs::write(dir.join(format!("{dead}.log")), b"").expect("a log");
    std::fs::write(dir.join("not-a-uuid.sock"), b"").expect("somebody else's file");

    assert!(
        d.stray_vms(&[known]).await.is_empty(),
        "nothing is serving either socket, so nothing here is a running vmm — \
         and a file is not a process"
    );
    assert!(
        d.stray_vms(&[]).await.is_empty(),
        "not even the one nobody claims"
    );
}

/// Retain nonempty VMM diagnostics under archived names; discard empty logs.
#[tokio::test]
async fn what_a_torn_down_vmm_said_outlives_the_teardown() {
    let temp = tempfile::tempdir().expect("a temp dir");
    let dir = temp.path().to_path_buf();
    let d = CloudHypervisorDriver::new(
        "/nonexistent/cloud-hypervisor".into(),
        dir.clone(),
        Duration::from_millis(50),
        DEFAULT_UNPLUG_TIMEOUT,
    )
    .expect("the driver only needs its socket dir to exist");

    let id = VmId::new_v4();
    std::fs::write(
        d.vmm_log_path(&id),
        b"WARN Migration aborted as migration command State failed\n",
    )
    .expect("a vmm that said something");

    // Exercise file cleanup shared by ordinary and stray VMM destruction.
    d.remove_files(&id);

    assert!(
        !d.vmm_log_path(&id).exists(),
        "the live name is free again for the next vmm of this id"
    );
    let kept = d.kept_logs(&id);
    assert_eq!(kept.len(), 1, "and what it said is still here: {kept:?}");
    let said = std::fs::read_to_string(&kept[0]).expect("readable");
    assert!(said.contains("Migration aborted"), "{said}");

    // And `vm logs --streams vmm` finds it: the agent reads exactly this
    // list, and the live path is last so the newest is what a reader ends on.
    let served = d.diagnostic_paths(&id);
    assert!(served.contains(&kept[0]), "{served:?}");
    assert_eq!(served.last(), Some(&d.vmm_log_path(&id)));

    // Do not retain empty VMM logs.
    let quiet = VmId::new_v4();
    std::fs::write(d.vmm_log_path(&quiet), b"").expect("an empty log");
    d.remove_files(&quiet);
    assert!(d.kept_logs(&quiet).is_empty());
    assert!(!d.vmm_log_path(&quiet).exists());

    // Twice for one id is two files: a reception that failed and then one
    // that worked must not silently replace the evidence of the first.
    std::fs::write(d.vmm_log_path(&id), b"the second attempt\n").expect("a second log");
    // Separate timestamps because retained-log names use whole seconds.
    let earlier = d.kept_log_path(&id, std::time::SystemTime::now() - Duration::from_secs(5));
    std::fs::rename(&kept[0], &earlier).expect("age the first one");
    d.remove_files(&id);
    assert_eq!(
        d.kept_logs(&id).len(),
        2,
        "both attempts are on disk: {:?}",
        d.kept_logs(&id)
    );
}

/// Hand disk and seed files to the VMM user. Shared boot images and backend sockets keep ownership.
#[test]
fn only_the_files_this_vm_writes_change_hands() {
    let mut s = spec(
        vec![
            VolumeAttachment::Path("/vol/a.raw".into()),
            VolumeAttachment::VhostUserBlk {
                socket: "/run/blk.sock".into(),
                pid: 7,
            },
            VolumeAttachment::FsShare {
                socket: "/run/fs.sock".into(),
                tag: "share".into(),
                pid: 8,
            },
        ],
        vec![],
    );
    s.boot = BootSource::DirectKernel {
        kernel: "/images/vmlinux".into(),
        cmdline: "console=hvc0".into(),
        initramfs: Some("/images/initrd".into()),
    };
    s.cloud_init_seed = Some("/run/seed.raw".into());

    let files = writable_files(&s);
    assert_eq!(
        files,
        vec![PathBuf::from("/vol/a.raw"), PathBuf::from("/run/seed.raw")]
    );
}

/// Without a VMM user, leave file ownership unchanged.
#[test]
fn without_a_vmm_user_nothing_changes_hands() {
    let dir = tempfile::tempdir().unwrap();
    let ch = CloudHypervisorDriver::new(
        PathBuf::from("/nonexistent/cloud-hypervisor"),
        dir.path().join("vms"),
        Duration::from_millis(10),
        Duration::from_millis(10),
    )
    .unwrap();
    let mut s = spec(
        vec![VolumeAttachment::Path("/nonexistent/a.raw".into())],
        vec![],
    );
    s.nics = vec![nic(None)];
    // A path that does not exist would be an error if it were touched.
    ch.hand_over_files(&s).expect("nothing to do");
    assert_eq!(ch.net_form(), NetForm::TapName);
}

/// Landlock must cover configured future hotplug directories at VM creation,
/// because the rules cannot be widened for a later attachment.
#[test]
fn a_sandboxed_vmm_gets_a_rule_for_everything_a_hotplug_could_name() {
    let dir = tempfile::tempdir().unwrap();
    let run = dir.path().join("run");
    let ch = CloudHypervisorDriver::new(
        PathBuf::from("/nonexistent/cloud-hypervisor"),
        run.join("vms"),
        Duration::from_millis(10),
        Duration::from_millis(10),
    )
    .unwrap()
    .with_vmm_user(Some(agent_api::VmmUser {
        name: "meister-vmm".into(),
        uid: 991,
        gid: 991,
        groups: vec![991],
    }))
    .with_landlock_paths(vec![
        PathBuf::from("/images"),
        PathBuf::from("/var/volumes"),
    ]);

    let mut s = spec(
        vec![VolumeAttachment::Path("/dev/mapper/meister-vm0".into())],
        vec![],
    );
    s.nics = vec![nic(None)];
    let form = ch.vm_form(&s);
    let rules = form.landlock.clone().expect("a vmm_user turns landlock on");
    let paths: Vec<&str> = rules.iter().map(|r| r.path.to_str().unwrap()).collect();

    // The run directory, one level ABOVE this driver's own corner: the
    // backends' sockets are siblings of `vms/`, not children.
    assert!(paths.contains(&run.to_str().unwrap()), "{paths:?}");
    assert!(paths.contains(&"/images"), "{paths:?}");
    assert!(paths.contains(&"/var/volumes"), "{paths:?}");
    // And the directory an existing volume came out of, which is how a
    // storage driver that does not put its volumes under `volume_dir` gets
    // covered at all.
    assert!(paths.contains(&"/dev/mapper"), "{paths:?}");
    assert!(rules.iter().all(|r| r.access == "rw"), "{rules:?}");

    let cfg = build_vm_config(&s, &PathBuf::from("/c"), &PathBuf::from("/s"), &form)
        .expect("config builds");
    assert_eq!(cfg["landlock_enable"], true);
    assert_eq!(
        cfg["landlock_rules"][0]["path"],
        run.to_str().unwrap().to_string()
    );
    assert_eq!(cfg["landlock_rules"][0]["access"], "rw");
}

/// Without a VMM user, omit Landlock configuration.
#[test]
fn without_a_vmm_user_the_document_says_nothing_about_landlock() {
    let s = spec(vec![VolumeAttachment::Path("/vol/a.raw".into())], vec![]);
    let cfg = config(&s);
    assert!(cfg.get("landlock_enable").is_none());
    assert!(cfg.get("landlock_rules").is_none());
}

/// Pass the seccomp setting explicitly so a changed upstream default cannot disable it.
#[test]
fn every_vmm_is_started_with_its_seccomp_filter_stated() {
    let args = vmm_args(Path::new("/run/vms/x.sock"), None);
    let at = args.iter().position(|a| a == "--seccomp").expect("stated");
    assert_eq!(args[at + 1], "true");
}
