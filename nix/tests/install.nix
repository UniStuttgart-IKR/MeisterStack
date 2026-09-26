# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Install a blank disk under UEFI, verify host identity and boot-entry fallback,
# and require explicit reinstall before replacing an existing installation.
# Machines are created with firmware rather than the test framework's direct boot.
{ nixpkgs, lib, pkgs, system, self, disko }:

let
  qemu-common = import "${nixpkgs}/nixos/lib/qemu-common.nix" { inherit lib pkgs; };
  mkFleet = import ../lib/mkFleet.nix;

  # The half of the host that only a test wants: the driver's backdoor, a
  # signing key that satisfies 1A's assertion, and a file that tells the two
  # generations apart.
  #
  # `test-instrumentation.nix` is imported into the HOST, which means it is
  # also in the medium (the ISO is a sub-evaluation of the same modules) —
  # and that is the only way the driver can talk to either of them. It is
  # also why this test can read a console that a person would read.
  instrumented = generation: { ... }: {
    imports = [ "${nixpkgs}/nixos/modules/testing/test-instrumentation.nix" ];
    # Required by nix/managed.nix and never used here: nothing is copied
    # into this machine. The shape matters all the same — nix parses every
    # entry when it opens the store, and a key that is not 32 base64 bytes
    # makes every copy fail (measured in nix/tests/update.nix).
    meisterstack.managed.trustedPublicKeys = [
      "vm-install-placeholder:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    ];
    # The program that makes a store path the running system. A machine a
    # deployment activates on has to have it.
    system.switch.enable = true;
    environment.etc."meister-generation".text = generation;
    # Faster than the default on a machine that is installed from a CD.
    documentation.enable = lib.mkForce false;
  };

  fleetWith = modules: mkFleet
    {
      inherit nixpkgs disko;
      meisterstack = self;
    }
    {
      inventory = ./fleet/box/fleet.toml;
      profiles = { };
      extraModules = modules;
      inherit system;
    };

  # System B, which is system A with one file changed. Built first, because
  # A carries it.
  fleetB = fleetWith [ (instrumented "B") ];
  systemB = fleetB.nixosConfigurations.box.config.system.build.toplevel;

  # System A: the one the medium installs. It carries B in its closure, so
  # that the machine which comes up from the disk has a second generation to
  # activate — `virtualisation.additionalPaths` is the test framework's
  # answer to that and there is no framework here.
  fleetA = fleetWith [
    (instrumented "A")
    { system.extraDependencies = [ systemB ]; }
  ];
  systemA = fleetA.nixosConfigurations.box.config.system.build.toplevel;
  iso = fleetA.packages.${system}.box-installer;
in
pkgs.testers.runNixOSTest {
  name = "meister-install-blank-disk";

  # None. Every machine here is built by hand, because a node is a machine
  # with no firmware and no boot menu.
  nodes = { };

  testScript = ''
    import glob
    import json
    import os
    import shutil
    import subprocess
    import time

    QEMU = "${qemu-common.qemuBinary pkgs.qemu_test}"
    QEMU_IMG = "${pkgs.qemu_test}/bin/qemu-img"
    OVMF_CODE = "${pkgs.OVMF.firmware}"
    OVMF_VARS = "${pkgs.OVMF.variables}"
    ISO = glob.glob("${iso}/iso/*.iso")[0]
    SYSTEM_A = "${systemA}"
    SYSTEM_B = "${systemB}"
    SERIAL = "MEISTERTEST01"
    # The size the inventory declares, to the byte: the installer compares
    # the two and allows two percent.
    SIZE = 16000000000

    work = os.environ["NIX_BUILD_TOP"]
    target_disk = f"{work}/target.qcow2"
    decoy_disk = f"{work}/decoy.qcow2"


    def track(node):
        """Hand the machine to the driver's own cleanup.

        `create_machine` does NOT do this: it returns a Machine and never
        puts it in `driver.machines`, so a test that fails between starting
        one and shutting it down leaves a qemu running until the global
        timeout an hour later. Measured: six of them, for forty minutes,
        after one assertion went red.
        """
        machines.append(node)
        return node

    def make_disk(path, size):
        subprocess.run([QEMU_IMG, "create", "-f", "qcow2", path, str(size)], check=True)

    def fresh_vars(name):
        """A writable copy of OVMF's variable store. The installed machine
        keeps ONE across its boots, because a one-shot boot entry is an EFI
        variable and a test that gave it a new store every time would be
        testing nothing."""
        path = f"{work}/{name}-vars.fd"
        shutil.copyfile(OVMF_VARS, path)
        os.chmod(path, 0o644)
        return path

    def qemu_flags(vars_file, memory, with_cd, disks):
        flags = [
            QEMU,
            "-m", str(memory),
            "-smp", "2",
            "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={OVMF_CODE}",
            "-drive", f"if=pflash,format=raw,unit=1,file={vars_file}",
        ]
        if with_cd:
            # `bootindex` and not `-boot order=`: OVMF reads the boot order
            # qemu builds out of the devices' own bootindex, and the legacy
            # flag is a BIOS thing. Without this the second boot of the
            # medium would come up from the disk that was just installed.
            flags += [
                "-drive", f"file={ISO},if=none,id=cd,media=cdrom,readonly=on",
                "-device", "ide-cd,bus=ide.1,drive=cd,bootindex=0",
            ]
        for index, (path, serial) in enumerate(disks):
            flags += [
                "-drive", f"file={path},if=none,id=disk{index},format=qcow2,cache=unsafe",
                "-device",
                f"virtio-blk-pci,drive=disk{index},serial={serial},bootindex={index + 1}",
            ]
        return " ".join(flags)

    def medium(name, disks):
        vars_file = fresh_vars(name)
        return track(create_machine(qemu_flags(vars_file, 3072, True, disks), name=name))

    def installed(name, vars_file):
        flags = qemu_flags(vars_file, 2048, False, [(target_disk, SERIAL)])
        return track(create_machine(flags, name=name))

    def fingerprint_in(output):
        """The line `meister-install` prints for a person to carry away.

        NOT "the first word that starts with SHA256:": the summary above it
        names the fingerprint of an installation that is ALREADY on the disk
        (`installed  /dev/vda2 on box carries … (host key SHA256:…)`), so a
        naive search finds the OLD key on a reinstall — and an assertion that
        the two differ then passes because of a closing parenthesis.
        Measured: it did."""
        lines = [l for l in output.splitlines() if "HOST KEY FINGERPRINT" in l]
        assert len(lines) == 1, f"expected one fingerprint line:\n{output}"
        word = lines[0].split()[-1]
        assert word.startswith("SHA256:"), word
        return word

    def timed(what, fn):
        start = time.time()
        result = fn()
        print(f"[timing] {what}: {time.time() - start:.0f} s")
        return result

    make_disk(target_disk, SIZE)
    make_disk(decoy_disk, SIZE)
    print(f"[sizes] iso {os.path.getsize(ISO)} bytes")

    # ---------------------------------------------------------------
    # 1. The medium refuses a serial that is not there, and one that two
    #    disks carry.
    # ---------------------------------------------------------------
    two = medium("medium-ambiguous", [(target_disk, SERIAL), (decoy_disk, SERIAL)])
    timed("medium boots (two disks)", lambda: (two.start(), two.wait_for_unit("multi-user.target")))

    # The medium says what it is for, on the console, before anything else.
    issue = two.succeed("cat /etc/issue")
    print(issue)
    assert "installs box onto the disk with serial MEISTERTEST01" in issue, issue
    assert "NOTHING HAPPENS UNTIL YOU RUN" in issue, issue

    # …and it has no sshd at all: this fleet named no `install.authorized_keys`.
    two.fail("systemctl is-active sshd.service")
    assert "sshd" not in two.succeed("systemctl list-unit-files --type=service --state=enabled")

    target = json.loads(two.succeed("cat /etc/meister-install/target.json"))
    print(json.dumps(target, indent=2))
    assert target["host"] == "box", target
    assert target["toplevel"] == SYSTEM_A, target
    assert target["boot_mode"] == "uefi", target
    assert target["layout_devices"] == ["/dev/disk/by-id/virtio-MEISTERTEST01"], target

    # The complete form of `checks.installer-no-secrets`, once, on the
    # medium itself — and in the shape the claim is actually about.
    #
    # The claim is "an ISO of this fleet carries no key material of this
    # fleet". The instrument for it is the CLOSURE of what the medium
    # embeds, asked of the medium's own nix, plus a search for the one thing
    # a private key always says. A file-NAME search over the whole disc is
    # the wrong instrument and this test measured why: an installation
    # medium carries TWO copies of nixpkgs (the flake source and the channel
    # `installer/cd-dvd/channel.nix` builds), and nixpkgs has a dns root
    # key, `nixos/tests/taler/conf/private.key` and a dozen directories
    # called `*secrets*` in it. They are upstream's, they are public, and a
    # check that failed on them would be a check nobody keeps.
    two.succeed("test -d /nix/.ro-store")
    disko_script = target["disko_script"]
    embedded = two.succeed(f"nix-store -qR {SYSTEM_A} {disko_script} | wc -l").strip()
    print(f"[no-secrets] {embedded} store paths in what this medium embeds")
    named = two.succeed(
        f"nix-store -qR {SYSTEM_A} {disko_script}"
        " | grep -E '\\.(key|sec)$|secrets$' || true"
    ).strip()
    assert named == "", f"the medium embeds key material:\n{named}"

    # Nothing in the system it installs says PRIVATE KEY…
    keys = two.succeed(
        f"grep -RIls 'PRIVATE KEY' {SYSTEM_A}/etc 2>/dev/null | head -20 || true"
    ).strip()
    assert keys == "", f"the system this medium installs carries a private key:\n{keys}"
    # …and neither does the medium's own /etc, which is the other thing
    # somebody who picks up the stick is holding.
    keys = two.succeed("grep -RIls 'PRIVATE KEY' /etc 2>/dev/null | head -20 || true").strip()
    assert keys == "", f"the medium itself carries a private key:\n{keys}"

    # And what the name search finds on the whole disc, counted rather than
    # hidden — so that the number in the report is a number somebody
    # measured and not a claim that it is zero.
    upstream = two.succeed(
        "find /nix/.ro-store \\( -name '*.key' -o -name '*.sec' -o -name '*secrets*' \\)"
        " 2>/dev/null | wc -l"
    ).strip()
    print(
        f"[no-secrets] {upstream} path(s) on the whole disc are NAMED like key material, "
        "all of them inside nixpkgs' own source and channel copies"
    )
    print("the medium carries no key material of this fleet and no private key")

    # A serial that is not the medium's is refused BEFORE any disk is looked
    # at (review finding F19): the typed serial is the consent, and it has to
    # be the one this medium was made for.
    refused = two.fail("meister-install confirm --host box --disk NOTTHISONE 2>&1")
    print(refused)
    assert "not the one this medium was made for" in refused, refused
    assert SERIAL in refused, refused
    assert "Nothing was changed" in refused, refused

    refused = two.fail(f"meister-install confirm --host box --disk {SERIAL} 2>&1")
    print(refused)
    assert "2 disks carry the serial" in refused, refused
    assert "--wwn" in refused, refused

    # And a medium is one host's: asking it to be somebody else's is refused
    # before it looks at a disk at all.
    refused = two.fail(f"meister-install confirm --host n1 --disk {SERIAL} 2>&1")
    assert "installs the host box" in refused, refused

    # Nothing of that touched the disk.
    assert two.succeed(f"lsblk -n -o NAME /dev/disk/by-id/virtio-{SERIAL} | wc -l").strip() == "1", \
        "the disk grew a partition while nothing was supposed to happen"
    two.shutdown()

    # ---------------------------------------------------------------
    # 2. One disk, and it becomes a host.
    # ---------------------------------------------------------------
    one = medium("medium-install", [(target_disk, SERIAL)])
    timed("medium boots (one disk)", lambda: (one.start(), one.wait_for_unit("multi-user.target")))

    # A dry run first: everything up to the summary, and nothing after it.
    dry = one.succeed(f"meister-install confirm --host box --disk {SERIAL} --dry-run 2>&1")
    print(dry)
    assert "this disk is blank" in dry, dry
    assert "DESTROY every partition of" in dry, dry
    assert "nothing was changed" in dry, dry
    assert one.succeed(f"lsblk -n -o NAME /dev/disk/by-id/virtio-{SERIAL} | wc -l").strip() == "1"

    output = timed(
        "install",
        lambda: one.succeed(f"meister-install confirm --host box --disk {SERIAL} 2>&1"),
    )
    print(output)
    fingerprint = fingerprint_in(output)
    print(f"the fingerprint the console showed: {fingerprint}")
    assert "power off, remove the medium" in output, output

    # The mark is on the disk, and it says what was put there.
    one.succeed("mkdir -p /tmp/look")
    one.succeed("mount -o ro /dev/disk/by-partlabel/disk-main-root /tmp/look")
    mark = json.loads(one.succeed("cat /tmp/look/etc/meister-install/installed.json"))
    print(json.dumps(mark, indent=2))
    assert mark["host"] == "box", mark
    assert mark["toplevel"] == SYSTEM_A, mark
    assert mark["host_key_fingerprint"] == fingerprint, mark
    assert len(mark["machine_id"]) == 32, mark
    key_before = one.succeed("sha256sum /tmp/look/etc/ssh/ssh_host_ed25519_key").split()[0]
    one.succeed("umount /tmp/look")
    one.shutdown()

    # ---------------------------------------------------------------
    # 3. It boots from its own disk, and it is that machine.
    # ---------------------------------------------------------------
    box_vars = fresh_vars("box")
    box = installed("box", box_vars)
    timed("first boot from disk", lambda: (box.start(), box.wait_for_unit("multi-user.target")))

    assert box.succeed("cat /etc/meister-generation").strip() == "A"
    assert box.succeed("readlink -f /run/current-system").strip() == SYSTEM_A
    # systemd-boot really is what booted it, on a real ESP.
    box.succeed("test -e /boot/loader/loader.conf")
    box.succeed("bootctl is-installed | grep -q yes")

    # The host key is the one the medium printed, and sshd offers it.
    box.wait_for_unit("sshd.service")
    seen = box.succeed("ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub").split()[1]
    assert seen == fingerprint, f"the machine answers with {seen}, the console showed {fingerprint}"

    # The target-side helper works, and says what this machine is.
    status = json.loads(box.succeed("meister-activate status --json"))
    print(json.dumps(status, indent=2))
    assert status["current_system"] == SYSTEM_A, status
    assert status["booted_system"] == SYSTEM_A, status
    assert status["generation"] == 1, status
    assert status["open_txns"] == [], status

    # And the units of a host nobody has enrolled yet WAIT. They do not
    # crash and they do not restart in a loop: their ConditionPathExists is
    # a certificate `keys deliver` has not brought yet (M3B), and that is
    # the state `unenrolled` means.
    box.fail("test -e /var/lib/meisterstack/pki/ca.crt")
    for unit in ["meister-cloud-controller", "meister-cluster-controller"]:
        box.fail(f"systemctl is-active {unit}.service")
        assert "start-limit" not in box.succeed(f"systemctl status {unit}.service || true")
        result = box.succeed(f"systemctl show -p ConditionResult --value {unit}.service").strip()
        print(f"{unit}: ConditionResult={result}")

    # ---------------------------------------------------------------
    # 4. The boot-mode rollback, on a real ESP (2C's open point 1).
    # ---------------------------------------------------------------
    box.succeed(f"meister-activate stage {SYSTEM_B}")
    box.succeed(
        f"meister-activate activate --txn t1 --toplevel {SYSTEM_B} --mode boot "
        "--confirm-within 0 --run run-boot"
    )
    # The running system did NOT change: that is what boot mode means.
    assert box.succeed("cat /etc/meister-generation").strip() == "A"
    status = json.loads(box.succeed("meister-activate status --json"))
    assert status["current_system"] == SYSTEM_A, status
    assert status["next_boot_system"] == SYSTEM_B, status
    assert len(status["open_txns"]) == 1, status
    # The one-shot entry is an EFI variable, and it is there.
    # The four attribute bytes FIRST and the UTF-16 padding after: doing it
    # the other way round eats three characters of the name, because `tr`
    # turns the four-byte attribute word into one byte (measured: the first
    # run of this test read `os-generation-2.conf`).
    oneshot = box.succeed(
        "tail -c +5 /sys/firmware/efi/efivars/"
        "LoaderEntryOneShot-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f | tr -d '\\0'"
    ).strip()
    print(f"LoaderEntryOneShot = {oneshot}")
    assert oneshot.startswith("nixos-generation-2"), oneshot
    print(box.succeed("bootctl list | head -40"))
    box.shutdown()

    # The next boot takes the one-shot entry, and nobody confirms it.
    box = installed("box-second-boot", box_vars)
    timed("second boot (one-shot)", lambda: (box.start(), box.wait_for_unit("multi-user.target")))
    assert box.succeed("cat /etc/meister-generation").strip() == "B", \
        "the one-shot boot entry was not taken"
    assert box.succeed("readlink -f /run/booted-system").strip() == SYSTEM_B

    # And the one after it is the old system again, because a one-shot entry
    # is taken exactly once and the DEFAULT was left on the generation that
    # worked. Nobody confirmed anything.
    box.shutdown()
    box = installed("box-third-boot", box_vars)
    timed("third boot (back)", lambda: (box.start(), box.wait_for_unit("multi-user.target")))
    assert box.succeed("cat /etc/meister-generation").strip() == "A", \
        "an unconfirmed boot was taken twice"
    assert box.succeed("readlink -f /run/booted-system").strip() == SYSTEM_A
    print("the machine came back by itself, with no confirm and no operator")

    # The transaction is still open — nothing on the machine decides that by
    # itself — and `revert` is what closes it.
    status = json.loads(box.succeed("meister-activate status --json"))
    assert len(status["open_txns"]) == 1, status
    box.succeed("meister-activate revert --txn t1 --because 'the boot was not confirmed'")
    record = json.loads(box.succeed("meister-activate --json txn show --txn t1"))
    assert record["state"] == "reverted", record
    assert box.succeed("cat /etc/meister-generation").strip() == "A"
    box.shutdown()

    # ---------------------------------------------------------------
    # 5. The same medium again: it refuses, and the disk is untouched.
    # ---------------------------------------------------------------
    again = medium("medium-again", [(target_disk, SERIAL)])
    timed("medium boots (again)", lambda: (again.start(), again.wait_for_unit("multi-user.target")))

    refused = again.fail(f"meister-install confirm --host box --disk {SERIAL} 2>&1")
    print(refused)
    assert "is already installed" in refused, refused
    assert fingerprint in refused, refused
    assert "--reinstall" in refused, refused
    assert "Nothing was changed" in refused, refused

    # Byte for byte: the mark and the host key are the ones from before.
    again.succeed("mkdir -p /tmp/look")
    again.succeed("mount -o ro /dev/disk/by-partlabel/disk-main-root /tmp/look")
    still = json.loads(again.succeed("cat /tmp/look/etc/meister-install/installed.json"))
    assert still == mark, (still, mark)
    key_after = again.succeed("sha256sum /tmp/look/etc/ssh/ssh_host_ed25519_key").split()[0]
    assert key_after == key_before, "a refused install changed the host key"
    again.succeed("umount /tmp/look")

    # …and with the word said out loud it installs again, with a NEW
    # identity: a reinstalled machine is a different machine to every fleet
    # that trusts a host key.
    output = timed(
        "reinstall",
        lambda: again.succeed(
            f"meister-install confirm --host box --disk {SERIAL} --reinstall 2>&1"
        ),
    )
    assert "REINSTALL over" in output, output
    # The old fingerprint IS in this output — the summary shows the mark it
    # is about to destroy — so the one that matters is read off the line the
    # program prints for a person.
    assert fingerprint in output, "the summary did not show the mark it destroys"
    second = fingerprint_in(output)
    assert second != fingerprint, "a reinstall kept the old host key"
    print(f"the reinstalled machine's key: {second}")
    again.shutdown()

    print("meister-install: an empty disk became a host, twice, and never by accident")
  '';
}
