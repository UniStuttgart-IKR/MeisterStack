# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# The other boot mode, end to end: an empty disk becomes a guest that has no
# boot loader at all, and its hypervisor is what starts it.
#
# A `boot = "direct"` host carries no ESP, no systemd-boot and no boot menu.
# What `meister-deploy build` makes for it instead is a bundle — a kernel, an
# initrd and a command line with `init=<toplevel>/init` in it — and the thing
# that loads them is outside the machine. In this test the TEST DRIVER is
# that thing: it starts the second virtual machine with `-kernel`, `-initrd`
# and `-append`, which is exactly what a hypervisor does with the bundle and
# what `lab.py up` will do with it in L2.
#
# What it shows: the medium installs without a boot loader and leaves no
# `/boot` behind; the machine comes up from the bundle and is running the
# system the `init=` in the command line names; `meister-activate` agrees
# about what it booted; boot-mode activation is REFUSED there, with the
# sentence D5 asks for, because there is no boot menu to put a one-shot entry
# in; and switch-mode activation works unchanged, because that half is
# userland.
{ nixpkgs, lib, pkgs, system, self, disko }:

let
  qemu-common = import "${nixpkgs}/nixos/lib/qemu-common.nix" { inherit lib pkgs; };
  mkFleet = import ../lib/mkFleet.nix;

  instrumented = generation: { ... }: {
    imports = [ "${nixpkgs}/nixos/modules/testing/test-instrumentation.nix" ];
    meisterstack.managed.trustedPublicKeys = [
      "vm-direct-placeholder:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    ];
    system.switch.enable = true;
    environment.etc."meister-generation".text = generation;
    documentation.enable = lib.mkForce false;
  };

  fleetWith = modules: mkFleet
    {
      inherit nixpkgs disko;
      meisterstack = self;
    }
    {
      inventory = ./fleet/n1/fleet.toml;
      profiles = { };
      extraModules = modules;
      inherit system;
    };

  fleetB = fleetWith [ (instrumented "B") ];
  systemB = fleetB.nixosConfigurations.n1.config.system.build.toplevel;

  fleetA = fleetWith [
    (instrumented "A")
    { system.extraDependencies = [ systemB ]; }
  ];
  systemA = fleetA.nixosConfigurations.n1.config.system.build.toplevel;
  iso = fleetA.packages.${system}.n1-installer;
  # The three things a hypervisor is handed. The same package
  # `meister-deploy image --kind direct-boot` builds and the same one a
  # release records.
  bundle = fleetA.packages.${system}.n1-direct-boot;
in
pkgs.testers.runNixOSTest {
  name = "meister-install-direct-boot";

  nodes = { };

  testScript = ''
    import glob
    import json
    import os
    import shlex
    import subprocess
    import time

    QEMU = "${qemu-common.qemuBinary pkgs.qemu_test}"
    QEMU_IMG = "${pkgs.qemu_test}/bin/qemu-img"
    ISO = glob.glob("${iso}/iso/*.iso")[0]
    BUNDLE = "${bundle}"
    SYSTEM_A = "${systemA}"
    SYSTEM_B = "${systemB}"
    SERIAL = "MEISTERDIRECT1"
    SIZE = 16000000000

    work = os.environ["NIX_BUILD_TOP"]
    target_disk = f"{work}/target.qcow2"
    subprocess.run([QEMU_IMG, "create", "-f", "qcow2", target_disk, str(SIZE)], check=True)
    print(f"[sizes] iso {os.path.getsize(ISO)} bytes")


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

    def disk_flags():
        return [
            "-drive", f"file={target_disk},if=none,id=disk0,format=qcow2,cache=unsafe",
            "-device", f"virtio-blk-pci,drive=disk0,serial={SERIAL},bootindex=1",
        ]

    def medium(name):
        # No OVMF here, and that is the point: a direct-boot host installs
        # no boot loader, so `nixos-install` never touches an EFI variable
        # and the medium needs no firmware that has them. The ISO's own
        # loader is what starts the medium.
        flags = [QEMU, "-m", "3072", "-smp", "2",
                 "-drive", f"file={ISO},if=none,id=cd,media=cdrom,readonly=on",
                 "-device", "ide-cd,bus=ide.1,drive=cd,bootindex=0"] + disk_flags()
        return track(create_machine(" ".join(flags), name=name))

    def provider_boot(name, kernel, initrd, cmdline):
        """What a hypervisor does with the bundle: load these three and
        start the machine. There is nothing on the disk that could boot it —
        no ESP, no loader, no menu — so if this comes up, it came up because
        the provider was handed the right bytes."""
        flags = [QEMU, "-m", "2048", "-smp", "2",
                 "-kernel", kernel,
                 "-initrd", initrd,
                 "-append", shlex.quote(cmdline)] + disk_flags()
        return track(create_machine(" ".join(flags), name=name))

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

    # ---------------------------------------------------------------
    # 1. The bundle: three names, and a command line that says which
    #    system the kernel is to start.
    # ---------------------------------------------------------------
    kernel = os.path.realpath(f"{BUNDLE}/kernel")
    initrd = os.path.realpath(f"{BUNDLE}/initrd")
    with open(f"{BUNDLE}/cmdline") as fh:
        cmdline = fh.read().strip()
    print(f"kernel  {kernel}")
    print(f"initrd  {initrd}")
    print(f"cmdline {cmdline}")
    assert cmdline.endswith(f"init={SYSTEM_A}/init"), cmdline
    assert kernel.startswith("/nix/store/"), kernel

    # ---------------------------------------------------------------
    # 2. The medium installs, and leaves no boot loader behind.
    # ---------------------------------------------------------------
    one = medium("medium-direct")
    timed("medium boots", lambda: (one.start(), one.wait_for_unit("multi-user.target")))

    target = json.loads(one.succeed("cat /etc/meister-install/target.json"))
    assert target["boot_mode"] == "direct", target
    assert target["toplevel"] == SYSTEM_A, target
    issue = one.succeed("cat /etc/issue")
    assert "boot mode direct" in issue, issue

    output = timed(
        "install",
        lambda: one.succeed(f"meister-install confirm --host n1 --disk {SERIAL} 2>&1"),
    )
    print(output)
    fingerprint = fingerprint_in(output)
    # The sentence a direct host gets instead of "boot from the disk".
    assert "no boot loader" in output, output
    assert "--kind direct-boot" in output, output

    # One partition and no ESP: the layout said so and disko did it.
    parts = one.succeed(f"lsblk -n -o NAME,FSTYPE /dev/disk/by-id/virtio-{SERIAL}")
    print(parts)
    assert parts.count("\n") == 2, f"expected one partition under the disk:\n{parts}"
    assert "vfat" not in parts, parts

    one.succeed("mkdir -p /tmp/look && mount -o ro /dev/disk/by-partlabel/disk-main-root /tmp/look")
    # Nothing was installed into a boot partition, because there is none.
    # `test -e` and not `ls`: on a machine with no /boot at all `ls` exits 2,
    # and a check that reads the right answer out of a failed command is a
    # check that will one day read it out of the wrong one.
    one.succeed(
        'test ! -e /tmp/look/boot || test -z "$(ls -A /tmp/look/boot)"'
    )
    mark = json.loads(one.succeed("cat /tmp/look/etc/meister-install/installed.json"))
    assert mark["host_key_fingerprint"] == fingerprint, mark
    one.succeed("umount /tmp/look")
    one.shutdown()

    # ---------------------------------------------------------------
    # 3. The provider starts it, and it is the system the command line
    #    named.
    # ---------------------------------------------------------------
    n1 = provider_boot("n1", kernel, initrd, cmdline)
    timed("provider boot", lambda: (n1.start(), n1.wait_for_unit("multi-user.target")))

    assert n1.succeed("cat /etc/meister-generation").strip() == "A"
    assert n1.succeed("readlink -f /run/booted-system").strip() == SYSTEM_A
    assert f"init={SYSTEM_A}/init" in n1.succeed("cat /proc/cmdline")
    # …and there is no boot menu on this machine at all.
    n1.fail("test -d /boot/loader")
    n1.fail("bootctl is-installed 2>/dev/null | grep -q yes")

    status = json.loads(n1.succeed("meister-activate status --json"))
    print(json.dumps(status, indent=2))
    assert status["current_system"] == SYSTEM_A, status
    assert status["booted_system"] == SYSTEM_A, status
    # The PROFILE is what `next_boot_system` reads, and on a direct host
    # that is a statement about the system profile and not about the next
    # boot: the hypervisor decides that, out of the bundle it was handed.
    assert status["next_boot_system"] == SYSTEM_A, status
    assert status["generation"] == 1, status

    # ---------------------------------------------------------------
    # 4. Boot mode is refused here, and switch mode is not.
    # ---------------------------------------------------------------
    n1.succeed(f"meister-activate stage {SYSTEM_B}")
    refused = n1.fail(
        f"meister-activate activate --txn t1 --toplevel {SYSTEM_B} --mode boot "
        "--confirm-within 60 --run run-direct 2>&1"
    )
    print(refused)
    assert "no boot fallback" in refused, refused
    assert "--mode switch" in refused, refused
    assert json.loads(n1.succeed("meister-activate status --json"))["open_txns"] == [], \
        "a refused activation left a record"

    n1.succeed(
        f"meister-activate activate --txn t2 --toplevel {SYSTEM_B} --mode switch "
        "--confirm-within 300 --run run-direct"
    )
    assert n1.succeed("cat /etc/meister-generation").strip() == "B", "the switch did not take"
    n1.succeed("meister-activate confirm --txn t2")
    status = json.loads(n1.succeed("meister-activate status --json"))
    assert status["current_system"] == SYSTEM_B, status
    # And the machine still BOOTED the old one: a switch is userland, and
    # the kernel this guest is running came from the provider.
    assert status["booted_system"] == SYSTEM_A, status
    assert status["next_boot_system"] == SYSTEM_B, status
    print(
        "a direct-boot guest takes a switch and refuses a boot, which is the "
        "documented limit of D5 on a machine with no boot menu"
    )
    n1.shutdown()

    print("meister-install: an empty disk became a guest its hypervisor starts")
  '';
}
