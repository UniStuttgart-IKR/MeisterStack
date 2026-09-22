# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# One image, two machines, two identities — V08 and L04.
#
# `packages.managed-disk-image` is the generic managed host: no host name of
# a fleet member, no roles, no addresses and no keys. It is what a lab boots
# fresh virtual machines from (L2) before `keys enroll` and the first `apply`
# make each of them a host. The whole idea only works if an image carries NO
# identity — because an image is copied, and two machines that share a
# machine id are one machine as far as systemd, etcd and every log line is
# concerned, while two that share an ssh host key are one machine as far as
# every operator's `known_hosts` is concerned.
#
# So this test does the thing that would expose it: it copies one image
# twice, boots both copies at once, and asks each of them who it is. And it
# looks INSIDE the image as well — mounted read-only as a second disk on one
# of the two — because "the identity is made at first boot" is only true if
# the image did not carry one to begin with.
{ nixpkgs, lib, pkgs, system, self, disko }:

let
  qemu-common = import "${nixpkgs}/nixos/lib/qemu-common.nix" { inherit lib pkgs; };
  mkFleet = import ../lib/mkFleet.nix;

  fleet = mkFleet
    {
      inherit nixpkgs disko;
      meisterstack = self;
    }
    {
      inventory = ./fleet/box/fleet.toml;
      profiles = { };
      extraModules = [
        ({ ... }: {
          imports = [ "${nixpkgs}/nixos/modules/testing/test-instrumentation.nix" ];
          meisterstack.managed.trustedPublicKeys = [
            "two-instances-placeholder:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
          ];
          documentation.enable = lib.mkForce false;
        })
      ];
      inherit system;
    };

  image = fleet.packages.${system}.managed-disk-image;
  generic = fleet.nixosConfigurations.box.config;
in
pkgs.testers.runNixOSTest {
  name = "meister-two-instances-same-image";

  nodes = { };

  testScript = ''
    import glob
    import os
    import shutil
    import time

    QEMU = "${qemu-common.qemuBinary pkgs.qemu_test}"
    IMAGE = glob.glob("${image}/*.qcow2")[0]
    PKI = "${generic.meisterstack.pki.dir}"

    work = os.environ["NIX_BUILD_TOP"]
    print(f"[sizes] managed-disk-image {os.path.getsize(IMAGE)} bytes")


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

    def copy_of(name):
        """A COPY and not a backing file: what a provider does with an image
        is hand each machine its own, and a test that shared one file
        between two guests would be testing something else."""
        path = f"{work}/{name}.qcow2"
        shutil.copyfile(IMAGE, path)
        os.chmod(path, 0o644)
        return path

    def machine(name, disk, pristine=False):
        flags = [
            QEMU, "-m", "2048", "-smp", "2",
            "-drive", f"file={disk},if=none,id=root,format=qcow2,cache=unsafe",
            "-device", f"virtio-blk-pci,drive=root,serial={name.upper()},bootindex=0",
        ]
        if pristine:
            # The image itself, untouched, read-only, as a second disk — so
            # that what is IN it can be read by a machine rather than by a
            # loop device the build sandbox is not allowed to make.
            flags += [
                "-drive", f"file={IMAGE},if=none,id=pristine,format=qcow2,readonly=on",
                "-device", "virtio-blk-pci,drive=pristine,serial=PRISTINE",
            ]
        return track(create_machine(" ".join(flags), name=name))

    start = time.time()
    a = machine("first", copy_of("first"), pristine=True)
    b = machine("second", copy_of("second"))
    a.start()
    b.start()
    a.wait_for_unit("multi-user.target")
    b.wait_for_unit("multi-user.target")
    print(f"[timing] two machines from one image: {time.time() - start:.0f} s")

    # ---------------------------------------------------------------
    # Two machines, two identities.
    # ---------------------------------------------------------------
    ids = {}
    keys = {}
    for name, node in [("first", a), ("second", b)]:
        node.wait_for_unit("sshd.service")
        ids[name] = node.succeed("cat /etc/machine-id").strip()
        keys[name] = node.succeed(
            "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub"
        ).split()[1]
        print(f"{name}: machine-id {ids[name]}  host key {keys[name]}")
        assert len(ids[name]) == 32, ids[name]
        assert keys[name].startswith("SHA256:"), keys[name]

    assert ids["first"] != ids["second"], \
        "two machines from one image share a machine id"
    assert keys["first"] != keys["second"], \
        "two machines from one image share an ssh host key"

    # And neither of them has any key material of this stack: an image is
    # not enrolled, and what makes a machine a host of a fleet arrives
    # afterwards, in a closure and through `keys deliver`.
    for name, node in [("first", a), ("second", b)]:
        left = node.succeed(f"ls -A {PKI} 2>/dev/null | wc -l").strip()
        assert left == "0", f"{name} has {left} file(s) under {PKI}"

    # ---------------------------------------------------------------
    # And the image itself carried none of it.
    # ---------------------------------------------------------------
    a.succeed("mkdir -p /mnt/pristine")
    # The root filesystem of the pristine image, whichever partition it is.
    root = a.succeed(
        "lsblk -ln -o PATH,FSTYPE /dev/disk/by-id/virtio-PRISTINE"
        " | awk '$2 == \"ext4\" { print $1; exit }'"
    ).strip()
    print(f"the pristine image's root filesystem: {root}")
    a.succeed(f"mount -o ro,noload {root} /mnt/pristine")

    # No identity in the image's own filesystem: not a host key, not an
    # identity or serving key of this stack, not an empty directory where
    # one would go.
    #
    # The STORE is excluded, and named rather than hidden: a managed host's
    # closure carries a copy of nixpkgs (the flake registry entry pins the
    # source), and nixpkgs ships example host keys for its netboot profile
    # and its initrd-ssh test — `nixos/modules/profiles/keys/
    # ssh_host_ed25519_key` and friends. They are upstream, they are public,
    # nothing on this machine reads them, and they are the same on every
    # NixOS system in the world. What would make two machines ONE machine is
    # an identity in the place a machine keeps its identity, and that is
    # what is checked here.
    upstream = a.succeed(
        "find /mnt/pristine/nix/store -name 'ssh_host_*' 2>/dev/null | wc -l"
    ).strip()
    print(f"[identity] {upstream} example host key file(s) inside nixpkgs' own source in "
          "the store — upstream's, public, and read by nothing here")
    found = a.succeed(
        "find /mnt/pristine -path /mnt/pristine/nix/store -prune -o"
        " \\( -name 'ssh_host_*' -o -name 'identity.key' -o -name 'serving.key' \\)"
        " -print 2>/dev/null | head -20"
    ).strip()
    assert found == "", f"the image carries key material:\n{found}"

    # And nothing under this stack's key directory either.
    left = a.succeed(f"ls -A /mnt/pristine{PKI} 2>/dev/null | wc -l").strip()
    assert left == "0", f"the image carries {left} file(s) under {PKI}"

    machine_id = a.succeed(
        "cat /mnt/pristine/etc/machine-id 2>/dev/null || true"
    ).strip()
    assert machine_id in ("", "uninitialized"), \
        f"the image carries the machine id {machine_id!r}"

    # A grep over the small, mutable half of the image — /etc and /var are
    # where a key would have to land to be read; the store is world-readable
    # by construction and `checks.installer-no-secrets` is what walks it.
    hits = a.succeed(
        "grep -rls 'PRIVATE KEY' /mnt/pristine/etc /mnt/pristine/var /mnt/pristine/root"
        " 2>/dev/null | head -20 || true"
    ).strip()
    assert hits == "", f"the image carries something that says PRIVATE KEY:\n{hits}"
    a.succeed("umount /mnt/pristine")

    a.shutdown()
    b.shutdown()
    print("one image, two machines, two identities — and the image had none")
  '';
}
