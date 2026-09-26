# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Install a UEFI controller and direct-boot agent, enroll their identities,
# bootstrap the fleet, update it, and exercise a provider-managed kernel change.
# Manifests are evaluated at build time; target machines use real closures,
# certificates, SSH transport, and nested virtualization.
{ nixpkgs, lib, pkgs, system, self, disko }:

let
  qemu-common = import "${nixpkgs}/nixos/lib/qemu-common.nix" { inherit lib pkgs; };
  sshKeys = import "${nixpkgs}/nixos/tests/ssh-keys.nix" pkgs;
  mkFleet = import ../lib/mkFleet.nix;

  # The CA, as an operator has it: the script from this repository with an
  # openssl it can find. Not a package of this flake — `meister-ca` is not
  # packaged yet (G5 of lane 3B) — and a test that shipped a different script
  # from the one an operator runs would prove nothing about that one.
  meisterCa = pkgs.writeShellScriptBin "meister-ca" (builtins.readFile ../../tools/meister-ca);

  # The half of a host of this fleet that only a test wants.
  #
  # `test-instrumentation.nix` is what the driver talks through, and it is
  # imported into the HOST — so it is in the medium as well (the ISO is a
  # sub-evaluation of the same modules), which is how the test can read a
  # console a person would read.
  instrumented = generation: extra: { config, ... }: {
    imports = [ "${nixpkgs}/nixos/modules/testing/test-instrumentation.nix" ];
    # What this fleet listens on, opened where it listens.
    #
    # In an operator's repository this line lives in `profiles/base.nix` —
    # the template writes it there, because a host's firewall belongs to the
    # host and the service modules publish the numbers rather than opening
    # them (`meisterstack.ports`, nix/services.nix). This test has no
    # profiles, so it lives with the rest of the test's own half.
    #
    # Measured, not assumed: without it the agent's session to its cluster is
    # dropped by the CLUSTER host's firewall — `tcp connect error: deadline
    # has elapsed`, every few seconds, for as long as the run waited — while
    # the cluster's own session to the cloud on the same machine came up
    # fine. A node that cannot register is a node that never appears in
    # `meister node ls`.
    networking.firewall.allowedTCPPorts = with config.meisterstack.ports; [
      cloud.api
      cloud.grpc
      cluster.api
      cluster.grpc
      etcd.peer
    ];
    # Required by nix/managed.nix. The key this fleet really signs with is
    # generated while the test runs and reaches the targets through
    # `extra-keys.conf` (the road M0 probe S12 measured). The SHAPE matters
    # even for a placeholder: nix parses every entry of
    # `trusted-public-keys` when it opens the store, and one that is not 32
    # base64 bytes makes every copy fail — measured in nix/tests/update.nix.
    meisterstack.managed.trustedPublicKeys = [
      "vm-bootstrap-placeholder:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    ];
    nix.extraOptions = ''
      !include /etc/nix/extra-keys.conf
    '';
    # The operator's key, so that `nix copy` and `meister-activate` have a
    # way in. `managed.nix` enables sshd and says `prohibit-password`.
    users.users.root.openssh.authorizedKeys.keys = [ sshKeys.snakeOilPublicKey ];
    # The program that makes a store path the running system.
    system.switch.enable = true;
    environment.etc."meister-generation".text = generation;
    documentation.enable = lib.mkForce false;
  } // extra;

  fleetWith = modules: mkFleet
    {
      inherit nixpkgs disko;
      meisterstack = self;
    }
    {
      inventory = ./fleet/bootstrap/fleet.toml;
      profiles = { };
      extraModules = modules;
      inherit system;
    };

  # Four evaluations of one fleet, and the difference between each pair is
  # one line:
  #
  #   A  what the medium installs
  #   B  one file changed        — what the BOOTSTRAP activates
  #   C  one file changed again  — the update over the same verbs
  #   D  C with another kernel command line — the reboot class, and on a
  #      direct-boot host that is a `provider-reboot`
  #
  # The kernel command line is the cheapest kernel change there is: the
  # kernel and the initrd are the same store paths and
  # `kernel_params_sha256` is not, which is exactly one of the three fields
  # the planner compares.
  fleetA = fleetWith [ (instrumented "A" { }) ];
  fleetB = fleetWith [ (instrumented "B" { }) ];
  fleetC = fleetWith [ (instrumented "C" { }) ];
  fleetD = fleetWith [ (instrumented "C" { boot.kernelParams = [ "meister.round=D" ]; }) ];

  toplevel = fleet: id: fleet.nixosConfigurations.${id}.config.system.build.toplevel;
  bundle = fleet: id: fleet.packages.${system}."${id}-direct-boot";
  manifestOf = fleet: fleet.packages.${system}.manifest;

  # Everything the operator's store has to hold: it builds nothing and
  # reaches no cache, so every derivation `resolve`, `build` and `install`
  # realise has to be valid there already.
  storeOf = fleet: [
    (toplevel fleet "box")
    (toplevel fleet "box").drvPath
    (toplevel fleet "n1")
    (toplevel fleet "n1").drvPath
    (bundle fleet "n1")
    (bundle fleet "n1").drvPath
  ];
in
pkgs.testers.runNixOSTest {
  name = "meister-bootstrap-fleet";

  nodes = {
    # 192.168.1.1 on vlan 1. The workstation: the tool, the cli, the CA
    # script, a git repository, a signing key — and the store.
    operator = { ... }: {
      environment.systemPackages = [
        pkgs.meisterstack
        pkgs.git
        pkgs.jq
        pkgs.openssl
        meisterCa
      ];
      nix.settings.experimental-features = [ "nix-command" ];
      virtualisation.writableStore = true;
      virtualisation.memorySize = 4096;
      virtualisation.diskSize = 16384;
      virtualisation.additionalPaths =
        storeOf fleetA
        ++ storeOf fleetB
        ++ storeOf fleetC
        ++ storeOf fleetD
        ++ [
          # The two mediums. `meister-deploy install` realises the
          # derivation the release names, and a derivation whose output is
          # already valid is realised without building anything — which is
          # what makes a real `install` possible in a VM with no network.
          fleetA.packages.${system}.box-installer
          fleetA.packages.${system}.box-installer.drvPath
          fleetA.packages.${system}.n1-installer
          fleetA.packages.${system}.n1-installer.drvPath
          # And the packages the manifests name beside the systems.
          pkgs.meisterstack
          pkgs.meisterstack.drvPath
          pkgs.cloud-hypervisor-meister
          pkgs.cloud-hypervisor-meister.drvPath
          pkgs.guest-tiny
          pkgs.guest-tiny.drvPath
        ];
      environment.etc."vm-fleet/nix-manifest-a.json".source = manifestOf fleetA;
      environment.etc."vm-fleet/nix-manifest-b.json".source = manifestOf fleetB;
      environment.etc."vm-fleet/nix-manifest-c.json".source = manifestOf fleetC;
      environment.etc."vm-fleet/nix-manifest-d.json".source = manifestOf fleetD;
      environment.etc."vm-fleet/fleet.toml".source = ./fleet/bootstrap/fleet.toml;
    };
  };

  testScript = ''
    import glob
    import json
    import os
    import shlex
    import shutil
    import subprocess
    import time

    QEMU = "${qemu-common.qemuBinary pkgs.qemu_test}"
    QEMU_IMG = "${pkgs.qemu_test}/bin/qemu-img"
    OVMF_CODE = "${pkgs.OVMF.firmware}"
    OVMF_VARS = "${pkgs.OVMF.variables}"
    ISO_BOX = glob.glob("${fleetA.packages.${system}.box-installer}/iso/*.iso")[0]
    ISO_N1 = glob.glob("${fleetA.packages.${system}.n1-installer}/iso/*.iso")[0]
    BUNDLE_A = "${bundle fleetA "n1"}"
    BUNDLE_B = "${bundle fleetB "n1"}"
    BUNDLE_D = "${bundle fleetD "n1"}"
    SYSTEM_A_N1 = "${toplevel fleetA "n1"}"
    SIZE = 16000000000

    # The switch the test framework already runs for its own node, which is
    # how a machine built by hand here reaches the operator at 192.168.1.1.
    VDE = os.environ["QEMU_VDE_SOCKET_1"]

    work = os.environ["NIX_BUILD_TOP"]
    box_disk = f"{work}/box.qcow2"
    n1_disk = f"{work}/n1.qcow2"

    start = time.time()

    def elapsed(what):
        print(f"[timing] {what}: {time.time() - start:.0f} s from the start")

    def timed(what, fn):
        began = time.time()
        result = fn()
        print(f"[timing] {what}: {time.time() - began:.0f} s")
        return result

    def track(node):
        """Hand the machine to the driver's own cleanup.

        `create_machine` does NOT do this: it returns a Machine and never
        puts it in `driver.machines`, so a test that fails between starting
        one and shutting it down leaves a qemu running until the global
        timeout an hour later (measured in lane 3A: six of them, for forty
        minutes, after one assertion went red)."""
        machines.append(node)
        return node

    def make_disk(path):
        subprocess.run([QEMU_IMG, "create", "-f", "qcow2", path, str(SIZE)], check=True)

    def fresh_vars(name):
        """A writable copy of OVMF's variable store. `box` keeps ONE across
        its boots, because a one-shot boot entry is an EFI variable."""
        path = f"{work}/{name}-vars.fd"
        shutil.copyfile(OVMF_VARS, path)
        os.chmod(path, 0o644)
        return path

    def net(mac):
        # The same flags the framework gives its own nodes
        # (nixos/lib/qemu-common.nix), with the machine's number in the mac.
        return [
            "-device", f"virtio-net-pci,netdev=vlan1,mac={mac}",
            "-netdev", f"vde,id=vlan1,sock={VDE}",
        ]

    def disk(path, serial, index=1):
        return [
            "-drive", f"file={path},if=none,id=disk0,format=qcow2,cache=unsafe",
            "-device", f"virtio-blk-pci,drive=disk0,serial={serial},bootindex={index}",
        ]

    def medium_of(name, iso, path, serial, mac, vars_file=None):
        """The machine with the installer medium in its drive.

        `bootindex` and not `-boot order=`: OVMF reads the boot order qemu
        builds out of the devices' own bootindex, and the legacy flag is a
        BIOS thing. `n1` has no firmware at all — a direct-boot host installs
        no loader, so `nixos-install` never touches an EFI variable and the
        medium needs no OVMF to have them."""
        flags = [QEMU, "-m", "3072", "-smp", "2"]
        if vars_file:
            flags += [
                "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={OVMF_CODE}",
                "-drive", f"if=pflash,format=raw,unit=1,file={vars_file}",
            ]
        flags += [
            "-drive", f"file={iso},if=none,id=cd,media=cdrom,readonly=on",
            "-device", "ide-cd,bus=ide.1,drive=cd,bootindex=0",
        ] + disk(path, serial) + net(mac)
        return track(create_machine(" ".join(flags), name=name))

    def from_disk(name, vars_file, mac):
        """`box`, booting itself: OVMF, the same variable store every time,
        and systemd-boot on the ESP the layout made."""
        flags = [
            QEMU, "-m", "2048", "-smp", "2",
            "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={OVMF_CODE}",
            "-drive", f"if=pflash,format=raw,unit=1,file={vars_file}",
        ] + disk(box_disk, "MEISTERBOX01") + net(mac)
        return track(create_machine(" ".join(flags), name=name))

    def provider_boot(name, kernel, initrd, cmdline, mac):
        """What a hypervisor does with the bundle: load these three and start
        the machine. There is nothing on that disk that could boot it — no
        ESP, no loader, no menu — so if it comes up, it came up because the
        provider was handed the right bytes."""
        flags = [
            QEMU, "-m", "2048", "-smp", "2",
            "-kernel", kernel,
            "-initrd", initrd,
            "-append", shlex.quote(cmdline),
        ] + disk(n1_disk, "MEISTERN101") + net(mac)
        return track(create_machine(" ".join(flags), name=name))

    def bundle_of(path):
        """The three values a provider is handed, read out of the directory
        `meister-deploy image --kind direct-boot` builds."""
        with open(f"{path}/cmdline") as fh:
            cmdline = fh.read().strip()
        return (
            os.path.realpath(f"{path}/kernel"),
            os.path.realpath(f"{path}/initrd"),
            cmdline,
        )

    def fingerprint_in(output):
        """The line `meister-install` prints for a person to carry away.

        NOT "the first word that starts with SHA256:": the summary above it
        names the fingerprint of an installation that is already on the disk,
        so a naive search finds the OLD key on a reinstall (measured in lane
        3A, where exactly that made an assertion pass for the wrong
        reason)."""
        lines = [l for l in output.splitlines() if "HOST KEY FINGERPRINT" in l]
        assert len(lines) == 1, f"expected one fingerprint line:\n{output}"
        word = lines[0].split()[-1]
        assert word.startswith("SHA256:"), word
        return word

    def reconnect(m):
        """The machine rebooted under us, because the TOOL rebooted it over
        ssh. The driver's shell died with it; the socket did not (qemu holds
        that end), so what is needed is to wait for the new one rather than
        to write into the old."""
        m.connected = False
        m.connect()

    make_disk(box_disk)
    make_disk(n1_disk)
    print(f"[sizes] box iso {os.path.getsize(ISO_BOX)} bytes")
    print(f"[sizes] n1  iso {os.path.getsize(ISO_N1)} bytes")

    operator.start()
    operator.wait_for_unit("multi-user.target")
    operator.succeed("ip -4 addr show eth1 | grep -q 'inet 192.168.1.1/24'")

    # ---------------------------------------------------------------
    # 0. The operator's repository, its CA and its signing key
    # ---------------------------------------------------------------
    operator.succeed("mkdir -p /root/.ssh /root/fleet /root/keys /root/out /root/ca")
    operator.copy_from_host("${sshKeys.snakeOilPrivateKey}", "/root/.ssh/id_ed25519")
    operator.succeed("chmod 600 /root/.ssh/id_ed25519")
    operator.succeed("cp /etc/vm-fleet/fleet.toml /root/fleet/fleet.toml")
    operator.succeed("chmod 644 /root/fleet/fleet.toml")
    operator.succeed(
        "printf '.meister-deploy/\\nresult*\\n' > /root/fleet/.gitignore"
    )
    # A manifest says what its inputs were locked to. This repository has no
    # inputs — the evaluation happened elsewhere — and an empty lock is what
    # that looks like; a missing one is refused.
    operator.succeed(
        "printf '%s' '{\"nodes\":{\"root\":{}},\"root\":\"root\",\"version\":7}' "
        "> /root/fleet/flake.lock"
    )

    def commit(what):
        """A manifest names the TREE it came from, and `resolve` refuses a
        dirty one — so every file this test writes into the repository is
        committed before the next evaluation, which is also what an operator
        does with them: `known_hosts`, the requests and the certificates are
        public and belong in git (lane 3B)."""
        operator.succeed("git -C /root/fleet add -A")
        operator.succeed(
            f"git -C /root/fleet -c user.name=test -c user.email=test@example "
            f"commit -q --allow-empty -m {shlex.quote(what)}"
        )

    operator.succeed("git -C /root/fleet init -q")
    commit("the fleet")

    operator.succeed(
        "nix-store --generate-binary-cache-key vm-bootstrap "
        "/root/keys/signing.sec /root/keys/signing.pub"
    )
    public = operator.succeed("cat /root/keys/signing.pub").strip()

    # The fleet's own certificate authority, beside the repository. Its key
    # is made here and stays here.
    operator.succeed("meister-ca --dir /root/ca")
    operator.succeed("test -f /root/ca/ca.key && test -f /root/ca/ca.crt")
    # The cloud's key-encryption key: an OPERATOR FILE, which this tool never
    # makes and never replaces. 64 hex characters and no newline.
    operator.succeed(
        "openssl rand -hex 32 | tr -d '\\n' > /root/ca/secrets.key && "
        "chmod 600 /root/ca/secrets.key"
    )
    # And the operator's own client certificate, which is what the cordon and
    # the drain of D7 authenticate with. `--admin` is `O=system:masters`,
    # which is the identity above the user directory — the one a fleet has
    # before it has users.
    operator.succeed("meister-ca --dir /root/ca --admin operator")
    operator.succeed("test -f /root/ca/operator.crt && test -f /root/ca/operator.key")
    operator.succeed(
        "printf '%s\\n' "
        "'default_profile = \"cloud\"' "
        "'[profiles.cloud]' "
        "'endpoint = \"https://192.168.1.2:3000\"' "
        "'ca_cert = \"../ca/ca.crt\"' "
        "'credential = { type = \"mtls\", cert = \"../ca/operator.crt\", "
        "key = \"../ca/operator.key\" }' "
        "> /root/fleet/cli.toml"
    )
    # …and it belongs to the repository, so it is committed like the rest:
    # `resolve` refuses a tree with an uncommitted file in it.
    commit("the operator's cli")

    def deploy(name, manifest):
        """resolve -> build: the two verbs that turn an evaluation into a
        release."""
        operator.succeed(
            f"cd /root/fleet && meister-deploy resolve --from /etc/vm-fleet/{manifest} "
            f"--repo /root/fleet --out /root/out/m-{name}.json"
        )
        operator.succeed(
            f"cd /root/fleet && meister-deploy build --manifest /root/out/m-{name}.json "
            f"--sign-key /root/keys/signing.sec --repo /root/fleet "
            f"--out /root/out/r-{name}.json"
        )
        return f"/root/out/r-{name}.json"

    def make_plan(release, name, kind="upgrade", select="all", extra=""):
        status, _ = operator.execute(
            f"cd /root/fleet && meister-deploy plan --release {release} --select {select} "
            f"--kind {kind} --repo /root/fleet --identity /root/.ssh/id_ed25519 "
            f"--inventory /root/fleet/fleet.toml --out /root/out/p-{name}.json {extra}"
        )
        return status, f"/root/out/p-{name}.json"

    def read(path):
        return json.loads(operator.succeed(f"cat {path}"))

    def approvals(plan):
        return " ".join(
            f"--approve {a['class']}={a['bound_plan_id']}" for a in read(plan)["approvals"]
        )

    def apply(plan, release, extra="", expect=0):
        status, out = operator.execute(
            f"cd /root/fleet && meister-deploy apply --plan {plan} --release {release} "
            f"--repo /root/fleet --identity /root/.ssh/id_ed25519 "
            f"--inventory /root/fleet/fleet.toml {approvals(plan)} {extra}"
        )
        assert status == expect, f"apply exited {status}, expected {expect}:\n{out}"
        return out

    def run_of(out):
        return out.splitlines()[0].strip()

    def receipt_of(run):
        return read(f"/root/fleet/.meister-deploy/runs/{run}/receipt.json")

    def generation(machine):
        return machine.succeed("cat /etc/meister-generation").strip()

    # ---------------------------------------------------------------
    # 1. `plan --kind install`, and the mediums it asks for
    # ---------------------------------------------------------------
    release_a = deploy("a", "nix-manifest-a.json")
    status, plan_install = make_plan(release_a, "install", kind="install")
    assert status == 0, f"an install of two blank machines is exit 0, was {status}"
    the_plan = read(plan_install)
    installs = [a for a in the_plan["actions"] if a["kind"] == "install"]
    assert len(installs) == 2, installs
    assert {a["host"] for a in installs} == {"box", "n1"}, installs
    assert [a["class"] for a in the_plan["approvals"]] == ["destructive"], the_plan["approvals"]
    for action in installs:
        assert action["approval_class"] == "destructive", action
    plan_id = the_plan["plan_id"]

    for host, serial in [("box", "MEISTERBOX01"), ("n1", "MEISTERN101")]:
        sheet = timed(
            f"install {host}",
            lambda host=host: operator.succeed(
                f"cd /root/fleet && meister-deploy install --plan {plan_install} "
                f"--release {release_a} --host {host} "
                f"--approve destructive={plan_id} 2>&1"
            ),
        )
        print(sheet)
        assert serial in sheet, sheet
        assert f"meister-install confirm --host {host} --disk {serial}" in sheet, sheet
        record = read(f"/root/fleet/.meister-deploy/media/{host}.json")
        assert record["plan_id"] == plan_id, record
        assert record["release_id"] == read(release_a)["release_id"], record
    # The medium the driver boots is the medium the tool named.
    assert read("/root/fleet/.meister-deploy/media/box.json")["store_path"] == ISO_BOX
    assert read("/root/fleet/.meister-deploy/media/n1.json")["store_path"] == ISO_N1
    elapsed("release, install plan and both mediums")

    # …and an approval is bound to its plan: the same medium with another
    # plan's id is refused.
    refused = operator.fail(
        f"cd /root/fleet && meister-deploy install --plan {plan_install} "
        f"--release {release_a} --host box --approve destructive=plan-somebody-elses 2>&1"
    )
    assert "destructive" in refused, refused

    # ---------------------------------------------------------------
    # 2. Two empty disks become two machines
    # ---------------------------------------------------------------
    box_vars = fresh_vars("box")
    medium = medium_of(
        "medium-box", ISO_BOX, box_disk, "MEISTERBOX01", "52:54:00:12:01:02", box_vars
    )
    timed("box medium boots", lambda: (medium.start(), medium.wait_for_unit("multi-user.target")))
    issue = medium.succeed("cat /etc/issue")
    assert "installs box onto the disk with serial MEISTERBOX01" in issue, issue
    out = timed(
        "box installs",
        lambda: medium.succeed("meister-install confirm --host box --disk MEISTERBOX01 2>&1"),
    )
    box_fingerprint = fingerprint_in(out)
    print(f"box shows: {box_fingerprint}")
    medium.shutdown()

    medium = medium_of("medium-n1", ISO_N1, n1_disk, "MEISTERN101", "52:54:00:12:01:03")
    timed("n1 medium boots", lambda: (medium.start(), medium.wait_for_unit("multi-user.target")))
    out = timed(
        "n1 installs",
        lambda: medium.succeed("meister-install confirm --host n1 --disk MEISTERN101 2>&1"),
    )
    n1_fingerprint = fingerprint_in(out)
    print(f"n1 shows: {n1_fingerprint}")
    # A direct-boot host is told it has no loader and what to hand its
    # provider instead.
    assert "no boot loader" in out, out
    medium.shutdown()
    elapsed("both disks installed")

    # ---------------------------------------------------------------
    # 3. They come up — one by itself, one because its provider says so
    # ---------------------------------------------------------------
    box = from_disk("box", box_vars, "52:54:00:12:01:02")
    # `allow_reboot`: without it the driver adds `-no-reboot` and the machine
    # would DISAPPEAR when the rollout reboots it later.
    timed("box first boot", lambda: (box.start(allow_reboot=True), box.wait_for_unit("multi-user.target")))
    kernel, initrd, cmdline = bundle_of(BUNDLE_A)
    print(f"n1 bundle A: {kernel} / {initrd} / {cmdline}")
    assert cmdline.endswith(f"init={SYSTEM_A_N1}/init"), cmdline
    n1 = provider_boot("n1", kernel, initrd, cmdline, "52:54:00:12:01:03")
    timed("n1 provider boot", lambda: (n1.start(allow_reboot=True), n1.wait_for_unit("multi-user.target")))

    for machine, address in [(box, "192.168.1.2"), (n1, "192.168.1.3")]:
        machine.wait_for_unit("sshd.service")
        machine.succeed(f"ip -4 addr show eth0 | grep -q 'inet {address}/24'")
    # box boots itself; n1 has no menu to boot from.
    box.succeed("bootctl is-installed | grep -q yes")
    n1.fail("test -d /boot/loader")
    assert generation(box) == "A" and generation(n1) == "A"

    # The signing key the targets accept, the way M0 probe S12 measured it.
    for machine in [box, n1]:
        machine.succeed(f"echo 'extra-trusted-public-keys = {public}' > /etc/nix/extra-keys.conf")
        machine.succeed("systemctl restart nix-daemon.service")
        machine.wait_until_succeeds("nix config show | grep -q vm-bootstrap", timeout=30)

    # Neither of them has an identity, and their units say so rather than
    # restarting for ever: `unenrolled` is a state and never a pass.
    box.fail("test -e /var/lib/meisterstack/pki/ca.crt")
    n1.fail("test -e /var/lib/meisterstack/pki/ca.crt")
    box.fail("systemctl is-active meister-cloud-controller.service")
    n1.fail("systemctl is-active meister-agent.service")
    elapsed("both hosts up from their own disks")

    # ---------------------------------------------------------------
    # 4. Enrolment: a fingerprint from a console, and nothing else
    # ---------------------------------------------------------------
    wrong = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    refused = operator.fail(
        f"cd /root/fleet && meister-deploy keys enroll box --fingerprint {wrong} 2>&1"
    )
    assert "is not the one you typed" in refused, refused
    assert box_fingerprint in refused, refused
    operator.fail("test -e /root/fleet/known_hosts")

    for host, fingerprint in [("box", box_fingerprint), ("n1", n1_fingerprint)]:
        out = operator.succeed(
            f"cd /root/fleet && meister-deploy keys enroll {host} "
            f"--fingerprint {fingerprint} 2>&1"
        )
        assert "ssh.host_key" in out, out
    known = operator.succeed("cat /root/fleet/known_hosts")
    assert "192.168.1.2 ssh-ed25519 " in known, known
    assert "192.168.1.3 ssh-ed25519 " in known, known

    # The inventory is the operator's own file: the tool prints the line and
    # does not edit it. The manifests are the evaluation, and the fingerprint
    # the machine showed goes into both.
    for host, fingerprint in [("BOX", box_fingerprint), ("N1", n1_fingerprint)]:
        operator.succeed(
            f"sed -i 's|SHA256:PLACEHOLDER-THE-TEST-FILLS-IN-{host}|{fingerprint}|' "
            f"/root/fleet/fleet.toml"
        )
        for name in ["a", "b", "c", "d"]:
            operator.succeed(
                f"sed -i 's|SHA256:PLACEHOLDER-THE-TEST-FILLS-IN-{host}|{fingerprint}|' "
                f"/etc/vm-fleet/nix-manifest-{name}.json"
            )
    commit("the fingerprints the machines showed")

    # ---------------------------------------------------------------
    # 5. What an upgrade may not do, and what a bootstrap needs first
    # ---------------------------------------------------------------
    release_b = deploy("b", "nix-manifest-b.json")
    status, plan_up = make_plan(release_b, "upgrade")
    assert status == 2, f"an unenrolled host blocks an upgrade, exit was {status}"
    blocked = read(plan_up)
    for host in ["box", "n1"]:
        assert blocked["hosts"][host]["verdict"] == "unenrolled", blocked["hosts"][host]
        why = " ".join(blocked["hosts"][host]["reasons"])
        assert "--kind bootstrap" in why, why

    status, plan_early = make_plan(release_b, "early", kind="bootstrap")
    assert status == 2, f"nothing issued yet, exit was {status}"
    why = " ".join(read(plan_early)["hosts"]["n1"]["reasons"])
    assert "keys csr --host n1" in why, why

    # ---------------------------------------------------------------
    # 6. The keys are made ON the hosts; only requests travel
    # ---------------------------------------------------------------
    # `box` carries two tiers and the fleet gives it ONE identity.key
    # (grenze G1 of lane 3B), so the operator says which tier it is for. The
    # cloud identity of a cloud with no siblings is not needed — nothing
    # dials it.
    out = operator.succeed(
        "cd /root/fleet && meister-deploy keys csr --host box --kind identity "
        "--as cluster --manifest /root/out/m-b.json --repo /root/fleet "
        "--identity /root/.ssh/id_ed25519 2>&1"
    )
    assert "CN=system:cluster:cp" in out, out
    operator.succeed(
        "cd /root/fleet && meister-deploy keys csr --host box --kind serving "
        "--manifest /root/out/m-b.json --repo /root/fleet "
        "--identity /root/.ssh/id_ed25519"
    )
    # An agent has one role and needs no `--as`, and it serves no port, so it
    # needs no serving certificate either.
    out = operator.succeed(
        "cd /root/fleet && meister-deploy keys csr --host n1 --kind identity "
        "--manifest /root/out/m-b.json --repo /root/fleet "
        "--identity /root/.ssh/id_ed25519 2>&1"
    )
    assert "CN=system:node:n1" in out, out

    for machine, names in [(box, ["identity", "serving"]), (n1, ["identity"])]:
        for name in names:
            assert machine.succeed(
                f"stat -c '%a %U:%G' /var/lib/meisterstack/pki/{name}.key"
            ).strip() == "600 meister:meister"
            machine.fail(f"test -e /var/lib/meisterstack/pki/{name}.crt")
    for text in [
        operator.succeed("cat /root/fleet/pki/csr/box-identity.csr"),
        operator.succeed("cat /root/fleet/pki/csr/n1-identity.csr"),
    ]:
        assert "BEGIN CERTIFICATE REQUEST" in text, text
        assert "PRIVATE KEY" not in text, "a key left a host"

    for host, ca_kinds in [("box", ["cluster", "serving"]), ("n1", ["node"])]:
        for kind in ca_kinds:
            operator.succeed(
                f"cd /root/fleet && meister-deploy keys issue --host {host} --kind {kind} "
                f"--manifest /root/out/m-b.json --repo /root/fleet "
                f"--inventory /root/fleet/fleet.toml --meister-ca meister-ca"
            )
    subject = operator.succeed(
        "openssl x509 -in /root/fleet/pki/issued/n1/identity.crt -noout -subject"
    )
    assert "CN=system:node:n1" in subject, subject
    assert "O=system:nodes" in subject, subject
    commit("the requests and the certificates")
    elapsed("enrolled and issued")

    # ---------------------------------------------------------------
    # 7. The bootstrap
    # ---------------------------------------------------------------
    status, plan_boot = make_plan(release_b, "boot", kind="bootstrap")
    assert status == 0, f"a bootstrap that can be carried out is exit 0, was {status}"
    the_plan = read(plan_boot)
    for host in ["box", "n1"]:
        assert the_plan["hosts"][host]["verdict"] == "change", the_plan["hosts"][host]
    # The prerequisite stands before the dependant looks for it: the control
    # plane is wave 0 and the node that registers with it is wave 1.
    assert the_plan["hosts"]["box"]["wave"] < the_plan["hosts"]["n1"]["wave"], the_plan["hosts"]
    for host in ["box", "n1"]:
        steps = [a["kind"] for a in the_plan["actions"] if a["host"] == host and not a["blocked"]]
        last_deliver = max(i for i, k in enumerate(steps) if k == "deliver-secret")
        assert last_deliver < steps.index("activate"), (host, steps)
    # A raft group of one: whatever it serves is gone while this runs, and
    # that is a question of its own.
    classes = {a["class"] for a in the_plan["approvals"]}
    assert "singleton" in classes, the_plan["approvals"]

    run = run_of(timed("bootstrap apply", lambda: apply(plan_boot, release_b)))
    receipt = receipt_of(run)
    assert receipt["outcome"] == "success", receipt
    for host in ["box", "n1"]:
        assert receipt["hosts"][host]["outcome"] == "success", receipt["hosts"][host]
    assert generation(box) == "B" and generation(n1) == "B"
    elapsed("bootstrapped")

    # The files are there, with the modes the fleet named — and the
    # tmpfiles rule of a controller is what keeps them that way (N2).
    for machine, names in [(box, ["identity", "serving"]), (n1, ["identity"])]:
        for name in names:
            assert machine.succeed(
                f"stat -c '%a %U:%G' /var/lib/meisterstack/pki/{name}.key"
            ).strip() == "600 meister:meister"
    # Nothing that was sent is in the journal or in the receipt.
    kek = operator.succeed("cat /root/ca/secrets.key").strip()
    journal = operator.succeed(f"cat /root/fleet/.meister-deploy/runs/{run}/journal.jsonl")
    assert "PRIVATE KEY" not in journal, "a key is in the journal"
    assert kek not in journal, "the key-encryption key is in the journal"

    # ---------------------------------------------------------------
    # 8. The fleet works: two sessions and a node the cli can see
    # ---------------------------------------------------------------
    box.wait_for_unit("meister-cloud-controller.service")
    box.wait_for_unit("meister-cluster-controller.service")
    n1.wait_for_unit("meister-agent.service")

    # The cluster registers with the cloud…
    box.wait_until_succeeds(
        "journalctl -u meister-cloud-controller.service --no-pager "
        "| grep -qiE 'system:cluster:cp'",
        timeout=180,
    )
    # …and the AGENT registers with the cluster, with the certificate this
    # fleet's CA issued over a key that was made on n1. That is the half of
    # V09 a fleet of one host could not have.
    box.wait_until_succeeds(
        "journalctl -u meister-cluster-controller.service --no-pager "
        "| grep -qiE 'system:node:n1'",
        timeout=180,
    )
    print(box.succeed(
        "journalctl -u meister-cluster-controller.service --no-pager | grep -i 'system:node:n1' | tail -3"
    ))

    # And the operator's own cli reaches the control plane it just installed.
    #
    # `wait_until_succeeds` and not `succeed`: the session is authenticated
    # (the line above says so) and the node OBJECT is written afterwards, so
    # asking two seconds later answered "no nodes known here" — a race, and
    # it was measured before it was guessed.
    operator.wait_until_succeeds(
        "cd /root/fleet && meister --config cli.toml -p cloud node ls --cluster cp "
        "| grep -q n1",
        timeout=180,
    )
    nodes = operator.succeed(
        "cd /root/fleet && meister --config cli.toml -p cloud node ls --cluster cp"
    )
    print(nodes)
    assert "n1" in nodes, nodes

    status, _ = operator.execute(
        f"cd /root/fleet && meister-deploy check --release {release_b} "
        f"--repo /root/fleet --identity /root/.ssh/id_ed25519"
    )
    assert status == 0, "every required check of this fleet passes"
    report = json.loads(operator.succeed(
        f"cd /root/fleet && meister-deploy check --release {release_b} --json "
        f"--repo /root/fleet --identity /root/.ssh/id_ed25519"
    ))
    etcd = [c for c in report["checks"] if c["id"] == "etcd"]
    assert etcd and all(c["status"] == "pass" for c in etcd), etcd
    elapsed("checked")

    # ---------------------------------------------------------------
    # 9. A restart and a cold start: the identity survives both
    # ---------------------------------------------------------------
    n1.succeed("systemctl restart meister-agent.service")
    box.succeed("journalctl --rotate && journalctl --vacuum-time=1s")
    box.wait_until_succeeds(
        "journalctl -u meister-cluster-controller.service --no-pager "
        "| grep -qiE 'system:node:n1'",
        timeout=180,
    )
    # A cold start, and the provider is handed the bundle of the system the
    # bootstrap activated.
    #
    # The bundle of the system it was INSTALLED with would have been just as
    # honest an answer and a different test: a direct-boot guest whose
    # provider was never told about the new system comes back on the old one,
    # consistently, because its command line names it (that is what the
    # `booted` check says between an activation and a provider's reboot).
    # What is measured here is the other half — the identity survives a cold
    # start — so the guest is started with the bundle that matches what it
    # runs, which is what `lab.py boot publish` hands a provider after a
    # bootstrap (L2).
    kernel_b, initrd_b, cmdline_b = bundle_of(BUNDLE_B)
    n1.shutdown()
    n1 = provider_boot("n1-again", kernel_b, initrd_b, cmdline_b, "52:54:00:12:01:03")
    n1.start(allow_reboot=True)
    n1.wait_for_unit("multi-user.target")
    assert n1.succeed("readlink -f /run/booted-system").strip() == \
        n1.succeed("readlink -f /run/current-system").strip(), \
        "after the provider loaded the new bundle, what it booted is what it runs"
    assert n1.succeed(
        "stat -c '%a %U:%G' /var/lib/meisterstack/pki/identity.key"
    ).strip() == "600 meister:meister"
    n1.wait_for_unit("meister-agent.service")
    box.wait_until_succeeds(
        "journalctl -u meister-cluster-controller.service --no-pager "
        "| grep -qiE 'system:node:n1'",
        timeout=180,
    )
    elapsed("restart and cold start survived")

    # ---------------------------------------------------------------
    # 10. An update over the same verbs
    # ---------------------------------------------------------------
    release_c = deploy("c", "nix-manifest-c.json")
    status, plan_c = make_plan(release_c, "c")
    assert status == 0, status
    the_plan = read(plan_c)
    planned_kinds = [a["kind"] for a in the_plan["actions"] if not a["blocked"]]
    assert "deliver-secret" not in planned_kinds, \
        "what the hosts have is what this repository holds"
    assert "stage" in planned_kinds and "activate" in planned_kinds, planned_kinds
    # The agent is the host that carries guests, so it is the host that is
    # cordoned and drained — through the operator's cli (D7).
    n1_steps = [a["kind"] for a in the_plan["actions"] if a["host"] == "n1" and not a["blocked"]]
    assert "cordon" in n1_steps and "drain" in n1_steps, n1_steps
    box_steps = [a["kind"] for a in the_plan["actions"] if a["host"] == "box" and not a["blocked"]]
    assert "cordon" not in box_steps, box_steps

    run = run_of(timed("update apply", lambda: apply(plan_c, release_c)))
    receipt = receipt_of(run)
    assert receipt["outcome"] == "success", receipt
    assert generation(box) == "C" and generation(n1) == "C"
    # The drain really ran, and it ran through the cli against the cluster.
    drain = [
        a for a in receipt["hosts"]["n1"]["actions"] if a["kind"] == "drain"
    ]
    assert drain and drain[0]["result"] == "ok", drain
    assert any("0 guest(s) left on n1" in e for e in drain[0]["evidence"]), drain
    assert any("node drain n1 --cluster cp" in r for r in drain[0]["cmd_refs"]), drain
    # …and the host was given back whole: `node uncordon` alone leaves
    # `spec.drain` where the drain put it, and a node that is still draining
    # is a node the scheduler never places on again.
    uncordon = [a for a in receipt["hosts"]["n1"]["actions"] if a["kind"] == "uncordon"]
    assert uncordon and any(
        "node undrain n1 --cluster cp" in r for r in uncordon[0]["cmd_refs"]
    ), uncordon
    # …and the uncordon gave the node back: the READY column of `node ls` is
    # `yes` / `cordoned` / `draining` / `no` (components/cli/src/output.rs),
    # so what a finished rollout looks like is the absence of the other three.
    after = operator.succeed(
        "cd /root/fleet && meister --config cli.toml -p cloud node ls --cluster cp"
    )
    print(after)
    assert "cordoned" not in after, after
    assert "draining" not in after, after
    elapsed("updated")

    # ---------------------------------------------------------------
    # 11. A kernel change: one host reboots itself, one waits for its
    #     provider
    # ---------------------------------------------------------------
    release_d = deploy("d", "nix-manifest-d.json")
    status, plan_d = make_plan(release_d, "d")
    assert status == 0, status
    the_plan = read(plan_d)
    for host in ["box", "n1"]:
        assert the_plan["hosts"][host]["reboot_required"], the_plan["hosts"][host]
    box_steps = [a["kind"] for a in the_plan["actions"] if a["host"] == "box" and not a["blocked"]]
    n1_steps = [a["kind"] for a in the_plan["actions"] if a["host"] == "n1" and not a["blocked"]]
    assert "reboot" in box_steps and "provider-reboot" not in box_steps, box_steps
    assert "provider-reboot" in n1_steps and "reboot" not in n1_steps, n1_steps
    halt_action = [
        a for a in the_plan["actions"] if a["kind"] == "provider-reboot"
    ][0]
    assert halt_action["provider_boot"]["cmdline"].endswith(
        f"init={the_plan['hosts']['n1']['desired_system']}/init"
    ), halt_action["provider_boot"]
    assert "reboot" in {a["class"] for a in the_plan["approvals"]}, the_plan["approvals"]

    booted_before = n1.succeed("readlink -f /run/booted-system").strip()
    # The agent goes first (a node is taken forward before the tier that
    # gives it orders), so the run stops before it ever reaches box.
    out = timed("apply until the halt", lambda: apply(plan_d, release_d, expect=2))
    halt = json.loads([l for l in out.splitlines() if l.startswith("{")][0])
    assert halt["waiting_for"] == "provider-reboot", halt
    assert halt["host"] == "n1", halt
    interrupted = halt["resume"]
    kernel_d, initrd_d, cmdline_d = bundle_of(BUNDLE_D)
    assert halt["bundle"]["cmdline"] == cmdline_d, (halt["bundle"], cmdline_d)
    assert os.path.realpath(halt["bundle"]["kernel"]["store_path"]) == kernel_d
    # The switch moved the USERLAND and left the boot where it was: that is
    # what a direct-boot host looks like between its activation and its
    # provider's reboot, and it is why the confirmation comes first.
    assert n1.succeed("readlink -f /run/booted-system").strip() == booted_before, \
        "something rebooted n1"
    assert n1.succeed("readlink -f /run/current-system").strip() != booted_before, \
        "the switch did not take"

    # The counter-probe: a resume BEFORE the provider did its half is the
    # same answer again, and nothing moves.
    out = apply(plan_d, release_d, extra=f"--resume {interrupted}", expect=2)
    again = json.loads([l for l in out.splitlines() if l.startswith("{")][0])
    assert again["resume"] == interrupted, again
    assert generation(box) == "C", "box was touched while n1 was waiting"

    # The test driver is the provider: it loads the bundle and starts the
    # guest with it.
    n1.shutdown()
    n1 = provider_boot("n1-rebooted", kernel_d, initrd_d, cmdline_d, "52:54:00:12:01:03")
    timed("provider reboot", lambda: (n1.start(allow_reboot=True), n1.wait_for_unit("multi-user.target")))
    assert "meister.round=D" in n1.succeed("cat /proc/cmdline")

    # …and now the resume finishes n1 and goes on to box, which reboots
    # itself through the helper.
    out = timed("apply --resume", lambda: apply(plan_d, release_d, extra=f"--resume {interrupted}"))
    reconnect(box)
    receipt = receipt_of(interrupted)
    assert receipt["outcome"] == "success", receipt
    for host in ["box", "n1"]:
        assert receipt["hosts"][host]["outcome"] == "success", receipt["hosts"][host]
    # Nothing was activated twice.
    for host in ["box", "n1"]:
        kinds = [a["kind"] for a in receipt["hosts"][host]["actions"]]
        assert kinds.count("activate") == 1, (host, kinds)
    assert box.succeed("cat /proc/cmdline").find("meister.round=D") >= 0
    assert n1.succeed("readlink -f /run/booted-system").strip() == \
        n1.succeed("readlink -f /run/current-system").strip(), "n1 runs what it booted"
    assert box.succeed("readlink -f /run/booted-system").strip() == \
        box.succeed("readlink -f /run/current-system").strip(), "box runs what it booted"
    elapsed("kernel change done")

    # And a plan made now has nothing left to do.
    status, plan_noop = make_plan(release_d, "noop")
    assert status == 0, status
    for host in ["box", "n1"]:
        assert read(plan_noop)["hosts"][host]["verdict"] == "unchanged", read(plan_noop)["hosts"]

    print("meister-deploy: two empty disks became a fleet, took an update, and "
          "one of them waited for its provider")
  '';
}
