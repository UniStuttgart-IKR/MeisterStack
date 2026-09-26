# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Check reboot approval for changed kernel parameters using boot IDs. Exercise
# UEFI boot activation, a later userland-only update, and reboot=never refusal.
{ nixpkgs, lib, pkgs, system, self }:

let
  keys = import "${nixpkgs}/nixos/tests/ssh-keys.nix" pkgs;
  inventoryLib = import ../lib/inventory.nix { inherit lib; };

  # Alphabetical attribute order is what the framework numbers by:
  # operator 1, target 2, unused-b 3, unused-c 4.
  fleetToml = builtins.toFile "fleet.toml" ''
    schema = 2

    [fleet]
    name = "vm-kernel"
    domain = "vm.example"

    [defaults]
    ssh = { user = "root", port = 22 }
    profiles = [ ]
    # `approve` and not `auto`: the whole point is that a reboot is a thing
    # somebody says yes to.
    rollout = { max_unavailable = 1, reboot = "approve" }
    checks = { required = [ ] }

    [[group]]
    id = "cp"
    kind = "raft"

    [[host]]
    id = "target"
    name = "target"
    deployment = "nixos"
    roles = ["cloud", "cluster"]
    groups = ["cp"]
    controller_group = "cp"
    site = "vm"
    networks.management = { address = "192.168.1.2", prefix = 24, interface = "eth1" }
    ssh.host_key = "SHA256:PLACEHOLDER-THE-TEST-FILLS-THIS-IN"
  '';

  inv = inventoryLib.load fleetToml;

  # What all three systems of this one machine share, boot loader included.
  targetCommon = { ... }: {
    imports = [ self.nixosModules.services self.nixosModules.managed ];
    meisterstack.roles = [ "cloud" "cluster" ];
    meisterstack.managed.enable = true;
    meisterstack.managed.trustedPublicKeys = [
      "vm-kernel-placeholder:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    ];
    nix.extraOptions = ''
      !include /etc/nix/extra-keys.conf
    '';

    services.openssh.enable = true;
    users.users.root.openssh.authorizedKeys.keys = [ keys.snakeOilPublicKey ];

    system.switch.enable = true;

    # A machine that boots itself. Without these four lines the framework
    # starts the guest with `-kernel`, the boot half of a release is
    # decided outside the machine, and this test would be the direct-boot
    # case nix/tests/bootstrap.nix already covers.
    virtualisation.useBootLoader = true;
    virtualisation.useEFIBoot = true;
    boot.loader.systemd-boot.enable = true;
    boot.loader.efi.canTouchEfiVariables = true;

    # Room, and why it has to be said here. The image the framework builds
    # for a boot-loader VM is sized EXACTLY to the closure it contains
    # (`diskSize = "auto"; additionalSpace = "0M"` in qemu-vm.nix), so a
    # fresh machine of this kind has some two hundred megabytes free — and
    # this lane's preflight compares the free space against the WHOLE
    # closure of the release. That is the conservative comparison the lane
    # brief asks for, and on a machine like this it refuses a copy that in
    # truth needs a few megabytes. (Measured: the first run of this test
    # stopped with "target has 213381120 byte(s) free … and the closure …
    # is 1141721200 byte(s)".) So the machine gets room the way a real
    # managed host has it: the partition grows into its disk at boot.
    boot.growPartition = true;
    virtualisation.fileSystems."/".autoResize = true;

    virtualisation.writableStore = true;
    virtualisation.memorySize = 2048;
    virtualisation.diskSize = 12288;
  };

  # The spare systems, built and never started. Their MAC rule, their etcd
  # member name and their address come from the machine they stand for —
  # the three things nix/tests/update.nix names, each of which would
  # otherwise turn this into a test about something else.
  spareOf = node: extra: { ... }: {
    imports = [ targetCommon extra ];
    boot.initrd.services.udev.rules = lib.mkForce node.boot.initrd.services.udev.rules;
    services.etcd.name = lib.mkForce node.services.etcd.name;
    networking.interfaces = lib.mkForce (
      lib.mapAttrs (_: i: { inherit (i) ipv4 ipv6; }) node.networking.interfaces
    );
  };

  manifestOf = node: builtins.toFile "nix-manifest.json"
    (builtins.unsafeDiscardStringContext
      (builtins.toJSON (import ../lib/manifest.nix { inherit lib; } {
        inventory = inv;
        configs = { target = node; };
        packages = {
          inherit (pkgs) meisterstack;
          cloudHypervisor = pkgs.cloud-hypervisor-meister;
          guestTiny = pkgs.guest-tiny;
          leandro = null;
          patchDir = ../../patches;
          srcRev = "vm-kernel-test";
        };
      })));
in
pkgs.testers.runNixOSTest {
  name = "meister-deploy-kernel-change";

  nodes = {
    operator = { nodes, ... }: {
      environment.systemPackages = [ pkgs.meisterstack pkgs.git pkgs.jq ];
      nix.settings.experimental-features = [ "nix-command" ];
      virtualisation.writableStore = true;
      virtualisation.memorySize = 3072;
      virtualisation.diskSize = 20480;
      virtualisation.additionalPaths = [
        nodes.target.system.build.toplevel
        nodes.target.system.build.toplevel.drvPath
        nodes.unused-b.system.build.toplevel
        nodes.unused-b.system.build.toplevel.drvPath
        nodes.unused-c.system.build.toplevel
        nodes.unused-c.system.build.toplevel.drvPath
        pkgs.meisterstack
        pkgs.meisterstack.drvPath
        pkgs.cloud-hypervisor-meister
        pkgs.cloud-hypervisor-meister.drvPath
        pkgs.guest-tiny
        pkgs.guest-tiny.drvPath
      ];
      environment.etc."vm-fleet/fleet.toml".source = fleetToml;
      environment.etc."vm-fleet/flake.lock".text =
        builtins.toJSON { nodes.root = { }; root = "root"; version = 7; };
      environment.etc."vm-fleet/nix-manifest-a.json".source = manifestOf nodes.target;
      environment.etc."vm-fleet/nix-manifest-b.json".source = manifestOf nodes.unused-b;
      environment.etc."vm-fleet/nix-manifest-c.json".source = manifestOf nodes.unused-c;
    };

    # A. What the machine runs at the start.
    target = { ... }: {
      imports = [ targetCommon ];
      environment.etc."meister-generation".text = "A";
    };

    # B. The same machine with ANOTHER KERNEL COMMAND LINE — the cheapest
    # kernel change there is: the kernel and the initrd stay the same store
    # paths and only `kernel_params_sha256` moves, so what the reboot class
    # is decided from is exactly one of its three fields.
    unused-b = { nodes, ... }: {
      imports = [
        (spareOf nodes.target {
          environment.etc."meister-generation".text = "B";
          boot.kernelParams = [ "meister.round=B" ];
        })
      ];
    };

    # C. B's kernel command line and another file: an ordinary switch, and
    # the proof that a machine which has just rebooted is settled again.
    unused-c = { nodes, ... }: {
      imports = [
        (spareOf nodes.target {
          environment.etc."meister-generation".text = "C";
          boot.kernelParams = [ "meister.round=B" ];
        })
      ];
    };
  };

  testScript = ''
    import json

    # `allow_reboot`: without it the driver starts qemu with `-no-reboot`
    # and the machine would DISAPPEAR the moment the rollout reboots it.
    operator.start()
    target.start(allow_reboot=True)
    operator.wait_for_unit("multi-user.target")
    target.wait_for_unit("sshd.service")
    target.succeed("ip -4 addr show eth1 | grep -q 'inet 192.168.1.2/24'")
    # A real ESP with a real loader on it, or the rest of this test is
    # about something else.
    target.succeed("bootctl is-installed | grep -q yes")

    def reconnect(m):
        """The machine rebooted under us, because the TOOL rebooted it over
        ssh. The driver's shell died with it; the socket did not."""
        m.connected = False
        m.connect()

    def boot_id():
        return target.succeed("cat /proc/sys/kernel/random/boot_id").strip()

    def booted():
        return target.succeed("readlink -f /run/booted-system").strip()

    def current():
        return target.succeed("readlink -f /run/current-system").strip()

    def generation():
        return target.succeed("cat /etc/meister-generation").strip()

    first_boot = boot_id()

    # Lane 4A position 5, measured here because it costs one line and
    # decides whether a drain with a REAL guest is provable in a VM at all:
    # is there a hypervisor inside a test guest? Nothing loads a kvm module
    # in this configuration, so a `yes` means udev autoloaded one, which is
    # what makes nix/tests/fleet/bootstrap/hosts/n1.nix work on a machine
    # whose `boot.kernelModules = [ "kvm-intel" ]` line cannot apply.
    print("[nested] /dev/kvm inside a test guest: " + target.succeed(
        "test -c /dev/kvm && echo yes || echo no"
    ).strip())

    # --- the operator's repository ----------------------------------------
    operator.succeed("mkdir -p /root/.ssh /root/fleet /root/keys /root/out")
    operator.copy_from_host("${keys.snakeOilPrivateKey}", "/root/.ssh/id_ed25519")
    operator.succeed("chmod 600 /root/.ssh/id_ed25519")
    operator.succeed("cp /etc/vm-fleet/fleet.toml /root/fleet/fleet.toml")
    operator.succeed("cp /etc/vm-fleet/flake.lock /root/fleet/flake.lock")
    operator.succeed("printf '.meister-deploy/\n' > /root/fleet/.gitignore")
    operator.succeed("chmod 644 /root/fleet/fleet.toml /root/fleet/flake.lock")
    for name in ["a", "b", "c"]:
        operator.succeed(f"cp /etc/vm-fleet/nix-manifest-{name}.json /root/out/m-nix-{name}.json")
        operator.succeed(f"chmod 644 /root/out/m-nix-{name}.json")

    host_key = target.succeed("cat /etc/ssh/ssh_host_ed25519_key.pub").strip()
    fingerprint = target.succeed(
        "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub | cut -d' ' -f2"
    ).strip()
    operator.succeed(
        f"printf '192.168.1.2 %s\\n' '{' '.join(host_key.split()[:2])}' > /root/fleet/known_hosts"
    )
    for path in ["/root/fleet/fleet.toml"] + [f"/root/out/m-nix-{n}.json" for n in ["a", "b", "c"]]:
        operator.succeed(
            f"sed -i 's|SHA256:PLACEHOLDER-THE-TEST-FILLS-THIS-IN|{fingerprint}|' {path}"
        )

    operator.succeed("git -C /root/fleet init -q")
    operator.succeed("git -C /root/fleet add -A")
    operator.succeed(
        "git -C /root/fleet -c user.name=test -c user.email=test@example commit -qm 'the fleet'"
    )

    operator.succeed(
        "nix-store --generate-binary-cache-key vm-kernel /root/keys/signing.sec /root/keys/signing.pub"
    )
    public = operator.succeed("cat /root/keys/signing.pub").strip()
    target.succeed(f"echo 'extra-trusted-public-keys = {public}' > /etc/nix/extra-keys.conf")
    target.succeed("systemctl restart nix-daemon.service")
    target.wait_until_succeeds("nix config show | grep -q vm-kernel", timeout=30)
    target.succeed(
        "nix-env -p /nix/var/nix/profiles/system --set \"$(readlink -f /run/current-system)\""
    )
    target.succeed("mkdir -p /var/lib/meisterstack/pki")
    target.succeed("echo not-a-key > /var/lib/meisterstack/pki/identity.key")
    target.succeed("echo not-a-cert > /var/lib/meisterstack/pki/identity.crt")
    target.succeed("chown meister:meister /var/lib/meisterstack/pki/identity.key")
    target.succeed("chmod 600 /var/lib/meisterstack/pki/identity.key")

    # --- the verbs ---------------------------------------------------------
    def read(path):
        return json.loads(operator.succeed(f"cat {path}"))

    def deploy(name, manifest=None):
        manifest = manifest or f"/root/out/m-nix-{name}.json"
        operator.succeed(
            f"cd /root/fleet && meister-deploy resolve --from {manifest} "
            f"--repo /root/fleet --out /root/out/m-{name}.json"
        )
        operator.succeed(
            f"cd /root/fleet && meister-deploy build --manifest /root/out/m-{name}.json "
            f"--sign-key /root/keys/signing.sec --repo /root/fleet --out /root/out/r-{name}.json"
        )
        return f"/root/out/r-{name}.json"

    def make_plan(release, name, expect=0):
        status, _ = operator.execute(
            f"cd /root/fleet && meister-deploy plan --release {release} --select all "
            f"--repo /root/fleet --identity /root/.ssh/id_ed25519 --out /root/out/p-{name}.json"
        )
        assert status == expect, f"plan {name}: exit {status}, wanted {expect}"
        return f"/root/out/p-{name}.json"

    def approvals(plan, without=()):
        return " ".join(
            f"--approve {a['class']}={a['bound_plan_id']}"
            for a in read(plan)["approvals"]
            if a["class"] not in without
        )

    def apply_cmd(plan, release, without=()):
        return (
            f"cd /root/fleet && meister-deploy apply --plan {plan} --release {release} "
            f"--repo /root/fleet --identity /root/.ssh/id_ed25519 "
            f"--inventory /root/fleet/fleet.toml {approvals(plan, without)}"
        )

    def last_run():
        runs = operator.succeed("ls -1t /root/fleet/.meister-deploy/runs").split()
        return runs[0]

    def receipt_of(run):
        return read(f"/root/fleet/.meister-deploy/runs/{run}/receipt.json")

    # A is built and never planned against on its own; its file is what the
    # `reboot = never` case below is edited from.
    deploy("a")
    release_b = deploy("b")
    release_c = deploy("c")

    # The three evaluations, side by side, so a reader of the log can see
    # that A -> B is a kernel command line and nothing else, and that
    # B -> C is not a kernel change at all.
    for name in ["a", "b", "c"]:
        print(name + ": " + operator.succeed(
            f"jq -c '.artifacts.target.boot' /root/out/r-{name}.json"
        ).strip())

    # --- the class ----------------------------------------------------------
    plan_b = make_plan(release_b, "b")
    the_plan = read(plan_b)
    host = the_plan["hosts"]["target"]
    assert host["verdict"] == "change", host
    assert host["reboot_required"] is True, host
    kinds = [a["kind"] for a in the_plan["actions"] if a["blocked"] is None]
    assert "reboot" in kinds, kinds
    assert "provider-reboot" not in kinds, kinds
    activate = [a for a in the_plan["actions"] if a["kind"] == "activate"][0]
    assert activate["reboot_required"] is True, activate
    assert activate["rollback"]["mode"] == "boot", activate
    # `approval_class` on an action is the HARDEST class that action needs,
    # and this fleet's control plane is a raft group of one — so the
    # hardest thing about touching it is that it is the only one there is.
    # What the plan asks for is the UNION, and `reboot` is in it.
    assert activate["approval_class"] in ("reboot", "singleton"), activate
    assert "reboot" in {a["class"] for a in the_plan["approvals"]}, the_plan["approvals"]
    said = " ".join(r for a in the_plan["actions"] for r in a["preconditions"])
    assert "kernel command line" in said, said

    # --- V15: no approval, no reboot ---------------------------------------
    #
    # Everything else this plan asks for IS granted, so what is refused is
    # the reboot and nothing else. Exit 2 and not 1: a rollout waiting for a
    # person to say yes is blocked, not broken (§5).
    status, out = operator.execute(
        apply_cmd(plan_b, release_b, without=("reboot",)) + " 2>&1"
    )
    assert status == 2, (status, out)
    assert "--approve reboot=" in out, out
    print("refused: " + out.strip().splitlines()[-1])
    # And this is the assertion the whole test is for: the machine did not
    # move. Not "the plan said it would not" — the machine.
    assert boot_id() == first_boot, "something rebooted the target without an approval"
    assert generation() == "A"
    assert booted() == current(), "the target was switched without an approval"
    assert json.loads(target.succeed("meister-activate --json txn list")) == []

    # --- with the approval --------------------------------------------------
    desired = read(release_b)["artifacts"]["target"]["toplevel"]["store_path"]
    operator.succeed(apply_cmd(plan_b, release_b))
    reconnect(target)
    run = last_run()
    receipt = receipt_of(run)
    assert receipt["outcome"] == "success", receipt
    assert receipt["hosts"]["target"]["outcome"] == "success", receipt["hosts"]["target"]

    second_boot = boot_id()
    assert second_boot != first_boot, "the approved reboot did not happen"
    assert generation() == "B"
    assert booted() == desired, (booted(), desired)
    assert current() == desired, (current(), desired)
    assert "meister.round=B" in target.succeed("cat /proc/cmdline")

    # The activation really went through the boot menu and not through a
    # switch: the command line the receipt kept says `--mode boot`.
    activate_run = [
        a for a in receipt["hosts"]["target"]["actions"] if a["kind"] == "activate"
    ][0]
    assert any("--mode boot" in ref for ref in activate_run["cmd_refs"]), activate_run
    assert [a["kind"] for a in receipt["hosts"]["target"]["actions"]].count("activate") == 1

    # And what the machine now boots is what the release says it should:
    # the third field of the boot triple, read off the machine.
    release_boot = read(release_b)["artifacts"]["target"]["boot"]
    digest = target.succeed(
        "sha256sum /run/booted-system/kernel-params | cut -d' ' -f1"
    ).strip()
    assert digest == release_boot["kernel_params_sha256"], (digest, release_boot)
    assert target.succeed("readlink -f /run/booted-system/kernel").strip() == \
        release_boot["kernel_store_path"]
    print("the target booted what the release built, and said so in the same digest")

    # A plan made now has nothing left to do.
    assert read(make_plan(release_b, "noop"))["hosts"]["target"]["verdict"] == "unchanged"

    # --- a release that changes no kernel -----------------------------------
    plan_c = make_plan(release_c, "c")
    the_plan = read(plan_c)
    host = the_plan["hosts"]["target"]
    assert host["verdict"] == "change", host
    assert host["reboot_required"] is False, host
    kinds = [a["kind"] for a in the_plan["actions"] if a["blocked"] is None]
    assert "reboot" not in kinds, kinds
    activate = [a for a in the_plan["actions"] if a["kind"] == "activate"][0]
    assert activate["disruption"] == "service", activate
    assert activate["rollback"]["mode"] == "switch", activate
    assert "reboot" not in {a["class"] for a in the_plan["approvals"]}, the_plan["approvals"]

    desired_c = read(release_c)["artifacts"]["target"]["toplevel"]["store_path"]
    operator.succeed(apply_cmd(plan_c, release_c))
    receipt = receipt_of(last_run())
    assert receipt["outcome"] == "success", receipt
    assert generation() == "C"
    # The boot id did NOT move: an ordinary switch is an ordinary switch,
    # even on a machine that rebooted five minutes ago.
    assert boot_id() == second_boot, "a service change rebooted the machine"
    # And a switch is a switch: what the machine RUNS moved, what it BOOTED
    # did not. Those are two facts and the planner keeps them apart — the
    # next plan over C is therefore the reboot that makes them one, and
    # nothing else (the same shape nix/tests/update.nix pins).
    assert current() == desired_c, (current(), desired_c)
    assert booted() == desired, "a switch must not change what was booted"
    pending = read(make_plan(release_c, "pending"))
    assert pending["hosts"]["target"]["verdict"] == "change", pending["hosts"]
    steps = [a["kind"] for a in pending["actions"] if a["blocked"] is None]
    assert "reboot" in steps and "stage" not in steps and "activate" not in steps, steps

    # --- a host that said no ------------------------------------------------
    #
    # The same machine, the same release A (whose kernel command line is the
    # one this machine does NOT run any more), and an inventory that says
    # this host is never rebooted. A plan, not a run: the refusal is the
    # document.
    # `.hosts` and not `.inventory.hosts`: the rollout policy of a host is
    # part of the EVALUATED half of a nix manifest (`nix/lib/manifest.nix`
    # resolves defaults < group < host there), and the inventory half
    # carries no `rollout` key at all — writing one in would be a field the
    # parser refuses.
    operator.succeed(
        "jq '.hosts.target.rollout.reboot = \"never\"' "
        "/root/out/m-nix-a.json > /root/out/m-nix-never.json"
    )
    release_never = deploy("never", "/root/out/m-nix-never.json")
    plan_never = make_plan(release_never, "never", expect=2)
    never = read(plan_never)
    host = never["hosts"]["target"]
    assert host["verdict"] == "blocked", host
    why = " ".join(host["reasons"])
    assert "reboot = never" in why, why
    assert "does not reboot a machine that said no" in why, why
    print("reboot = never: " + why)
    # Blocked is not broken, and `reboot = never` is a `stop_disruptive`:
    # it holds what INTERRUPTS. Looking is free, and so is copying a
    # closure onto the machine — the same rule the quorum test measures.
    def blocked_of(kind):
        return [a["blocked"] for a in never["actions"] if a["kind"] == kind]

    for kind in ["preflight", "verify"]:
        assert blocked_of(kind) and all(b is None for b in blocked_of(kind)), kind
    for kind in ["activate", "reboot"]:
        assert blocked_of(kind) and all(b is not None for b in blocked_of(kind)), kind
    # And nothing happened to the machine over all of it.
    assert boot_id() == second_boot
    assert generation() == "C"

    print(
        "meister-deploy: a kernel change is a reboot, a reboot is an approval, "
        "and the boot id moved exactly once"
    )
  '';
}
