# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# V14 against a real raft: three etcd members, one of them stopped, and a
# rollout that refuses to take a second one down.
#
# Everything about the quorum here is real. The three members bootstrap a
# static three-member cluster over their peer urls, `etcdctl member list` and
# `endpoint health` are asked by the tool's own read-only probe over ssh, and
# what stops the second interruption is the arithmetic of D8 — floor((n-1)/2)
# minus whoever is already down — applied to what those commands answered.
# Nothing is mocked but the evaluation, which a test VM cannot do (see
# nix/tests/update.nix for why) and which `resolve --from` therefore receives
# as the file `nix/lib/manifest.nix` writes.
#
# In order: a healthy group of three plans as three waves with one member
# allowed down; a member is stopped and the same plan is refused with the
# quorum sentence; an `apply` of a plan made BEFORE the outage stops in
# `validate_against` and touches nobody; the member comes back and the plan
# goes through; the rollout runs, and while the first member is mid-
# activation the other two answer healthy; and a manifest whose etcd
# membership is not the one etcd reports blocks the whole group (D8's
# topology half).
{ nixpkgs, lib, pkgs, system, self }:

let
  keys = import "${nixpkgs}/nixos/tests/ssh-keys.nix" pkgs;
  inventoryLib = import ../lib/inventory.nix { inherit lib; };

  # The framework hands out `192.168.1.<node number>` and numbers the nodes
  # in the order of the attribute set below: operator 1, r1 2, r2 3, r3 4,
  # and the three spare systems 5, 6, 7.
  peers = {
    r1 = "192.168.1.2";
    r2 = "192.168.1.3";
    r3 = "192.168.1.4";
  };

  fleetToml = builtins.toFile "fleet.toml" ''
    schema = 2

    [fleet]
    name = "vm-quorum"
    domain = "vm.example"

    [defaults]
    ssh = { user = "root", port = 22 }
    profiles = [ ]
    rollout = { max_unavailable = 1, reboot = "approve" }
    # Nothing but the three checks that decide themselves (identity,
    # enrolled, system). The controller units of these hosts are gated on a
    # CA certificate a bootstrap would deliver (M3), so they are inactive
    # here on purpose and must not block a rollout this test is not about —
    # the same arrangement nix/tests/update.nix uses and for the same
    # reason. What this test IS about, etcd, is not a unit check: it is the
    # group arithmetic, and that reads the probe's etcd answer directly.
    checks = { required = [ ] }

    [[group]]
    id = "cp"
    kind = "raft"

    [[host]]
    id = "r1"
    name = "r1"
    deployment = "nixos"
    roles = ["cloud", "cluster"]
    groups = ["cp"]
    controller_group = "cp"
    site = "vm"
    networks.management = { address = "192.168.1.2", prefix = 24, interface = "eth1" }
    ssh.host_key = "SHA256:PLACEHOLDER-R1"

    [[host]]
    id = "r2"
    name = "r2"
    deployment = "nixos"
    roles = ["cloud", "cluster"]
    groups = ["cp"]
    controller_group = "cp"
    site = "vm"
    networks.management = { address = "192.168.1.3", prefix = 24, interface = "eth1" }
    ssh.host_key = "SHA256:PLACEHOLDER-R2"

    [[host]]
    id = "r3"
    name = "r3"
    deployment = "nixos"
    roles = ["cloud", "cluster"]
    groups = ["cp"]
    controller_group = "cp"
    site = "vm"
    networks.management = { address = "192.168.1.4", prefix = 24, interface = "eth1" }
    ssh.host_key = "SHA256:PLACEHOLDER-R3"
  '';

  inv = inventoryLib.load fleetToml;

  # What all six systems share. The difference between the A systems and the
  # B systems is one file, so the switch changes a file and no unit — which
  # keeps the driver's own backdoor and the etcd member alive across it.
  memberCommon = member: { ... }: {
    imports = [ self.nixosModules.services self.nixosModules.managed ];
    meisterstack.roles = [ "cloud" "cluster" ];
    meisterstack.managed.enable = true;
    # The whole point of this test: three members, a static bootstrap, and
    # every member talking to its own loopback client url (nix/etcd.nix).
    meisterstack.etcd.peers = peers;
    meisterstack.etcd.member = member;
    meisterstack.managed.trustedPublicKeys = [
      "vm-quorum-placeholder:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    ];
    nix.extraOptions = ''
      !include /etc/nix/extra-keys.conf
    '';

    # Peer traffic is the only traffic that leaves these machines, and the
    # service modules open nothing on purpose (`meisterstack.ports` is there
    # to be READ — the operator's own profile opens them). A fleet whose
    # members cannot reach each other's 2380 never forms a cluster, which
    # the M3 integration found the hard way for the controller ports.
    networking.firewall.allowedTCPPorts = [ 2380 ];

    services.openssh.enable = true;
    users.users.root.openssh.authorizedKeys.keys = [ keys.snakeOilPublicKey ];

    system.switch.enable = true;
    boot.loader.grub.enable = false;

    virtualisation.writableStore = true;
    virtualisation.memorySize = 1536;
    virtualisation.diskSize = 6144;
  };

  # A spare system: the same machine, one file different. Everything a boot
  # or an identity depends on is taken from the node it stands for, for the
  # reasons nix/tests/update.nix sets out at length — the MAC in the initrd,
  # the etcd member name, and the address, each of which would otherwise
  # make this a test about something else.
  spareOf = node: member: { ... }: {
    imports = [ (memberCommon member) ];
    environment.etc."meister-generation".text = "B";
    boot.initrd.services.udev.rules = lib.mkForce node.boot.initrd.services.udev.rules;
    networking.interfaces = lib.mkForce (
      lib.mapAttrs (_: i: { inherit (i) ipv4 ipv6; }) node.networking.interfaces
    );
  };

  manifestOf = configs: builtins.toFile "nix-manifest.json"
    (builtins.unsafeDiscardStringContext
      (builtins.toJSON (import ../lib/manifest.nix { inherit lib; } {
        inventory = inv;
        inherit configs;
        packages = {
          inherit (pkgs) meisterstack;
          cloudHypervisor = pkgs.cloud-hypervisor-meister;
          guestTiny = pkgs.guest-tiny;
          leandro = null;
          patchDir = ../../patches;
          srcRev = "vm-quorum-test";
        };
      })));
in
pkgs.testers.runNixOSTest {
  name = "meister-deploy-quorum-degraded";

  nodes = {
    operator = { nodes, ... }: {
      environment.systemPackages = [ pkgs.meisterstack pkgs.git pkgs.jq ];
      nix.settings.experimental-features = [ "nix-command" ];
      virtualisation.writableStore = true;
      virtualisation.memorySize = 3072;
      virtualisation.diskSize = 24576;
      virtualisation.additionalPaths = [
        nodes.r1.system.build.toplevel
        nodes.r1.system.build.toplevel.drvPath
        nodes.r2.system.build.toplevel
        nodes.r2.system.build.toplevel.drvPath
        nodes.r3.system.build.toplevel
        nodes.r3.system.build.toplevel.drvPath
        nodes.s1.system.build.toplevel
        nodes.s1.system.build.toplevel.drvPath
        nodes.s2.system.build.toplevel
        nodes.s2.system.build.toplevel.drvPath
        nodes.s3.system.build.toplevel
        nodes.s3.system.build.toplevel.drvPath
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
      environment.etc."vm-fleet/nix-manifest-a.json".source = manifestOf {
        inherit (nodes) r1 r2 r3;
      };
      environment.etc."vm-fleet/nix-manifest-b.json".source = manifestOf {
        r1 = nodes.s1;
        r2 = nodes.s2;
        r3 = nodes.s3;
      };
    };

    r1 = { ... }: {
      imports = [ (memberCommon "r1") ];
      environment.etc."meister-generation".text = "A";
    };
    r2 = { ... }: {
      imports = [ (memberCommon "r2") ];
      environment.etc."meister-generation".text = "A";
    };
    r3 = { ... }: {
      imports = [ (memberCommon "r3") ];
      environment.etc."meister-generation".text = "A";
    };

    # Never started. The B system of each member. The etcd member name is
    # not forced the way nix/tests/update.nix forces it, because here it is
    # not derived from the host name at all: `meisterstack.etcd.member` is
    # given explicitly, and a spare gets the name of the machine it stands
    # for.
    s1 = { nodes, ... }: { imports = [ (spareOf nodes.r1 "r1") ]; };
    s2 = { nodes, ... }: { imports = [ (spareOf nodes.r2 "r2") ]; };
    s3 = { nodes, ... }: { imports = [ (spareOf nodes.r3 "r3") ]; };
  };

  testScript = ''
    import json

    MEMBERS = ["r1", "r2", "r3"]
    machines = {"r1": r1, "r2": r2, "r3": r3}

    operator.start()
    for m in machines.values():
        m.start()
    operator.wait_for_unit("multi-user.target")
    for m in machines.values():
        m.wait_for_unit("sshd.service")

    for name, address in [("r1", "192.168.1.2"), ("r2", "192.168.1.3"), ("r3", "192.168.1.4")]:
        machines[name].succeed(f"ip -4 addr show eth1 | grep -q 'inet {address}/24'")

    # --- a raft of three, really bootstrapped -----------------------------
    for name, m in machines.items():
        m.wait_for_unit("etcd.service")
    # Not "the unit is up": the cluster has to have AGREED, which is what a
    # member list of three from every member means.
    def members_of(name):
        out = machines[name].succeed(
            "etcdctl --endpoints=http://127.0.0.1:2379 member list -w json"
        )
        return sorted(m["name"] for m in json.loads(out)["members"])

    for name in MEMBERS:
        machines[name].wait_until_succeeds(
            "etcdctl --endpoints=http://127.0.0.1:2379 endpoint health", timeout=120
        )
    for name in MEMBERS:
        assert members_of(name) == MEMBERS, (name, members_of(name))
    print("three members agree on being three")

    # --- the operator's repository ----------------------------------------
    operator.succeed("mkdir -p /root/.ssh /root/fleet /root/keys /root/out")
    operator.copy_from_host("${keys.snakeOilPrivateKey}", "/root/.ssh/id_ed25519")
    operator.succeed("chmod 600 /root/.ssh/id_ed25519")
    operator.succeed("cp /etc/vm-fleet/fleet.toml /root/fleet/fleet.toml")
    operator.succeed("cp /etc/vm-fleet/flake.lock /root/fleet/flake.lock")
    operator.succeed("printf '.meister-deploy/\n' > /root/fleet/.gitignore")
    operator.succeed("chmod 644 /root/fleet/fleet.toml /root/fleet/flake.lock")
    operator.succeed("cp /etc/vm-fleet/nix-manifest-a.json /root/out/m-nix-a.json")
    operator.succeed("cp /etc/vm-fleet/nix-manifest-b.json /root/out/m-nix-b.json")
    operator.succeed("chmod 644 /root/out/m-nix-a.json /root/out/m-nix-b.json")

    # Enrolment out of band, from the machine itself: the fingerprint goes
    # into the operator's known_hosts AND into the inventory and both
    # manifests, because a host key is what every connection of this tool
    # checks (D10).
    known = ""
    for name, address in [("r1", "192.168.1.2"), ("r2", "192.168.1.3"), ("r3", "192.168.1.4")]:
        host_key = machines[name].succeed("cat /etc/ssh/ssh_host_ed25519_key.pub").strip()
        fingerprint = machines[name].succeed(
            "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub | cut -d' ' -f2"
        ).strip()
        known += f"{address} {' '.join(host_key.split()[:2])}\n"
        placeholder = "SHA256:PLACEHOLDER-" + name.upper()
        for path in [
            "/root/fleet/fleet.toml",
            "/root/out/m-nix-a.json",
            "/root/out/m-nix-b.json",
        ]:
            operator.succeed(f"sed -i 's|{placeholder}|{fingerprint}|' {path}")
    operator.succeed(f"cat > /root/fleet/known_hosts <<'EOF'\n{known}EOF")

    operator.succeed("git -C /root/fleet init -q")
    operator.succeed("git -C /root/fleet add -A")
    operator.succeed(
        "git -C /root/fleet -c user.name=test -c user.email=test@example commit -qm 'the fleet'"
    )

    # --- the signing key and what every managed host needs ----------------
    operator.succeed(
        "nix-store --generate-binary-cache-key vm-quorum /root/keys/signing.sec /root/keys/signing.pub"
    )
    public = operator.succeed("cat /root/keys/signing.pub").strip()
    for name, m in machines.items():
        m.succeed(f"echo 'extra-trusted-public-keys = {public}' > /etc/nix/extra-keys.conf")
        m.succeed("systemctl restart nix-daemon.service")
        m.wait_until_succeeds("nix config show | grep -q vm-quorum", timeout=30)
        # What nixos-install leaves behind and a test machine does not have.
        m.succeed(
            "nix-env -p /nix/var/nix/profiles/system --set \"$(readlink -f /run/current-system)\""
        )
        # An identity is two files; what is behind them is lane 3B's test.
        m.succeed("mkdir -p /var/lib/meisterstack/pki")
        m.succeed("echo not-a-key > /var/lib/meisterstack/pki/identity.key")
        m.succeed("echo not-a-cert > /var/lib/meisterstack/pki/identity.crt")
        m.succeed("chown meister:meister /var/lib/meisterstack/pki/identity.key")
        m.succeed("chmod 600 /var/lib/meisterstack/pki/identity.key")

    # --- the verbs ---------------------------------------------------------
    def deploy(name, manifest):
        operator.succeed(
            f"cd /root/fleet && meister-deploy resolve --from {manifest} "
            f"--repo /root/fleet --out /root/out/m-{name}.json"
        )
        operator.succeed(
            f"cd /root/fleet && meister-deploy build --manifest /root/out/m-{name}.json "
            f"--sign-key /root/keys/signing.sec --repo /root/fleet --out /root/out/r-{name}.json"
        )
        return f"/root/out/r-{name}.json"

    def make_plan(release, name, select="all", expect=0):
        status, _ = operator.execute(
            f"cd /root/fleet && meister-deploy plan --release {release} --select {select} "
            f"--repo /root/fleet --identity /root/.ssh/id_ed25519 --out /root/out/p-{name}.json"
        )
        assert status == expect, f"plan {name}: exit {status}, wanted {expect}"
        return f"/root/out/p-{name}.json"

    def read(path):
        return json.loads(operator.succeed(f"cat {path}"))

    def approvals(plan):
        return " ".join(
            f"--approve {a['class']}={a['bound_plan_id']}" for a in read(plan)["approvals"]
        )

    def apply_cmd(plan, release, extra=""):
        return (
            f"cd /root/fleet && meister-deploy apply --plan {plan} --release {release} "
            f"--repo /root/fleet --identity /root/.ssh/id_ed25519 "
            f"--inventory /root/fleet/fleet.toml {approvals(plan)} {extra}"
        )

    release_a = deploy("a", "/root/out/m-nix-a.json")
    release_b = deploy("b", "/root/out/m-nix-b.json")

    # --- a healthy group of three ------------------------------------------
    plan_b = make_plan(release_b, "b")
    the_plan = read(plan_b)
    group = the_plan["groups"]["cp"]
    assert group["size"] == 3, group
    assert group["unhealthy_now"] == 0, group
    assert group["allowed_unavailable"] == 1, group
    assert group["blocked"] is None, group
    assert group["singleton"] is False, group
    for name in MEMBERS:
        assert the_plan["hosts"][name]["verdict"] == "change", the_plan["hosts"]
    # Three members, three waves: a raft group moves strictly one member at
    # a time whatever `max_unavailable` says.
    waves = sorted({the_plan["hosts"][name]["wave"] for name in MEMBERS})
    assert waves == [0, 1, 2], the_plan["hosts"]
    print(f"healthy: {group}")

    # --- one member down ---------------------------------------------------
    r3.succeed("systemctl stop etcd.service")
    r3.wait_until_fails("systemctl is-active etcd.service", timeout=30)

    # V14: the same release, the same fleet, one member gone — and the plan
    # refuses, with exit 2, which is "blocked" and not "broken".
    plan_degraded = make_plan(release_b, "degraded", expect=2)
    degraded = read(plan_degraded)
    group = degraded["groups"]["cp"]
    assert group["unhealthy_now"] == 1, group
    assert group["allowed_unavailable"] == 0, group
    assert "no further member may go down" in (group["blocked"] or ""), group
    assert "cp is at 2 of 3" in group["blocked"], group
    print("V14: " + group["blocked"])
    # Every member is blocked, and the two steps that only LOOK are not:
    # a preflight is exactly the step that should report this.
    for name in MEMBERS:
        assert degraded["hosts"][name]["verdict"] == "blocked", degraded["hosts"][name]
    free = {a["kind"] for a in degraded["actions"] if a["blocked"] is None}
    assert free == {"preflight", "verify"}, free
    for kind in ["stage", "activate", "confirm"]:
        assert all(
            a["blocked"] is not None for a in degraded["actions"] if a["kind"] == kind
        ), kind

    # --- and a plan made BEFORE the outage is stopped at the door ----------
    status, out = operator.execute(apply_cmd(plan_b, release_b) + " 2>&1")
    assert status != 0, out
    assert "cp" in out and ("quorum" in out or "member may go down" in out), out
    print("stopped before the first lock: " + out.strip().splitlines()[-1])
    # Nothing moved: no host holds a transaction, and every one of them
    # still runs generation A.
    for name, m in machines.items():
        assert json.loads(m.succeed("meister-activate --json txn list")) == [], name
        assert m.succeed("cat /etc/meister-generation").strip() == "A", name
    # The receipt of that run names the hosts nothing was done to.
    runs = operator.succeed("ls -1t /root/fleet/.meister-deploy/runs").split()
    receipt = read(f"/root/fleet/.meister-deploy/runs/{runs[0]}/receipt.json")
    assert set(receipt["untouched"]) >= {"r1", "r2"}, receipt["untouched"]
    print("untouched: " + ", ".join(receipt["untouched"]))

    # --- the member comes back ---------------------------------------------
    r3.succeed("systemctl start etcd.service")
    r3.wait_until_succeeds(
        "etcdctl --endpoints=http://127.0.0.1:2379 endpoint health", timeout=120
    )
    plan_ok = make_plan(release_b, "ok")
    assert read(plan_ok)["groups"]["cp"]["allowed_unavailable"] == 1

    # --- the rollout, with the other two watching --------------------------
    operator.succeed(
        "systemd-run --unit=apply-cp --collect --working-directory=/root/fleet "
        "--setenv=PATH=/run/current-system/sw/bin "
        "/bin/sh -c " + f"{repr(apply_cmd(plan_ok, release_b))}"
    )
    # The window this test is about: `r1` holds an open transaction exactly
    # between its activation and its confirmation, so this is the moment it
    # is mid-rollout — and the moment the other two have to be a quorum.
    r1.wait_until_succeeds(
        "meister-activate --json txn list | grep -q pending", timeout=300
    )
    for name in ["r2", "r3"]:
        health = json.loads(
            machines[name].succeed(
                "etcdctl --endpoints=http://127.0.0.1:2379 endpoint health -w json"
            )
        )
        assert all(entry["health"] for entry in health), (name, health)
        print(f"while r1 was activating, {name} answered healthy")

    operator.wait_until_fails("systemctl is-active apply-cp.service", timeout=900)
    run = operator.succeed(
        "grep -l run.end /root/fleet/.meister-deploy/runs/*/journal.jsonl | tail -1"
    ).strip().split("/")[-2]
    receipt = read(f"/root/fleet/.meister-deploy/runs/{run}/receipt.json")
    assert receipt["outcome"] == "success", receipt
    for name in MEMBERS:
        assert receipt["hosts"][name]["outcome"] == "success", receipt["hosts"][name]
        assert machines[name].succeed("cat /etc/meister-generation").strip() == "B", name
    # And the member that went first is a member again, with the cluster
    # still at three.
    for name in MEMBERS:
        machines[name].wait_until_succeeds(
            "etcdctl --endpoints=http://127.0.0.1:2379 endpoint health", timeout=120
        )
        assert members_of(name) == MEMBERS, (name, members_of(name))
    print("the group rolled one member at a time and is three again")

    # --- D8's other half: a membership that is not the declared one --------
    #
    # The manifest says the fleet configured a member this etcd has never
    # heard of. That is not a rollout problem, it is a different cluster,
    # and the group is blocked rather than rolled.
    operator.succeed(
        "jq '.hosts |= with_entries(.value.effective_settings.etcd.initial_cluster = "
        "\"r1=http://192.168.1.2:2380,r2=http://192.168.1.3:2380,r9=http://192.168.1.9:2380\")' "
        "/root/out/m-nix-b.json > /root/out/m-nix-moved.json"
    )
    deploy("moved", "/root/out/m-nix-moved.json")
    plan_moved = make_plan("/root/out/r-moved.json", "moved", expect=2)
    moved = read(plan_moved)
    why = moved["groups"]["cp"]["blocked"] or ""
    assert "membership" in why, why
    assert "r9" in why, why
    print("D8 topology: " + why)

    print(
        "meister-deploy: a raft of three refused to lose a second member, "
        "and rolled one at a time when it could"
    )
  '';
}
