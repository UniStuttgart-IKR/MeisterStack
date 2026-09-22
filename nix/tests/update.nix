# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# The exit criterion of M2, in two virtual machines: a host is changed and
# verifiably brought back.
#
# An operator workstation and a managed host. Everything between them is the
# real thing — `nix copy --to ssh-ng://` against a store with
# `require-sigs = true`, `nix path-info --store ssh-ng://` for what arrived,
# `meister-activate` over ssh, the journal on the workstation and the
# transaction record on the target. No shim, no fake runner.
#
# The one thing that is NOT the real thing is the evaluation. A test VM
# cannot evaluate the operator's flake — it has no nixpkgs and the systems it
# would have to produce are these test nodes, which carry the driver's own
# instrumentation. So the EVALUATION is done here, at build time, by
# `nix/lib/manifest.nix` — the same file `lib.mkFleet` uses — and handed to
# the workstation as a `nix-manifest/1` file, which `resolve --from` reads
# instead of calling `nix eval`. Everything after that is the tool's own
# road: resolve -> build -> plan -> apply.
#
# What this test shows, in order: V10 (a fleet that already runs the release
# is two steps and no commands), the change, the way back, V18 (a host
# somebody else holds), a release that was edited after it was built, and
# V17 (a workstation that dies after the irreversible step, and a resume
# that asks the target instead of repeating it).
{ nixpkgs, lib, pkgs, system, self }:

let
  keys = import "${nixpkgs}/nixos/tests/ssh-keys.nix" pkgs;
  inventoryLib = import ../lib/inventory.nix { inherit lib; };

  # The inventory of this two-host fleet. One host, `target`, at the address
  # the test framework gives the second node.
  # `builtins.toFile` and not `pkgs.writeText`: the inventory is READ during
  # evaluation (nix/lib/inventory.nix does `fromTOML (readFile …)`), and a
  # derivation read during evaluation is an import from derivation. `toFile`
  # puts the bytes in the store while evaluating, which is what this needs.
  fleetToml = builtins.toFile "fleet.toml" ''
    schema = 2

    [fleet]
    name = "vm-update"
    domain = "vm.example"

    [defaults]
    ssh = { user = "root", port = 22 }
    profiles = [ ]
    rollout = { max_unavailable = 1, reboot = "approve" }
    # Nothing beyond the three checks that decide themselves (identity,
    # enrolled, system). The agent unit of this host is gated on a CA
    # certificate that a bootstrap would deliver (M3), so it is inactive
    # here on purpose and must not block a rollout this test is not about.
    checks = { required = [ ] }

    # One host that is the whole control plane, which is the only shape a
    # fleet of one can have: a cloud places guests on clusters, a cluster
    # registers with a cloud, an agent reports to a cluster. The inventory
    # says all three out loud (nix/lib/inventory.nix), and a test that
    # worked around that would be a test about a fleet nobody can deploy.
    [[group]]
    id = "cp"
    kind = "raft"

    [[host]]
    id = "target"
    name = "target"
    deployment = "nixos"
    roles = ["cloud", "cluster", "agent"]
    groups = ["cp"]
    controller_group = "cp"
    site = "vm"
    networks.management = { address = "192.168.1.2", prefix = 24, interface = "eth1" }
    ssh.host_key = "SHA256:PLACEHOLDER-THE-TEST-FILLS-THIS-IN"
  '';

  inv = inventoryLib.load fleetToml;

  # What both systems of the target are. The difference between A and B is
  # one file, so the switch between them changes a file and no unit — which
  # is what keeps the test driver's own backdoor alive across it.
  targetCommon = { ... }: {
    imports = [ self.nixosModules.services self.nixosModules.managed ];
    meisterstack.roles = [ "cloud" "cluster" "agent" ];
    # No routing daemon and no nvme-over-tcp in a test VM: neither is what
    # this test is about, and both are modules the guest kernel would have
    # to carry.
    meisterstack.agent.frr.enable = false;
    meisterstack.agent.nvmeTcp.enable = false;
    meisterstack.managed.enable = true;
    # A placeholder, so that 1A's assertion is satisfied at build time. The
    # key this fleet really signs with is generated while the test runs and
    # reaches the target through `extra-keys.conf` below — which is the road
    # M0 probe S12 measured.
    meisterstack.managed.trustedPublicKeys = [ "vm-update-placeholder:AAAA" ];
    nix.extraOptions = ''
      !include /etc/nix/extra-keys.conf
    '';

    services.openssh.enable = true;
    users.users.root.openssh.authorizedKeys.keys = [ keys.snakeOilPublicKey ];

    # The two lines every machine a deployment activates on needs, and which
    # a test machine does not have by default (see nix/tests/activate.nix).
    system.switch.enable = true;
    boot.loader.grub.enable = false;

    virtualisation.writableStore = true;
    virtualisation.memorySize = 2048;
    virtualisation.diskSize = 8192;
  };

  # The manifest of a fleet whose one host runs these configs. The same file
  # `lib.mkFleet` feeds `meisterDeployment` with.
  # The same reason, plus one more: the context is discarded on purpose, so
  # that naming this file does not make the operator's VM image depend on
  # every system in it. The closures it needs travel through
  # `virtualisation.additionalPaths`, where the test says which ones and why.
  manifestOf = node: builtins.toFile "nix-manifest.json" (builtins.unsafeDiscardStringContext
    (builtins.toJSON (import ../lib/manifest.nix { inherit lib; } {
      inventory = inv;
      configs = { target = node; };
      packages = {
        inherit (pkgs) meisterstack;
        cloudHypervisor = pkgs.cloud-hypervisor-meister;
        guestTiny = pkgs.guest-tiny;
        leandro = null;
        patchDir = ../../patches;
        srcRev = "vm-update-test";
      };
    })));
in
pkgs.testers.runNixOSTest {
  name = "meister-deploy-managed-update";

  nodes = {
    # 192.168.1.1. The workstation: the tool, a git repository, a signing
    # key, and the closures of both target systems in its store.
    operator = { nodes, ... }: {
      environment.systemPackages = [ pkgs.meisterstack pkgs.git pkgs.jq ];
      nix.settings.experimental-features = [ "nix-command" ];
      virtualisation.writableStore = true;
      virtualisation.memorySize = 3072;
      virtualisation.diskSize = 16384;
      # Both systems AND their derivations: `build` realises the derivation
      # the manifest names, and a derivation whose output is already valid
      # is realised without building anything — which is what makes a real
      # `meister-deploy build` possible in a VM with no network.
      virtualisation.additionalPaths = [
        nodes.target.system.build.toplevel
        nodes.target.system.build.toplevel.drvPath
        nodes.unused.system.build.toplevel
        nodes.unused.system.build.toplevel.drvPath
        # And the packages the manifest names beside the systems: `build`
        # realises every derivation in it, and a package whose output is
        # not here would be a package this VM tried to fetch from a cache
        # it cannot reach.
        pkgs.meisterstack
        pkgs.meisterstack.drvPath
        pkgs.cloud-hypervisor-meister
        pkgs.cloud-hypervisor-meister.drvPath
        pkgs.guest-tiny
        pkgs.guest-tiny.drvPath
      ];
      environment.etc."vm-fleet/fleet.toml".source = fleetToml;
      # A manifest says what its inputs were locked to. This repository has
      # no inputs — the evaluation happened elsewhere — and an empty lock is
      # what that looks like; a missing one is refused, because then `nix
      # eval` would lock against whatever is current today.
      environment.etc."vm-fleet/flake.lock".text =
        builtins.toJSON { nodes.root = { }; root = "root"; version = 7; };
      environment.etc."vm-fleet/nix-manifest-a.json".source =
        manifestOf nodes.target;
      environment.etc."vm-fleet/nix-manifest-b.json".source =
        manifestOf nodes.unused;
    };

    # 192.168.1.2. The managed host, running system A.
    target = { ... }: {
      imports = [ targetCommon ];
      environment.etc."meister-generation".text = "A";
    };

    # 192.168.1.3, never started. It is system B: the same host with one
    # file changed.
    unused = { ... }: {
      imports = [ targetCommon ];
      environment.etc."meister-generation".text = "B";
    };
  };

  testScript = ''
    import json

    operator.start()
    target.start()
    operator.wait_for_unit("multi-user.target")
    target.wait_for_unit("sshd.service")

    # The address the inventory names has to be the address this host has,
    # or the whole test would be about somebody else.
    target.succeed("ip -4 addr show eth1 | grep -q 'inet 192.168.1.2/24'")

    # --- the operator's repository ------------------------------------
    operator.succeed("mkdir -p /root/.ssh /root/fleet /root/keys")
    operator.copy_from_host("${keys.snakeOilPrivateKey}", "/root/.ssh/id_ed25519")
    operator.succeed("chmod 600 /root/.ssh/id_ed25519")
    operator.succeed("cp /etc/vm-fleet/fleet.toml /root/fleet/fleet.toml")
    operator.succeed("cp /etc/vm-fleet/flake.lock /root/fleet/flake.lock")
    operator.succeed("chmod 644 /root/fleet/fleet.toml /root/fleet/flake.lock")

    # Enrolment, out of band: the host key is read off the MACHINE and
    # written into the operator's `known_hosts` and into the inventory. This
    # is what `keys enroll` will do in M3; here the console is the test.
    host_key = target.succeed("cat /etc/ssh/ssh_host_ed25519_key.pub").strip()
    fingerprint = target.succeed(
        "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub | cut -d' ' -f2"
    ).strip()
    print("target host key fingerprint: " + fingerprint)
    operator.succeed(f"printf '192.168.1.2 %s\\n' '{' '.join(host_key.split()[:2])}' > /root/fleet/known_hosts")
    operator.succeed(
        f"sed -i 's|SHA256:PLACEHOLDER-THE-TEST-FILLS-THIS-IN|{fingerprint}|' /root/fleet/fleet.toml"
    )
    for name in ["a", "b"]:
        operator.succeed(
            f"sed -i 's|SHA256:PLACEHOLDER-THE-TEST-FILLS-THIS-IN|{fingerprint}|' "
            f"/etc/vm-fleet/nix-manifest-{name}.json"
        )

    # A manifest names the tree it came from, so there has to be one.
    operator.succeed("git -C /root/fleet init -q")
    operator.succeed("git -C /root/fleet add -A")
    operator.succeed(
        "git -C /root/fleet -c user.name=test -c user.email=test@example commit -qm 'the fleet'"
    )

    # --- the signing key ------------------------------------------------
    #
    # `require-sigs = true` on the target takes no unsigned closure, root or
    # not (M0 probe S12). The public half reaches the target the way that
    # probe measured: an include in nix.conf that the managed profile
    # already carries.
    operator.succeed(
        "nix-store --generate-binary-cache-key vm-update /root/keys/signing.sec /root/keys/signing.pub"
    )
    public = operator.succeed("cat /root/keys/signing.pub").strip()
    target.succeed(f"echo 'extra-trusted-public-keys = {public}' > /etc/nix/extra-keys.conf")
    target.succeed("systemctl restart nix-daemon.service")
    target.wait_until_succeeds("nix config show | grep -q vm-update", timeout=30)

    # The identity a host of this fleet has. Two files and nothing behind
    # them: what `enrolled` asks is whether the machine HAS an identity, and
    # delivering a real one is `keys deliver` in M3.
    target.succeed("mkdir -p /var/lib/meisterstack/pki")
    target.succeed("echo not-a-key > /var/lib/meisterstack/pki/identity.key")
    target.succeed("echo not-a-cert > /var/lib/meisterstack/pki/identity.crt")
    target.succeed("chown meister:meister /var/lib/meisterstack/pki/identity.key")
    target.succeed("chmod 600 /var/lib/meisterstack/pki/identity.key")

    def deploy(name, manifest):
        """resolve -> build: the two verbs that turn an evaluation into a release."""
        operator.succeed(
            f"cd /root/fleet && meister-deploy resolve --from /etc/vm-fleet/{manifest} "
            f"--repo /root/fleet --out m-{name}.json"
        )
        operator.succeed(
            f"cd /root/fleet && meister-deploy build --manifest m-{name}.json "
            f"--sign-key /root/keys/signing.sec --repo /root/fleet --out r-{name}.json"
        )
        return f"/root/fleet/r-{name}.json"

    def make_plan(release, name):
        operator.succeed(
            f"cd /root/fleet && meister-deploy plan --release {release} --select all "
            f"--repo /root/fleet --identity /root/.ssh/id_ed25519 --out p-{name}.json"
        )
        return f"/root/fleet/p-{name}.json"

    def approvals(plan):
        text = operator.succeed(f"cat {plan}")
        the_plan = json.loads(text)
        return " ".join(
            f"--approve {a['class']}={a['bound_plan_id']}" for a in the_plan["approvals"]
        )

    def apply(plan, release, extra=""):
        out = operator.succeed(
            f"cd /root/fleet && meister-deploy apply --plan {plan} --release {release} "
            f"--repo /root/fleet --identity /root/.ssh/id_ed25519 "
            f"--inventory /root/fleet/fleet.toml {approvals(plan)} {extra}"
        )
        return out.splitlines()[0].strip()

    def receipt_of(run):
        return json.loads(operator.succeed(f"cat /root/fleet/.meister-deploy/runs/{run}/receipt.json"))

    def generation():
        return target.succeed("cat /etc/meister-generation").strip()

    # --- V10: a fleet that already runs the release ---------------------
    release_a = deploy("a", "nix-manifest-a.json")
    plan_a = make_plan(release_a, "a")
    the_plan = json.loads(operator.succeed(f"cat {plan_a}"))
    assert the_plan["hosts"]["target"]["verdict"] == "unchanged", the_plan["hosts"]
    assert len(the_plan["actions"]) == 2, the_plan["actions"]

    run = apply(plan_a, release_a)
    receipt = receipt_of(run)
    assert receipt["outcome"] == "success", receipt
    assert receipt["hosts"]["target"]["outcome"] == "unchanged", receipt
    assert generation() == "A"
    # Nothing was copied and nothing was activated: the host has no
    # transaction record at all.
    assert json.loads(target.succeed("meister-activate --json txn list")) == []

    # --- the change -----------------------------------------------------
    release_b = deploy("b", "nix-manifest-b.json")
    plan_b = make_plan(release_b, "b")
    the_plan = json.loads(operator.succeed(f"cat {plan_b}"))
    assert the_plan["hosts"]["target"]["verdict"] == "change", the_plan["hosts"]
    print("approvals: " + approvals(plan_b))

    run = apply(plan_b, release_b)
    receipt = receipt_of(run)
    print(json.dumps(receipt["hosts"]["target"], indent=2))
    assert receipt["outcome"] == "success", receipt
    assert receipt["hosts"]["target"]["outcome"] == "success", receipt
    assert generation() == "B", "the target did not take the new system"
    # The receipt says where it came from and where it went, and the run
    # gave the host back afterwards.
    assert receipt["hosts"]["target"]["before"]["system"] != receipt["hosts"]["target"]["after"]["system"]
    assert target.succeed("meister-activate --json lock show").strip() == "null"
    assert json.loads(target.succeed("meister-activate --json txn list")) == []

    # And the journal of that run has the line a resume stands on, before
    # the activation and after its beginning.
    events = [
        json.loads(line)
        for line in operator.succeed(
            f"cat /root/fleet/.meister-deploy/runs/{run}/journal.jsonl"
        ).splitlines()
        if line.strip()
    ]
    kinds = [e["event"] for e in events]
    assert "action.irreversible" in kinds, kinds
    irreversible = kinds.index("action.irreversible")
    assert kinds.index("action.begin") < irreversible, kinds
    assert "run.end" in kinds, kinds

    # --- the same plan again --------------------------------------------
    #
    # Refused, and this is the honest answer rather than the "unchanged"
    # the lane brief expected: the plan's own observation says this host
    # runs A, and it runs B now. A plan is about a fleet at a moment.
    refused = operator.fail(
        f"cd /root/fleet && meister-deploy apply --plan {plan_b} --release {release_b} "
        f"--repo /root/fleet --identity /root/.ssh/id_ed25519 "
        f"--inventory /root/fleet/fleet.toml {approvals(plan_b)} 2>&1"
    )
    assert "the fleet moved under this plan" in refused, refused

    # The whole chain again IS a no-op, which is what idempotence means for
    # a tool whose plan is a document (V10, after a change).
    plan_b2 = make_plan(release_b, "b2")
    the_plan = json.loads(operator.succeed(f"cat {plan_b2}"))
    assert the_plan["hosts"]["target"]["verdict"] == "unchanged", the_plan["hosts"]
    run = apply(plan_b2, release_b)
    assert receipt_of(run)["hosts"]["target"]["outcome"] == "unchanged"
    assert generation() == "B"

    # --- and back ------------------------------------------------------
    plan_back = make_plan(release_a, "back")
    run = apply(plan_back, release_a)
    receipt = receipt_of(run)
    assert receipt["outcome"] == "success", receipt
    assert generation() == "A", "the target was not brought back"
    print("the host was changed and brought back, both with a receipt")

    # --- V18: a host somebody else holds --------------------------------
    target.succeed(
        "meister-activate lock acquire --run somebody-elses-run "
        "--operator somebody@elsewhere --pid 4242"
    )
    plan_v18 = make_plan(release_b, "v18")
    refused = operator.fail(
        f"cd /root/fleet && meister-deploy apply --plan {plan_v18} --release {release_b} "
        f"--repo /root/fleet --identity /root/.ssh/id_ed25519 "
        f"--inventory /root/fleet/fleet.toml {approvals(plan_v18)} 2>&1"
    )
    assert "somebody-elses-run" in refused, refused
    assert generation() == "A", "a refused run changed the host anyway"
    target.succeed("meister-activate lock release --run somebody-elses-run")

    # --- a release that was edited after it was built --------------------
    #
    # The nar hash of what is in the store is what a plan is about. Changing
    # it in the file changes the release's own id, and the id is checked
    # before anything else happens.
    operator.succeed(
        "cd /root/fleet && jq '.artifacts.target.toplevel.nar_hash = \"sha256-somethingelse\"' "
        "r-b.json > r-tampered.json"
    )
    refused = operator.fail(
        f"cd /root/fleet && meister-deploy apply --plan {plan_v18} "
        "--release /root/fleet/r-tampered.json --repo /root/fleet "
        "--identity /root/.ssh/id_ed25519 --inventory /root/fleet/fleet.toml 2>&1"
    )
    assert "edited after it was built" in refused, refused

    # --- V17: the workstation dies after the irreversible step -----------
    #
    # Started as a transient unit so that it can be killed at a decided
    # moment: the journal says when the activation has begun, and that is
    # the one window the resume table exists for.
    plan_v17 = make_plan(release_b, "v17")
    operator.succeed(
        f"systemd-run --unit=apply-v17 --collect --working-directory=/root/fleet "
        f"--setenv=PATH=/run/current-system/sw/bin "
        f"meister-deploy apply --plan {plan_v17} --release {release_b} "
        f"--repo /root/fleet --identity /root/.ssh/id_ed25519 "
        f"--inventory /root/fleet/fleet.toml {approvals(plan_v17)}"
    )
    operator.wait_until_succeeds(
        "grep -l action.irreversible /root/fleet/.meister-deploy/runs/*/journal.jsonl",
        timeout=120,
    )
    operator.succeed("systemctl kill -s SIGKILL apply-v17.service || true")
    operator.wait_until_fails("systemctl is-active apply-v17.service", timeout=60)

    # Which run was that: the one whose journal has no `run.end`.
    interrupted = operator.succeed(
        "grep -L run.end /root/fleet/.meister-deploy/runs/*/journal.jsonl | head -1"
    ).strip().split("/")[-2]
    print("the interrupted run: " + interrupted)
    open_txns = json.loads(target.succeed("meister-activate --json txn list"))
    assert len(open_txns) == 1, open_txns
    assert open_txns[0]["state"] == "pending", open_txns

    # A fresh plan is refused while that record is there, and says why.
    operator.succeed(
        f"cd /root/fleet && meister-deploy plan --release {release_b} --select all "
        f"--repo /root/fleet --identity /root/.ssh/id_ed25519 --out p-blocked.json; "
        "test $? -le 2"
    )
    blocked = json.loads(operator.succeed("cat /root/fleet/p-blocked.json"))
    reasons = " ".join(blocked["hosts"]["target"]["reasons"])
    assert "apply --resume" in reasons, reasons

    # The resume asks the target, finds the activation pending, and finishes
    # it — without a second `nix copy` and without a second activation.
    run = apply(plan_v17, release_b, extra=f"--resume {interrupted}")
    assert run == interrupted, (run, interrupted)
    receipt = receipt_of(interrupted)
    assert receipt["hosts"]["target"]["outcome"] == "success", receipt
    assert generation() == "B"
    actions = [a["kind"] for a in receipt["hosts"]["target"]["actions"]]
    assert actions.count("activate") == 1, actions
    assert json.loads(target.succeed("meister-activate --json txn list")) == []

    print("meister-deploy: a managed host was changed, brought back, and resumed")
  '';
}
