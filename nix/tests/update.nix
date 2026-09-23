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
    roles = ["cloud", "cluster"]
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
    # A control plane and no agent. The inventory insists that a cloud has a
    # cluster and a cluster has a cloud, so a fleet of one host carries both
    # — and NOT the agent role, because an agent that carries guests may
    # only be interrupted through `meister node drain` (D7), and a drain
    # against a control plane that is not really serving anything would be
    # a step this test could only fake. What the drain does is pinned in
    # execute.rs, against the command line it produces.
    meisterstack.roles = [ "cloud" "cluster" ];
    meisterstack.managed.enable = true;
    # A placeholder, so that 1A's assertion is satisfied at build time. The
    # key this fleet really signs with is generated while the test runs and
    # reaches the target through `extra-keys.conf` below — which is the road
    # M0 probe S12 measured.
    # The shape matters as much as the value: nix PARSES every entry of
    # `trusted-public-keys` when it opens the store, and a key that is not
    # 32 base64 bytes makes every copy fail with "public key is not valid" —
    # including the ones signed with a key that IS trusted. Measured here.
    meisterstack.managed.trustedPublicKeys = [
      "vm-update-placeholder:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    ];
    # --- lane 4C: this host may FETCH, and only from the fleet's own cache.
    #
    # The operator serves `/root/cache` — where `build --cache` put the
    # signed closures — over http on its own address. `require-sigs` stays
    # `true`, so a path that comes out of there is held to exactly the rule
    # a path pushed over ssh-ng is: signed by a key in
    # `trustedPublicKeys`, which for this fleet is the one key the test
    # makes. That is the whole claim, and it is what makes a fleet's own
    # cache safe to name.
    #
    # In the inventory of a real fleet this line is
    # `[defaults] managed.substituters` (nix/lib/inventory.nix); here the
    # host module IS the inventory, because this test hands `resolve` a
    # manifest rather than evaluating a flake.
    meisterstack.managed.substituters = [ "http://192.168.1.1:8080" ];
    # --- end lane 4C ---
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
      # python3: the http server that puts `/root/cache` on the wire, which
      # is what a real operator's cache is reached over (lane 4C).
      environment.systemPackages = [ pkgs.meisterstack pkgs.git pkgs.jq pkgs.python3 ];
      # The cache's port, and it has to be said out loud: a NixOS host has a
      # firewall on by default, sshd opens its own port and nothing opens
      # this one. Without this line the target's `nix copy --from http://…`
      # hangs on a port that is filtered rather than closed.
      networking.firewall.allowedTCPPorts = [ 8080 ];
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

    # Never started. It is system B: the same host with one file changed.
    #
    # `nodeNumber` is forced to the target's, and that is not cosmetic: the
    # test framework derives each node's MAC address from it and writes a
    # udev rule with that MAC INTO THE INITRD. A spare node with a number of
    # its own would therefore have a different initrd, the planner would
    # rightly call the change a reboot class, and this test would be about
    # the boot menu instead of about the update path. Two systems of one
    # machine have to be the same machine in everything the boot depends on.
    unused = { nodes, ... }: {
      imports = [ targetCommon ];
      environment.etc."meister-generation".text = "B";
      # The same udev rule the TARGET has, and this is not cosmetic: the
      # test framework derives each node's MAC address from its position in
      # the node list and writes a rule with that MAC INTO THE INITRD. A
      # spare node with a number of its own therefore has a different
      # initrd, the planner rightly calls the change a reboot class, and
      # this test would be about the boot menu instead of about the update
      # path. Two systems of one machine have to be the same machine in
      # everything the boot depends on — so the rule is the one node 2 gets,
      # built with the framework's own function rather than typed out.
      # (`virtualisation.test.nodeNumber` itself is read-only.)
      # The TARGET's boot-time udev rules, verbatim.
      #
      # Not cosmetic: the test framework derives each node's MAC address
      # from its position in the node list and writes a rule with that MAC
      # into the INITRD (nixos/lib/testing/network.nix). A spare node with a
      # number of its own therefore has a different initrd, the planner
      # rightly calls the change a reboot class, and this test would be
      # about the boot menu instead of about the update path. Two systems of
      # one machine have to be the same machine in everything a boot depends
      # on — and taking the value from the other node is the only spelling
      # of that which cannot drift.
      boot.initrd.services.udev.rules =
        lib.mkForce nodes.target.boot.initrd.services.udev.rules;
      # And the etcd member name, which NixOS derives from the host name and
      # which is the one identity a rollout compares against the inventory
      # (the topology check of D8). A spare system that called itself
      # something else would look like a membership change — which is
      # exactly what that check is for, and exactly not what this is.
      services.etcd.name = lib.mkForce nodes.target.services.etcd.name;
      # And the ADDRESS, for the same reason one step further on: the
      # framework gives each node `192.168.1.<its number>`, so a switch to
      # this system would reconfigure the machine's interface to an address
      # the operator is not talking to — and the host would be gone the
      # moment it took the new system. Measured: it was.
      # Only the two address families, because the evaluated value of the
      # other node still carries the deprecated `ip4`/`ip6` aliases and
      # copying those would print a renaming warning for a value nobody
      # wrote here.
      networking.interfaces = lib.mkForce (
        lib.mapAttrs
          (_: i: { inherit (i) ipv4 ipv6; })
          nodes.target.networking.interfaces
      );
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
    # The manifests, releases and plans go BESIDE the repository: a file
    # written into the tree it describes makes that tree dirty, and a dirty
    # tree is refused — which is a rule this test should not have to work
    # around. The state directory stays in the repository, where an operator
    # keeps it, and is ignored there.
    operator.succeed("mkdir -p /root/.ssh /root/fleet /root/keys /root/out")
    operator.copy_from_host("${keys.snakeOilPrivateKey}", "/root/.ssh/id_ed25519")
    operator.succeed("chmod 600 /root/.ssh/id_ed25519")
    operator.succeed("cp /etc/vm-fleet/fleet.toml /root/fleet/fleet.toml")
    operator.succeed("cp /etc/vm-fleet/flake.lock /root/fleet/flake.lock")
    operator.succeed("printf '.meister-deploy/\n' > /root/fleet/.gitignore")
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

    # What the two evaluations say about booting. They have to agree, or the
    # change between them is a reboot and this test would be about something
    # else; printed so that a reader of the log can see that they do.
    for name in ["a", "b"]:
        print(
            name
            + ": "
            + operator.succeed(f"jq -c '.hosts.target.build.boot' /etc/vm-fleet/nix-manifest-{name}.json")
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

    # What `nixos-install` leaves behind and a test machine does not have:
    # a system profile. Without it there is no answer to "what does this
    # host boot next", and a host that cannot say that is a host the planner
    # will not call unchanged — rightly.
    target.succeed(
        "nix-env -p /nix/var/nix/profiles/system --set \"$(readlink -f /run/current-system)\""
    )

    # The identity a host of this fleet has. Two files and nothing behind
    # them: what `enrolled` asks is whether the machine HAS an identity, and
    # delivering a real one is `keys deliver` in M3.
    target.succeed("mkdir -p /var/lib/meisterstack/pki")
    target.succeed("echo not-a-key > /var/lib/meisterstack/pki/identity.key")
    target.succeed("echo not-a-cert > /var/lib/meisterstack/pki/identity.crt")
    target.succeed("chown meister:meister /var/lib/meisterstack/pki/identity.key")
    target.succeed("chmod 600 /var/lib/meisterstack/pki/identity.key")

    # --- lane 4C: the fleet's own cache -------------------------------
    #
    # `file:///root/cache` is where `build --cache` puts the signed
    # closures, and the operator serves that directory over http on the
    # address the target's `managed.substituters` names.
    #
    # `compression=none`, and that is not a shortcut: the default for a
    # `file://` store is xz, and xz-ing a NixOS system closure in a test VM
    # is minutes of cpu for a property this test is not about. What it IS
    # about — that the signature travels into the cache and that the far
    # side accepts it — is the same either way.
    CACHE = "file:///root/cache?compression=none"
    operator.succeed("mkdir -p /root/cache")
    operator.succeed(
        "systemd-run --unit=cache-http --collect "
        "--working-directory=/root/cache "
        "/run/current-system/sw/bin/python3 -m http.server 8080"
    )
    operator.wait_for_open_port(8080)
    # --- end lane 4C ---

    def deploy(name, manifest):
        """resolve -> build: the two verbs that turn an evaluation into a release."""
        operator.succeed(
            f"cd /root/fleet && meister-deploy resolve --from /etc/vm-fleet/{manifest} "
            f"--repo /root/fleet --out /root/out/m-{name}.json"
        )
        operator.succeed(
            f"cd /root/fleet && meister-deploy build --manifest /root/out/m-{name}.json "
            f"--sign-key /root/keys/signing.sec --repo /root/fleet "
            f"--cache '{CACHE}' --out /root/out/r-{name}.json"
        )
        return f"/root/out/r-{name}.json"

    def make_plan(release, name):
        operator.succeed(
            f"cd /root/fleet && meister-deploy plan --release {release} --select all "
            f"--repo /root/fleet --identity /root/.ssh/id_ed25519 --out /root/out/p-{name}.json"
        )
        return f"/root/out/p-{name}.json"

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

    # --- lane 4C: what went into the cache, and who can take it out -----
    #
    # Here and not after release A on purpose: A is the system this target
    # is RUNNING, so it is already in its store and fetching it would prove
    # nothing. B is a system this machine has never seen.
    #
    # (1) The release says where its closures went, beside the name of the
    #     key they were signed with. It is a statement about what happened
    #     and instructs nobody: what a host may FETCH is decided by that
    #     host's own configuration.
    the_release = json.loads(operator.succeed(f"cat {release_b}"))
    assert the_release["build_env"]["cache_url"] == CACHE, the_release["build_env"]
    assert the_release["build_env"]["signing_key_name"] == "vm-update", the_release["build_env"]
    top_b = the_release["artifacts"]["target"]["toplevel"]["store_path"]
    # --- lane 5C ---
    # `nix path-info` and not `test -e`, and the difference is what a VM
    # test's /nix/store is. Both machines mount the SAME store — the one
    # the build sandbox holds — and the operator declares system B in its
    # `additionalPaths`, so the bytes are under that path on the target too
    # and `test -e` was always true. What the target does not have is the
    # path in its own database, which is the only sense in which a store
    # has something: nothing may be substituted from it, copied out of it
    # or activated off it. Measured 2026-09-23 (lane 4C wrote this line and
    # never ran the test; the first run of it failed here).
    not_yet = target.fail(f"nix path-info {top_b} 2>&1")
    assert "not valid" in not_yet or "No such file" in not_yet, not_yet
    # --- end lane 5C ---

    # (2) The cache really holds that closure, and the SIGNATURE travelled
    #     with it — which is the whole reason the push happens after the
    #     signing and not before.
    in_cache = json.loads(
        operator.succeed(f"nix path-info --json --sigs --store '{CACHE}' {top_b}")
    )
    entries = in_cache["info"] if "info" in in_cache else in_cache
    sigs = list(entries.values())[0]["signatures"]
    print("what the cache says about the toplevel: " + json.dumps(sigs))
    assert any(s.startswith("vm-update:") for s in sigs), sigs

    # (3) And the TARGET takes it out of there by itself, over http, into
    #     its own store — the one with `require-sigs = true`. No
    #     `--no-check-sigs` anywhere on that line, and that is the point: a
    #     fleet's own cache is usable exactly because the closures in it
    #     carry the signature the fleet already trusts.
    target.succeed(f"nix copy --from http://192.168.1.1:8080 {top_b}")
    # --- lane 5C: the same probe as above, the other way round ---
    target.succeed(f"nix path-info {top_b}")
    target.succeed(f"test -e {top_b}/init")
    print("the target fetched " + top_b + " out of the operator's cache, signature and all")

    # And the other half, which is what makes that guarantee worth having:
    # an UNSIGNED path out of the same cache is refused by the same store.
    # `nix store sign` writes into the local store only, so a path the
    # release never signed and that was pushed anyway is exactly that case.
    # `nix-store --add` and not `nix store add-path`, which is a deprecated
    # alias in 2.35 and prints a warning this test would have to filter.
    operator.succeed("echo not-signed > /root/unsigned.txt")
    unsigned = operator.succeed("nix-store --add /root/unsigned.txt").strip()
    operator.succeed(f"nix copy --to '{CACHE}' {unsigned}")
    refused = target.fail(f"nix copy --from http://192.168.1.1:8080 {unsigned} 2>&1")
    assert "signature" in refused, refused
    print("and an unsigned path out of the same cache is refused: "
          + refused.strip().splitlines()[-1])
    # --- end lane 4C ---
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

    # --- lane 4C: the stage was allowed to use the cache ----------------
    #
    # The copy is still ONE `nix copy --to ssh-ng://` and the nar hash at
    # the target is still compared against the release — the cache is a
    # shortcut inside the transfer and never an exception to it. What
    # changed is that the far store was allowed to fetch what it can reach
    # itself, and the receipt says so with the store the HOST's own
    # configuration names.
    staged = [
        line
        for action in receipt["hosts"]["target"]["actions"]
        if action["kind"] == "stage"
        for line in action["evidence"]
    ]
    print("stage evidence: " + json.dumps(staged, indent=2))
    assert any("as the release says" in line for line in staged), staged
    assert any(
        "allowed to fetch" in line and "http://192.168.1.1:8080" in line for line in staged
    ), staged
    # --- end lane 4C ---
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

    # A switch leaves the machine RUNNING one system and having BOOTED
    # another, and the planner says so: the next plan over the same release
    # is the reboot that makes the two the same, and nothing else. It is
    # read here and not carried out — the boot half lives in
    # nix/tests/activate.nix — because a rollout that called a switched host
    # finished would be hiding a pending reboot.
    plan_pending = make_plan(release_b, "pending")
    the_plan = json.loads(operator.succeed(f"cat {plan_pending}"))
    assert the_plan["hosts"]["target"]["verdict"] == "change", the_plan["hosts"]
    steps = [a["kind"] for a in the_plan["actions"] if a["blocked"] is None]
    assert "reboot" in steps, steps
    assert "stage" not in steps, ("what is already there is not staged again", steps)
    assert "activate" not in steps, ("there is nothing left to activate", steps)
    # And it says WHY, in the words of the plan rather than of this test.
    said = " ".join(
        reason for a in the_plan["actions"] for reason in a["preconditions"]
    )
    assert "has not booted it" in said, said

    # --- and back ------------------------------------------------------
    plan_back = make_plan(release_a, "back")
    run = apply(plan_back, release_a)
    receipt = receipt_of(run)
    assert receipt["outcome"] == "success", receipt
    assert generation() == "A", "the target was not brought back"
    print("the host was changed and brought back, both with a receipt")

    # And NOW it is unchanged: it runs what it booted and what the release
    # says. So the whole chain again is two steps and no commands — which is
    # what idempotence means for a tool whose plan is a document (V10).
    plan_noop = make_plan(release_a, "noop")
    the_plan = json.loads(operator.succeed(f"cat {plan_noop}"))
    assert the_plan["hosts"]["target"]["verdict"] == "unchanged", the_plan["hosts"]
    run = apply(plan_noop, release_a)
    assert receipt_of(run)["hosts"]["target"]["outcome"] == "unchanged"
    assert generation() == "A"
    assert json.loads(target.succeed("meister-activate --json txn list")) == []

    # --- V18: a host somebody else holds --------------------------------
    # The plan is made first and the host is taken afterwards, which is the
    # order this actually happens in: somebody else starts a run between the
    # planning and the applying.
    plan_v18 = make_plan(release_b, "v18")
    target.succeed(
        "meister-activate lock acquire --run somebody-elses-run "
        "--operator somebody@elsewhere --pid 4242"
    )
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
        "jq '.artifacts.target.toplevel.nar_hash = \"sha256-somethingelse\"' "
        "/root/out/r-b.json > /root/out/r-tampered.json"
    )
    refused = operator.fail(
        f"cd /root/fleet && meister-deploy apply --plan {plan_v18} "
        "--release /root/out/r-tampered.json --repo /root/fleet "
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
    # The moment to kill it is when the TARGET holds the record: the journal
    # line is written BEFORE the command, so killing on the line alone would
    # kill a run that had not yet reached the machine — and prove nothing.
    target.wait_until_succeeds(
        "meister-activate --json txn list | grep -q pending", timeout=180
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
    # `execute` and not `succeed`: exit 2 is "blocked", which is an answer
    # and not a failure — and the driver's `succeed` runs `set -e`.
    status, _ = operator.execute(
        f"cd /root/fleet && meister-deploy plan --release {release_b} --select all "
        f"--repo /root/fleet --identity /root/.ssh/id_ed25519 --out /root/out/p-blocked.json"
    )
    assert status == 2, f"a blocked plan is exit 2, not {status}"
    blocked = json.loads(operator.succeed("cat /root/out/p-blocked.json"))
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
