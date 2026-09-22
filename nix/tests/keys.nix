# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# The exit criterion of lane 3B, in two virtual machines: a host nobody has
# ever spoken to gets an identity, and the control plane on it authenticates
# with a certificate this fleet's own CA issued over a key that never left
# the machine.
#
# What is real here:
#
# * the host key is read off the TARGET's console (the test plays the person
#   at the console) and `keys enroll` compares it with what `ssh-keyscan`
#   answers; a fingerprint that is not the one is refused;
# * the private key is generated ON `box` by `meister-activate keygen` and
#   only the certificate request travels;
# * `tools/meister-ca --sign-csr` is the real script with real openssl, and
#   its CA key never leaves the operator VM;
# * the delivery is the plan's own action, carried out by `apply` over ssh;
# * and what proves it at the end is not a file's mode but a SESSION: the
#   cluster controller registers with the cloud controller over mTLS, and it
#   comes back after a restart and after a reboot.
#
# What is NOT real is the same one thing as in nix/tests/update.nix: the
# EVALUATION. A test VM has no nixpkgs and could not evaluate its own test
# nodes, so the manifest is built here at build time by `nix/lib/manifest.nix`
# — the file `lib.mkFleet` uses — and handed over with `resolve --from`.
{ nixpkgs, lib, pkgs, system, self }:

let
  keys = import "${nixpkgs}/nixos/tests/ssh-keys.nix" pkgs;
  inventoryLib = import ../lib/inventory.nix { inherit lib; };

  # The CA, as an operator would have it: the script from this repository,
  # with an openssl it can find. Not a package of this flake — `meister-ca`
  # is not packaged yet (see the lane's report), and a test that shipped a
  # different script from the one an operator runs would prove nothing about
  # that one.
  meisterCa = pkgs.writeShellScriptBin "meister-ca" (builtins.readFile ../../tools/meister-ca);

  # One host, and it is the whole control plane: the inventory insists that a
  # cloud has a cluster and a cluster has a cloud, so a fleet of one can only
  # have this shape.
  fleetToml = builtins.toFile "fleet.toml" ''
    schema = 2

    [fleet]
    name = "vm-keys"
    domain = "vm.example"

    [operator]
    # A REFERENCE and not a secret: what lives there is the CA key, and it is
    # outside the repository on purpose — `keys issue` refuses a `ca_dir`
    # under the committed tree.
    ca_dir = "../ca"

    [defaults]
    ssh = { user = "root", port = 22 }
    profiles = [ ]
    rollout = { max_unavailable = 1, reboot = "approve" }
    checks = { required = [ "units" ] }

    [[group]]
    id = "cp"
    kind = "raft"

    [[host]]
    id = "box"
    name = "box"
    deployment = "nixos"
    roles = ["cloud", "cluster"]
    groups = ["cp"]
    controller_group = "cp"
    site = "vm"
    networks.management = { address = "192.168.1.1", prefix = 24, interface = "eth1" }
    ssh.host_key = "SHA256:PLACEHOLDER-THE-TEST-FILLS-THIS-IN"
  '';

  inv = inventoryLib.load fleetToml;

  pki = "/var/lib/meisterstack/pki";

  # What both systems of the target are. They differ in one file, so the
  # switch between them changes a file and no unit — which is what keeps the
  # test driver's backdoor alive across it.
  boxCommon = { ... }: {
    imports = [
      self.nixosModules.services
      self.nixosModules.managed
      # The module `lib.mkFleet` gives a host of this fleet: its roles, and
      # the per-host values the one derivation computes from the inventory
      # — the cluster's name, the address it dials the cloud at, the etcd
      # membership. Without it a controller comes up with its built-in
      # defaults and "runs standalone", which is a test about nothing. (The
      # first run of this test measured exactly that.)
      (inv.hostModule "box")
    ];
    meisterstack.managed.enable = true;
    # A test node boots with `-kernel` and has no ESP, and the fleet's host
    # module asks for systemd-boot (gate M0 (b)). Both loaders off is what
    # nixos-test-base wants.
    boot.loader.systemd-boot.enable = lib.mkForce false;
    boot.loader.efi.canTouchEfiVariables = lib.mkForce false;
    # The cloud's key-encryption key: the one DATA secret of this fleet, and
    # the one file the planner must never replace once it is there (a present
    # `secrets.key` is the key the stored secrets were encrypted with).
    meisterstack.cloud.settings.secrets_key = "${pki}/secrets.key";
    meisterstack.managed.trustedPublicKeys = [
      "vm-keys-placeholder:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    ];
    nix.extraOptions = ''
      !include /etc/nix/extra-keys.conf
    '';

    services.openssh.enable = true;
    users.users.root.openssh.authorizedKeys.keys = [ keys.snakeOilPublicKey ];

    system.switch.enable = true;
    boot.loader.grub.enable = false;

    virtualisation.writableStore = true;
    virtualisation.memorySize = 2048;
    virtualisation.diskSize = 8192;
  };

  manifestOf = node: builtins.toFile "nix-manifest.json" (builtins.unsafeDiscardStringContext
    (builtins.toJSON (import ../lib/manifest.nix { inherit lib; } {
      inventory = inv;
      configs = { box = node; };
      packages = {
        inherit (pkgs) meisterstack;
        cloudHypervisor = pkgs.cloud-hypervisor-meister;
        guestTiny = pkgs.guest-tiny;
        leandro = null;
        patchDir = ../../patches;
        srcRev = "vm-keys-test";
      };
    })));
in
pkgs.testers.runNixOSTest {
  name = "meister-keys-roundtrip";

  nodes = {
    # The workstation: the tool, the CA script, a git repository, a signing
    # key and both of the target's closures.
    #
    # The test framework numbers the nodes in the order Nix sorts their
    # names and gives each `192.168.1.<number>`, so `box` is .1 and this is
    # .2. Which is which does not matter as long as the INVENTORY says what
    # the machine really has — and the first assertion of the script is
    # exactly that.
    operator = { nodes, ... }: {
      environment.systemPackages = [
        pkgs.meisterstack
        pkgs.git
        pkgs.jq
        pkgs.openssl
        meisterCa
      ];
      nix.settings.experimental-features = [ "nix-command" ];
      virtualisation.writableStore = true;
      virtualisation.memorySize = 3072;
      virtualisation.diskSize = 16384;
      virtualisation.additionalPaths = [
        nodes.box.system.build.toplevel
        nodes.box.system.build.toplevel.drvPath
        nodes.unused.system.build.toplevel
        nodes.unused.system.build.toplevel.drvPath
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
      environment.etc."vm-fleet/nix-manifest-a.json".source = manifestOf nodes.box;
      environment.etc."vm-fleet/nix-manifest-b.json".source = manifestOf nodes.unused;
    };

    # The managed host, fresh: no certificate of any kind, and
    # its units waiting on a CA certificate that has never arrived.
    box = { ... }: {
      imports = [ boxCommon ];
      environment.etc."meister-generation".text = "A";
    };

    # Never started. The same machine with one file changed — what the
    # bootstrap activates. The three `mkForce`s are the ones
    # nix/tests/update.nix explains: two systems of one host have to be the
    # same host in everything a boot and an identity hang on.
    unused = { nodes, ... }: {
      imports = [ boxCommon ];
      environment.etc."meister-generation".text = "B";
      boot.initrd.services.udev.rules =
        lib.mkForce nodes.box.boot.initrd.services.udev.rules;
      services.etcd.name = lib.mkForce nodes.box.services.etcd.name;
      networking.interfaces = lib.mkForce (
        lib.mapAttrs
          (_: i: { inherit (i) ipv4 ipv6; })
          nodes.box.networking.interfaces
      );
    };
  };

  testScript = ''
    import json

    operator.start()
    box.start()
    operator.wait_for_unit("multi-user.target")
    box.wait_for_unit("sshd.service")
    box.succeed("ip -4 addr show eth1 | grep -q 'inet 192.168.1.1/24'")

    pki = "${pki}"

    def mode_of(path):
        return box.succeed(f"stat -c '%a %U:%G' {path}").strip()

    # --- the operator's repository --------------------------------------
    operator.succeed("mkdir -p /root/.ssh /root/fleet /root/keys /root/out /root/ca")
    operator.copy_from_host("${keys.snakeOilPrivateKey}", "/root/.ssh/id_ed25519")
    operator.succeed("chmod 600 /root/.ssh/id_ed25519")
    operator.succeed("cp /etc/vm-fleet/fleet.toml /root/fleet/fleet.toml")
    operator.succeed("cp /etc/vm-fleet/flake.lock /root/fleet/flake.lock")
    operator.succeed("printf '.meister-deploy/\n' > /root/fleet/.gitignore")
    operator.succeed("chmod 644 /root/fleet/fleet.toml /root/fleet/flake.lock")

    # --- step 1: the fingerprint off the console -------------------------
    #
    # `ssh-keygen -lf` ON THE MACHINE is what a person reads off a console or
    # out of an installer's output. Nothing the operator VM can ask over the
    # network is allowed to stand in for it — that is the whole of D10.
    fingerprint = box.succeed(
        "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub | cut -d' ' -f2"
    ).strip()
    print("box shows: " + fingerprint)

    # A fingerprint that is not the one this machine shows: refused, both
    # named, nothing written.
    wrong = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    refused = operator.fail(
        f"cd /root/fleet && meister-deploy keys enroll box --fingerprint {wrong} 2>&1"
    )
    assert "is not the one you typed" in refused, refused
    assert fingerprint in refused, refused
    operator.fail("test -e /root/fleet/known_hosts")

    # The right one: enrolled.
    out = operator.succeed(
        f"cd /root/fleet && meister-deploy keys enroll box --fingerprint {fingerprint} 2>&1"
    )
    print(out)
    assert "ssh.host_key" in out, out
    known = operator.succeed("cat /root/fleet/known_hosts")
    assert known.startswith("192.168.1.1 ssh-ed25519 "), known

    # Twice is not a change.
    again = operator.succeed(
        f"cd /root/fleet && meister-deploy keys enroll box --fingerprint {fingerprint} 2>&1"
    )
    assert "already enrolled" in again, again
    assert operator.succeed("cat /root/fleet/known_hosts") == known

    # The inventory is the operator's own file: the tool prints the line and
    # does not edit it.
    operator.succeed(
        f"sed -i 's|SHA256:PLACEHOLDER-THE-TEST-FILLS-THIS-IN|{fingerprint}|' /root/fleet/fleet.toml"
    )
    for name in ["a", "b"]:
        operator.succeed(
            f"sed -i 's|SHA256:PLACEHOLDER-THE-TEST-FILLS-THIS-IN|{fingerprint}|' "
            f"/etc/vm-fleet/nix-manifest-{name}.json"
        )

    operator.succeed("git -C /root/fleet init -q")
    operator.succeed("git -C /root/fleet add -A")
    operator.succeed(
        "git -C /root/fleet -c user.name=test -c user.email=test@example commit -qm 'the fleet'"
    )

    # --- the signing key, and the CA -------------------------------------
    operator.succeed(
        "nix-store --generate-binary-cache-key vm-keys /root/keys/signing.sec /root/keys/signing.pub"
    )
    public = operator.succeed("cat /root/keys/signing.pub").strip()
    box.succeed(f"echo 'extra-trusted-public-keys = {public}' > /etc/nix/extra-keys.conf")
    box.succeed("systemctl restart nix-daemon.service")
    box.wait_until_succeeds("nix config show | grep -q vm-keys", timeout=30)

    # The fleet's own certificate authority, in a directory beside the
    # repository. Its key is generated here and stays here.
    operator.succeed("meister-ca --dir /root/ca")
    operator.succeed("test -f /root/ca/ca.key && test -f /root/ca/ca.crt")
    # And the cloud's key-encryption key, which is an OPERATOR FILE: this
    # tool never makes one and never replaces one.
    # 64 hex characters and no newline: the cloud reads 32 raw bytes or 64
    # hex, and anything else is a start-up error naming the length it got.
    operator.succeed(
        "openssl rand -hex 32 | tr -d '\n' > /root/ca/secrets.key && chmod 600 /root/ca/secrets.key"
    )

    # What `nixos-install` leaves and a test machine does not have.
    box.succeed(
        "nix-env -p /nix/var/nix/profiles/system --set \"$(readlink -f /run/current-system)\""
    )

    # --- what a fresh host looks like ------------------------------------
    box.fail(f"test -e {pki}/identity.key")
    box.fail(f"test -e {pki}/ca.crt")
    # The units are waiting for a file nobody has delivered, and they say so
    # rather than restarting for ever.
    box.fail("systemctl is-active meister-cloud-controller.service")
    box.fail("systemctl is-active meister-cluster-controller.service")

    def deploy(name, manifest):
        operator.succeed(
            f"cd /root/fleet && meister-deploy resolve --from /etc/vm-fleet/{manifest} "
            f"--repo /root/fleet --out /root/out/m-{name}.json"
        )
        operator.succeed(
            f"cd /root/fleet && meister-deploy build --manifest /root/out/m-{name}.json "
            f"--sign-key /root/keys/signing.sec --repo /root/fleet --out /root/out/r-{name}.json"
        )
        return f"/root/out/r-{name}.json"

    def make_plan(release, name, kind="upgrade"):
        status, _ = operator.execute(
            f"cd /root/fleet && meister-deploy plan --release {release} --select all "
            f"--kind {kind} --repo /root/fleet --identity /root/.ssh/id_ed25519 "
            f"--inventory /root/fleet/fleet.toml --out /root/out/p-{name}.json"
        )
        return status, f"/root/out/p-{name}.json"

    def approvals(plan):
        the_plan = json.loads(operator.succeed(f"cat {plan}"))
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
        return json.loads(
            operator.succeed(f"cat /root/fleet/.meister-deploy/runs/{run}/receipt.json")
        )

    # --- step 2: an upgrade cannot act on a host with no identity --------
    release_a = deploy("a", "nix-manifest-a.json")
    status, plan_up = make_plan(release_a, "upgrade")
    assert status == 2, f"an unenrolled host blocks an upgrade, exit was {status}"
    the_plan = json.loads(operator.succeed(f"cat {plan_up}"))
    assert the_plan["hosts"]["box"]["verdict"] == "unenrolled", the_plan["hosts"]
    why = " ".join(the_plan["hosts"]["box"]["reasons"])
    assert "--kind bootstrap" in why, why

    # A bootstrap cannot act either, YET: nothing has been issued, and it
    # says which verb makes it.
    release_b = deploy("b", "nix-manifest-b.json")
    status, plan_early = make_plan(release_b, "early", kind="bootstrap")
    assert status == 2, f"nothing issued, exit was {status}"
    the_plan = json.loads(operator.succeed(f"cat {plan_early}"))
    why = " ".join(the_plan["hosts"]["box"]["reasons"])
    assert "keys csr --host box" in why, why
    assert "keys issue --host box" in why, why

    # --- step 3: the key is made on the host -----------------------------
    #
    # `--as cluster` because this host carries two tiers and the fleet gives
    # it ONE identity.key: every rendered configuration names the same file,
    # so it holds one identity and the operator says which.
    out = operator.succeed(
        "cd /root/fleet && meister-deploy keys csr --host box --kind identity "
        "--as cluster --manifest /root/out/m-b.json --repo /root/fleet "
        "--identity /root/.ssh/id_ed25519 2>&1"
    )
    print(out)
    assert "CN=system:cluster:cp" in out, out
    operator.succeed(
        "cd /root/fleet && meister-deploy keys csr --host box --kind serving "
        "--manifest /root/out/m-b.json --repo /root/fleet "
        "--identity /root/.ssh/id_ed25519"
    )

    # On the host: two private keys, 0600, owned by the user that reads them
    # — and NO certificate, because nobody has signed anything yet.
    assert mode_of(f"{pki}/identity.key") == "600 meister:meister"
    assert mode_of(f"{pki}/serving.key") == "600 meister:meister"
    box.fail(f"test -e {pki}/identity.crt")
    box.fail(f"test -e {pki}/serving.crt")

    # What travelled is a request and nothing else.
    for kind in ["identity", "serving"]:
        text = operator.succeed(f"cat /root/fleet/pki/csr/box-{kind}.csr")
        assert "BEGIN CERTIFICATE REQUEST" in text, text
        assert "PRIVATE KEY" not in text, "a key left the host"

    # And asking again does not make a second identity.
    before = box.succeed(f"sha256sum {pki}/identity.key").split()[0]
    operator.succeed(
        "cd /root/fleet && meister-deploy keys csr --host box --kind identity "
        "--as cluster --manifest /root/out/m-b.json --repo /root/fleet "
        "--identity /root/.ssh/id_ed25519"
    )
    assert box.succeed(f"sha256sum {pki}/identity.key").split()[0] == before, (
        "a second run made a second key"
    )

    # --- step 4: the CA signs them ---------------------------------------
    for kind, ca_kind in [("identity", "cluster"), ("serving", "serving")]:
        out = operator.succeed(
            f"cd /root/fleet && meister-deploy keys issue --host box --kind {ca_kind} "
            f"--manifest /root/out/m-b.json --repo /root/fleet "
            f"--inventory /root/fleet/fleet.toml --meister-ca meister-ca 2>&1"
        )
        print(out)
    issued = operator.succeed("ls /root/fleet/pki/issued/box/").split()
    assert sorted(issued) == ["identity.crt", "serving.crt"], issued

    # The subjects are the fleet's, not the requests'.
    subject = operator.succeed(
        "openssl x509 -in /root/fleet/pki/issued/box/identity.crt -noout -subject"
    )
    assert "CN=system:cluster:cp" in subject, subject
    assert "O=system:clusters" in subject, subject
    serving = operator.succeed(
        "openssl x509 -in /root/fleet/pki/issued/box/serving.crt -noout -subject -ext subjectAltName"
    )
    assert "CN=box" in serving, serving
    assert "IP Address:192.168.1.1" in serving, serving
    # And the CA never made a key for either of them.
    operator.fail("test -e /root/fleet/pki/issued/box/identity.key")

    # --- step 5: the bootstrap plan --------------------------------------
    status, plan_boot = make_plan(release_b, "boot", kind="bootstrap")
    assert status == 0, f"a bootstrap that can be carried out is exit 0, was {status}"
    the_plan = json.loads(operator.succeed(f"cat {plan_boot}"))
    assert the_plan["hosts"]["box"]["verdict"] == "change", the_plan["hosts"]
    steps = [a["kind"] for a in the_plan["actions"] if a["blocked"] is None]
    print("bootstrap: " + ", ".join(steps))
    delivered = [
        a["desired"] for a in the_plan["actions"] if a["kind"] == "deliver-secret"
    ]
    print("delivering: " + ", ".join(delivered))
    # Every file the fleet says comes from somewhere else, and NOT the two
    # keys the host made itself.
    for want in ["ca.crt", "identity.crt", "serving.crt", "secrets.key"]:
        assert any(want in d for d in delivered), (want, delivered)
    for never in ["identity.key", "serving.key"]:
        assert not any(d.endswith(never) for d in delivered), (never, delivered)
    # And every one of them before the activation.
    last_deliver = max(i for i, k in enumerate(steps) if k == "deliver-secret")
    assert "activate" in steps, steps
    assert last_deliver < steps.index("activate"), steps

    # --- step 6: apply ----------------------------------------------------
    run = apply(plan_boot, release_b)
    receipt = receipt_of(run)
    print(json.dumps(receipt["hosts"]["box"]["actions"], indent=2))
    assert receipt["outcome"] == "success", receipt
    assert box.succeed("cat /etc/meister-generation").strip() == "B"

    # The files are there, with the modes and the owners the fleet named.
    assert mode_of(f"{pki}/identity.key") == "600 meister:meister"
    assert mode_of(f"{pki}/serving.key") == "600 meister:meister"
    assert mode_of(f"{pki}/secrets.key") == "600 meister:meister"
    assert mode_of(f"{pki}/ca.crt").startswith("644 ")
    assert mode_of(f"{pki}/identity.crt").startswith("644 ")
    # And they are the files the operator signed.
    for name in ["identity.crt", "serving.crt"]:
        here = operator.succeed(f"sha256sum /root/fleet/pki/issued/box/{name}").split()[0]
        there = box.succeed(f"sha256sum {pki}/{name}").split()[0]
        assert here == there, (name, here, there)

    # Nothing that was sent is in the journal or in the receipt.
    journal = operator.succeed(f"cat /root/fleet/.meister-deploy/runs/{run}/journal.jsonl")
    assert "PRIVATE KEY" not in journal, "a key is in the journal"
    kek = operator.succeed("cat /root/ca/secrets.key").strip()
    assert kek not in journal, "the key-encryption key is in the journal"
    assert kek not in operator.succeed(
        f"cat /root/fleet/.meister-deploy/runs/{run}/receipt.json"
    ), "the key-encryption key is in the receipt"

    # --- step 7: V09, the rest — a real mTLS session ---------------------
    #
    # Not a mode and not a digest: the cluster controller registers with the
    # cloud controller, both ends presenting certificates this fleet's CA
    # signed over keys that were made on this machine.
    box.wait_for_unit("meister-cloud-controller.service")
    box.wait_for_unit("meister-cluster-controller.service")

    def session_lines():
        return box.succeed(
            "journalctl -u meister-cloud-controller.service --no-pager | tail -200"
        )

    box.wait_until_succeeds(
        "journalctl -u meister-cloud-controller.service --no-pager "
        "| grep -qiE 'system:cluster:cp'",
        timeout=120,
    )
    print(session_lines())

    # It comes back after a restart of the tier that dials…
    box.succeed("systemctl restart meister-cluster-controller.service")
    box.succeed("journalctl --rotate && journalctl --vacuum-time=1s")
    box.wait_until_succeeds(
        "journalctl -u meister-cloud-controller.service --no-pager "
        "| grep -qiE 'system:cluster:cp'",
        timeout=120,
    )

    # …and after a reboot of the whole machine, which is the half a mode
    # cannot show: the key survives, the tmpfiles rule keeps it at 0600, and
    # the session is opened again from a cold start.
    box.shutdown()
    box.start()
    box.wait_for_unit("multi-user.target")
    assert mode_of(f"{pki}/identity.key") == "600 meister:meister"
    box.wait_for_unit("meister-cluster-controller.service")
    box.wait_until_succeeds(
        "journalctl -u meister-cloud-controller.service --no-pager "
        "| grep -qiE 'system:cluster:cp'",
        timeout=180,
    )

    # --- step 8: the counter-probe ---------------------------------------
    #
    # A key the group can read is refused by the loader, in its own words
    # (nix/tests/credentials.nix measures the same sentence on the agent).
    box.succeed(f"chmod 640 {pki}/identity.key")
    box.succeed("systemctl restart meister-cluster-controller.service || true")
    box.wait_until_succeeds(
        "journalctl -u meister-cluster-controller.service --no-pager | grep -q 'too open'",
        timeout=60,
    )
    said = box.succeed(
        "journalctl -u meister-cluster-controller.service --no-pager | grep 'too open' | tail -1"
    )
    print(said)
    assert "permissions 0640" in said, said
    box.succeed(f"chmod 600 {pki}/identity.key")
    box.succeed("systemctl restart meister-cluster-controller.service")

    # --- step 9: and now there is nothing left to deliver ----------------
    status, plan_noop = make_plan(release_b, "noop")
    the_plan = json.loads(operator.succeed(f"cat {plan_noop}"))
    kinds = [a["kind"] for a in the_plan["actions"] if a["blocked"] is None]
    assert "deliver-secret" not in kinds, kinds
    assert the_plan["hosts"]["box"]["verdict"] == "unchanged", the_plan["hosts"]
    assert status == 0, status

    print("meister-deploy: a fresh host was enrolled, made its own key, and the "
          "control plane on it authenticates with a certificate this fleet issued")
  '';
}
