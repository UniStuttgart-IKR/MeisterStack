# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Exercise real certificate revocation, existing-session enforcement, and
# interrupted key rotation. Manifest evaluation happens at build time;
# certificates, controller authentication, and SSH operations run in test VMs.
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
    name = "vm-keys-revoke"
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
    # The one line that turns revocation on for a fleet. It is a DEVIATION
    # and not something the one derivation renders by itself, and that is
    # deliberate: a controller that names a list refuses to start without
    # it, so rendering it for every fleet would stop every controller that
    # has never been delivered one. Naming it here makes `crl.pem` a
    # `secret_refs` entry of both roles — which is how `keys revoke` finds
    # the hosts that read one.
    deviations.settings.cloud = { auth = { crl = "/var/lib/meisterstack/pki/crl.pem" } }
    deviations.settings.cluster = { auth = { crl = "/var/lib/meisterstack/pki/crl.pem" } }
    # No deviation for `cloud_addrs`: the cluster's session with the cloud
    # below is proof that the ONE derivation renders an address the dialing
    # tier accepts (finding N1 of lane 3B -- a bare `address:port` was
    # refused by tonic; the derivation now carries the scheme).
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
    # The operator's own line, and it belongs here rather than in the
    # fleet's modules: `nixosModules.services` sets nothing host-global
    # (D1), so which ports a host opens is the owner's decision. Without it
    # the REST edge of this test would be a port nobody can reach.
    networking.firewall.allowedTCPPorts = [ 3000 ];

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
  name = "meister-keys-revoke";

  nodes = {
    # The workstation: the tool, the CA script, a git repository, a signing
    # key, curl for the REST edge, and both of the target's closures.
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
        pkgs.curl
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
      # The fleet's host module gives every host of this fleet the hostname
      # the INVENTORY gives it, so both nodes are called `box` — and the
      # test driver names its machine variables after that. This one keeps
      # the hostname (it is the same machine) and takes a name of its own
      # for the driver and for the store path.
      system.name = lib.mkForce "unused";
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
    # An empty revocation list, before anything is bootstrapped: the two
    # controllers name one in their configuration and refuse to start
    # without it, so it is a file the fleet needs from its first day. An
    # empty list is a list — it says nothing has been taken back — and the
    # difference between that and a file nobody can read is the whole point
    # of the refusal.
    operator.succeed("meister-ca --dir /root/ca --index-rebuild --gencrl")
    operator.succeed("mkdir -p /root/fleet/pki && cp /root/ca/crl.pem /root/fleet/pki/crl.pem")
    operator.succeed("openssl crl -in /root/fleet/pki/crl.pem -noout -crlnumber")

    # Two people with certificates from this CA. `root` stays good and is
    # the counter-probe; `alice` is the one that gets taken back.
    operator.succeed("meister-ca --dir /root/ca --admin root --admin alice")

    # And into the repository, where it is a committed, public file like
    # `known_hosts`. `resolve` refuses a working tree with untracked files
    # in it (a manifest resolved from one could not be resolved again), so
    # this is the moment it is committed.
    operator.succeed("git -C /root/fleet add -A")
    operator.succeed(
        "git -C /root/fleet -c user.name=test -c user.email=test@example "
        "commit -qm 'the revocation list'"
    )

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
    for want in ["ca.crt", "identity.crt", "serving.crt", "secrets.key", "crl.pem"]:
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


    # --- step 7: the session, before anything is taken back --------------
    box.wait_for_unit("meister-cloud-controller.service")
    box.wait_for_unit("meister-cluster-controller.service")

    def cloud_log(pattern, timeout=120):
        box.wait_until_succeeds(
            "journalctl -u meister-cloud-controller.service --no-pager "
            f"| grep -qiE '{pattern}'",
            timeout=timeout,
        )

    cloud_log("system:cluster:cp")
    print(box.succeed(
        "journalctl -u meister-cloud-controller.service --no-pager | tail -30"
    ))

    # The list the controllers started with says nothing is revoked, and
    # --check-config reads the same file the same way.
    said = box.succeed(
        "meister-cloud-controller --check-config --config /etc/meisterstack/cloud.toml 2>&1"
    )
    print(said)
    assert "0 revoked serial(s)" in said, said

    # --- step 8: a REST client, and the one that gets taken back ---------
    #
    # curl and a certificate this CA issued: no mock, no test-only route.
    whoami = "https://192.168.1.1:3000/apis/meister.io/v1/whoami"

    def ask(who):
        status, out = operator.execute(
            f"curl -sS -o /root/out/{who}.body -w '%{{http_code}}' "
            f"--cacert /root/ca/ca.crt --cert /root/ca/{who}.crt --key /root/ca/{who}.key "
            f"{whoami} 2>/root/out/{who}.err"
        )
        body = operator.succeed(f"cat /root/out/{who}.body || true")
        err = operator.succeed(f"cat /root/out/{who}.err || true")
        return status, out.strip(), body, err

    status, code, body, _ = ask("alice")
    assert status == 0 and code == "200", (status, code, body)
    assert '"name":"alice"' in body.replace(" ", ""), body
    status, code, body, _ = ask("root")
    assert status == 0 and code == "200", (status, code, body)

    # --- step 9: take alice's certificate back ---------------------------
    alice_serial = operator.succeed(
        "openssl x509 -in /root/ca/alice.crt -noout -serial | cut -d= -f2"
    ).strip()
    print("revoking " + alice_serial)
    before_pid = box.succeed(
        "systemctl show -p MainPID --value meister-cloud-controller.service"
    ).strip()

    out = operator.succeed(
        f"cd /root/fleet && meister-deploy keys revoke --serial {alice_serial} "
        # Astra finding F21, 2026-09-23: this used to be --reason; it is
        # the openssl CRL reason, not free text, so the flag is now
        # --crl-reason.
        f"--crl-reason keyCompromise --release {release_b} --repo /root/fleet "
        "--identity /root/.ssh/id_ed25519 --inventory /root/fleet/fleet.toml "
        "--out /root/out/p-revoke.json 2>&1"
    )
    print(out)
    assert "crl number" in out, out
    # The plan is one file per host that reads one, and nothing else.
    the_plan = json.loads(operator.succeed("cat /root/out/p-revoke.json"))
    assert the_plan["kind"] == "keys-revoke", the_plan["kind"]
    kinds = [a["kind"] for a in the_plan["actions"] if a["blocked"] is None]
    print("revoke: " + ", ".join(kinds))
    assert set(kinds) == {"preflight", "lock", "deliver-secret", "verify", "unlock"}, kinds
    assert the_plan["approvals"] == [], the_plan["approvals"]

    run = apply("/root/out/p-revoke.json", release_b)
    receipt = receipt_of(run)
    assert receipt["outcome"] == "success", receipt
    evidence = " ".join(
        e
        for a in receipt["hosts"]["box"]["actions"]
        if a["kind"] == "deliver-secret"
        for e in a["evidence"]
    )
    assert "re-reads its revocation list" in evidence, evidence

    here = operator.succeed("sha256sum /root/fleet/pki/crl.pem").split()[0]
    there = box.succeed(f"sha256sum {pki}/crl.pem").split()[0]
    assert here == there, (here, there)

    # NOTHING was restarted. This is the property the whole design is for:
    # a revocation that needed a restart would be a revocation nobody dares
    # to do at three in the morning.
    after_pid = box.succeed(
        "systemctl show -p MainPID --value meister-cloud-controller.service"
    ).strip()
    assert before_pid == after_pid, (before_pid, after_pid)

    # --- step 10: and within half a minute it is in force ----------------
    #
    # `wait_until_succeeds` and not a sleep: what is being measured is that
    # it happens by itself, and the bound is the 30 s of
    # `controller_api::auth::REVOCATION_RELOAD_SECS`.
    def alice_is_refused():
        status, code, body, err = ask("alice")
        return code == "401" and "revoked" in body

    ok = False
    for _ in range(40):
        if alice_is_refused():
            ok = True
            break
        box.succeed("sleep 2")
    status, code, body, err = ask("alice")
    assert ok, ("alice was not refused", status, code, body, err)
    print("alice: " + code + " " + body)
    assert alice_serial.lower()[:8] in body.lower().replace(":", "") or "revoked" in body, body

    # …and the certificate nobody took back still works, through the same
    # process, at the same moment.
    status, code, body, _ = ask("root")
    assert status == 0 and code == "200", ("root was refused too", status, code, body)
    assert before_pid == box.succeed(
        "systemctl show -p MainPID --value meister-cloud-controller.service"
    ).strip(), "something restarted after all"

    # --- step 11: a rollback does not revive it --------------------------
    #
    # The list lives under `pki.dir`, not in the system generation, so going
    # back to the system that was running before the revocation changes
    # nothing about it.
    system_b = box.succeed("readlink -f /run/current-system").strip()
    system_a = box.succeed(
        "readlink -f /nix/var/nix/profiles/system-1-link"
    ).strip()
    assert system_a != system_b, (system_a, system_b)
    box.succeed(
        f"meister-activate activate --txn rollback --toplevel {system_a} "
        "--mode switch --confirm-within 0"
    )
    box.succeed("meister-activate confirm --txn rollback")
    box.succeed("meister-activate txn retire --txn rollback")
    box.wait_for_unit("meister-cloud-controller.service")
    ok = False
    for _ in range(40):
        status, code, body, err = ask("alice")
        if code == "401":
            ok = True
            break
        box.succeed("sleep 2")
    assert ok, ("a rollback revived a revoked certificate", code, body)
    status, code, body, _ = ask("root")
    assert code == "200", (code, body)

    # And forward again, so that the host runs what the release builds: the
    # steps below are rollouts like any other, and a host that runs the
    # system BEFORE the one in the release is a host whose `system` check
    # fails — which would take the rotation below back for a reason that
    # has nothing to do with keys.
    box.succeed(
        f"meister-activate activate --txn forward --toplevel {system_b} "
        "--mode switch --confirm-within 0"
    )
    box.succeed("meister-activate confirm --txn forward")
    box.succeed("meister-activate txn retire --txn forward")
    assert box.succeed("readlink -f /run/current-system").strip() == system_b

    # --- step 12: and rustls' half, which needs the restart --------------
    #
    # The list the REST edge hands rustls is read when the ServerConfig is
    # built. Before the restart the refusal is the authenticator's (401 with
    # a sentence); after it, the handshake itself ends.
    box.succeed("systemctl restart meister-cloud-controller.service")
    box.wait_for_unit("meister-cloud-controller.service")
    ok = False
    for _ in range(30):
        status, code, body, err = ask("alice")
        if status != 0:
            ok = True
            break
        box.succeed("sleep 2")
    assert ok, ("rustls let the revoked certificate through", status, code, body)
    print("after the restart curl says: " + err.strip())
    status, code, body, _ = ask("root")
    assert code == "200", ("the good certificate stopped working", code, body)

    # --- step 13: a session that is already running ----------------------
    #
    # box's own identity is what its cluster controller dials the cloud
    # with. Taking it back ends the session it is holding — the same
    # process, no restart — and the node goes the way a connection loss
    # takes it.
    box.succeed("journalctl --rotate && journalctl --vacuum-time=1s")
    cluster_pid = box.succeed(
        "systemctl show -p MainPID --value meister-cluster-controller.service"
    ).strip()
    out = operator.succeed(
        f"cd /root/fleet && meister-deploy keys revoke --host box "
        # Astra finding F21, 2026-09-23: --reason -> --crl-reason, see above.
        f"--crl-reason keyCompromise --release {release_b} --repo /root/fleet "
        "--identity /root/.ssh/id_ed25519 --inventory /root/fleet/fleet.toml "
        "--out /root/out/p-revoke-box.json 2>&1"
    )
    print(out)
    run = apply("/root/out/p-revoke-box.json", release_b)
    assert receipt_of(run)["outcome"] == "success"

    cloud_log("revoked", timeout=180)
    said = box.succeed(
        "journalctl -u meister-cloud-controller.service --no-pager | grep -i revoked | tail -3"
    )
    print(said)
    assert "revoked" in said.lower(), said
    assert cluster_pid == box.succeed(
        "systemctl show -p MainPID --value meister-cluster-controller.service"
    ).strip(), "the cluster controller was restarted, which is not what ended its session"

    # --- step 14: the rotation, interrupted after the overlap ------------
    #
    # And now the repair: a new key, a new certificate, in five phases. The
    # apply is killed the moment the certificate lands beside the one in
    # use, and a second apply picks the rotation up where the HOST is.
    before_key = box.succeed(f"sha256sum {pki}/identity.key").split()[0]
    out = operator.succeed(
        f"cd /root/fleet && meister-deploy keys rotate --host box --kind identity "
        f"--as cluster --release {release_b} --repo /root/fleet "
        "--identity /root/.ssh/id_ed25519 --inventory /root/fleet/fleet.toml "
        "--meister-ca meister-ca --out /root/out/p-rotate.json 2>&1"
    )
    print(out)
    # The new key is on the host and nothing reads it yet.
    assert mode_of(f"{pki}/identity.key.next") == "600 meister:meister"
    assert box.succeed(f"sha256sum {pki}/identity.key").split()[0] == before_key
    box.fail(f"test -e {pki}/identity.crt.next")
    the_plan = json.loads(operator.succeed("cat /root/out/p-rotate.json"))
    kinds = [a["kind"] for a in the_plan["actions"] if a["blocked"] is None]
    print("rotate: " + ", ".join(kinds))
    assert kinds == [
        "preflight", "lock",
        "keys-prepare", "keys-overlap", "keys-switch", "keys-verify", "keys-remove",
        "unlock",
    ], kinds

    grants = " ".join(
        f"--approve {a['class']}={a['bound_plan_id']}" for a in the_plan["approvals"]
    )
    operator.succeed(
        "cd /root/fleet && (meister-deploy apply --plan /root/out/p-rotate.json "
        f"--release {release_b} --repo /root/fleet --identity /root/.ssh/id_ed25519 "
        f"--inventory /root/fleet/fleet.toml {grants} > /root/out/rot.log 2>&1 & "
        "echo $! > /root/out/rot.pid)"
    )
    box.wait_until_succeeds(f"test -e {pki}/identity.crt.next", timeout=180)
    operator.succeed("kill -9 $(cat /root/out/rot.pid) || true")
    state = json.loads(
        box.succeed("meister-activate --json keys status --kind identity")
    )
    print(json.dumps(state, indent=2))
    where = state.get("result", state).get("state")
    assert where in ("overlap", "switched"), state
    # The run id, and not "the first line": stdout and stderr are in one
    # file here, and the notes on stderr come and go.
    first_run = operator.succeed(
        "grep -oE '^[0-9a-f-]{36}$' /root/out/rot.log | head -1"
    ).strip()
    assert first_run, operator.succeed("cat /root/out/rot.log")
    print("the interrupted run was " + first_run)

    # The resume asks the host where it is and carries on from there.
    out = operator.succeed(
        f"cd /root/fleet && meister-deploy apply --plan /root/out/p-rotate.json "
        f"--release {release_b} --repo /root/fleet --identity /root/.ssh/id_ed25519 "
        f"--inventory /root/fleet/fleet.toml {grants} --resume {first_run} 2>&1"
    )
    print(out)
    receipt = receipt_of(first_run)
    assert receipt["hosts"]["box"]["outcome"] == "success", receipt
    # The rotation is over: the new pair is in, the old one is gone, and
    # nothing is left beside it.
    box.fail(f"test -e {pki}/identity.key.next")
    box.fail(f"test -e {pki}/identity.crt.next")
    box.fail(f"test -e {pki}/identity.key.prev")
    box.fail(f"test -e {pki}/identity.crt.prev")
    assert box.succeed(f"sha256sum {pki}/identity.key").split()[0] != before_key, (
        "the key was not rotated"
    )
    assert mode_of(f"{pki}/identity.key") == "600 meister:meister"
    # The repository caught up with the host: what the planner compares
    # every host against is the certificate the host now holds, and the one
    # it replaced is beside it under a name nothing compares.
    operator.fail("test -e /root/fleet/pki/issued/box/identity.next.crt")
    operator.succeed("test -e /root/fleet/pki/issued/box/identity.prev.crt")
    here = operator.succeed(
        "sha256sum /root/fleet/pki/issued/box/identity.crt"
    ).split()[0]
    there = box.succeed(f"sha256sum {pki}/identity.crt").split()[0]
    assert here == there, (here, there)

    # A second `prepare` would have been a second key. The journal of the
    # resume says it did not happen.
    resumed = operator.succeed(
        f"cat /root/fleet/.meister-deploy/runs/{first_run}/journal.jsonl"
    )
    assert resumed.count('"kind":"keys-prepare"') <= 2, (
        "prepare ran twice: " + resumed
    )

    # And the session comes back — with a certificate that was made after
    # the old one was taken back.
    box.succeed("journalctl --rotate && journalctl --vacuum-time=1s")
    box.succeed("systemctl restart meister-cluster-controller.service")
    cloud_log("system:cluster:cp", timeout=180)
    said = box.succeed(
        "journalctl -u meister-cloud-controller.service --no-pager "
        "| grep -i 'cluster session authenticated' | tail -1"
    )
    print(said)

    # --- step 15: a rotation is never a side effect ----------------------
    #
    # The plan an operator makes every day carries no phase of a rotation,
    # and the one they make after one carries none either.
    status, plan_after = make_plan(release_b, "after")
    the_plan = json.loads(operator.succeed(f"cat {plan_after}"))
    kinds = [a["kind"] for a in the_plan["actions"] if a["blocked"] is None]
    print("after the rotation: " + ", ".join(kinds))
    assert not any(k.startswith("keys-") for k in kinds), kinds
    assert "rotations" not in operator.succeed(f"cat {plan_after}"), "an upgrade carries one"

    print("meister-deploy: a certificate that was taken back stopped working at both "
          "ports, in a session that was already running, without anything being "
          "restarted — and the key that replaced it went in in five phases with a "
          "kill -9 in the middle")
  '';
}
