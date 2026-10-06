# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# A control plane and an agent on two machines built from nixosModules.services
# and nixosModules.store-host alone, with no deployment tool anywhere: the keys
# are made on the machine that uses them and signed by meister-ca inside the
# test, the cluster registers with the cloud, the agent with the cluster, and a
# VM created through the cloud API boots on the agent. Requires nested KVM on
# the test host.
{ nixpkgs, lib, pkgs, system, self }:
let
  marker = "MS-S0-TINY-OK";
  cloudName = "c1";
  clusterName = "cp";
  pki = "/var/lib/meisterstack/pki";

  # The CA script as the repository has it, run with the PATH of the machine
  # (openssl, coreutils, grep, sed, awk and find are on every test VM).
  meisterCa = pkgs.writeShellScriptBin "meister-ca" (builtins.readFile ../../tools/meister-ca);

  # The NewVmSpec the cloud hands down: the guest's kernel and initrd out of the
  # agent's image directory, no disk and no network.
  spec = pkgs.writeText "tiny.json" (builtins.toJSON {
    vcpus = 1;
    memory_mib = 256;
    boot = {
      kind = "direct_kernel";
      kernel = "bzImage";
      initramfs = "initrd";
      cmdline = "console=ttyS0 reboot=k panic=1";
    };
    volumes = [ ];
    nics = [ ];
    devices = [ ];
  });

  # A break-glass administrator talking to the cloud on its own host.
  cliConfig = pkgs.writeText "cli.toml" ''
    default_profile = "t"
    [profiles.t]
    endpoint = "https://127.0.0.1:3000"
    ca_cert = "/root/ca/ca.crt"
    credential = { type = "mtls", cert = "/root/ca/root.crt", key = "/root/ca/root.key" }
  '';
in
pkgs.testers.runNixOSTest {
  name = "meister-two-node-services";

  nodes.cp = { config, ... }: {
    imports = [ self.nixosModules.services self.nixosModules.store-host ];
    meisterstack.storeHost.enable = true;
    meisterstack.roles = [ "cloud" "cluster" ];
    meisterstack.context.defaults = {
      MEISTER_CLOUD_NAME = cloudName;
      MEISTER_CLUSTER_NAME = clusterName;
      # The cluster dials the cloud on this host; meister-ca puts 127.0.0.1
      # into every serving certificate.
      MEISTER_CLOUD_ADDRS = "https://127.0.0.1:${toString config.meisterstack.ports.cloud.grpc}";
      MEISTER_CLOUD_ADVERTISE_API =
        "${config.networking.primaryIPAddress}:${toString config.meisterstack.ports.cloud.api}";
      MEISTER_CLUSTER_ADVERTISE_API =
        "${config.networking.primaryIPAddress}:${toString config.meisterstack.ports.cluster.api}";
    };
    # identity.crt on this host is the cluster's; the cloud gets its own.
    meisterstack.cloud.settings = {
      identity_cert = "${pki}/cloud-identity.crt";
      identity_key = "${pki}/cloud-identity.key";
    };
    networking.firewall.allowedTCPPorts = with config.meisterstack.ports; [ cluster.grpc ];
    environment.systemPackages = [ meisterCa pkgs.openssl ];
    environment.variables.MEISTER_CONFIG = "${cliConfig}";
    virtualisation.memorySize = 2048;
  };

  nodes.n1 = { nodes, ... }: {
    imports = [ self.nixosModules.services self.nixosModules.store-host ];
    meisterstack.storeHost.enable = true;
    meisterstack.roles = [ "agent" ];
    meisterstack.context.defaults.MEISTER_CONTROLLER_ADDRS =
      "https://${nodes.cp.networking.primaryIPAddress}:${toString nodes.cp.meisterstack.ports.cluster.grpc}";
    # Nothing to route to, nothing to attach over fabrics.
    meisterstack.agent.frr.enable = false;
    meisterstack.agent.nvmeTcp.enable = false;
    # The guest's kernel and initrd, in this machine's closure so that they
    # can be copied into the agent's image directory.
    environment.etc."guest-tiny".source = pkgs.guest-tiny;
    environment.systemPackages = [ pkgs.openssl ];
    virtualisation.memorySize = 2048;
    virtualisation.diskSize = 4096;
  };

  testScript = { nodes, ... }: ''
    pki = "${pki}"
    cp_address = "${nodes.cp.networking.primaryIPAddress}"
    # The agent's own socket on n1, which root may use without a profile.
    on_n1 = "meister --endpoint unix:///run/meisterstack/agent/agent.sock"

    def keygen(machine, stem):
        """A key made on the machine that uses it; only the request leaves it."""
        machine.succeed(
            f"openssl ecparam -name prime256v1 -genkey -noout -out {pki}/{stem}.key",
            f"chown meister:meister {pki}/{stem}.key",
            f"chmod 600 {pki}/{stem}.key",
        )
        return machine.succeed(
            f"openssl req -new -key {pki}/{stem}.key -subj /CN={stem} -batch"
        )

    def sign(csr, kind, name, san=None):
        """meister-ca on cp signs a request and answers with the certificate."""
        cp.succeed(f"cat > /root/req.csr <<'EOF'\n{csr}EOF")
        extra = f" --san {san}" if san else ""
        cp.succeed(
            "meister-ca --dir /root/ca --sign-csr /root/req.csr "
            f"--kind {kind} --name {name}{extra} --out /root/signed.crt"
        )
        return cp.succeed("cat /root/signed.crt")

    def install(machine, stem, cert):
        machine.succeed(f"cat > {pki}/{stem}.crt <<'EOF'\n{cert}EOF", f"chmod 644 {pki}/{stem}.crt")

    def held_back_by_its_condition(machine, unit):
        """Down because a condition was checked and failed, not because the
        process started without its keys and is crash-looping, which is
        down between two restarts as well."""
        shown = machine.succeed(
            "systemctl show -p ConditionResult -p ConditionTimestampMonotonic "
            f"-p ExecMainStartTimestampMonotonic -p NRestarts {unit}"
        )
        props = dict(line.split("=", 1) for line in shown.splitlines())
        assert props["ConditionResult"] == "no" and props["ConditionTimestampMonotonic"] != "0", \
            f"{unit}: no condition of it was checked and failed: {props}"
        assert props["ExecMainStartTimestampMonotonic"] == "0" and props["NRestarts"] == "0", \
            f"{unit} ran without its keys: {props}"

    start_all()
    cp.wait_for_unit("multi-user.target")
    n1.wait_for_unit("multi-user.target")

    with subtest("no unit starts before its keys are there"):
        held_back_by_its_condition(cp, "meister-cloud-controller")
        held_back_by_its_condition(cp, "meister-cluster-controller")
        held_back_by_its_condition(n1, "meister-agent")

    with subtest("every host gets its keys from a CA it never sees"):
        cp.succeed("meister-ca --dir /root/ca --init", "meister-ca --dir /root/ca --admin root")
        ca = cp.succeed("cat /root/ca/ca.crt")
        install(cp, "serving", sign(keygen(cp, "serving"), "serving", "cp", cp_address))
        install(cp, "identity", sign(keygen(cp, "identity"), "cluster", "${clusterName}"))
        install(cp, "cloud-identity", sign(keygen(cp, "cloud-identity"), "cloud", "${cloudName}"))
        install(cp, "ca", ca)
        install(n1, "identity", sign(keygen(n1, "identity"), "node", "n1"))
        install(n1, "ca", ca)

    with subtest("the control plane runs and the cluster reaches the cloud"):
        cp.succeed("systemctl start meister-cloud-controller meister-cluster-controller")
        cp.wait_for_open_port(3000)
        cp.wait_until_succeeds("meister cluster ls | grep -q ${clusterName}", timeout=180)

    with subtest("the agent registers with the cluster"):
        n1.succeed("systemctl start meister-agent")
        n1.wait_for_unit("meister-agent.service")
        cp.wait_until_succeeds("meister node ls --cluster ${clusterName} | grep -q n1", timeout=180)
        print(cp.succeed("meister node ls --cluster ${clusterName}"))

    with subtest("a VM created at the cloud boots on the agent"):
        n1.succeed(
            "install -m 0644 /etc/guest-tiny/bzImage /var/lib/meisterstack/images/bzImage",
            "install -m 0644 /etc/guest-tiny/initrd /var/lib/meisterstack/images/initrd",
            "test -e /dev/kvm",
        )
        cp.succeed("meister tenant create t1")
        cp.succeed("meister -t t1 vm create tiny -f ${spec}")
        # What the cloud made of it, before the wait: a guest that never boots
        # says why here and nowhere else.
        print(cp.execute("meister -t t1 vm get tiny -o json 2>&1")[1])
        cp.wait_until_succeeds("meister -t t1 vm logs tiny 2>&1 | grep -q '${marker}'", timeout=300)
        vms = n1.succeed(f"{on_n1} agent vm ls")
        print(vms)
        assert "no vms on this node" not in vms, vms

    with subtest("and goes away again"):
        cp.succeed("meister --yes -t t1 vm rm tiny")
        n1.wait_until_succeeds(f"{on_n1} agent vm ls 2>&1 | grep -q 'no vms on this node'", timeout=180)
  '';
}
