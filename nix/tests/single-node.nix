# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Boot a standalone agent, check socket group permissions and CLI fallback,
# and run a nested guest. Requires nested KVM on the test host.
{ nixpkgs, lib, pkgs, system, self }:
let
  marker = "MS-S0-TINY-OK";
  spec = pkgs.writeText "tiny.json" (builtins.toJSON {
    vcpus = 1;
    memory_mib = 256;
    boot = {
      kind = "direct_kernel";
      kernel = "bzImage";
      initramfs = "initrd";
      cmdline = "console=ttyS0 reboot=k panic=1";
    };
    volumes = [{ size_bytes = 67108864; }];
  });
in
pkgs.testers.runNixOSTest {
  name = "meister-single-node";
  nodes.rig = { ... }: {
    imports = [ self.nixosModules.services self.nixosModules.store-host ];
    meisterstack.storeHost.enable = true;
    # The whole of what makes it a single node: the one role, the profile,
    # and no controller anywhere — nix/single-node.nix asserts both.
    meisterstack.roles = [ "agent" ];
    meisterstack.singleNode.enable = true;
    meisterstack.singleNode.operators = [ "tester" ];
    users.users.tester = { isNormalUser = true; };
    # Nothing to route to, nothing to attach over fabrics.
    meisterstack.agent.frr.enable = false;
    meisterstack.agent.nvmeTcp.enable = false;
    # The guest's kernel and initrd, in this machine's closure so that they
    # can be copied into the agent's image directory.
    environment.etc."guest-tiny".source = pkgs.guest-tiny;
    virtualisation.memorySize = 2048;
    virtualisation.diskSize = 4096;
  };
  testScript = ''
    rig.wait_for_unit("multi-user.target")
    rig.wait_for_unit("meister-agent.service")
    rig.wait_until_succeeds("journalctl -u meister-agent.service | grep -q 'running standalone'", timeout=60)
    rig.wait_for_file("/run/meisterstack/agent/agent.sock")

    # The socket, and who owns it.
    assert rig.succeed("stat -c %G /run/meisterstack/agent/agent.sock").strip() == "meister"
    assert rig.succeed("stat -c %a /run/meisterstack/agent/agent.sock").strip() == "660"

    # The machine's config is the fallback: nobody here has one of their own.
    rig.fail("test -e /root/.config/meisterstack/config.toml")
    assert "no vms on this node" in rig.succeed("meister agent vm ls 2>&1")
    assert "no vms on this node" in rig.succeed("su tester -c 'meister agent vm ls' 2>&1")
    # …and the group is the access rule.
    refused = rig.fail("su nobody -s /bin/sh -c 'meister agent vm ls' 2>&1")
    assert "ermission denied" in refused, refused

    # One guest, made at the socket, booted, seen, taken away.
    rig.succeed("install -m 0644 /etc/guest-tiny/bzImage /var/lib/meisterstack/images/bzImage")
    rig.succeed("install -m 0644 /etc/guest-tiny/initrd /var/lib/meisterstack/images/initrd")
    rig.succeed("test -e /dev/kvm")
    vm = rig.succeed("meister agent vm create -f ${spec}").strip()
    assert vm, "create printed no id"
    # What the node made of it, before the wait: a guest that never boots
    # says why here and nowhere else.
    print(rig.execute(f"meister agent vm observe {vm} 2>&1")[1])
    # The whole boot, not what a recorder attached thirty seconds later got
    # out of the VMM's ring: the api attaches it at create
    # (Reconciler::record_console), which is what makes this line hold.
    rig.wait_until_succeeds(f"meister agent vm logs {vm} 2>&1 | grep -q '${marker}'", timeout=120)
    assert vm in rig.succeed("meister agent vm ls")
    # `--yes`: an rm asks a person first, and a script has no person.
    rig.succeed(f"meister --yes agent vm rm {vm}")
    rig.wait_until_succeeds("meister agent vm ls 2>&1 | grep -q 'no vms on this node'", timeout=60)
  '';
}
