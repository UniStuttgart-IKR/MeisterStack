# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Boot an agent host without nix/managed.nix and stand in for a guest with a
# network namespace on the default bridge. The guest must not open
# connections to the host over IPv4 or IPv6, except to a port the host lists,
# and the host must still reach the guest.
{ nixpkgs, lib, pkgs, system, self }:
pkgs.testers.runNixOSTest {
  name = "meister-guest-guard";
  nodes.host = { pkgs, ... }: {
    imports = [ self.nixosModules.services ];
    meisterstack.roles = [ "agent" ];
    meisterstack.agent.frr.enable = false;
    meisterstack.agent.nvmeTcp.enable = false;
    meisterstack.agent.volumes.device = null;
    meisterstack.agent.guestGuard.allowedTCPPorts = [ 8081 ];
    # Ports the guard must keep closed although the host's firewall is off.
    networking.firewall.enable = false;
    environment.systemPackages = [ pkgs.netcat-openbsd pkgs.python3 ];
  };
  testScript = ''
    host.wait_for_unit("meister-guest-guard.service")
    host.succeed("nft list table inet meister-guest-guard")

    # What the agent builds for a NIC on the default bridge, with the host
    # address the fleet profile used to set on it.
    host.succeed(
        "ip link add meister_br0 type bridge",
        "ip addr add 10.42.0.1/24 dev meister_br0",
        "ip link set meister_br0 up",
        "ip netns add guest",
        "ip link add msk0 type veth peer name eth0 netns guest",
        "ip link set msk0 master meister_br0",
        "ip link set msk0 up",
        "ip -n guest addr add 10.42.0.5/24 dev eth0",
        "ip -n guest link set eth0 up",
        "ip -n guest link set lo up",
    )
    # Dual-stack listeners on every address of the host.
    for port in (8080, 8081):
        host.succeed(f"(python3 -m http.server --bind :: {port} >/dev/null 2>&1 &)")
        host.wait_for_open_port(port)
    host.wait_until_succeeds("ip -6 addr show dev meister_br0 scope link | grep -q 'inet6 fe80'")
    link_local = host.succeed(
        "ip -6 -o addr show dev meister_br0 scope link | awk '{print $4}' | cut -d/ -f1"
    ).strip()

    # Each refusal follows an allowed connection over the same path, so a
    # refusal is the guard's and not a path that does not work at all.
    with subtest("a port the host lists is open to guests, over IPv4 and IPv6"):
        host.succeed("ip netns exec guest nc -z -w 2 10.42.0.1 8081")
        host.wait_until_succeeds(f"ip netns exec guest nc -6 -z -w 2 {link_local}%eth0 8081")

    with subtest("a guest cannot open a connection to the host's bridge address"):
        host.fail("ip netns exec guest nc -z -w 2 10.42.0.1 8080")

    with subtest("nor to any other address of the host, routed through the bridge"):
        uplink = host.succeed("ip -4 -o addr show dev eth1 | awk '{print $4}' | cut -d/ -f1").strip()
        host.succeed("ip -n guest route add default via 10.42.0.1")
        host.succeed(f"ip netns exec guest nc -z -w 2 {uplink} 8081")
        host.fail(f"ip netns exec guest nc -z -w 2 {uplink} 8080")

    with subtest("nor to the host's IPv6 link-local address on the bridge"):
        host.fail(f"ip netns exec guest nc -6 -z -w 2 {link_local}%eth0 8080")

    with subtest("the host still reaches the guest"):
        host.succeed("(ip netns exec guest python3 -m http.server --bind 10.42.0.5 9000 >/dev/null 2>&1 &)")
        host.wait_until_succeeds("nc -z -w 2 10.42.0.5 9000")

    with subtest("stopping the guard leaves the guests shut out"):
        host.succeed("systemctl stop meister-guest-guard.service")
        host.succeed("nft list table inet meister-guest-guard")
        host.fail("ip netns exec guest nc -z -w 2 10.42.0.1 8080")

    with subtest("without the table the same connection goes through"):
        host.succeed("nft delete table inet meister-guest-guard")
        host.succeed("ip netns exec guest nc -z -w 2 10.42.0.1 8080")
  '';
}
