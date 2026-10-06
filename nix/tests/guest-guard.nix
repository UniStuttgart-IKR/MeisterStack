# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Boot an agent host without nix/managed.nix and stand in for a guest with a
# network namespace on the default bridge. The guest must not open
# connections to the host over IPv4 or IPv6, except to a port the host lists,
# and the host must still reach the guest.
#
# With `hostRunsNftables` the host runs a NixOS nftables firewall with a
# ruleset of its own, which flushes the whole ruleset on every load: the
# guard has to survive that firewall's reload, restart and stop, and the
# agent must not be stopped or restarted by any of them.
{ nixpkgs, lib, pkgs, system, self, hostRunsNftables ? false }:
let
  # The unit wiring is under test, not the agent: a process that stays up
  # shows whether systemd stopped or restarted the unit.
  agentStandIn = pkgs.writeShellScriptBin "meister-agent" "exec sleep infinity";
  loader = if hostRunsNftables then "nftables.service" else "meister-guest-guard.service";

  # Answers every line it is sent, over IPv4 and IPv6, on the port the guard keeps closed.
  echoServer = pkgs.writeText "echo-server.py" ''
    import socket, socketserver

    class Echo(socketserver.StreamRequestHandler):
        def handle(self):
            for line in self.rfile:
                self.wfile.write(line)

    class DualStack(socketserver.ThreadingTCPServer):
        address_family = socket.AF_INET6
        allow_reuse_address = True

    DualStack(("::", 8082), Echo).serve_forever()
  '';

  # A guest's connection to the host that is open while the guard returns:
  # the guard is missing for the first line and back for the second.
  openAcrossReload = pkgs.writeText "open-across-reload.py" ''
    import socket, subprocess, sys

    conn = socket.create_connection(("10.42.0.1", 8082), timeout=3)
    conn.sendall(b"one\n")
    assert conn.recv(16) == b"one\n", "the connection did not open while the guard was missing"
    subprocess.run(["systemctl", "restart", sys.argv[1]], check=True)
    conn.sendall(b"two\n")
    try:
        answer = conn.recv(16)
    except socket.timeout:
        sys.exit(0)
    sys.exit(f"the guard let a connection it never allowed carry on: {answer!r}")
  '';
in
pkgs.testers.runNixOSTest {
  name = "meister-guest-guard${lib.optionalString hostRunsNftables "-nftables"}";
  nodes.host = { pkgs, ... }: {
    imports = [ self.nixosModules.services ];
    meisterstack.roles = [ "agent" ];
    meisterstack.autostart = true;
    meisterstack.binDir = "${agentStandIn}/bin";
    meisterstack.agent.frr.enable = false;
    meisterstack.agent.nvmeTcp.enable = false;
    meisterstack.agent.volumes.device = null;
    meisterstack.agent.guestGuard.allowedTCPPorts = [ 8081 ];
    # The agent waits for a CA before it starts; its contents do not matter here.
    systemd.tmpfiles.rules = [
      "d /opt/meisterstack/pki 0755 root root -"
      "f /opt/meisterstack/pki/ca.crt 0644 root root -"
    ];
    # Ports the guard must keep closed although the host's firewall lets
    # everything in.
    networking.firewall.enable = false;
    networking.nftables = lib.mkIf hostRunsNftables {
      enable = true;
      ruleset = ''
        table inet host-own {
          chain input {
            type filter hook input priority filter + 10; policy accept;
            counter
          }
        }
      '';
    };
    environment.systemPackages = [ pkgs.netcat-openbsd pkgs.python3 ];
  };
  testScript = ''
    host.wait_for_unit("meister-agent.service")
    host.succeed("nft list table inet meister-guest-guard")

    def agent_pid():
        pid = host.succeed("systemctl show -P MainPID meister-agent.service").strip()
        assert pid != "0", "the agent is not running"
        return pid

    agent_before = agent_pid()

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

    def guests_shut_out_and_agent_untouched():
        host.succeed("nft list table inet meister-guest-guard")
        host.succeed("ip netns exec guest nc -z -w 2 10.42.0.1 8081")
        host.fail("ip netns exec guest nc -z -w 2 10.42.0.1 8080")
        assert agent_pid() == agent_before, "the agent was stopped or restarted"

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
  '' + (if hostRunsNftables then ''

    with subtest("the host's firewall loads the guard; there is no unit of its own"):
        host.succeed("nft list table inet host-own")
        host.fail("systemctl cat meister-guest-guard.service")

    for verb in ("reload", "restart"):
        with subtest(f"a {verb} of the host's firewall keeps the guard and the agent"):
            host.succeed(f"systemctl {verb} nftables.service")
            host.succeed("nft list table inet host-own")
            guests_shut_out_and_agent_untouched()

    with subtest("stopping the host's firewall leaves the guests shut out and the agent running"):
        host.succeed("systemctl stop nftables.service")
        host.fail("nft list table inet host-own")
        guests_shut_out_and_agent_untouched()

    with subtest("starting it again brings its own rules back beside the guard"):
        host.succeed("systemctl start nftables.service")
        host.succeed("nft list table inet host-own")
        guests_shut_out_and_agent_untouched()
  '' else ''

    with subtest("restarting the guard leaves the agent running"):
        host.succeed("systemctl restart meister-guest-guard.service")
        guests_shut_out_and_agent_untouched()

    with subtest("stopping the guard leaves the guests shut out and the agent running"):
        host.succeed("systemctl stop meister-guest-guard.service")
        guests_shut_out_and_agent_untouched()
  '') + ''

    with subtest("a connection a guest opened while the guard was missing ends when it is back"):
        # Connection tracking runs only while some table uses it. A host with a
        # NAT or another firewall has it running in the gap too, and only then
        # does the connection become an established one the guard could accept.
        host.succeed(
            "nft add table inet tracker",
            "nft add chain inet tracker pre '{ type filter hook prerouting priority -300; }'",
            "nft add rule inet tracker pre ct state new counter",
        )
        host.succeed("nft delete table inet meister-guest-guard")
        host.succeed("(python3 ${echoServer} >/dev/null 2>&1 &)")
        host.wait_for_open_port(8082)
        host.succeed("ip netns exec guest python3 ${openAcrossReload} ${loader}")
        host.succeed("nft list table inet meister-guest-guard")
        host.execute("nft delete table inet tracker")

    with subtest("without the table the same connection goes through"):
        # Its loader is up and has nothing left to do, so only the table is missing.
        host.succeed("systemctl start ${loader}")
        host.succeed("nft delete table inet meister-guest-guard")
        host.succeed("ip netns exec guest nc -z -w 2 10.42.0.1 8080")

    with subtest("and the agent does not start without it"):
        host.fail("systemctl restart meister-agent.service")
        host.fail("systemctl is-active meister-agent.service")
  '';
}
