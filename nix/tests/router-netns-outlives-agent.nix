# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# IKR-B69: a tenant router the agent built outlives the agent. The real agent
# builds one active router for a stand-in controller, then is restarted and
# then killed with SIGKILL; after each the host still lists the router's
# namespace, the very same one (its nsfs inode), with the same leg MACs.
#
# A unit with a mount namespace of its own (ProtectHome and every other path
# sandbox) pins `ip netns` inside that namespace: the host never sees the pin,
# and the namespace dies with the agent. agent-unit-sandbox checks the unit's
# keys; this shows what they are for.
{ nixpkgs, lib, pkgs, system, self }:
let
  routerId = "1a2b3c4d-5e6f-4a00-8000-000000000001";
  netns = "meister-rt-${routerId}";
  port = 50051;

  # The session protocol's Python bindings, generated from the schema the
  # agent is built against.
  sessionBindings = pkgs.runCommand "meister-control-proto-python"
    {
      nativeBuildInputs = [ (pkgs.python3.withPackages (p: [ p.grpcio-tools ])) ];
    } ''
    mkdir $out
    python -m grpc_tools.protoc -I ${../../shared/proto/proto} \
      --python_out=$out --grpc_python_out=$out control.proto
  '';

  # Stands in for the cluster: serves every session, and asks the first one
  # for one active router. Later sessions are asked for nothing, so the router
  # found after a restart is the one the agent built before it.
  controller = pkgs.writeText "stand-in-controller.py" ''
    import queue
    import sys
    import threading
    from concurrent import futures

    import grpc
    import control_pb2 as pb
    import control_pb2_grpc as rpc

    ROUTER = pb.EnsureRouter(
        id="${routerId}",
        physnet="ext",
        external_addr="203.0.113.10/24",
        external_gateway="203.0.113.1",
        vni=10000,
        internal_addr="10.7.1.1/24",
        active=True,
    )


    class Plane(rpc.ControlPlaneServicer):
        def __init__(self):
            self.lock = threading.Lock()
            self.asked = False

        def ask_once(self):
            with self.lock:
                first, self.asked = not self.asked, True
            return first

        def Session(self, inbound, context):
            out = queue.Queue()
            threading.Thread(target=self.read, args=(inbound, out), daemon=True).start()
            while (message := out.get()) is not None:
                yield message

        def read(self, inbound, out):
            try:
                for message in inbound:
                    kind = message.WhichOneof("kind")
                    if kind == "hello":
                        print("hello", flush=True)
                        if self.ask_once():
                            command = pb.Command(request_id="ensure-1", ensure_router=ROUTER)
                            out.put(pb.ControllerMessage(command=command))
                    elif kind == "result":
                        result = message.result
                        outcome = result.WhichOneof("outcome")
                        said = result.error.message if outcome == "error" else ""
                        print("result", result.request_id, outcome, said, flush=True)
            except grpc.RpcError:
                pass
            finally:
                out.put(None)


    key, cert = (open(path, "rb").read() for path in sys.argv[1:3])
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    rpc.add_ControlPlaneServicer_to_server(Plane(), server)
    server.add_secure_port("127.0.0.1:${toString port}", grpc.ssl_server_credentials([(key, cert)]))
    server.start()
    server.wait_for_termination()
  '';

  python = pkgs.python3.withPackages (p: [ p.grpcio p.protobuf ]);
  stand = "/var/lib/stand-in";
  pki = "/var/lib/meisterstack/pki";
in
pkgs.testers.runNixOSTest {
  name = "meister-router-netns-outlives-agent";
  nodes.gw = { config, ... }: {
    imports = [ self.nixosModules.services ];
    meisterstack.roles = [ "agent" ];
    meisterstack.binDir = "${config.meisterstack.runtime}/bin";
    meisterstack.configDir = "/etc/meisterstack";
    meisterstack.pki.dir = pki;
    meisterstack.agent.frr.enable = false;
    meisterstack.agent.nvmeTcp.enable = false;
    meisterstack.agent.volumes.device = null;
    # eth1 carries the overlay, eth2 is given away to the provider network.
    meisterstack.agent.physnets = { ext = "eth2"; };
    meisterstack.agent.settings = {
      node_id = "gw";
      controller_addr = "https://127.0.0.1:${toString port}";
      network.vxlan.uplink = "eth1";
    };
    virtualisation.vlans = [ 1 2 ];
    # The test network numbers every interface; a provider network's carries no address.
    networking.interfaces.eth2.ipv4.addresses = lib.mkForce [ ];
    networking.interfaces.eth2.ipv6.addresses = lib.mkForce [ ];
    networking.firewall.enable = false;
    virtualisation.memorySize = 1536;
    environment.systemPackages = [ pkgs.openssl ];

    systemd.services.stand-in-controller = {
      description = "Stand-in cluster controller";
      environment.PYTHONPATH = "${sessionBindings}";
      serviceConfig.ExecStart =
        "${python}/bin/python ${controller} ${stand}/controller.key ${stand}/controller.crt";
    };
  };

  testScript = ''
    import re

    gw.wait_for_unit("multi-user.target")

    # One CA for both ends: the controller's serving certificate for 127.0.0.1,
    # and the agent's identity, which the stand-in does not ask for.
    gw.succeed(
        "mkdir -p ${stand} ${pki} && cd ${stand}"
        " && printf 'subjectAltName=IP:127.0.0.1\\n' > san.ext"
        " && openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2"
        "    -subj /CN=stand-in-ca -keyout ca.key -out ca.crt"
        " && openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes"
        "    -subj /CN=controller -keyout controller.key -out controller.csr"
        " && openssl x509 -req -in controller.csr -CA ca.crt -CAkey ca.key -CAcreateserial"
        "    -days 2 -extfile san.ext -out controller.crt"
        " && openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes"
        "    -subj /CN=gw -keyout identity.key -out identity.csr"
        " && openssl x509 -req -in identity.csr -CA ca.crt -CAkey ca.key -CAcreateserial"
        "    -days 2 -out identity.crt"
        " && install -m 0644 ca.crt identity.crt ${pki}/"
        " && install -m 0600 identity.key ${pki}/"
    )
    gw.succeed("systemctl start stand-in-controller")
    gw.wait_for_open_port(${toString port})
    gw.succeed("systemctl start meister-agent")

    def controller_said():
        return gw.succeed("journalctl -u stand-in-controller -o cat")

    def hellos():
        return controller_said().splitlines().count("hello")

    gw.wait_until_succeeds(
        "journalctl -u stand-in-controller -o cat | grep -q '^result ensure-1'", timeout=120
    )
    built = controller_said()
    assert "result ensure-1 ok" in built, built

    def router():
        """The namespace the host lists for the router, by nsfs inode, and its legs' MACs."""
        assert "${netns}" in gw.succeed("ip netns list"), gw.succeed("ip netns list")
        inode = gw.succeed("stat -L -c %i /run/netns/${netns}").strip()
        links = gw.succeed("ip -n ${netns} -o link show")
        macs = {
            leg: re.search(rf" {leg}@[^:]*:.* link/ether ([0-9a-f:]+)", links).group(1)
            for leg in ("ext", "int")
        }
        return inode, macs

    def agent_pid():
        pid = gw.succeed("systemctl show -P MainPID meister-agent.service").strip()
        assert pid != "0", "the agent is not running"
        return pid

    def back_after(action, sessions_before, pid_before):
        action()
        gw.wait_until_succeeds(
            f"test $(journalctl -u stand-in-controller -o cat | grep -c '^hello') -gt {sessions_before}",
            timeout=120,
        )
        assert agent_pid() != pid_before, "the agent was not started again"

    first = router()
    print(f"router before: {first}")

    sessions, pid = hellos(), agent_pid()
    back_after(lambda: gw.succeed("systemctl restart meister-agent"), sessions, pid)
    after_restart = router()
    assert after_restart == first, f"restart: {first} became {after_restart}"

    sessions, pid = hellos(), agent_pid()
    back_after(
        lambda: gw.succeed("systemctl kill --signal=SIGKILL meister-agent"), sessions, pid
    )
    after_kill = router()
    assert after_kill == first, f"SIGKILL: {first} became {after_kill}"
  '';
}
