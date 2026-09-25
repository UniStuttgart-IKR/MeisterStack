# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR
# The single node: one machine that runs the agent and nothing above it, and
# the CLI on the same machine, pointed at the agent's own socket.
#
# What this is for: a workstation or a lab box that should make guests the
# way the fleet makes them — the same VMM, the same spec, the same device
# drivers (vfio, nvrm, crosvm-gpu, input) — without a cloud, a cluster or a
# scheduler. The agent already runs that way: with no controller configured
# it "runs standalone" (components/agent/src/lib.rs), serves its unix socket
# and reports to nobody; `meister agent vm …` drives that socket
# (components/cli/src/agent.rs). This module adds the two things a person
# would otherwise write by hand on every such box:
#
#   * the CLI's config, at /etc/meisterstack/cli.toml, with one profile
#     `local` that names the socket and needs no credential (the socket has
#     none: `[paths] socket_group` IS the access rule). The CLI takes that
#     file when the person has none of their own
#     (components/cli/src/config.rs, `SYSTEM_CONFIG`), so `meister agent vm
#     ls` works on the box as it is installed;
#   * the operators — the people who may use that socket — in the `meister`
#     group, which is what the socket's mode 0660 asks for.
#
# What it refuses: a host that carries any other role, or one whose
# inventory gives it a controller. A single node that reports to a control
# plane is a fleet host and takes the fleet's road (nix/managed.nix,
# meister-deploy plan/apply) — the same road this module is normally
# reached by, with an inventory of exactly one host and no group
# (examples/fleet/single-node.toml).
{ lib, pkgs, config, ... }:
let
  cfg = config.meisterstack;
  sn = cfg.singleNode;
  toml = pkgs.formats.toml { };
  # The socket is `<run_dir>/agent.sock` (components/agent/src/lib.rs), and
  # run_dir is what the agent role baked (nix/agent.nix). Read from the
  # effective config rather than repeated here, so that the two cannot
  # disagree.
  runDir = cfg.agent.effective.paths.run_dir or "/run/meisterstack/agent";
  socket = "${runDir}/agent.sock";
  cliConfig = toml.generate "cli.toml" {
    default_profile = "local";
    profiles.local = {
      endpoint = "unix://${socket}";
      credential = { type = "none"; };
    };
  };
in
{
  options.meisterstack.singleNode = {
    enable = lib.mkEnableOption "the single node: the agent and the CLI on one machine, and no control plane";

    operators = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "silas" ];
      description = ''
        The users who may drive this node's agent: each is put into the
        `meister` group, which owns the agent's socket. Nobody by default,
        because a group membership is a grant and a module should not guess
        who is entitled to one; root needs no entry.
      '';
    };
  };

  config = lib.mkIf sn.enable {
    assertions = [
      {
        assertion = cfg.roles == [ "agent" ];
        message =
          "meisterstack.singleNode is an agent and nothing else: this host's roles are "
          + builtins.toJSON cfg.roles + ", and a single node has exactly [\"agent\"]. A "
          + "machine that also carries a controller is a one-box fleet (examples/fleet/one-box.toml).";
      }
      {
        assertion =
          (cfg.agent.effective.controller_addrs or [ ]) == [ ]
          && !(cfg.agent.effective ? controller_addr);
        message =
          "meisterstack.singleNode reports to nobody, and this host's agent config names a "
          + "controller. In a fleet inventory that is a `controller_group` or a raft group on "
          + "the host; a single node has neither.";
      }
    ];

    # The machine's CLI config: the fallback the CLI takes when the person
    # running it has no config of their own (`meister --config` and
    # `MEISTER_CONFIG` still win, as does ~/.config/meisterstack/config.toml).
    environment.etc."meisterstack/cli.toml".source = cliConfig;

    users.users = lib.genAttrs sn.operators (_: { extraGroups = [ "meister" ]; });
  };
}
