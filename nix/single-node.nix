# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Standalone agent profile with a system CLI configuration and local operators.
# Require only the agent role and no controller addresses. Membership in the
# meister group grants full access to the local administration socket.
{ lib, pkgs, config, ... }:
let
  cfg = config.meisterstack;
  sn = cfg.singleNode;
  toml = pkgs.formats.toml { };
  # Derive the socket path from the effective agent configuration.
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
          + "machine that also carries a controller is a one-box fleet.";
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

    # Install the system CLI fallback; an explicit or per-user config takes precedence.
    environment.etc."meisterstack/cli.toml".source = cliConfig;

    users.users = lib.genAttrs sn.operators (_: { extraGroups = [ "meister" ]; });
  };
}
