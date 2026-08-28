# Both controller units ship in the one image; the OpenNebula context
# (MEISTER_ROLE) starts the right one. ConditionPathExists keeps a unit
# quietly skipped until push.sh delivered its binary.
#
# Central cluster setup: everything configurable lives in
# meisterstack.<role>.settings (free-form TOML), rendered to
# /etc/meisterstack/<role>.toml and consumed by the binaries via --config.
# Empty settings = the binaries' built-in defaults (the lab topology).
{ lib, pkgs, config, ... }:
let
  toml = pkgs.formats.toml { };
  cfg = config.meisterstack;
  controller = name: {
    description = "MeisterStack ${name}-controller";
    after = [ "etcd.service" "one-context.service" ];
    wants = [ "etcd.service" ];
    unitConfig.ConditionPathExists = "/opt/meisterstack/bin/meister-${name}-controller";
    serviceConfig = {
      # one-context renders /etc templates to /run and appends per-VM values
      # (e.g. cluster_name) from the context — units consume the /run copy.
      ExecStart = "/opt/meisterstack/bin/meister-${name}-controller --config /run/meisterstack/${name}.toml";
      Restart = "always";
      RestartSec = 2;
      Environment = "RUST_LOG=info";
    };
  };
in
{
  options.meisterstack = {
    cluster.settings = lib.mkOption {
      type = toml.type;
      default = { };
      description = ''
        cluster-controller config. Free-form TOML: nothing here validates a
        key, the binary does that at start-up with deny_unknown_fields.
        config/examples/cluster.toml is the reference for every key it takes,
        and config/examples/hardened/cluster.toml for a control plane that is
        not on a lab switch.

        Empty (the default) = the binary's built-in defaults, which are the
        lab topology. cluster_name, cloud_addr and cloud_addrs are normally
        left out here and written by one-context from the OpenNebula context
        instead — a key in both places would be a duplicate TOML key.
      '';
    };
    cloud.settings = lib.mkOption {
      type = toml.type;
      default = { };
      description = ''
        cloud-controller config, same shape and same rules; see
        config/examples/cloud.toml. This is the one tier with a public port,
        so config/examples/hardened/cloud.toml is worth reading before any
        deployment that is reachable from outside the lab.
      '';
    };
  };

  config = {
    environment.etc."meisterstack/cluster.toml".source =
      toml.generate "cluster.toml" cfg.cluster.settings;
    environment.etc."meisterstack/cloud.toml".source =
      toml.generate "cloud.toml" cfg.cloud.settings;

    systemd.services.meister-cloud-controller = controller "cloud";
    systemd.services.meister-cluster-controller = controller "cluster";
  };
}
