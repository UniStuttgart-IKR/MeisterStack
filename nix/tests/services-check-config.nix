# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Run the binaries' own --check-config over the files these modules render, so
# that a module and the Rust config parser cannot drift apart unnoticed. The
# hosts are store-built (nix/store-host.nix) and get their settings from
# context defaults, the way a deployment tool hands them over: mTLS and OIDC
# controllers with an etcd group, an agent with an overlay, physnets and BGP,
# an agent with a GPU backend and a single node. Nothing is started.
{ nixpkgs, lib, pkgs, system, self }:

let
  hostOf = name: extra: (nixpkgs.lib.nixosSystem {
    modules = [
      {
        nixpkgs.hostPlatform = system;
        nixpkgs.overlays = [ self.overlays.default ];
        networking.hostName = name;
        system.stateVersion = "25.11";
        fileSystems."/" = { device = "/dev/disk/by-label/nixos"; fsType = "ext4"; };
        boot.loader.grub.device = "nodev";
      }
      self.nixosModules.services
      self.nixosModules.store-host
      { meisterstack.storeHost.enable = true; }
      extra
    ];
  }).config;

  controllers = {
    meisterstack.roles = [ "cluster" "cloud" ];
    meisterstack.etcd.enable = true;
    meisterstack.context.defaults = {
      MEISTER_CLOUD_NAME = "cp1";
      MEISTER_CLUSTER_NAME = "cp1";
      MEISTER_CLOUD_ADVERTISE_API = "10.0.0.10:3000";
      MEISTER_CLUSTER_ADVERTISE_API = "10.0.0.10:3001";
      MEISTER_CLOUD_ADDRS = "https://10.0.0.10:50050, https://10.0.0.11:50050";
      MEISTER_ETCD_PEERS = "cp1=10.0.0.10,cp2=10.0.0.11,cp3=10.0.0.12";
      MEISTER_ETCD_TOKEN = "check-config";
      MEISTER_LOG_FORMAT = "json";
      MEISTER_OTLP_ENDPOINT = "http://10.0.0.20:4317";
    };
  };

  oidc = {
    meisterstack.context.defaults = {
      MEISTER_OIDC_ISSUER = "https://addons.lab.example:8443/oauth2/openid/meister-cli";
      MEISTER_OIDC_AUDIENCE = "meister-cli";
      MEISTER_OIDC_CA = "/var/lib/meisterstack/pki/ca.crt";
    };
  };

  agent = {
    meisterstack.roles = [ "agent" ];
    meisterstack.context.defaults = {
      MEISTER_CONTROLLER_ADDRS = "https://10.0.0.10:50051,https://10.0.0.11:50051";
      MEISTER_VXLAN_UPLINK = "eth0";
      MEISTER_VXLAN_MTU = "1450";
      MEISTER_PHYSNETS = "provider=eth1";
      MEISTER_BGP_ASN = "65001";
      MEISTER_BGP_ROUTER_ID = "10.0.0.21";
      MEISTER_BGP_NEIGHBORS = "10.0.0.1=65000";
    };
  };

  # A GPU backend as the agent sees it: two programs it is told the paths of.
  nvrm = {
    meisterstack.agent.settings.device.nvrm = {
      binary = "${pkgs.writeShellScriptBin "vhost-user-nvrm" "exit 0"}/bin/vhost-user-nvrm";
      vgpuprofile = "${pkgs.writeShellScriptBin "vgpuprofile" "exit 0"}/bin/vgpuprofile";
    };
  };

  single = {
    meisterstack.roles = [ "agent" ];
    meisterstack.singleNode.enable = true;
  };

  hosts = {
    controllers-mtls = hostOf "cp1" controllers;
    controllers-oidc = hostOf "cp1" { imports = [ controllers oidc ]; };
    agent = hostOf "n1" agent;
    agent-nvrm = hostOf "g1" { imports = [ agent nvrm ]; };
    single-node = hostOf "rig" single;
  };

  binaryOf = role: if role == "agent" then "meister-agent" else "meister-${role}-controller";

  checkHost = name: cfg: lib.concatMapStrings
    (role: ''
      echo "== ${name}: ${role}.toml"
      ${cfg.meisterstack.package}/bin/${binaryOf role} --check-config \
        --config ${cfg.environment.etc."meisterstack/${role}.toml".source} || fail=1
    '')
    cfg.meisterstack.unitsFor;

  failedAssertions = lib.concatLists (lib.mapAttrsToList
    (name: cfg: map (a: "${name}: ${a.message}") (lib.filter (a: !a.assertion) cfg.assertions))
    hosts);
in
pkgs.runCommand "services-check-config" { } ''
  fail=0
  ${lib.concatMapStrings (m: "echo ${lib.escapeShellArg "assertion: ${m}"}; fail=1\n") failedAssertions}
  ${lib.concatStrings (lib.mapAttrsToList checkHost hosts)}
  grep -q 'device.nvrm' ${hosts.agent-nvrm.environment.etc."meisterstack/agent.toml".source} \
    || { echo "-> the GPU host's agent.toml has no nvrm device"; fail=1; }
  grep -q '\[auth.oidc\]' ${hosts.controllers-oidc.environment.etc."meisterstack/cloud.toml".source} \
    || { echo "-> the OIDC cloud's cloud.toml has no [auth.oidc] table"; fail=1; }
  test $fail = 0 || { echo "-> a module renders a file its binary refuses"; exit 1; }
  touch $out
''
