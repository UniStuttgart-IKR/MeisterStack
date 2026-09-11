# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# `fleet.toml`, read by Nix.
#
# The same file `tools/meister-deploy` reads, and the same derivations: the
# etcd peer set of a raft group, the cluster name, an agent's controller
# addresses, a cluster's cloud addresses, every advertise address. A plan says
# who is a member of what, and the addresses follow — the twelve context
# variables `lab/LAB.md` lists by hand are exactly what is derived here.
#
# Two readers of one file rather than a generator: neither half can be down
# when the other one runs, `nix build` needs no Rust and `meister-deploy plan`
# needs no Nix evaluation. What keeps them honest is that both spell the
# derivations out in the same order, and that the Rust side has a test per
# rule (tools/meister-deploy/src/fleet.rs).
#
# Everything a node ends up being is expressed through the SAME options a
# foreign flake would use — `meisterstack.roles`, `meisterstack.context
# .defaults`, `meisterstack.<role>.settings` — so there is one road into these
# modules and the plan is just a caller of it.
{ lib }:

let
  knownRoles = [ "cloud" "cluster" "agent" "addons" ];

  # The order roles are DEPLOYED in, and therefore the order they are written
  # in: the bottom tier first, so that a controller never issues a command the
  # tier below it does not understand yet. It is the order deploy/push.sh has
  # used since M4.6 and the order `meister-deploy push` rolls a fleet in — and
  # on a one-box, where all four roles are one machine, it is also the order
  # one-context starts the units in.
  roleRank = { agent = 0; cluster = 1; cloud = 2; addons = 3; };
  sortRoles = rs: builtins.sort
    (a: b: (roleRank.${a} or 99) < (roleRank.${b} or 99))
    (lib.unique rs);

  # The four ports, once. Same numbers as tools/meister-deploy/src/fleet.rs.
  cloudApiPort = 3000;
  cloudSessionPort = 50050;
  clusterApiPort = 3001;
  clusterSessionPort = 50051;
  kanidmPort = 8443;
  lokiPort = 3100;
  otlpPort = 4317;

  isLabel = s:
    builtins.isString s && builtins.match "[a-z0-9]([a-z0-9-]*[a-z0-9])?" s != null
    && builtins.stringLength s <= 63;

  load = file:
    let
      raw = builtins.fromTOML (builtins.readFile file);
      where = toString file;
      planDir = builtins.dirOf file;

      header = raw.fleet or (throw "${where}: no [fleet] table; a plan says what it is called");
      defaults = raw.defaults or { };
      defaultRoles = defaults.roles or [ "agent" ];
      opennebula = raw.opennebula or null;

      mkNodeData = n: rec {
        name = n.name or (throw "${where}: a [[node]] without a name");
        # A node alone in its group is the single-member case, and that is why
        # the default is its own name rather than a shared bucket: nothing
        # accidentally joins somebody else's raft.
        group = n.group or name;
        roles = sortRoles (n.roles or defaultRoles);
        address = n.address or (throw "${where}: node ${name} has no address");
        sshUser = n.ssh_user or (defaults.ssh_user or "root");
        disk = n.disk or null;
        data = n.data or null;
        labels = n.labels or { };
        settings = n.settings or { };
        interface = n.interface or (defaults.interface or "eth0");
        # Files of the operator's own, relative to the plan. Almost every real
        # box needs one — a driver, a firmware, a kernel option, its own
        # hardware-configuration.nix — and none of that is something this
        # stack should be trying to describe.
        modules = map (m: planDir + "/${m}") (n.modules or [ ]);
        controllerAddrs = n.controller_addrs or null;
        cloudAddrs = n.cloud_addrs or null;
        # Metal or context, and the whole difference is how a push reaches it:
        # a node that names a disk is a box this flake builds an image FOR; a
        # node without one is a VM somebody else instantiated, and the push is
        # rsync plus a unit restart, as deploy/push.sh has always done.
        kind = if disk == null then "context" else "metal";
        has = role: builtins.elem role roles;
      };

      nodes' = map mkNodeData (raw.node or [ ]);
      names = map (n: n.name) nodes';

      raftMembers = group:
        builtins.filter (n: n.group == group && (n.has "cloud" || n.has "cluster")) nodes';
      raftGroups = lib.unique
        (map (n: n.group) (builtins.filter (n: n.has "cloud" || n.has "cluster") nodes'));

      cloudNodes = builtins.filter (n: n.has "cloud") nodes';
      cloudGroups = lib.unique (map (n: n.group) cloudNodes);
      clusterNodesOf = group: builtins.filter (n: n.has "cluster" && n.group == group) nodes';
      addonsNodes = builtins.filter (n: n.has "addons") nodes';
      addonsNode = if addonsNodes == [ ] then null else builtins.head addonsNodes;
      # Kanidm's origin is an https url and its certificate has to match it,
      # so an addons node is reached under a NAME. Never an address: kanidm's
      # `domain` is an `iname`, which refuses anything starting with a digit,
      # so a fleet without a domain built an image that came up dead on its
      # first boot and said so nowhere earlier (D-P6). The plan is refused
      # instead — see `errors` below.
      addonsHost =
        if addonsNode == null then null
        else if header ? domain then "${addonsNode.name}.${header.domain}"
        else null;

      # --- everything that is wrong with this plan, each with a sentence ---
      errors =
        (lib.optional (nodes' == [ ])
          "${where}: the plan has no [[node]]; there is nothing to deploy")
        ++ (lib.optional (lib.length (lib.unique names) != lib.length names)
          ("${where}: two nodes share a name (${lib.concatStringsSep ", " names}); a name is how "
            + "a certificate and a hostname find each other"))
        ++ (lib.concatMap
          (n:
            (lib.optional (!isLabel n.name)
              "${where}: the node name ${n.name} is not a dns label (lowercase letters, digits and '-')")
            ++ (lib.optional (!isLabel n.group)
              "${where}: node ${n.name}: the group ${n.group} is not a dns label")
            ++ (lib.optional (n.roles == [ ])
              "${where}: node ${n.name} has no role; a node that is nothing is not a plan")
            ++ (map
              (r: "${where}: node ${n.name} has the unknown role ${r}; "
                + "a plan knows ${lib.concatStringsSep ", " knownRoles}")
              (builtins.filter (r: !(builtins.elem r knownRoles)) n.roles))
            ++ (lib.optional
              (n.has "agent" && n.controllerAddrs == null && clusterNodesOf n.group == [ ])
              ("${where}: agent ${n.name} is in the group ${n.group}, and no node of that group "
                + "runs a cluster controller; name the cluster's group, or give the node its own "
                + "controller_addrs"))
            ++ (lib.optional (n.has "cluster" && n.cloudAddrs == null && cloudNodes == [ ])
              ("${where}: cluster ${n.name} has no cloud to register with; add a node with the "
                + "cloud role, or give this one its own cloud_addrs")))
          nodes')
        # A raft group tolerates a loss only at an odd size; an even one costs
        # a box and buys nothing.
        ++ (builtins.filter (e: e != null) (map
          (g:
            let m = raftMembers g; in
            if builtins.elem (lib.length m) [ 1 3 5 ] then null
            else "${where}: the raft group ${g} has ${toString (lib.length m)} members "
              + "(${lib.concatStringsSep ", " (map (n: n.name) m)}); a group is 1, 3 or 5 — an "
              + "even count tolerates exactly as many losses as the odd count below it")
          raftGroups))
        ++ (lib.optional (lib.length cloudGroups > 1)
          ("${where}: this plan has two clouds (${lib.concatStringsSep ", " cloudGroups}); a fleet "
            + "has one, and a cluster told two addresses does not know which is its own"))
        ++ (lib.optional (cloudNodes != [ ] && !(builtins.any (n: n.has "cluster") nodes'))
          ("${where}: this plan has a cloud and no cluster; a cloud places vms on clusters and "
            + "this one would have none to place on"))
        # D-P6. Said here rather than discovered on the first boot: kanidm's
        # `domain` is an `iname` and refuses anything that starts with a
        # digit, so an addons node falling back to its ADDRESS builds an
        # image whose identity provider cannot start.
        ++ (lib.optional (addonsNode != null && !(header ? domain))
          ("${where}: node ${addonsNode.name} has the addons role and this plan has no "
            + "[fleet] domain; kanidm is reached under a NAME (its issuer is an https url and "
            + "its certificate has to match), and an address is not one. Set [fleet] domain"));

      # Forced by every consumer below, so a broken plan fails at evaluation
      # — `nix flake check` and `nix build .#image-<name>` alike — rather than
      # producing an image nobody can use.
      nodes = if errors == [ ] then nodes' else throw (builtins.head errors);

      controllerAddrsOf = n:
        if n.controllerAddrs != null then n.controllerAddrs
        else map (c: "${c.address}:${toString clusterSessionPort}") (clusterNodesOf n.group);
      cloudAddrsOf = n:
        if n.cloudAddrs != null then n.cloudAddrs
        else map (c: "${c.address}:${toString cloudSessionPort}") cloudNodes;

      # `name=ip,…` for a controller in a group of more than one, and nothing
      # at all for a group of one: an empty peer set IS the loopback single
      # member nix/etcd.nix bakes, which is what a one-box lab has always run.
      etcdPeersOf = n:
        let m = raftMembers n.group; in
        if lib.length m < 2 then null
        else lib.concatStringsSep "," (map (p: "${p.name}=${p.address}") m);

      # One port per node AND ROLE: a box with two roles has two listeners
      # (9100 cloud, 9101 cluster, 9102 agent — the numbers controllers.nix
      # and agent.nix picked so that exactly this list can exist).
      scrapeTargets = lib.concatMap
        (n: lib.concatMap
          (r: lib.optional (r != "addons")
            "${n.address}:${toString ({ cloud = 9100; cluster = 9101; agent = 9102; }.${r})}")
          n.roles)
        nodes;

      contextEnv = n:
        { MEISTER_ROLE = lib.concatStringsSep "," n.roles; }
        // (lib.optionalAttrs (n.has "cloud") {
          MEISTER_CLOUD_NAME = n.group;
          MEISTER_CLOUD_ADVERTISE_API = "${n.address}:${toString cloudApiPort}";
        })
        // (lib.optionalAttrs (n.has "cluster") ({
          MEISTER_CLUSTER_NAME = n.group;
          MEISTER_CLUSTER_ADVERTISE_API = "${n.address}:${toString clusterApiPort}";
        } // lib.optionalAttrs (cloudAddrsOf n != [ ]) {
          MEISTER_CLOUD_ADDRS = lib.concatStringsSep "," (cloudAddrsOf n);
        }))
        // (lib.optionalAttrs (n.has "agent" && controllerAddrsOf n != [ ]) {
          MEISTER_CONTROLLER_ADDRS = lib.concatStringsSep "," (controllerAddrsOf n);
        })
        // (lib.optionalAttrs (etcdPeersOf n != null) {
          MEISTER_ETCD_PEERS = etcdPeersOf n;
          MEISTER_ETCD_MEMBER = n.name;
          # Two tiers bootstrapping on one network must not share a token: it
          # is what keeps a cloud member out of a cluster's raft.
          MEISTER_ETCD_TOKEN = "${header.name}-${n.group}";
        })
        # A plan with an addons node points the whole fleet at it, the addons
        # node included. A plan without one says nothing, and a fleet that
        # says nothing exports nothing — the shape this lab ran before Image 58.
        // (lib.optionalAttrs (addonsNode != null) ({
          MEISTER_OTLP_ENDPOINT = "http://${addonsNode.address}:${toString otlpPort}";
          MEISTER_LOKI_URL = "http://${addonsNode.address}:${toString lokiPort}/loki/api/v1/push";
          MEISTER_LOG_FORMAT = "json";
        } // {
          # The addons node is reached under a NAME -- always, since a plan
          # with an addons node and no [fleet] domain is refused above -- and
          # an issuer url cannot be flattened to an address: the name in
          # the certificate, the origin and every redirect are that same
          # name. A fleet with no dns has to be told it, so it is told it —
          # to every node, because the addons node's own origin is the name
          # as well. `networking.hosts` is the build-time half of the same
          # as well. It is a CONTEXT value and not a `networking.hosts` entry
          # on purpose: /etc/hosts then has one owner (one-context, the same
          # one resolv.conf has), and a fleet can be re-pointed at a new
          # addons box without rebuilding an image.
          MEISTER_HOSTS = "${addonsNode.address} ${addonsHost}";
        } // lib.optionalAttrs (n.has "cloud") {
          # Kanidm publishes one issuer per oauth2 client, and the cloud's
          # client is the cli's.
          MEISTER_OIDC_ISSUER =
            "https://${addonsHost}:${toString kanidmPort}/oauth2/openid/meister-cli";
          # Kanidm writes the NAME OF THE CLIENT into `aud` and has no
          # audience mapper to say anything else with — where Keycloak's
          # mapper said "meister". The cloud checks this string, so it travels
          # with the issuer.
          MEISTER_OIDC_AUDIENCE = "meister-cli";
          MEISTER_OIDC_CA = "/opt/meisterstack/pki/ca.crt";
        }));

      # The module a plan node is, expressed only through the options a
      # foreign flake has too.
      nodeModule = n: { lib, ... }: {
        networking.hostName = n.name;
        meisterstack.roles = n.roles;
        # Without MEISTER_ROLE: `meisterstack.roles` above is what derives
        # it (nix/roles.nix), and two owners for one variable is a conflict
        # waiting for the day the two disagree.
        meisterstack.context.defaults = removeAttrs (contextEnv n) [ "MEISTER_ROLE" ];

        # The addons role is build time (nix/addons.nix says why), so its two
        # deployment values come from the plan as options rather than as
        # context variables.
        meisterstack.addons.fqdn = lib.mkIf (n.has "addons") addonsHost;
        meisterstack.addons.scrapeTargets = lib.mkIf (n.has "addons") scrapeTargets;

        # A node that names a second disk keeps its state on it: etcd under
        # `etcd/`, the addons under `addons/`, one block and one label.
        meisterstack.data.label = lib.mkIf (n.data != null) "meister-data";
        meisterstack.cloud.settings = n.settings.cloud or { };
        meisterstack.cluster.settings = n.settings.cluster or { };
        meisterstack.agent.settings = n.settings.agent or { };

        # base.nix turns dhcp off because the OpenNebula context owns the
        # address there. A plan node has no context, so the plan owns it: a
        # static address when the plan says how wide the net is, and dhcp when
        # it does not — an address nobody configured is how a box comes up
        # unreachable with a perfectly good image on it.
        networking.useDHCP = lib.mkForce (!(defaults ? prefix));
        networking.interfaces = lib.mkIf (defaults ? prefix) {
          ${n.interface}.ipv4.addresses = [{
            address = n.address;
            prefixLength = defaults.prefix;
          }];
        };
        networking.defaultGateway = lib.mkIf (defaults ? gateway) defaults.gateway;
        networking.nameservers = lib.mkIf (defaults ? nameservers) defaults.nameservers;
        # base.nix hands /etc/resolv.conf to one-context; on a plan node
        # nobody writes it unless resolvconf does.
        networking.resolvconf.enable = lib.mkIf (defaults ? nameservers) (lib.mkForce true);

        # Where this system lives once it is on the box. Every value is a
        # mkDefault because the image format says the same things louder: the
        # raw-efi generator writes the partition table these labels name, and
        # it is the authority while it is building. Outside a build — a plain
        # `nixos-rebuild switch --target-host`, which is what `push` does —
        # these are what makes the configuration complete, and `disk` is the
        # one fact only the plan has.
        fileSystems."/" = {
          device = lib.mkDefault "/dev/disk/by-label/nixos";
          fsType = lib.mkDefault "ext4";
        };
        fileSystems."/boot" = {
          device = lib.mkDefault "/dev/disk/by-label/ESP";
          fsType = lib.mkDefault "vfat";
        };
        boot.loader.grub.device = lib.mkDefault n.disk;
        boot.loader.grub.efiSupport = lib.mkDefault true;
        boot.loader.grub.efiInstallAsRemovable = lib.mkDefault true;

        # `data` is the second disk of the box: etcd's state and the addons'
        # state, by LABEL rather than by device name, because which slot a
        # disk lands in is not a promise anybody made (nix/etcd.nix learned
        # that in the lab). The plan names the device so that the recipe in
        # config/examples/one-box can say `mkfs.ext4 -L meister-data <it>`.
      };
    in
    {
      inherit header opennebula nodes scrapeTargets addonsHost;
      metalNodes = builtins.filter (n: n.kind == "metal") nodes;
      inherit contextEnv nodeModule controllerAddrsOf cloudAddrsOf etcdPeersOf;
    };
in
{
  inherit load;
}
