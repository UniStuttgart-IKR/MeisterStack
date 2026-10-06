# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Read schema-2 fleet inventories, validate topology and inheritance, and derive
# host modules, renderer inputs, and manifest inventory. Scalar precedence is
# defaults < group < host; equal-rank group conflicts are errors. Lists accumulate
# in declaration order. inventory-parity.py checks the shared precedence contract.
{ lib }:

let
  knownRoles = [ "cloud" "cluster" "agent" "addons" ];
  knownKinds = [ "raft" "compute" "custom" ];
  knownReboot = [ "auto" "approve" "never" ];
  knownDeployments = [ "nixos" "context" ];

  # Boot ownership: uefi uses systemd-boot; direct receives its kernel from the
  # provider; grub keeps an existing loader. Only uefi supports boot-entry rollback.
  # This fleet can install uefi and direct hosts; grub hosts must already be installed.
  knownBootModes = [ "uefi" "direct" "grub" ];
  # Deploy roles from the agent toward the cloud so lower tiers are updated first.
  roleRank = { agent = 0; cluster = 1; cloud = 2; addons = 3; };
  sortRoles = rs: builtins.sort
    (a: b: (roleRank.${a} or 99) < (roleRank.${b} or 99))
    (lib.unique rs);

  # Ports used to derive session and API addresses; keep aligned with services.nix.
  ports = {
    cloudApi = 3000;
    cloudSession = 50050;
    clusterApi = 3001;
    clusterSession = 50051;
    kanidm = 8443;
    loki = 3100;
    otlp = 4317;
    metrics = { cloud = 9100; cluster = 9101; agent = 9102; };
  };

  # Inventory disk sizes use decimal GB; installer comparisons use bytes.
  gb = 1000000000;

  isLabel = s:
    builtins.isString s
    && builtins.match "[a-z0-9]([a-z0-9-]*[a-z0-9])?" s != null
    && builtins.stringLength s <= 63;

  # Host IDs identify plan entries and need not be DNS labels.
  isIdent = s:
    builtins.isString s
    && builtins.match "[A-Za-z0-9][A-Za-z0-9_-]*" s != null
    && builtins.stringLength s <= 63;

  deviceRefPrefixes = [ "label:" "uuid:" "partlabel:" "serial:" ];

  load = file:
    let
      raw = builtins.fromTOML (builtins.readFile file);
      where = toString file;
      planDir = builtins.dirOf file;

      # Check the schema before reporting missing schema-2 fields.
      schema =
        if !(raw ? schema) then
          throw ("${where}: no `schema` key. An inventory of this tool says `schema = 2` "
            + "on its first line; a file without one is the pre-v1 plan, which nothing "
            + "reads any more (M5B removed the reader).")
        else if raw.schema != 2 then
          throw ("${where}: schema ${toString raw.schema}, and this flake reads schema 2. "
            + "Schema 1 is the pre-v1 plan (nodes, not hosts; no groups, no install, no "
            + "persistence) and nothing reads it any more; migrating means naming an id, "
            + "a deployment and the groups of every host.")
        else 2;

      # Reject unknown top-level tables, including obsolete provider configuration.
      knownTop = [ "schema" "fleet" "defaults" "operator" "group" "host" "service" ];
      unknownTop = lib.filter (k: !(lib.elem k knownTop)) (builtins.attrNames raw);
      checkedRaw =
        if unknownTop == [ ] then raw
        else if lib.elem "opennebula" unknownTop then
          throw ("${where}: the table [opennebula] is not part of a schema 2 inventory. It "
            + "was parsed and exported by the pre-v1 plan and read by nothing; the "
            + "OpenNebula adapter moved to the lab repository "
            + "(~/git/meisterstack-lab/providers/opennebula/). Delete the table.")
        else
          throw ("${where}: the inventory has the table(s) "
            + lib.concatStringsSep ", " (map (k: "[${k}]") unknownTop)
            + ", and a schema 2 inventory knows "
            + lib.concatStringsSep ", " (map (k: "[${k}]") knownTop)
            + ". A key nobody declared is a typo and not a feature.");

      header = checkedRaw.fleet or (throw "${where}: no [fleet] table; a fleet says what it is called");
      domain = header.domain or null;
      defaults = checkedRaw.defaults or { };
      operator = checkedRaw.operator or null;

      groupList = checkedRaw.group or [ ];
      hostList = checkedRaw.host or [ ];
      serviceList = checkedRaw.service or [ ];

      groupIds = map (g: g.id or (throw "${where}: a [[group]] without an id")) groupList;
      hostIds' = map (h: h.id or (throw "${where}: a [[host]] without an id")) hostList;
      serviceIds = map (s: s.id or (throw "${where}: a [[service]] without an id")) serviceList;

      byId = list: builtins.listToAttrs (map (x: lib.nameValuePair x.id x) list);
      groupsRaw = byId groupList;
      hostsRaw = byId hostList;
      servicesRaw = byId serviceList;

      dups = ids: lib.length (lib.unique ids) != lib.length ids;

      # Scalar precedence: defaults < groups < host. Equal-rank groups must agree.
      groupsOf = h: map (g: groupsRaw.${g}) (lib.filter (g: groupsRaw ? ${g}) (h.groups or [ ]));

      settle = h: key: get: fallback:
        let
          fromHost = get h;
          named = lib.filter (x: x.value != null)
            (map (g: { id = g.id; value = get g; }) (groupsOf h));
          fromGroups =
            if named == [ ] then null
            else
              let
                first = builtins.head named;
                disagreeing = lib.filter (x: x.value != first.value) named;
              in
              if disagreeing == [ ] then first.value
              else
                let other = builtins.head disagreeing; in
                throw ("${where}: host ${h.id} is in the groups ${first.id} and ${other.id}, "
                  + "and they set ${key} to ${builtins.toJSON first.value} and "
                  + "${builtins.toJSON other.value}. Two groups of equal rank cannot both "
                  + "decide it: set ${key} on the host, or take it out of one of the groups.");
          fromDefaults = get defaults;
        in
        if fromHost != null then fromHost
        else if fromGroups != null then fromGroups
        else if fromDefaults != null then fromDefaults
        else fallback;

      # Accumulate lists in declaration order, keeping each value once.
      accumulate = h: get:
        lib.unique (get defaults ++ lib.concatMap get (groupsOf h) ++ get h);

      effective = h: {
        ssh = {
          user = settle h "ssh.user" (x: (x.ssh or { }).user or null) "root";
          port = settle h "ssh.port" (x: (x.ssh or { }).port or null) 22;
          # SSH host fingerprints belong to individual hosts and are never inherited.
          host_key = (h.ssh or { }).host_key or null;
        };
        profiles = accumulate h (x: x.profiles or [ ]);
        # Default to a host-managed UEFI boot; direct and existing grub are explicit.
        boot = settle h "boot" (x: x.boot or null) "uefi";
        rollout = {
          max_unavailable =
            settle h "rollout.max_unavailable" (x: (x.rollout or { }).max_unavailable or null) 1;
          # Require approval for reboots unless the inventory specifies another policy.
          reboot = settle h "rollout.reboot" (x: (x.rollout or { }).reboot or null) "approve";
          canary = settle h "rollout.canary" (x: (x.rollout or { }).canary or null) null;
        };
        checks = {
          required = accumulate h (x: (x.checks or { }).required or [ ]);
          functional = accumulate h (x: (x.checks or { }).functional or [ ]);
        };
        # Accumulate substituters in lookup order. An empty list uses pushed closures.
        # Managed hosts require signatures from their configured trusted keys.
        substituters = accumulate h (x: (x.managed or { }).substituters or [ ]);
      };

      # --- the hosts -------------------------------------------------------
      mkHost = h:
        let
          eff = effective h;
          roles = sortRoles (h.roles or [ ]);
          networks = h.networks or { };
          management = networks.management or null;
        in
        rec {
          id = h.id;
          # The hostname may differ from the stable host ID used as MEISTER_NODE_ID.
          name = h.name or (throw "${where}: host ${h.id} has no name");
          deployment = h.deployment or (throw
            ("${where}: host ${h.id} has no `deployment`. It is `nixos` (this flake builds its "
              + "system and meister-deploy takes it forward closure by closure) or `context` "
              + "(a VM somebody else instantiated, served by the push in the lab "
              + "repository, ~/git/meisterstack-lab/legacy/push.sh)."));
          inherit roles networks management;
          groups = h.groups or [ ];
          controllerGroup = h.controller_group or null;
          site = h.site or null;
          failureDomain = h.failure_domain or null;
          address =
            if management != null then management.address
            else throw ("${where}: host ${h.id} has no networks.management, so nothing knows "
              + "which address to reach it at");
          # Resolve operator modules relative to the inventory file.
          modules = h.modules or [ ];
          modulePaths = map (m: planDir + "/${m}") (h.modules or [ ]);
          capabilities = h.capabilities or [ ];
          hardware = h.hardware or { };
          install = h.install or null;
          persistence = h.persistence or [ ];
          deviations = h.deviations or { };
          ssh = eff.ssh;
          profiles = eff.profiles;
          boot = eff.boot;
          rollout = eff.rollout;
          checks = eff.checks;
          substituters = eff.substituters;
          has = role: builtins.elem role roles;
          # A host may belong to at most one Raft group.
          raftGroups = lib.filter (g: (groupsRaw.${g}.kind or null) == "raft")
            (lib.filter (g: groupsRaw ? ${g}) groups);
          raftGroup = if raftGroups == [ ] then null else builtins.head raftGroups;
        };

      hosts' = lib.mapAttrs (_: mkHost) hostsRaw;

      membersOf = gid: lib.filter (h: builtins.elem gid h.groups) (lib.attrValues hosts');

      cloudHosts = lib.filter (h: h.has "cloud") (lib.attrValues hosts');
      clusterHostsOf = gid: lib.filter (h: h.has "cluster") (membersOf gid);
      addonsHosts = lib.filter (h: h.has "addons") (lib.attrValues hosts');
      addonsHost = if addonsHosts == [ ] then null else builtins.head addonsHosts;
      # The addons identity provider requires a domain for its origin and certificates.
      addonsFqdn =
        if addonsHost == null then null
        else if domain != null then "${addonsHost.name}.${domain}"
        else null;

      # Force the schema check before host validation to report incompatible input clearly.
      errors = builtins.seq schema (
        (lib.optional (hostList == [ ])
          "${where}: no [[host]]; there is nothing to deploy")
        ++ (lib.optional (dups hostIds')
          "${where}: two hosts share an id (${lib.concatStringsSep ", " hostIds'})")
        ++ (lib.optional (dups groupIds)
          "${where}: two groups share an id (${lib.concatStringsSep ", " groupIds})")
        ++ (lib.optional (dups serviceIds)
          "${where}: two services share an id (${lib.concatStringsSep ", " serviceIds})")
        ++ (lib.optional (!isLabel header.name)
          "${where}: the fleet name ${header.name} is not a dns label")
        ++ (lib.concatMap
          (g:
            (lib.optional (!isIdent g.id) "${where}: the group id ${g.id} is not an identifier")
            ++ (lib.optional (!(builtins.elem (g.kind or "") knownKinds))
              ("${where}: group ${g.id} has the kind ${g.kind or "<none>"}; a group is "
                + lib.concatStringsSep ", " knownKinds)))
          groupList)
        ++ (lib.concatMap
          (h:
            (lib.optional (!isIdent h.id) "${where}: the host id ${h.id} is not an identifier")
            ++ (lib.optional (!isLabel h.name)
              "${where}: host ${h.id}: the name ${h.name} is not a dns label (it is a hostname)")
            ++ (lib.optional (!(builtins.elem h.deployment knownDeployments))
              ("${where}: host ${h.id} is deployed as ${h.deployment}; it is "
                + lib.concatStringsSep " or " knownDeployments))
            ++ (lib.optional (h.roles == [ ])
              "${where}: host ${h.id} has no role; a host that is nothing is not a plan")
            ++ (map
              (r: "${where}: host ${h.id} has the unknown role ${r}; a fleet knows "
                + lib.concatStringsSep ", " knownRoles)
              (lib.filter (r: !(builtins.elem r knownRoles)) h.roles))
            ++ (map
              (g: "${where}: host ${h.id} is in the group ${g}, which is not declared")
              (lib.filter (g: !(groupsRaw ? ${g})) h.groups))
            ++ (lib.optional (dups h.groups) "${where}: host ${h.id} lists one of its groups twice")
            ++ (lib.optional (h.controllerGroup != null && !(groupsRaw ? ${h.controllerGroup}))
              ("${where}: host ${h.id} reports to the group ${h.controllerGroup}, which is not "
                + "declared"))
            ++ (lib.optional (lib.length h.raftGroups > 1)
              ("${where}: host ${h.id} is in the raft groups "
                + "${lib.concatStringsSep ", " h.raftGroups}; one machine is one member of one "
                + "quorum"))
            ++ (lib.optional (!(builtins.elem h.rollout.reboot knownReboot))
              ("${where}: host ${h.id} has rollout.reboot = ${h.rollout.reboot}; it is "
                + lib.concatStringsSep ", " knownReboot))
            # Explain that BIOS firmware does not identify the installed bootloader.
            ++ (lib.optional (h.boot == "bios")
              ("${where}: host ${h.id} asks for boot = \"bios\". This flake installs uefi or "
                + "direct, and it deploys to a machine that already has grub — that value is "
                + "\"grub\". A grub host has no boot "
                + "fallback either way, because `bootctl set-oneshot` is what a boot fallback is made "
                + "of and grub has no equivalent."))
            ++ (lib.optional (h.boot != "bios" && !(builtins.elem h.boot knownBootModes))
              ("${where}: host ${h.id} has boot = ${builtins.toJSON h.boot}; a host of this "
                + "fleet boots " + lib.concatStringsSep " or " knownBootModes))
            # Existing grub hosts are deployment targets, but this installer cannot create
            # or roll back their boot menu. Reject install tables during inventory validation.
            ++ (lib.optional (h.boot == "grub" && h.install != null)
              ("${where}: host ${h.id} has boot = \"grub\" AND an install table. This flake "
                + "installs uefi (systemd-boot) or direct (no loader at all); a grub host "
                + "brings its own loader, which is why it has no boot fallback. Drop the "
                + "install table, or set boot = \"uefi\" and give the layout an ESP."))

            ++ (lib.optional (h.install != null && !(h.install ? layout))
              ("${where}: host ${h.id} has an install table without a layout. The layout is "
                + "the disko module that decides the partition table, named relative to this "
                + "file — there is no default, because a default partition table is a "
                + "default answer to which bytes get destroyed."))
            ++ (map
              (k: "${where}: host ${h.id} names ${builtins.toJSON k} in "
                + "install.authorized_keys, and that is not an ssh public key. This list is "
                + "PUBLIC halves only (`ssh-ed25519 AAAA…`), because it is baked into an "
                + "installer medium that anybody who holds the medium can read.")
              (lib.filter
                (k: !(builtins.isString k)
                  || builtins.match "(ssh|ecdsa|sk)-[^ ]+ [A-Za-z0-9+/=]+( .*)?" k == null)
                (if h.install == null then [ ] else h.install.authorized_keys or [ ])))
            ++ (lib.optional (h.deployment == "nixos" && h.management == null)
              ("${where}: host ${h.id} is deployed as nixos and has no networks.management, "
                + "which is the address it would be reached at"))
            ++ (lib.optional (h.deployment == "context" && h.install != null)
              ("${where}: host ${h.id} is deployed as context and carries an install table. A "
                + "context VM is instantiated by somebody else; this tool never installs one."))
            ++ (lib.optional (h.install != null && !((h.install.disk or { }) ? serial))
              ("${where}: host ${h.id} has an install table whose disk has no serial. A device "
                + "path is not an answer: /dev/sda is a name the kernel hands out in boot "
                + "order, and installing over the wrong disk is not recoverable."))
            ++ (lib.concatMap
              (p:
                (lib.optional (!(builtins.any (pre: lib.hasPrefix pre p.device) deviceRefPrefixes))
                  ("${where}: host ${h.id} keeps ${p.path} on ${p.device}; a persistent device "
                    + "is named "
                    + "${lib.concatStringsSep ", " deviceRefPrefixes} and never a device path"))
                ++ (lib.optional
                  (h.install != null && (p.preserve_on_reinstall or true)
                    && !(builtins.elem p.path (h.install.preserve or [ ])))
                  ("${where}: host ${h.id} keeps ${p.path} across a reinstall but "
                    + "install.preserve does not list it")))
              h.persistence)
            # Agents need a controller group when the fleet contains clusters.
            # An agent-only fleet may run standalone.
            ++ (lib.optional
              (h.has "agent" && h.controllerGroup == null
                && !(builtins.any (g: clusterHostsOf g != [ ]) h.groups)
                && builtins.any (o: o.has "cluster") (lib.attrValues hosts'))
              ("${where}: agent ${h.id} has no controller_group, and no group it is in runs a "
                + "cluster controller; name the cluster's group in controller_group"))
            ++ (lib.optional (h.has "cluster" && cloudHosts == [ ])
              ("${where}: cluster ${h.id} has no cloud to register with; add a host with the "
                + "cloud role")))
          (lib.attrValues hosts'))
        # Supported Raft group sizes are one, three, or five members.
        ++ (lib.concatMap
          (g:
            let m = membersOf g.id; in
            lib.optional (g.kind == "raft" && !(builtins.elem (lib.length m) [ 1 3 5 ]))
              ("${where}: the raft group ${g.id} has ${toString (lib.length m)} members "
                + "(${lib.concatStringsSep ", " (map (h: h.id) m)}); a group is 1, 3 or 5 — an "
                + "even count tolerates exactly as many losses as the odd count below it"))
          groupList)
        ++ (lib.optional
          (lib.length (lib.unique (map (h: toString h.raftGroup) cloudHosts)) > 1)
          ("${where}: this fleet has two clouds ("
            + lib.concatStringsSep ", " (lib.unique (map (h: toString h.raftGroup) cloudHosts))
            + "); a fleet has one, and a cluster told two addresses does not know which is its "
            + "own"))
        ++ (lib.optional
          (cloudHosts != [ ] && !(builtins.any (h: h.has "cluster") (lib.attrValues hosts')))
          ("${where}: this fleet has a cloud and no cluster; a cloud places vms on clusters and "
            + "this one would have none to place on"))
        ++ (lib.optional (addonsHost != null && domain == null)
          ("${where}: host ${addonsHost.id} has the addons role and this fleet has no [fleet] "
            + "domain; kanidm is reached under a NAME (its issuer is an https url and its "
            + "certificate has to match), and an address is not one. Set [fleet] domain"))
        ++ (lib.concatMap
          (s:
            (lib.optional (!isIdent s.id) "${where}: the service id ${s.id} is not an identifier")
            ++ (lib.optional ((s.host or null) != null && !(hostsRaw ? ${s.host}))
              "${where}: service ${s.id} runs on ${s.host}, which is not a declared host")
            ++ (lib.optional (!(s.managed or true) && (s.host or null) != null)
              ("${where}: service ${s.id} is not managed and names a host of this fleet. One of "
                + "the two is wrong.")))
          serviceList));

      # Every consumer forces validation before emitting deployment values.
      hosts = if errors == [ ] then hosts' else throw (builtins.head errors);

      # Session URLs include https because generated sessions use mTLS.
      sessionUrl = c: port: "https://${c.address}:${toString port}";

      controllerAddrsOf = h:
        let gid = if h.controllerGroup != null then h.controllerGroup else h.raftGroup; in
        if gid == null then [ ]
        else map (c: sessionUrl c ports.clusterSession) (clusterHostsOf gid);

      cloudAddrsOf = _: map (c: sessionUrl c ports.cloudSession) cloudHosts;

      # Use explicit peer membership for multi-member Raft groups; an empty set
      # selects the loopback single-member configuration in etcd.nix.
      etcdPeersOf = h:
        let m = if h.raftGroup == null then [ ] else membersOf h.raftGroup; in
        if lib.length m < 2 then null
        else lib.concatStringsSep "," (map (p: "${p.id}=${p.address}") m);

      # Allocate one metrics port per role: cloud 9100, cluster 9101, agent 9102.
      scrapeTargets = lib.concatMap
        (h: lib.concatMap
          (r: lib.optional (r != "addons") "${h.address}:${toString ports.metrics.${r}}")
          h.roles)
        (lib.attrValues hosts);

      contextEnv = id:
        let h = hosts.${id}; in
        {
          MEISTER_ROLE = lib.concatStringsSep "," h.roles;
          # Use the inventory ID for node identity, independently of the hostname.
          MEISTER_NODE_ID = h.id;
        }
        // (lib.optionalAttrs (h.has "cloud") {
          MEISTER_CLOUD_NAME = if h.raftGroup != null then h.raftGroup else h.id;
          MEISTER_CLOUD_ADVERTISE_API = "${h.address}:${toString ports.cloudApi}";
        })
        // (lib.optionalAttrs (h.has "cluster") ({
          MEISTER_CLUSTER_NAME = if h.raftGroup != null then h.raftGroup else h.id;
          MEISTER_CLUSTER_ADVERTISE_API = "${h.address}:${toString ports.clusterApi}";
        } // lib.optionalAttrs (cloudAddrsOf h != [ ]) {
          MEISTER_CLOUD_ADDRS = lib.concatStringsSep "," (cloudAddrsOf h);
        }))
        // (lib.optionalAttrs (h.has "agent" && controllerAddrsOf h != [ ]) {
          MEISTER_CONTROLLER_ADDRS = lib.concatStringsSep "," (controllerAddrsOf h);
        })
        // (lib.optionalAttrs (etcdPeersOf h != null) {
          MEISTER_ETCD_PEERS = etcdPeersOf h;
          MEISTER_ETCD_MEMBER = h.id;
          # Scope the bootstrap token to the fleet and Raft group.
          MEISTER_ETCD_TOKEN = "${header.name}-${h.raftGroup}";
        })
        # An addons host supplies telemetry endpoints for the entire fleet.
        // (lib.optionalAttrs (addonsHost != null) ({
          MEISTER_OTLP_ENDPOINT = "http://${addonsHost.address}:${toString ports.otlp}";
          MEISTER_LOKI_URL =
            "http://${addonsHost.address}:${toString ports.loki}/loki/api/v1/push";
          MEISTER_LOG_FORMAT = "json";
          # Distribute the addons FQDN for certificate, origin, and redirect resolution.
          MEISTER_HOSTS = "${addonsHost.address} ${addonsFqdn}";
        } // lib.optionalAttrs (h.has "cloud") {
          # Kanidm exposes an issuer for each OAuth2 client.
          MEISTER_OIDC_ISSUER =
            "https://${addonsFqdn}:${toString ports.kanidm}/oauth2/openid/meister-cli";
          # Kanidm uses the OAuth2 client name as the token audience.
          MEISTER_OIDC_AUDIENCE = "meister-cli";
        }));

      # Express inventory values through public module options. Host profiles own
      # stateVersion, firewall policy, filesystems, and other machine configuration.
      hostModule = id:
        let h = hosts.${id}; in
        { config, lib, ... }: {
          meisterstack.roles = h.roles;
          # The addons host scrapes every role's metrics on this address.
          meisterstack.metrics.listenAddress =
            lib.mkIf (h.management != null) (lib.mkDefault h.management.address);
          # roles.nix derives MEISTER_ROLE; do not define it twice.
          meisterstack.context.defaults =
            removeAttrs (contextEnv id) [ "MEISTER_ROLE" ]
            # Resolve the OIDC trust path against this host's PKI directory.
            // lib.optionalAttrs (addonsHost != null && h.has "cloud") {
              MEISTER_OIDC_CA = "${config.meisterstack.pki.dir}/ca.crt";
            };

          # Addons configuration is fixed when the system is evaluated.
          meisterstack.addons.fqdn = lib.mkIf (h.has "addons") addonsFqdn;
          meisterstack.addons.scrapeTargets = lib.mkIf (h.has "addons") scrapeTargets;

          # Map the declared data device into the runtime data mount.
          meisterstack.data.label = lib.mkIf
            (builtins.any (p: p.device == "label:meister-data") h.persistence)
            "meister-data";

          # Enable RDMA tools only on agents whose inventory declares an RDMA NIC.
          meisterstack.agent.rdma.enable =
            h.has "agent"
            && builtins.any (n: n.rdma or false) (h.hardware.nics or [ ]);
          # Apply named per-host deviations after generated role settings.
          meisterstack.cloud.settings = (h.deviations.settings or { }).cloud or { };
          meisterstack.cluster.settings = (h.deviations.settings or { }).cluster or { };
          meisterstack.agent.settings = (h.deviations.settings or { }).agent or { };

          # UEFI uses systemd-boot; direct disables local loaders; grub retains the
          # operator's loader. Defaults remain overridable by host modules. Direct and
          # grub hosts support userland switch rollback, but no boot-entry rollback.
          boot.loader.systemd-boot.enable = lib.mkDefault (h.boot == "uefi");
          boot.loader.efi.canTouchEfiVariables = lib.mkDefault (h.boot == "uefi");
          boot.loader.grub.enable = lib.mkDefault false;

          # For installable hosts, require the boot mode and disk layout to agree on
          # whether an EFI system partition exists.
          assertions = lib.optionals (h.install != null) [
            {
              assertion = h.boot != "uefi" || config.meisterstack.install.hasEsp;
              message =
                "host ${h.id} boots uefi and its layout ${h.install.layout} says it makes no "
                + "EFI system partition (meisterstack.install.hasEsp = false). systemd-boot "
                + "would have nowhere to install itself, and the machine would come back "
                + "from its first reboot with no way to start. Use a layout with an ESP, or "
                + "set boot = \"direct\" for this host.";
            }
            {
              assertion = h.boot != "direct" || !config.meisterstack.install.hasEsp;
              message =
                "host ${h.id} boots direct and its layout ${h.install.layout} makes an EFI "
                + "system partition (meisterstack.install.hasEsp = true). Nothing would ever "
                + "write to it: a direct-boot guest is handed its kernel from outside and "
                + "installs no loader. Use a layout without an ESP, or set boot = \"uefi\".";
            }
          ];

          # Filesystems belong to disko or host modules. Configure the management
          # interface only when the inventory explicitly sets static = true.
          networking = lib.mkMerge [
            { hostName = h.name; }
            (lib.mkIf (h.management != null && (h.management.static or false)) (
            {
              interfaces.${h.management.interface or "eth0"}.ipv4.addresses = [{
                address = h.management.address;
                prefixLength = h.management.prefix;
              }];
            }
            // lib.optionalAttrs (h.management ? gateway) {
              defaultGateway = h.management.gateway;
            }
            ))
          ];
        };

      # Emit the inventory half of the manifest with explicit null or empty fields.
      network = n:
        if n == null then null else {
          address = n.address;
          prefix = n.prefix;
          interface = n.interface or null;
          gateway = n.gateway or null;
        };

      manifestHost = h: {
        inherit (h) name address deployment roles groups site;
        ssh = {
          inherit (h.ssh) user port;
          host_key_fingerprint = h.ssh.host_key;
        };
        controller_group = h.controllerGroup;
        failure_domain = h.failureDomain;
        networks = {
          management = network h.management;
          storage = network (h.networks.storage or null);
          tenant = network (h.networks.tenant or null);
          bmc = network (h.networks.bmc or null);
        };
        inherit (h) profiles modules deviations substituters;
        hardware = {
          cpu = h.hardware.cpu or null;
          memory_gb = h.hardware.memory_gb or null;
          gpus = map
            (g: { inherit (g) model pci; selected_for = g.selected_for or null; })
            (h.hardware.gpus or [ ]);
          nics = map
            (n: { inherit (n) name mac role; rdma = n.rdma or false; })
            (h.hardware.nics or [ ]);
          capabilities = h.capabilities;
        };
        install =
          if h.install == null then null else {
            disk = {
              serial = h.install.disk.serial;
              wwn = h.install.disk.wwn or null;
              size_bytes =
                if h.install.disk ? size_gb then h.install.disk.size_gb * gb
                else throw ("${where}: host ${h.id}: install.disk has no size_gb, and the "
                  + "installer compares the size it was told against `lsblk -J`");
            };
            layout = h.install.layout;
            preserve = h.install.preserve or [ ];
            # Installer SSH access uses public keys; an empty list leaves console access only.
            authorized_keys = h.install.authorized_keys or [ ];
          };
      };

      # Only nixos hosts have system closures. Filter context hosts out of manifest
      # hosts, group membership, and service topology; keep them in inventory inspection.
      managedIds = lib.attrNames (lib.filterAttrs (_: h: h.deployment == "nixos") hosts);
      isManaged = id: builtins.elem id managedIds;

      manifestGroup = g: {
        kind = g.kind;
        members = lib.filter isManaged (map (h: h.id) (membersOf g.id));
        quorum = if g.kind == "raft" then { size = lib.length (membersOf g.id); } else null;
        profiles = g.profiles or [ ];
        # Group rollout policy inherits fleet defaults independently of host overrides.
        rollout = {
          canary_class = (g.rollout or { }).canary or ((defaults.rollout or { }).canary or null);
          max_unavailable = (g.rollout or { }).max_unavailable
            or ((defaults.rollout or { }).max_unavailable or 1);
          reboot = (g.rollout or { }).reboot or ((defaults.rollout or { }).reboot or "approve");
        };
      };

      manifestService = s: {
        kind = s.kind;
        managed = s.managed or true;
        host = s.host or null;
        endpoint = s.endpoint or null;
        trust_ref = s.trust_ref or null;
        required = s.required or true;
      };

      manifestInventory = {
        fleet = { name = header.name; inherit domain schema; };
        groups = lib.mapAttrs (_: manifestGroup) groupsRaw;
        hosts = lib.mapAttrs (_: manifestHost)
          (lib.filterAttrs (_: h: h.deployment == "nixos") hosts);
        services = lib.mapAttrs (_: manifestService)
          (lib.filterAttrs (_: s: (s.host or null) == null || isManaged s.host) servicesRaw);
      };
    in
    {
      inherit schema where planDir ports;
      # Hash the inventory file so consumers can verify which input was evaluated.
      sha256 = builtins.hashFile "sha256" file;
      fleet = { name = header.name; inherit domain schema; };
      inherit operator hosts defaults;
      groups = groupsRaw;
      services = servicesRaw;
      hostIds = lib.attrNames hosts;
      # Expose the hosts for which this flake builds NixOS systems.
      nixosHostIds = lib.attrNames (lib.filterAttrs (_: h: h.deployment == "nixos") hosts);
      inherit scrapeTargets addonsFqdn addonsHost;
      inherit contextEnv hostModule effective;
      inherit controllerAddrsOf cloudAddrsOf etcdPeersOf membersOf;
      inherit manifestInventory;
    };
in
{
  inherit load ports;
}
