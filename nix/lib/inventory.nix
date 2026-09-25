# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# `fleet.toml` of schema 2, read by Nix — and the ONLY place a deployment
# value is derived from it.
#
# Until v1 this file had a twin: `tools/meister-deploy/src/fleet.rs` derived
# the same etcd peer set, the same controller addresses and the same seventeen
# MEISTER_* variables in Rust, and a shell script (`scripts/check-fleet.sh`)
# compared the two. Two derivations of one fact are two facts waiting to
# disagree, so there is one now: Nix derives, and Rust reads the inventory for
# its SHAPE only (`tools/meister-deploy/src/inventory.rs`, and
# `tests/inventory_derives_nothing.rs` holds it to that). What the two still
# share is precedence — defaults < group < host — and `checks.inventory-parity`
# compares their answers for the same file rather than trusting this comment.
#
# The three roads out of here:
#
#   hostModule <id>       the NixOS module a host of this fleet is
#   contextEnv <id>       the MEISTER_* variables, for nix/lib/render.nix
#                         (build time) and nix/context.nix (boot time)
#   manifestInventory     the cheap half of `meisterDeployment`, which is
#                         `meister-deploy`'s `nix-manifest/1` contract
{ lib }:

let
  knownRoles = [ "cloud" "cluster" "agent" "addons" ];
  knownKinds = [ "raft" "compute" "custom" ];
  knownReboot = [ "auto" "approve" "never" ];
  knownDeployments = [ "nixos" "context" ];

  # How a machine of this fleet gets its kernel.
  #
  # `uefi` is a machine that boots itself: an ESP, systemd-boot, and with it
  # the boot-mode rollback of `meister-activate` (`bootctl set-oneshot`, D5).
  # `direct` is a machine whose kernel, initrd and command line are handed to
  # it from OUTSIDE — a hypervisor's direct kernel boot — so it carries no
  # boot loader at all and has no boot-mode rollback; what it keeps is the
  # switch rollback, which is userland and works unchanged.
  #
  # --- lane 5C ---
  # `grub` is the third: a machine that boots ITSELF out of a loader this
  # flake did not install and cannot drive. Every VM made from
  # `packages.managed-disk-image` is one — legacy MBR, grub, no ESP — and
  # the lab found (L2, 2026-09-23) that there was no word for it: calling
  # such a host `uefi` made `apply` hand the helper `--mode boot`, and the
  # helper refused, correctly, with "bootctl says systemd-boot is not
  # installed". Every release that changed the kernel then stopped there,
  # so such a host was not deployable at all.
  #
  # What `grub` keeps is the switch rollback, which is userland; what it
  # does not have is the boot rollback, because `bootctl set-oneshot` is
  # what one is made of. D5 called that a documented limit and this is the
  # word that documents it. It is NOT a mode this flake installs — the
  # assertion below says so — because installing a loader whose rollback
  # this tool cannot arrange would be a guarantee it cannot keep.
  #
  # `bios` is deliberately not a value: it describes firmware, and the
  # question here is who wrote the boot menu.
  knownBootModes = [ "uefi" "direct" "grub" ];
  # --- end lane 5C ---

  # The order roles are DEPLOYED in, and therefore the order they are written
  # in: the bottom tier first, so that a controller never issues a command the
  # tier below it does not understand yet.
  roleRank = { agent = 0; cluster = 1; cloud = 2; addons = 3; };
  sortRoles = rs: builtins.sort
    (a: b: (roleRank.${a} or 99) < (roleRank.${b} or 99))
    (lib.unique rs);

  # The ports, once, and the same numbers nix/services.nix publishes as
  # `meisterstack.ports`. They are here because the addresses in a context
  # are derived from them.
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

  # A disk's size is written in GB in the inventory and in BYTES in the
  # manifest, because `lsblk -J` answers in bytes and the comparison in
  # `meister-install confirm` (M3) is against that answer. GB is the decimal
  # unit every disk is sold in (10^9) and not 2^30: reading "960 GB" as GiB
  # would call the same disk 894 and the comparison would never match.
  gb = 1000000000;

  isLabel = s:
    builtins.isString s
    && builtins.match "[a-z0-9]([a-z0-9-]*[a-z0-9])?" s != null
    && builtins.stringLength s <= 63;

  # A host ID is not a DNS label: it is what a plan refers to, it may carry
  # an underscore or a capital, and it never has to resolve. Same rule as
  # `inventory.rs::check_identifier`.
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

      # The schema first and on its own: a schema 1 file is the pre-v1 plan,
      # and saying so is one sentence — not a sentence about thirty missing
      # keys.
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

      # --- lane 5B: a table nobody declared ---------------------------------
      #
      # `deny_unknown_fields` on the Rust side has refused an unknown table
      # since 1C (`inventory.rs`), and this is its twin: two readers of one
      # file that disagree about what is IN the file are two readers, and
      # `checks.inventory-parity` exists to keep them one.
      #
      # `[opennebula]` gets its own sentence because it is the one that was
      # really there: the pre-v1 plan carried `frontend` and `image`, Nix
      # and Rust both parsed them, and NOTHING read them. The provider lives
      # in the lab repository now, and so does that table.
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

      # --- precedence: defaults < group < host -----------------------------
      #
      # One function, and the only place precedence is spelled out. The twin
      # is `inventory.rs::settle`/`one_of`, and the group order is the order
      # the HOST wrote its groups in, so that the sentence about a conflict
      # names them the way the operator sees them.
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

      # Lists ACCUMULATE, in precedence order, first mention winning: a
      # profile list is an import order, and a group that adds a check makes
      # its members stricter rather than replacing what they had.
      accumulate = h: get:
        lib.unique (get defaults ++ lib.concatMap get (groupsOf h) ++ get h);

      effective = h: {
        ssh = {
          user = settle h "ssh.user" (x: (x.ssh or { }).user or null) "root";
          port = settle h "ssh.port" (x: (x.ssh or { }).port or null) 22;
          # No `host_key` in defaults or in a group, on purpose: a key shared
          # by several machines is not an identity.
          host_key = (h.ssh or { }).host_key or null;
        };
        profiles = accumulate h (x: x.profiles or [ ]);
        # How this machine is booted. `uefi` by default, because a machine
        # that boots itself is the only one that can take a boot back by
        # itself (D5); `direct` is the deliberate other answer for a guest
        # whose hypervisor loads the kernel.
        boot = settle h "boot" (x: x.boot or null) "uefi";
        rollout = {
          max_unavailable =
            settle h "rollout.max_unavailable" (x: (x.rollout or { }).max_unavailable or null) 1;
          # The conservative end of the three: a reboot nobody approved is the
          # failure this whole tool exists to prevent.
          reboot = settle h "rollout.reboot" (x: (x.rollout or { }).reboot or null) "approve";
          canary = settle h "rollout.canary" (x: (x.rollout or { }).canary or null) null;
        };
        checks = {
          required = accumulate h (x: (x.checks or { }).required or [ ]);
          functional = accumulate h (x: (x.checks or { }).functional or [ ]);
        };
        # The binary caches this host may FETCH from, in the order nix tries
        # them. Accumulated rather than settled, for the same reason
        # `profiles` is: a list of substituters is an order, and a group that
        # adds a regional mirror is adding one rather than replacing what the
        # fleet already had.
        #
        # Empty is the default and is a host that is only ever pushed to —
        # the whole closure comes over ssh and nothing a third party put in a
        # cache can surprise it. What makes a cache safe once it is named is
        # `meisterstack.managed.trustedPublicKeys`: a substituted path is
        # held to `require-sigs = true` exactly like a pushed one, so the
        # fleet's own signing key is what makes its own cache usable.
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
          # What the machine calls itself. The node ID is what a plan refers
          # to; the two are allowed to differ, and `MEISTER_NODE_ID` carries
          # the id (see `contextEnv`).
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
          # The operator's own files, relative to the inventory. Almost every
          # real box needs one — a driver, a firmware, a kernel option, its
          # own hardware-configuration.nix — and none of that is something
          # this stack should be trying to describe.
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
          # The raft group this host is a member of, if any: the group whose
          # kind says its members form a quorum. A host in two of them would
          # be a member of two rafts, which is why it is refused below.
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
      # Kanidm is reached under a NAME: its origin is an https url, its
      # certificate has to match it, and its `domain` is an `iname` that
      # refuses anything starting with a digit — so an address is not one
      # (D-P6: a fleet without a domain built an image that came up dead on
      # its first boot and said so nowhere earlier).
      addonsFqdn =
        if addonsHost == null then null
        else if domain != null then "${addonsHost.name}.${domain}"
        else null;

      # --- everything that is wrong with this inventory, each with a sentence
      #
      # `seq schema` first, and that is not decoration: a schema 1 file has
      # `[[node]]` and no `[[host]]`, so without it the first complaint would
      # be "no [[host]]; there is nothing to deploy" — true, and the wrong
      # sentence entirely for somebody holding the pre-v1 plan (measured).
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
            # The sentence for `bios` is its own, because it is the answer
            # somebody will try and the reason it is refused is not obvious
            # from a list of two words.
            ++ (lib.optional (h.boot == "bios")
              ("${where}: host ${h.id} asks for boot = \"bios\". This flake installs uefi or "
                + "direct, and it deploys to a machine that already has grub — that value is "
                + "\"grub\". A grub host has no boot "
                + "fallback either way, because `bootctl set-oneshot` is what a boot fallback is made "
                + "of and grub has no equivalent."))
            ++ (lib.optional (h.boot != "bios" && !(builtins.elem h.boot knownBootModes))
              ("${where}: host ${h.id} has boot = ${builtins.toJSON h.boot}; a host of this "
                + "fleet boots " + lib.concatStringsSep " or " knownBootModes))
            # --- lane 5C ---
            # A grub host is one this flake DEPLOYS TO and never installs:
            # `meister-install` writes systemd-boot (uefi) or no loader at
            # all (direct), and installing a loader whose rollback this tool
            # cannot arrange would be a guarantee it cannot keep. `grub` is
            # for a machine that is already bootable — a guest from
            # packages.managed-disk-image, or a box somebody installed by
            # hand — and such a machine has no install table.
            #
            # Here and not in `assertions` below, because this is a fact
            # about the inventory and needs no host to be evaluated: the
            # sentence has to reach somebody running `validate`, not
            # somebody building a system.
            ++ (lib.optional (h.boot == "grub" && h.install != null)
              ("${where}: host ${h.id} has boot = \"grub\" AND an install table. This flake "
                + "installs uefi (systemd-boot) or direct (no loader at all); a grub host "
                + "brings its own loader, which is why it has no boot fallback. Drop the "
                + "install table, or set boot = \"uefi\" and give the layout an ESP."))
            # --- end lane 5C ---
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
            # An agent has to know which cluster it reports to.
            # `controller_group` is the answer; a raft group it is itself a
            # member of is the one-box case.
            #
            # Unless there is no cluster to report to at all: a fleet without
            # a single cluster role is one or more SINGLE NODES
            # (nix/single-node.nix), and their agents run standalone by
            # design. The rule keeps catching the forgotten controller_group
            # in a fleet that has a cluster, which is the mistake it exists
            # for.
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
        # A raft group tolerates a loss only at an odd size; an even one costs
        # a box and buys nothing.
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

      # Forced by every consumer below, so a broken inventory fails at
      # EVALUATION — `nix flake check`, `nix build .#…` and `meister-deploy
      # resolve` alike — rather than producing a system nobody can use.
      hosts = if errors == [ ] then hosts' else throw (builtins.head errors);

      # --- the derivations, which live here and nowhere else ---------------
      # A session address carries its scheme. The tier that dials builds a
      # tonic endpoint out of the string (shared/proto/src/lib.rs
      # `session_endpoint`), and tonic refuses a url without one at connect
      # time ("invalid URL, scheme is missing" -- measured in
      # nix/tests/keys.nix, in a loop every 30 s, with a cluster that never
      # reached its cloud). The lab's hand-written context has always said
      # `https://`; this derivation has to say it too, and it is `https`
      # because the session ports speak mTLS and nothing else.
      sessionUrl = c: port: "https://${c.address}:${toString port}";

      controllerAddrsOf = h:
        let gid = if h.controllerGroup != null then h.controllerGroup else h.raftGroup; in
        if gid == null then [ ]
        else map (c: sessionUrl c ports.clusterSession) (clusterHostsOf gid);

      cloudAddrsOf = _: map (c: sessionUrl c ports.cloudSession) cloudHosts;

      # `id=ip,…` for a member of a raft group of more than one, and nothing
      # at all for a group of one: an empty peer set IS the loopback single
      # member nix/etcd.nix bakes, which is what a one-box lab has always run.
      etcdPeersOf = h:
        let m = if h.raftGroup == null then [ ] else membersOf h.raftGroup; in
        if lib.length m < 2 then null
        else lib.concatStringsSep "," (map (p: "${p.id}=${p.address}") m);

      # One port per host AND ROLE: a box with two roles has two listeners
      # (9100 cloud, 9101 cluster, 9102 agent).
      scrapeTargets = lib.concatMap
        (h: lib.concatMap
          (r: lib.optional (r != "addons") "${h.address}:${toString ports.metrics.${r}}")
          h.roles)
        (lib.attrValues hosts);

      contextEnv = id:
        let h = hosts.${id}; in
        {
          MEISTER_ROLE = lib.concatStringsSep "," h.roles;
          # The node id is the PLAN's identity and not the hostname: a plan
          # refers to `id`, a machine calls itself `name`, and the two are
          # allowed to differ. nix/context.nix falls back to the hostname
          # where nobody said otherwise, which is how a context VM with no
          # plan still has an id.
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
          # Two tiers bootstrapping on one network must not share a token: it
          # is what keeps a cloud member out of a cluster's raft.
          MEISTER_ETCD_TOKEN = "${header.name}-${h.raftGroup}";
        })
        # A fleet with an addons host points every host at it, the addons
        # host included. A fleet without one says nothing, and a fleet that
        # says nothing exports nothing.
        // (lib.optionalAttrs (addonsHost != null) ({
          MEISTER_OTLP_ENDPOINT = "http://${addonsHost.address}:${toString ports.otlp}";
          MEISTER_LOKI_URL =
            "http://${addonsHost.address}:${toString ports.loki}/loki/api/v1/push";
          MEISTER_LOG_FORMAT = "json";
          # The name in the certificate, the origin and every redirect are
          # that same name, so a fleet with no dns has to be told it — and
          # told it everywhere, because the addons host's own origin is the
          # name as well.
          MEISTER_HOSTS = "${addonsHost.address} ${addonsFqdn}";
        } // lib.optionalAttrs (h.has "cloud") {
          # Kanidm publishes one issuer per oauth2 client, and the cloud's
          # client is the cli's.
          MEISTER_OIDC_ISSUER =
            "https://${addonsFqdn}:${toString ports.kanidm}/oauth2/openid/meister-cli";
          # Kanidm writes the NAME OF THE CLIENT into `aud` and has no
          # audience mapper to say anything else with.
          MEISTER_OIDC_AUDIENCE = "meister-cli";
        }));

      # --- the module a host of this fleet is ------------------------------
      #
      # Expressed only through the options a foreign host has too, so that
      # there is one road into these modules and the inventory is a caller of
      # it. What it does NOT set: `stateVersion`, the firewall, resolvconf,
      # the filesystems — those are the operator's own answers, which is what
      # `templates/operator/profiles/base.nix` is for.
      hostModule = id:
        let h = hosts.${id}; in
        { config, lib, ... }: {
          meisterstack.roles = h.roles;
          # Without MEISTER_ROLE: `meisterstack.roles` above derives it
          # (nix/roles.nix), and two owners for one variable is a conflict
          # waiting for the day they disagree.
          meisterstack.context.defaults =
            removeAttrs (contextEnv id) [ "MEISTER_ROLE" ]
            # The OIDC trust anchor is a PATH, and only this module knows
            # where this host keeps its keys.
            // lib.optionalAttrs (addonsHost != null && h.has "cloud") {
              MEISTER_OIDC_CA = "${config.meisterstack.pki.dir}/ca.crt";
            };

          # The addons role is build time (nix/addons.nix says why), so its
          # two deployment values come from the inventory as options rather
          # than as context variables.
          meisterstack.addons.fqdn = lib.mkIf (h.has "addons") addonsFqdn;
          meisterstack.addons.scrapeTargets = lib.mkIf (h.has "addons") scrapeTargets;

          # A host that keeps state on a second block device says so in
          # `persistence`, and one of those labels is the one nix/data.nix
          # mounts.
          meisterstack.data.label = lib.mkIf
            (builtins.any (p: p.device == "label:meister-data") h.persistence)
            "meister-data";

          # --- lane 4B: a card is a fact about a machine ----------------
          #
          # A host whose inventory declares an RDMA nic gets the fabric
          # tools `verify --suite rdma` drives (nix/rdma.nix). Gated on the
          # agent role as well: a controller with a storage card is not a
          # machine this suite measures between, and a closure carries what
          # it is used for.
          meisterstack.agent.rdma.enable =
            h.has "agent"
            && builtins.any (n: n.rdma or false) (h.hardware.nics or [ ]);
          # --- end lane 4B ----------------------------------------------

          # Per-host overrides, in one named place, so that a review can list
          # the hosts that are not like the others by grepping for one word.
          meisterstack.cloud.settings = (h.deviations.settings or { }).cloud or { };
          meisterstack.cluster.settings = (h.deviations.settings or { }).cluster or { };
          meisterstack.agent.settings = (h.deviations.settings or { }).agent or { };

          # The bootloader of a host this tool installs, and it follows from
          # `boot` and from nothing else.
          #
          # `uefi`: systemd-boot, because the boot-mode rollback of
          # `meister-activate` (M2) is `bootctl set-oneshot` and grub has no
          # equivalent (gate M0 (b)).
          #
          # `direct`: no loader at all. The hypervisor holds the kernel, the
          # initrd and the command line, so a loader inside the guest would
          # be a menu nothing ever reads — and `canTouchEfiVariables` would
          # be an install-time failure on a machine that has no efivarfs.
          # What such a host loses is named rather than hidden:
          # `activate --mode boot` refuses there (D5, measured in
          # nix/tests/activate.nix), and the way forward for a new kernel is
          # the provider (`provider-reboot`, M3 integration).
          #
          # mkDefault throughout: a host module may say something else and
          # answer for it — a BIOS box keeps grub that way, and then it has
          # no boot-mode rollback either.
          #
          # --- lane 5C ---
          # `grub`: nothing, and that is the whole value. The loader is
          # already on the machine — a legacy-MBR guest image, or a box
          # somebody installed by hand — and this flake neither writes it
          # nor drives it. `boot.loader.grub.enable` stays at the mkDefault
          # below so that the image module or the host module that OWNS
          # that loader is the one that says so, with a `grub.device` this
          # inventory cannot know.
          # --- end lane 5C ---
          boot.loader.systemd-boot.enable = lib.mkDefault (h.boot == "uefi");
          boot.loader.efi.canTouchEfiVariables = lib.mkDefault (h.boot == "uefi");
          boot.loader.grub.enable = lib.mkDefault false;

          # And the two halves of the install have to agree about the ESP.
          # The layout is the one that knows — it is the file that either
          # makes an EF00 partition or does not — so it says so
          # (`meisterstack.install.hasEsp`, nix/managed.nix) and this is
          # where the two are compared. Only for a host this tool installs: a
          # machine somebody else partitioned has no layout to ask.
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

          # NO `fileSystems`, and that is the change from schema 1: where the
          # disk is partitioned is disko's answer (M3) or the operator's host
          # module, and a `fileSystems."/"` from the inventory would be a
          # second author for it.

          # The network belongs to the host unless the inventory says
          # otherwise. `networks.management.static = true` is that saying:
          # then this address comes from the plan and nothing else may own
          # the interface.
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

      # --- the manifest: the cheap half of `meisterDeployment` -------------
      #
      # This is `meister-deploy`'s `nix-manifest/1` contract
      # (tools/meister-deploy/src/manifest.rs). Every field is required and
      # the empty ones are `null` or `[ ]` rather than absent, so a key
      # nobody filled in is an error here and not a value quietly dropped on
      # the way to a receipt.
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
            # PUBLIC keys, and the list is what decides whether the installer
            # medium has an sshd at all (nix/install.nix). Empty means the
            # console is the only way in, which is the right default for a
            # medium that is carried to a machine by hand.
            authorized_keys = h.install.authorized_keys or [ ];
          };
      };

      # The manifest describes the hosts this flake BUILDS A SYSTEM FOR, and
      # a `context` host is not one of them: it has no closure, no toplevel
      # and no `build` — it is a VM somebody else instantiated, and the push
      # in the lab repository serves it. So
      # it is left out of both halves, of the group memberships and of the
      # services that name it, exactly as `resolve --hosts` narrows a
      # manifest to a sub-fleet. `meister-deploy inventory` still lists it
      # (that verb reads the file, not the evaluation), and
      # `checks.inventory-parity` compares the hosts both halves describe.
      managedIds = lib.attrNames (lib.filterAttrs (_: h: h.deployment == "nixos") hosts);
      isManaged = id: builtins.elem id managedIds;

      manifestGroup = g: {
        kind = g.kind;
        members = lib.filter isManaged (map (h: h.id) (membersOf g.id));
        quorum = if g.kind == "raft" then { size = lib.length (membersOf g.id); } else null;
        profiles = g.profiles or [ ];
        # A group's rollout is the GROUP's words with the fleet's defaults
        # behind them — not a host's effective rollout, which is a per-host
        # answer and lives in `hosts.<id>.rollout`.
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
      # The digest of the FILE this evaluation read. `meister-deploy resolve`
      # compares it with the file `-f` names: a flake that evaluates
      # `other.toml` while the workstation reads `fleet.toml` would otherwise
      # write a manifest whose `source.inventory_path` points at a file nobody
      # evaluated — measured in the lab (L4 finding W3: `keys issue` fell back
      # to that path and created a CA under the wrong `ca_dir`).
      sha256 = builtins.hashFile "sha256" file;
      fleet = { name = header.name; inherit domain schema; };
      inherit operator hosts defaults;
      groups = groupsRaw;
      services = servicesRaw;
      hostIds = lib.attrNames hosts;
      # The hosts this flake builds a system for. A `context` host is a VM
      # somebody else instantiated: it has no nixosConfiguration, and the
      # pre-v1 push serves it until L3.
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
