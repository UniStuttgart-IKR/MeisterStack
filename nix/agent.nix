# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# The agent role for lab VMs: GPU-less agent nodes that host tiny nested
# VMs (the ONE hosts must provide nested virt — /dev/kvm inside the VM).
# The image bakes an agent config TEMPLATE without node_id/controller_addr;
# one-context completes it at boot (/run/meisterstack/agent.toml) from the
# hostname and MEISTER_CONTROLLER_ADDR. Binaries and guest assets arrive
# via push.sh into /opt/meisterstack — the unit stays quietly skipped
# until they exist.
{ lib, pkgs, config, ... }:
let
  toml = pkgs.formats.toml { };

  physnets = config.meisterstack.agent.physnets;
  inputBackend = config.meisterstack.agent.inputBackend;

  unprivileged = config.meisterstack.agent.unprivileged;
  capabilities = config.meisterstack.agent.capabilities;

  # The cgroup of THIS unit, which is what `cgroup_root` becomes when the
  # agent is not root: a system unit's cgroup is
  # /sys/fs/cgroup/<slice>/<unit>, and `Delegate=` below is what hands the
  # subtree over. Written out rather than discovered at run time because it
  # goes into a config file the agent reads before it does anything.
  #
  # A SYSTEM unit and not a user unit, and that is measured, not a taste:
  # `system.slice/cgroup.subtree_control` offers `cpuset cpu io memory pids`,
  # `user@1000.service` offers `cpu memory pids`. A user unit can never have
  # `cgroup_cpuset`, so the two-agents-per-NUMA-node recipe would silently
  # stop enforcing.
  unitCgroup = "/sys/fs/cgroup/system.slice/meister-agent.service";

  # The role's config template. The reference for what every key means is
  # config/examples/agent.toml; what is here is only "which value, and why not
  # the example's".
  #
  # The rule this list follows, so that it does not drift into a second
  # unreviewed copy of the binary's defaults: bake a key only if the BINARY
  # requires it, or if this image must deviate — and say why in the second
  # case. Everything the binary defaults is left to the binary, which is the
  # same philosophy controllers.nix follows for the two controller roles.
  defaults = {
    # The one exception, kept on purpose. It equals the binary's own default
    # (default_stop_grace_secs in components/agent/src/config.rs) and so
    # carries no information — but one-context PREPENDS the per-VM keys
    # (node_id, controller_addr) in front of this template, and the rule that
    # makes prepending safe is that the template starts with top-level keys
    # rather than with a [table] header. Leaving one here keeps that property
    # true by construction, and one-context.nix names this key as the reason.
    stop_grace_secs = 30;

    # The binary defaults to "nothing listens", deliberately: the endpoint is
    # unauthenticated, so a node that does not know where it runs must not
    # open it. This image DOES know — a lab-internal agent VM — and there the
    # scrape target is the point. Its own listener and not the agent's http
    # api socket: that one is the node's local admin API, this is a scrape
    # port. 9102, one above the two controller ports (controllers.nix), so
    # that a box carrying two roles never has two listeners on one port.
    metrics_listen = "0.0.0.0:9102";

    # The session credential. Same reasoning as controllers.nix: private keys
    # do not travel in a qcow2, so they live in /opt/meisterstack/pki, which
    # push.sh fills and an image swap does not touch — and under FIXED names,
    # because `identity` here is `CN=system:node:<node_id>` and therefore a
    # different file on every node while the template is one for all of them.
    #
    # All three together, never a subset: a cert without a ca is a start-up
    # error on purpose (config.rs::session_tls — this node would present its
    # key to whoever answered on that address).
    controller_ca = "/opt/meisterstack/pki/ca.crt";
    controller_cert = "/opt/meisterstack/pki/identity.crt";
    controller_key = "/opt/meisterstack/pki/identity.key";

    # All five are REQUIRED by the binary — [paths] has no defaults — so
    # baking them is not duplication. Two of the five deviate from
    # config/examples/agent.toml, both deliberately:
    #
    #   run_dir     the example's /run/meisterstack is where one-context
    #               renders the CONFIG files (agent.toml, etcd.env). The
    #               agent's sockets and per-VM scratch get their own
    #               subdirectory rather than sharing that one.
    #   image_dir   the example's /var/lib/… is the FHS answer for a
    #               hand-installed node; here it is the push.sh target, which
    #               is also the directory tmpfiles creates below.
    paths = {
      # ON the volume block and not beside it, because it is the RECORD of
      # what is on that block. The two were split — bytes on the labelled
      # disk, records on the root disk — and round 4's e2e found what that
      # costs: rollout 59b swapped the image, `/var/lib/meisterstack/volumes`
      # came back with three `nvmeof-import` claim files and 100 GiB of
      # namespaces still spoken for, and `agent.redb` came back empty. Every
      # `volume rm` afterwards took the `no record; answering Gone` branch,
      # so the driver's `deprovision` never ran and the claims stayed on the
      # disk for a volume that no longer existed. Bytes that outlive an image
      # swap need bookkeeping that outlives it too.
      db_path = "/var/lib/meisterstack/volumes/agent.redb";
      run_dir = "/run/meisterstack/agent";
      image_dir = "/opt/meisterstack/images";
      volume_dir = "/var/lib/meisterstack/volumes";
      # Root's agent makes its own directory under the mount root and asks
      # systemd for nothing. An unprivileged one cannot: `/sys/fs/cgroup` is
      # not writable for anybody else, so its root has to BE the subtree
      # systemd delegated to it. See `unitCgroup` and `Delegate=` below.
      cgroup_root = if unprivileged then unitCgroup else "/sys/fs/cgroup/meisterstack";
      # Who may talk to this node's admin socket besides root. The agent
      # itself stays root — it writes nftables rules, makes taps, opens
      # /dev/kvm — but its socket does not have to be root-only for that:
      # 0660 owned by `meister` (base.nix) means `meister agent vm ls` on a
      # node is a group membership instead of sudo. There is no authenticator
      # on this socket, so the group IS the access rule.
      socket_group = "meister";
    };

    # Required (HypervisorConfig is an enum with no default), and both values
    # deviate from nothing — /opt/meisterstack/bin is where push.sh puts the
    # patched build, and 5000 ms is what the example shows.
    hypervisor.cloud-hypervisor = {
      binary = "/opt/meisterstack/bin/cloud-hypervisor";
      timeout_ms = 5000;
      # Absent, this node REFUSES to receive a live migration, and says so
      # (components/agent/src/migration.rs) — which is the right default for
      # a config somebody wrote by hand and the wrong one for an image whose
      # whole fleet is on one lab switch with no firewall (base.nix). A
      # hundred ports, because each incoming stream is its own listener and a
      # node may be receiving more than one guest at a time.
      #
      # A node behind a firewall wants this range opened between the nodes,
      # or a different one named in its own settings — that is what makes it
      # a range in the config rather than "any free port": somebody has to be
      # able to write the rule down.
      migration_ports = "49000-49099";
    };

    network = {
      # Required.
      default_bridge = "meister_br0";
      # Optional, and set here where the example leaves it commented out: the
      # agent writes this address onto default_bridge whenever a VM lands on
      # it, which is what gives these nested lab guests a gateway. On a node
      # whose addressing belongs to somebody else, drop this key.
      bridge_addr = "10.42.0.1/24";
      # The agent's default, written out rather than left implicit: this is a
      # lab whose nodes ARE the ones that grew the two VXLAN corpses of the
      # chaos run, and a reader of the rendered file should see that they get
      # swept at start-up rather than have to know it. Only overlay links no
      # record names, and only ever this driver's own.
      sweep_orphans = true;
    };

    # Which volume backends this node registers. A driver with no section is
    # a driver the agent does not build (components/agent/src/drivers.rs), and
    # what a node does not build it does not claim in its catalogue — so an
    # absent section here is a node the scheduler will never place a volume of
    # that kind on, silently and for ever.
    #
    # Both halves of the fabric, and both with their defaults:
    #
    #   nvmeof         the ATTACHER. `bin_dir` unset = `nvme` off PATH, which
    #                  is what the unit's `path` above provides.
    #   nvmeof-import  the PROVIDER for namespaces somebody else made. One
    #                  claim file per namespace that is spoken for, and
    #                  `state_dir` is the one value worth naming: its default
    #                  is beside the agent's database on the ROOT disk, and
    #                  an assignment that dies with the image is a node that
    #                  hands out a namespace which is already somebody's
    #                  disk. On the volume block it outlives the swap, next
    #                  to the volumes it is an assignment of.
    #
    # Every other backend keeps needing a value nobody can guess for a
    # generic image — lvm-thin a volume group, nfs a share — so they stay
    # absent and a node that has one says so in its own settings.
    volume = {
      nvmeof = { };
      nvmeof-import.state_dir = "/var/lib/meisterstack/volumes/nvmeof-import";
    };

    # Empty on purpose rather than absent: these are GPU-less lab nodes, and
    # an empty table says "no device backends configured" out loud in the
    # rendered file instead of leaving a reader to wonder. Optional either
    # way — the agent registers no device driver without a section.
    #
    # One of them has an option of its own: `inputBackend` renders
    # `[device.input]` when a node has Leandro's vhost-user-input, because a
    # keyboard for a guest is a path somebody pushed and not a GPU somebody
    # owns. Everything else goes through `settings`.
    device = { };
  };
in
{
  options.meisterstack.agent.physnets = lib.mkOption {
    type = lib.types.attrsOf lib.types.str;
    default = { };
    example = { ext = "eth1"; };
    description = ''
      The interfaces this node gives away to provider networks, by the name of
      the network each of them reaches. Empty (the default) is a node that
      gives none away: it still runs VMs and still carries tenant overlays, it
      is simply no candidate for a tenant router.

      A non-empty attrset renders `[network.provider] physnets` into the config
      template, and the agent then makes one bridge per provider network
      (`meister-px-<name>`, so a name has four characters), puts the interface
      in it, and claims `network/gateway:<name>` in its Hello. The tier above
      places routers only where that claim is.

      The interface must carry NO address: an address there is somebody still
      using the interface, and the agent refuses to start rather than put a
      router on a network the host is also on. This is per NODE and not per
      role, which is why it is its own option rather than a line in `settings`
      — a fleet plan says it per machine, and a machine that has no spare NIC
      says nothing.
    '';
  };

  options.meisterstack.agent.inputBackend = lib.mkOption {
    type = lib.types.nullOr lib.types.str;
    default = null;
    example = "/opt/meisterstack/bin/vhost-user-input";
    description = ''
      Where `vhost-user-input` is on this node, or null (the default) for a
      node that does not serve virtio-input.

      cloud-hypervisor has no virtio-input device of its own, so the keyboard
      and the mouse of a guest come from a backend beside the VMM — Leandro's
      `vhost-user-input`, the second one of the display rig. The PACKAGE is
      not in this repo and is not built by this flake: it is a path, pushed to
      the node like the patched cloud-hypervisor beside it, and naming it here
      is what makes the agent register the driver and claim `input/fifo` and
      `input/evdev` in its Hello.

      A path and not a bool, for the reason the hypervisor binary is one: an
      image that carried the backend would make every node claim a device it
      may not have, and a node that has it in another place has to be able to
      say so.

      The two profiles come with the backend and need no configuration: `fifo`
      takes `type code value` lines from a named pipe the driver makes beside
      the socket, which is how a test presses a key with no human; `evdev`
      forwards one host `/dev/input/eventN`, named per device in
      `params.evdev`. A node that wants a longer patience than the driver's
      5000 ms sets `settings.device.input.socket_timeout_ms` beside this.
    '';
  };

  options.meisterstack.agent.unprivileged = lib.mkOption {
    type = lib.types.bool;
    default = false;
    description = ''
      Run the agent as the user `meister` with exactly the capabilities in
      `meisterstack.agent.capabilities`, instead of as root.

      The default is false and stays false: root is what every node in this
      fleet has been, and the agent's behaviour as root does not change.

      What such a node can still do, all of it measured on 2026-09-16: boot
      guests (`/dev/kvm` through the group `kvm`), `filesystem` volumes,
      `input` with the `fifo` profile, and — with the default
      `CAP_NET_ADMIN` — every tap, bridge, VXLAN and nftables tap guard it
      makes today.

      What it cannot do, and says so at start-up, one sentence per driver:
      `lvm-thin` and `vfio` (CAP_SYS_ADMIN *and* CAP_DAC_OVERRIDE), `nfs`
      (CAP_SYS_ADMIN for mount(2)), `nvmeof` (the same, plus a root-owned
      /dev/nvme-fabrics), and a tenant router (CAP_SYS_ADMIN for
      `unshare(CLONE_NEWNET)` — a tap needs CAP_NET_ADMIN, a router does
      not stop at it). A driver whose need is missing is not registered, so
      this node claims none of that in its Hello and the scheduler places
      none of it here.

      This is a PROFILE for a compute-only node, not a hardening pass for
      the fleet: `deploy/README.md`, section "Ohne root", says what falls
      away, and in particular that the group `meister` on the agent socket
      is root-equivalent either way.
    '';
  };

  options.meisterstack.agent.capabilities = lib.mkOption {
    type = lib.types.listOf lib.types.str;
    default = [ "CAP_NET_ADMIN" ];
    example = [ "CAP_NET_ADMIN" "CAP_SETUID" "CAP_SETGID" ];
    description = ''
      The capabilities an unprivileged agent holds — both its ambient set
      (so that `nft`, `ip` and the VMM it spawns inherit them) and its
      bounding set (so that the list is the whole truth and not a floor).

      Only read when `meisterstack.agent.unprivileged` is true.

      The default is the one capability that buys something a node cannot
      work around: `CAP_NET_ADMIN`, which is exactly enough for taps,
      bridges, VXLAN and the tap guard, and exactly not enough for anything
      else (measured). An empty list is a node with no networking at all —
      legal, and then a VM with a NIC cannot run there.

      `CAP_SYS_ADMIN` in this list is not a middle ground: capabilities(7)
      says of it "It can plausibly be called 'the new root'". A node that
      needs LVM, NFS, NVMe-oF or vfio should run the agent as root and say
      so, rather than pretend.

      The list exists because the next lane needs two more: the VMM-as-
      `meister-vmm` step (`design/privilege-separation.md`, stage 3) adds
      `CAP_SETUID CAP_SETGID`, since dropping to another user is itself a
      privilege.
    '';
  };

  options.meisterstack.agent.settings = lib.mkOption {
    type = toml.type;
    default = { };
    description = ''
      Agent config template overrides, merged over the role defaults above.
      Free-form TOML: nothing here validates a key, the agent does that at
      start-up with deny_unknown_fields. config/examples/agent.toml is the
      reference for what may go in it, and config/examples/hardened/agent.toml
      for a node that is not on a lab switch.

      node_id and controller_addr are NOT settable here — one-context writes
      them into /run/meisterstack/agent.toml at boot from the hostname and the
      OpenNebula context, and a key in both places would be a duplicate TOML
      key and a parse error.
    '';
  };

  config = {
    # The storage/network backends the drivers shell out to (M4.6/M5.1):
    # lvm2 for the thin driver, virtiofsd for FsShare volumes, frr for
    # BGP/EVPN, nftables for the tap guards, nvme-cli for the nvmeof
    # attacher. In the image = a stable path (/run/current-system/sw/bin) for
    # the config files, and push.sh has nothing extra to ship.
    environment.systemPackages = with pkgs; [ lvm2 virtiofsd frr nftables nvme-cli iputils ];

    # FRR itself, running, and not only the package.
    #
    # `vtysh` is a CLIENT: it talks to the daemons over their vty sockets in
    # /run/frr, so a node that has the binary and no daemon answers every call
    # with "failed to connect to any daemons" — which is exactly what
    # `[network.bgp]` would have got. The package alone was what this image
    # had, and manacor showed the other half of the same gap from the outside:
    # no announcement, so the routed /29 had to be reached by a static route
    # somebody typed.
    #
    # bgpd is the only daemon named. zebra and staticd are started by the
    # module whatever is asked for, and they are the two the driver needs
    # beside it — zebra holds the routing table vtysh writes into. No `config`
    # is given: what this node says to its peers is the AGENT's to render
    # (drivers/linux-network/src/frr.rs writes a fragment and `vtysh -f`
    # merges it), and a second author of the same configuration is how two
    # halves start disagreeing about what is announced.
    #
    # On unconditionally, on every node of this role, and it costs a node with
    # no `[network.bgp]` one idle daemon: the image is generic and the section
    # arrives at BOOT from the context (MEISTER_BGP_*), so a daemon that were
    # conditional on build-time knowledge would be missing on exactly the
    # machines that turn out to need it.
    services.frr.bgpd.enable = true;

    # And the kernel half of the same backend, at boot rather than on demand.
    #
    # `nvme` reads the topology out of /sys/class/nvme BEFORE it opens
    # /dev/nvme-fabrics, and that directory does not exist until nvme_core is
    # loaded. On a node with no PCIe nvme disk — every VM in this lab —
    # nothing has loaded it, so the very first thing this driver does dies
    # with "Failed to scan topology: No such file or directory" and never
    # reaches the connect that would have autoloaded the module. Measured on
    # agent-2b: the same discover succeeds the moment nvme_tcp is in.
    #
    # nvme_tcp and not nvme_fabrics: it depends on the other two and pulls
    # them in, and tcp is the transport this fleet's fabric speaks. A host
    # with an RDMA card wants nvme_rdma beside it, which is a fact about that
    # host's hardware and belongs in that host's own configuration.
    boot.kernelModules = [ "nvme_tcp" ];

    environment.etc."meisterstack/agent.toml".source =
      toml.generate "agent.toml"
        (lib.recursiveUpdate
          (lib.recursiveUpdate defaults
            # Only when there is one. An empty `[network.provider]` table would
            # be a section without its required `physnets` key, which is a
            # start-up error and not "no gateway slot" — the agent tells the
            # two apart by the SECTION being there.
            (lib.optionalAttrs (physnets != { }) { network.provider = { inherit physnets; }; }))
          # The device half of the same rule: a section that is THERE is what
          # makes the agent build the driver, so the absent option has to
          # render no `[device.input]` at all rather than one with an empty
          # binary — which would be a start-up error on every node in the
          # fleet instead of "this node serves no virtio-input".
          (lib.recursiveUpdate
            (lib.optionalAttrs (inputBackend != null) {
              device.input.binary = inputBackend;
            })
            config.meisterstack.agent.settings));

    systemd.tmpfiles.rules = [
      "d /opt/meisterstack/images 0755 root root -"
      "d /var/lib/meisterstack 0755 root root -"
    ] ++ lib.optionals unprivileged [
      # The three directories [paths] names, given to the user that now has
      # to write them. tmpfiles and not `StateDirectory=`/`RuntimeDirectory=`,
      # because these paths are absolute in a config template one-context
      # renders — systemd's own directory options would put them under
      # /var/lib/<name> and /run/<name> and the agent would be told about a
      # different place than the one that was created.
      #
      # `/run/meisterstack` stays root-owned: one-context renders agent.toml
      # and etcd.env into it, and the agent only reads those.
      "d /run/meisterstack/agent 0750 meister meister -"
      "d /var/lib/meisterstack/volumes 0750 meister meister -"
      # The session credential, which the agent opens at start-up. push.sh
      # leaves the key 0600 root, so without this line an unprivileged agent
      # refuses to start on a line about a file it cannot read. The
      # certificate and the CA are public by construction (nix/base.nix says
      # why); only the key needs the group.
      "z /opt/meisterstack/pki/identity.key 0640 root meister -"
    ];

    # The device half of the same rule. On this fleet's own hosts /dev/kvm is
    # 0666 root:kvm, and then the group buys nothing — but that is a property
    # of one distribution's udev defaults (systemd ships
    # `KERNEL=="kvm", GROUP="kvm", MODE="{{DEV_KVM_MODE}}"`, and the
    # substitution is the packager's). Written down here so that an agent
    # which is not root has a documented way in on any node of this role,
    # rather than depending on which mode the image happened to be built
    # with. 0660 and not 0666 is the tighter of the two, and the group is the
    # access rule.
    services.udev.extraRules = lib.mkIf unprivileged ''
      KERNEL=="kvm", GROUP="kvm", MODE="0660"
    '';

    # The VMM's own user, created and not yet used.
    #
    # Stage 3 of `design/privilege-separation.md`: cloud-hypervisor and the
    # vhost-user backends beside it get their own account, so that a guest
    # breaking out of the VMM lands in a process that owns nothing. That is
    # the other lane's work (`Command::uid/gid` at the spawn, plus the file
    # ownership that has to follow it); the account is here because a user
    # that appears in the same release as the code which drops to it is a
    # rollout with two ways to fail.
    #
    # The groups are the VMM's reason to exist: `kvm` for the vcpu ioctls,
    # `video`/`render` for a GPU node's nodes, `input` for an evdev backend.
    # No shell, no home, no password.
    users.groups.meister-vmm = { };
    users.users.meister-vmm = {
      isSystemUser = true;
      group = "meister-vmm";
      extraGroups = [ "kvm" "video" "render" "input" ];
      description = "MeisterStack VMM (unprivileged, stage 3)";
      shell = "${pkgs.shadow}/bin/nologin";
    };

    # The agent's own device groups are NOT set here. `meister` is
    # nix/base.nix' account and the CONTROLLERS run as it too — a membership
    # in the system database would hand /dev/kvm to two services that have no
    # business with it. It belongs to this unit instead, as
    # `SupplementaryGroups=` below, which systemd documents as extending
    # rather than replacing what the database says.

    # The volume block, by the same rule etcd's follows (nix/etcd.nix): a
    # labelled disk or the root disk, and which one is a sentence somebody
    # wrote down rather than a surprise.
    #
    # A guest's disks are the one thing on an agent that is BIG and that must
    # outlive an image swap — the root disk of these lab VMs is 3.4 GiB with
    # a 2.2 GiB image on it, so a single provisioned volume fills it — and
    # `[paths] volume_dir` above names exactly this directory. Mounting the
    # block AT that path rather than pointing the config at the block is what
    # makes it work from the generic image: the rendered agent.toml is one
    # file for the whole fleet, and a per-VM key inside its [paths] table is
    # not something a context can append (nix/one-context.nix explains the
    # prepend/append rule that forbids it).
    #
    # nofail, like the etcd mount: a node whose block was not attached comes
    # up and keeps its volumes on the root disk, which is the honest degraded
    # state and not an emergency shell.
    fileSystems."/var/lib/meisterstack/volumes" = {
      device = "/dev/disk/by-label/meister-volumes";
      fsType = "ext4";
      options = [ "nofail" "x-systemd.device-timeout=5s" ];
    };

    systemd.services.meister-agent = {
      description = "MeisterStack agent";
      # The mount is ordering and NOT a requirement, which is the whole point
      # of it being `after` rather than `RequiresMountsFor`: the block is
      # `nofail`, a node whose disk was not attached is meant to come up and
      # keep its volumes on the root disk, and a hard requirement here would
      # turn that honest degraded state into a node that never starts. What
      # the ordering buys is the other half — the agent must not open its
      # store under a mount point that is about to be mounted OVER, which
      # would hide both the records and the bytes they describe.
      after = [
        "one-context.service"
        "network-online.target"
        "var-lib-meisterstack-volumes.mount"
      ];
      # Every external binary the drivers resolve over PATH, because a systemd
      # unit's PATH does NOT contain /run/current-system/sw/bin —
      # systemPackages alone serves the ssh shell, not this unit.
      #
      # What each one is for, and when it is missed:
      #   nftables    nft. The only HARD one: mac-pinning is promised for
      #               every VM this stack boots, so an agent that cannot
      #               write rules refuses to start rather than pretend.
      #   lvm2        lvs/lvcreate/lvremove, for [volume.lvm-thin] — unless
      #               that section names a bin_dir, which is the escape for a
      #               host where lvm2 is elsewhere.
      #   qemu-utils  qemu-img, also [volume.lvm-thin]: it writes the base
      #               image onto the fresh LV and reads qcow2 as well as raw.
      #   util-linux  mount, and nfs-utils its mount.nfs helper — needed only
      #               by [volume.nfs] with manage_mount = true, which is the
      #               shape where the driver mounts the share itself.
      #   iproute2    ip, only with [network.provider]: `ip netns` builds a
      #               router's namespace and pins it under /var/run/netns, so
      #               that `ip netns exec meister-rt-<uuid> ip a` shows an
      #               operator what the agent built. Missed only by a node
      #               that was given a router.
      #   procps      sysctl, the same section: ip_forward and the two
      #               arp_ignore values INSIDE the router's namespace, which
      #               is why it is `ip netns exec … sysctl` and not a write to
      #               this process's /proc.
      #   iputils     arping, the same section again: the gratuitous ARP a
      #               router sends the moment it becomes the active one. Best
      #               effort at the point of use — a node without it fails a
      #               failover over by five seconds of somebody else's ARP
      #               cache and nothing worse — which is why it is here and
      #               not a ConditionPathExists.
      #   frr         vtysh, only with [network.bgp].
      #   curl        fetching a base image registered with `image create
      #               --from-url`. Missed only by a node asked to boot such an
      #               image, and then it is a named error at the point of use
      #               ("is curl on the agent's PATH?") rather than a mystery:
      #               the vm goes Failed with that sentence, and the Image
      #               object goes Failed with it too, which is what the whole
      #               fetch-and-report road exists for.
      #   virtiofsd   NOT resolved over PATH by the driver: [volume.nfs]
      #               names a path to it. It is here so that a config may name
      #               the bare word, and in systemPackages above so that
      #               /run/current-system/sw/bin/virtiofsd is a stable path a
      #               config can point at.
      #   nvme-cli    nvme, for [volume.nvmeof] — connect, list-subsys,
      #               id-ns, disconnect. Missed the same way lvm2 would be:
      #               the attacher's own sentence ("Is nvme-cli installed,
      #               and is this process root?") at the first volume that
      #               needed the fabric, and not before. The escape is the
      #               same too, a bin_dir in that section. Its kernel half is
      #               boot.kernelModules below, and that one is not optional.

      # Everything except nftables fails later and less clearly than at
      # start-up: at the first VM that needed the backend in question.
      #
      # NOT here, and deliberately: nvidia-smi. The nvrm driver calls it
      # best-effort to warn about persistence mode, and these lab nodes are
      # GPU-less by design; a node with a card gets the NVIDIA packages from
      # its own configuration, not from this role.
      path = with pkgs; [
        nftables
        iproute2
        procps
        iputils
        frr
        lvm2
        virtiofsd
        qemu-utils
        util-linux
        nfs-utils
        curl
        nvme-cli
      ];
      unitConfig = {
        # All three must have been pushed before the agent can do anything.
        # The CA is on the list for the same reason as at the controllers: the
        # template names controller_ca/cert/key, and a missing one of them is a
        # start-up error, so a node that push.sh has not reached yet waits
        # visibly instead of restarting every two seconds.
        ConditionPathExists = [
          "/opt/meisterstack/bin/meister-agent"
          "/opt/meisterstack/bin/cloud-hypervisor"
          "/opt/meisterstack/pki/ca.crt"
        ];
      };
      serviceConfig = {
        ExecStart = "/opt/meisterstack/bin/meister-agent --config /run/meisterstack/agent.toml";
        Restart = "always";
        RestartSec = 2;
        Environment = "RUST_LOG=info";

        # Two lines of sandbox, and deliberately not the set the controllers
        # get (controllers.nix). This process IS the privileged half: it
        # programs nftables, creates taps and bridges, opens /dev/kvm and
        # hands PCI devices through vfio. PrivateDevices would take /dev/kvm
        # and the vfio nodes away, PrivateTmp would hide the sockets the VMM
        # and virtiofsd share, ProtectKernelTunables would stop it writing
        # the sysctls a bridge needs, and mdev needs sysfs writes besides.
        # These two cost it nothing:
        ProtectHome = true;
        # AF_NETLINK is how routes, links and nftables are programmed;
        # AF_VSOCK is the guest agent channel. Neither is optional here.
        RestrictAddressFamilies = "AF_INET AF_INET6 AF_UNIX AF_NETLINK AF_VSOCK";
        # And the line that pays for the one above. ProtectHome gives the unit
        # a mount namespace of its own, and a router's network namespace is
        # PINNED by a bind mount (`ip netns add` puts it under /run/netns) --
        # so without this the pin lives only inside that private namespace.
        # Three things followed, all seen in the lab on 2026-09-10:
        #
        #   * every router netns died with the agent on a restart, because the
        #     mount namespace that held its only reference went away;
        #   * a zero-byte file stayed behind in the host's /run/netns, so the
        #     next `ip netns add` of the same name would fail with EEXIST;
        #   * `ip netns exec meister-rt-<uid> ...` on the machine answered
        #     "Invalid argument" -- the file is there and is not a mount --
        #     which is exactly the command drivers/linux-network's own module
        #     doc tells an operator to run.
        #
        # `MountFlags = shared` makes the unit's mounts propagate back to the
        # host, which is what a service that creates namespaces for other
        # things to use has to do. It does not widen what the process may
        # touch; it says that what it mounts is not private to it.
        MountFlags = "shared";
      } // lib.optionalAttrs unprivileged {
        # --- the agent as `meister`, with exactly its capabilities ---------
        #
        # Model C of the reference study, and it is only honest for a
        # compute-only node: the moment CAP_SYS_ADMIN is in the list below,
        # this is root with extra steps (capabilities(7): "the new root").
        # The full node keeps running as root, which is the default.
        User = "meister";
        Group = "meister";

        # The device nodes this agent opens, by group rather than by
        # capability — which is how every reference does it (Kata: "crw-rw----
        # root:kvm" plus a supplemental group; QEMU: "configure UNIX groups
        # for access to /dev/kvm, /dev/net/tun"). `kvm` for the guest,
        # `video`/`render` for a GPU node, `input` for an evdev backend.
        SupplementaryGroups = [ "kvm" "video" "render" "input" ];

        # Exactly what the option says, in both sets. Ambient, because the
        # drivers work by execing `nft` and `ip` and those need the
        # capability themselves; bounding, so the list is a ceiling and not
        # just a starting point.
        AmbientCapabilities = capabilities;
        CapabilityBoundingSet = capabilities;

        # Written out, not `Delegate=yes`: the list IS the claim, and
        # docker.service (measured on this machine) writes it out for the
        # same reason. `cpuset` is in it because `cgroup_cpuset` in the agent
        # config is worthless without it — and because a system unit is the
        # only kind of unit that can have it (see `unitCgroup`).
        #
        # Delegation does not enable anything by itself: systemd's own
        # documentation says "you have to do that manually by writing to
        # cgroup.subtree_control", which is what drivers/cgroup does.
        Delegate = "cpu cpuset io memory pids";
        # cgroup v2 forbids processes in an inner node, so the agent cannot
        # sit in the directory it also wants to put VM slices under. systemd
        # 254+ does the move itself with this; the agent does it too, at
        # start-up, and finds nothing left to do. Both, because the two are
        # the same directory and either one alone is a node that limits
        # nothing.
        DelegateSubgroup = "supervisor";

        # `DeviceAllow=` and NOT `PrivateDevices=yes` — the trap the study
        # names, and systemd's own man page says it: "When access to some but
        # not all devices must be possible, the DeviceAllow= setting might be
        # used instead". PrivateDevices would give this unit a /dev with no
        # /dev/kvm in it, which is a node that cannot boot a guest.
        #
        # `closed` leaves the harmless pseudo-devices (null, zero, random,
        # tty) and nothing else. char-drm and char-input are whole device
        # groups because their numbers are the host's to choose; a GPU node
        # with an NVIDIA card needs its own line beside these, which is a
        # fact about that node and belongs in its own configuration.
        DevicePolicy = "closed";
        DeviceAllow = [
          "/dev/kvm rw"
          "/dev/net/tun rw"
          "/dev/vhost-net rw"
          "/dev/vhost-vsock rw"
          "char-drm rw"
          "char-input r"
        ];
      };
    };
  };
}
