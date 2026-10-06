# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Configure the node agent, its runtime helpers, and optional host capabilities.
# Role settings override generated defaults. The service can run as root or with
# explicit capabilities and device access; storage and network backends determine
# which privileges it needs.
{ lib, pkgs, config, ... }:
let
  toml = pkgs.formats.toml { };
  cfg = config.meisterstack;

  physnets = cfg.agent.physnets;
  inputBackend = cfg.agent.inputBackend;

  unprivileged = cfg.agent.unprivileged;
  capabilities = cfg.agent.capabilities;
  # Whether the agent can mount(2): a router's `ip netns` pin and an NFS volume are mounts.
  # systemd takes a capability in any case, as its number, or a whole list inverted with
  # `~`, so only canonical names without CAP_SYS_ADMIN are known not to mount; any other
  # spelling counts as mounting, which costs ProtectHome and never the routers.
  knownNotToMount = capability:
    builtins.match "CAP_[A-Z0-9_]+" capability != null && capability != "CAP_SYS_ADMIN";
  mounts = !unprivileged || !(lib.all knownNotToMount capabilities);
  volumes = cfg.agent.volumes;

  # Keep VM records and disks on the same persistent volume root.
  volumeDir = "/var/lib/meisterstack/volumes";

  # For an unprivileged unit, use its delegated cgroup subtree. The supervisor
  # occupies a child cgroup so VM children can use cgroup-v2 controllers.
  unitCgroup = "/sys/fs/cgroup/system.slice/meister-agent.service";

  # Module defaults cover required paths and NixOS integration. See
  # config/examples/agent.toml for individual settings.
  defaults = {
    # Keep a top-level key before generated TOML tables so prepended context keys
    # remain top-level in context-based rendering.
    stop_grace_secs = 30;

    # Metrics expose no authentication; see meisterstack.metrics.listenAddress.
    metrics_listen = cfg.metrics.listen.agent;

    # Use ordinary PEM files so the shared key loader can enforce private-key modes.
  } // lib.optionalAttrs (!cfg.singleNode.enable) {
    controller_ca = "${cfg.pki.dir}/ca.crt";
    controller_cert = "${cfg.pki.dir}/identity.crt";
    controller_key = "${cfg.pki.dir}/identity.key";
  } // {
    # Standalone nodes have no controller session and therefore need no session
    # credential paths or credential startup conditions.
    paths = {
      # Place the database beside VM disks so losing a separate root filesystem
      # does not leave persistent disks without their ownership records.
      db_path = "${volumeDir}/agent.redb";
      run_dir = "/run/meisterstack/agent";
      # Image assets use the configured persistent path.
      image_dir = cfg.agent.imageDir;
      volume_dir = volumeDir;
      # Privileged agents create a subtree under the cgroup mount; delegated agents
      # use their unit subtree.
      cgroup_root = if unprivileged then unitCgroup else "/sys/fs/cgroup/meisterstack";
      # The meister group grants full access to the local administration socket.
      socket_group = "meister";
    };

    # Select the configured Cloud Hypervisor binary and API timeout.
    hypervisor.cloud-hypervisor = {
      binary = "${cfg.binDir}/cloud-hypervisor";
      timeout_ms = 5000;
      # Reserve a destination listener port range for live migration. The advertised
      # address must be reachable from source nodes; absent migration settings refuse
      # incoming transfers.
      migration_ports = cfg.ports.agent.migration;
    };

    network = {
      # Required default bridge.
      default_bridge = "meister_br0";
      # Sweep orphaned driver-owned overlays once at startup.
      sweep_orphans = true;
    } // lib.optionalAttrs (cfg.agent.bridgeAddress != null) {
      bridge_addr = cfg.agent.bridgeAddress;
    };

    # Register backends only when their host support is enabled. NVMe/TCP settings
    # and kernel modules share one gate so a node does not advertise a fabric
    # backend it cannot initialize.
    volume = lib.optionalAttrs cfg.agent.nvmeTcp.enable {
      nvmeof = { };
      nvmeof-import.state_dir = "${volumeDir}/nvmeof-import";
    };
    # Start with no device backends; inputBackend and explicit settings add them.
    device = { };
  };
in
{
  options.meisterstack.agent.frr.enable = lib.mkOption {
    type = lib.types.bool;
    default = builtins.elem "agent" cfg.unitsFor;
    defaultText = lib.literalExpression ''an agent node runs it'';
    description = ''
      Whether FRR itself runs beside the agent, and not only the package.

      `vtysh` is a CLIENT: it talks to the daemons over their vty sockets in
      /run/frr, so a node that has the binary and no daemon answers every call
      with "failed to connect to any daemons" — which is exactly what
      `[network.bgp]` would have got. The package alone was what this image
      had, and manacor showed the other half of the same gap from the outside:
      no announcement, so the routed /29 had to be reached by a static route
      somebody typed.

      bgpd is the only daemon named. zebra and staticd are started by the
      module whatever is asked for, and they are the two the driver needs
      beside it — zebra holds the routing table vtysh writes into. No `config`
      is given: what this node says to its peers is the AGENT's to render
      (drivers/linux-network/src/frr.rs writes a fragment and `vtysh -f`
      merges it), and a second author of the same configuration is how two
      halves start disagreeing about what is announced.

      On by default on an agent node, and it costs a node with no
      `[network.bgp]` one idle daemon: the appliance image is generic and the
      section arrives at BOOT from the context (MEISTER_BGP_*), so a daemon
      that were conditional on build-time knowledge would be missing on
      exactly the machines that turn out to need it. A managed node whose plan
      names no BGP can turn it off.
    '';
  };

  options.meisterstack.agent.nvmeTcp.enable = lib.mkOption {
    type = lib.types.bool;
    default = builtins.elem "agent" cfg.unitsFor;
    defaultText = lib.literalExpression ''an agent node loads it'';
    description = ''
      Whether `nvme_tcp` is loaded at boot for the NVMe-oF attacher.

      `nvme` reads the topology out of /sys/class/nvme BEFORE it opens
      /dev/nvme-fabrics, and that directory does not exist until nvme_core is
      loaded. On a node with no PCIe nvme disk — every VM in this lab —
      nothing has loaded it, so the very first thing the driver does dies with
      "Failed to scan topology: No such file or directory" and never reaches
      the connect that would have autoloaded the module. Measured on
      agent-2b: the same discover succeeds the moment nvme_tcp is in.

      nvme_tcp and not nvme_fabrics: it depends on the other two and pulls
      them in, and tcp is the transport this fleet's fabric speaks. A host
      with an RDMA card wants nvme_rdma beside it, which is a fact about that
      host's hardware and belongs in that host's own configuration.
    '';
  };

  options.meisterstack.agent.volumes = {
    device = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = "/dev/disk/by-label/meister-volumes";
      example = "/dev/disk/by-id/nvme-SAMSUNG_MZQL2960HCJR_S6PENX0T123456";
      description = ''
        The block this node keeps its guests' disks on, mounted at
        ${volumeDir}. `null` keeps them on the root disk.

        A guest's disks are the one thing on an agent that is BIG and that
        must outlive an image swap — the root disk of these lab VMs is 3.4 GiB
        with a 2.2 GiB image on it, so a single provisioned volume fills it.
        By LABEL rather than by device name in the default, because which slot
        a disk lands in is not a promise anybody made: /dev/vdb quietly became
        sda+vda twice in the lab, and etcd lived on the root disk without
        saying so.
      '';
    };
    required = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Whether the agent may run WITHOUT that block.

        False (the default) mounts it `nofail`: a node whose disk was not
        attached comes up and keeps its volumes on the root disk, which is the
        honest degraded state and not an emergency shell — and what the lab
        has done since the block existed.

        True is the other answer, for a node whose disks are its job: no
        `nofail`, and the agent unit REQUIRES the mount. A node that silently
        provisions onto its root disk fills it and then fails at the worst
        moment, and "the volume block is not here" is a sentence worth
        stopping for.
      '';
    };
  };

  options.meisterstack.agent.bridgeAddress = lib.mkOption {
    type = lib.types.nullOr lib.types.str;
    default = null;
    example = "10.42.0.1/24";
    description = ''
      The address this host holds on the default guest bridge `meister_br0`,
      in CIDR notation; `null` (the default) is none.

      An address there lets the host reach guests on that bridge directly,
      and it is the same on every host, so it is a host-local segment and
      not a network. It is not needed for anything this stack does: there
      is no NAT, DHCP or metadata service behind it. On a host that was not
      built for this stack it can also collide with a network the site
      already uses. `nix/managed.nix` keeps the fleet's historical
      `10.42.0.1/24`. Whatever is set here, `meisterstack.agent.guestGuard`
      keeps guests from opening connections to the host.
    '';
  };

  # Runtime helper options.
  options.meisterstack.agent.imageDir = lib.mkOption {
    type = lib.types.str;
    default = "/opt/meisterstack/images";
    example = "/var/lib/meisterstack/images";
    description = ''
      Where this node keeps the guest images it has been handed.

      The default is the APPLIANCE's answer and is what it has always been:
      on that road images arrive next to the binaries, both pushed into
      /opt/meisterstack by `meister-deploy legacy context-push`, and moving
      them would move a directory the push writes.

      A MANAGED host has no push (nix/managed.nix sets
      `/var/lib/meisterstack/images`): nothing writes into its filesystem by
      hand any more, and the FHS answer for state a service owns is
      /var/lib — which is where `meisterstack.pki.dir` and the volume
      records already live. Named as an option rather than derived from the
      profile so that a node with its images on a separate block can say so
      in one line.
    '';
  };


  options.meisterstack.agent.effective = lib.mkOption {
    type = toml.type;
    internal = true;
    default = { };
    description = ''
      The agent's config file as a VALUE: role defaults, the two
      option-driven sections, `generated`, then `settings`.
      `environment.etc` turns it into TOML and `lib.mkFleet` puts the same
      attrset into `meisterDeployment.hosts.<id>.effective_settings`, so the
      manifest cannot describe a file different from the one the unit reads.
    '';
  };

  options.meisterstack.agent.generated = lib.mkOption {
    type = toml.type;
    default = { };
    internal = true;
    description = ''
      The per-machine keys of the agent config — node_id, the controller
      addresses, the network sections — merged BETWEEN the role defaults and
      the operator's `settings`.

      Empty on an appliance, where the context renderer writes exactly these
      at boot; filled by nix/managed.nix from `meisterstack.context.defaults`
      through nix/lib/render.nix, where there is no renderer to write them.
    '';
  };

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

  options.meisterstack.agent.vmm.package = lib.mkOption {
    type = lib.types.package;
    default = pkgs.cloud-hypervisor-meister or (throw (
      "meisterstack.agent.vmm.package has no default here: this nixpkgs has no "
      + "`cloud-hypervisor-meister` attribute, so the overlay that declares it is not "
      + "in it. Add `nixpkgs.overlays = [ meisterstack.overlays.default ];` "
      + "(lib.mkFleet does that for you), or set the option to your own build."));
    defaultText = lib.literalExpression "pkgs.cloud-hypervisor-meister";
    description = ''
      The hypervisor this node's agent starts guests with: cloud-hypervisor
      with this repository's patch series (nix/packages/cloud-hypervisor.nix
      says why it is not nixpkgs' own).

      Read only where `meisterstack.binDir` is derived from a package — an
      appliance has its hypervisor pushed into /opt/meisterstack/bin — and
      joined with `meisterstack.package` into one directory there, because
      the agent's unit names both programs in `binDir`.
    '';
  };

  options.meisterstack.agent.inputBackend = lib.mkOption {
    type = lib.types.nullOr lib.types.str;
    default = null;
    example = "/opt/meisterstack/bin/vhost-device-input";
    description = ''
      Path to upstream vhost-device-input; null disables the input driver.
      Each device uses profile "evdev" and params.evdev to select a host
      /dev/input/eventN node, which must be listed exactly as named in
      settings.device.input.evdev; an unlisted node is never given to a
      guest. The backend user needs read access to that node.
      Set settings.device.input.socket_timeout_ms to override the 5000 ms
      startup timeout. The package is supplied separately.
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
      and — with the default
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

      node_id and controller_addr are NOT settable here ON AN APPLIANCE —
      there the context renderer writes them into <configDir>/agent.toml at
      boot from the hostname and the context, and a key in both places would
      be a duplicate TOML key and a parse error.

      On a managed host they are not written at boot but BAKED
      (`meisterstack.agent.generated`, from nix/lib/render.nix), and this
      option still wins over them: there is one file, written once, and
      naming a key twice in it is not possible.
    '';
  };

  # Gate role units, managed configuration, and optional hardware independently.
  config = lib.mkMerge [
    (lib.mkIf (builtins.elem "agent" cfg.unitsFor) {
      # Install the helpers used by enabled storage and network backends.
      environment.systemPackages = with pkgs; [ lvm2 virtiofsd frr nftables nvme-cli iputils ];

      # BGP needs running FRR daemons as well as command-line tools.

      environment.etc."meisterstack/agent.toml".source =
        toml.generate "agent.toml" cfg.agent.effective;

      meisterstack.agent.effective =
          (lib.recursiveUpdate
            (lib.recursiveUpdate defaults
              # Emit provider network settings only when physnets are configured.
              (lib.optionalAttrs (physnets != { }) { network.provider = { inherit physnets; }; }))
            # Emit an input backend section only when the backend is configured.
            (lib.recursiveUpdate
              (lib.recursiveUpdate
                (lib.optionalAttrs (inputBackend != null) {
                  device.input.binary = inputBackend;
                })
                # Merge module defaults, generated context settings, then explicit role settings.
                cfg.agent.generated)
              cfg.agent.settings));

      systemd.tmpfiles.rules = [
        "d ${cfg.agent.imageDir} 0755 root root -"
        "d /var/lib/meisterstack 0755 root root -"
      ] ++ lib.optionals unprivileged [
        # Create runtime and persistent directories with the service ownership.
        "d /run/meisterstack/agent 0750 meister meister -"
        "d ${volumeDir} 0750 meister meister -"
        # Enforce credential ownership and permissions without creating placeholder
        # keys. Startup conditions wait for files to be delivered.
        "z ${cfg.pki.dir}/identity.key 0600 meister meister -"
      ];

      # Grant the configured agent access to host virtualization and device nodes.
      services.udev.extraRules = lib.mkIf unprivileged ''
        KERNEL=="kvm", GROUP="kvm", MODE="0660"
      '';

      # Provide an optional VMM account with device groups. Creating the account
      # alone does not select it; the agent configuration controls VMM privilege dropping.
      users.groups.meister-vmm = { };
      users.users.meister-vmm = {
        isSystemUser = true;
        group = "meister-vmm";
        extraGroups = [ "kvm" "video" "render" "input" ];
        description = "MeisterStack VMM (unprivileged, stage 3)";
        shell = "${pkgs.shadow}/bin/nologin";
      };

      # Device groups belong to the agent unit, keeping controller credentials
      # separate from host device access.

      systemd.services.meister-agent = {
        description = "MeisterStack agent";
        wantedBy = lib.mkIf cfg.autostart [ "multi-user.target" ];
        # Order the agent after its volume mount. Require the mount only when
        # volumes.required is set; optional mounts permit root-filesystem fallback.
        after = [
          "meister-context.service"
          "network-online.target"
          "var-lib-meisterstack-volumes.mount"
        ];
        wants = lib.optional cfg.metrics.waitsForNetwork "network-online.target";
        # Populate the service PATH explicitly with networking, storage, image, and
        # process helpers used by drivers. A systemd unit does not inherit an operator
        # shell PATH, and helpers launched by other helpers also need these entries.
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
          # systemd-run launches isolated base-image conversion units.
          systemd
        ];
        unitConfig = {
          # Wait for session credentials when the agent is connected to a controller.
          ConditionPathExists =
            # Check external binaries only when they are supplied outside the runtime package.
            lib.optionals (!cfg.binariesInStore) [
              "${cfg.binDir}/meister-agent"
              "${cfg.binDir}/cloud-hypervisor"
            ]
            ++ lib.optional (!cfg.singleNode.enable) "${cfg.pki.dir}/ca.crt";
        } // lib.optionalAttrs (volumes.device != null && volumes.required) {
          # Required volume mounts must succeed before the agent starts.
          RequiresMountsFor = volumeDir;
        };
        serviceConfig = {
          ExecStart = "${cfg.binDir}/meister-agent --config ${cfg.configDir}/agent.toml";
          Restart = "always";
          RestartSec = 2;
          Environment = "RUST_LOG=info";

          # Allow netlink for link, route, and nftables configuration, and packet sockets
          # for the gratuitous ARP an activated router sends with arping (IKR-B75).
          RestrictAddressFamilies = "AF_INET AF_INET6 AF_UNIX AF_NETLINK AF_PACKET AF_VSOCK";

          # No mount namespace of its own for an agent that mounts (IKR-B69). Every path
          # sandbox (ProtectHome, ProtectSystem, PrivateTmp, ReadOnlyPaths, InaccessiblePaths,
          # ...) gives the unit a private mount namespace that systemd makes a slave of the
          # host's, and MountFlags=shared does not undo that: the `ip netns` pins of the
          # tenant routers and the NFS mounts the agent makes never reach the host, and die
          # with the namespace on every restart or crash, taking the routers with them. For a
          # root agent ProtectHome was no boundary anyway: CAP_SYS_ADMIN enters PID 1's mount
          # namespace.
        } // lib.optionalAttrs (!mounts) {
          # An agent that cannot mount makes no mount the host has to see, and cannot leave
          # its namespace: for it ProtectHome is a boundary and costs nothing.
          ProtectHome = true;
        } // lib.optionalAttrs unprivileged {
          # Optional unprivileged agent: explicit capabilities and device access.
          User = "meister";
          Group = "meister";

          # Grant device groups to this service instance only.
          SupplementaryGroups = [ "kvm" "video" "render" "input" ];

          # Keep ambient and bounding capabilities aligned for child helpers.
          AmbientCapabilities = capabilities;
          CapabilityBoundingSet = capabilities;

          # Delegate only the cgroup controllers used by VM resource management.
          Delegate = "cpu cpuset io memory pids";
          # Move the supervisor into a child cgroup before creating VM children.
          DelegateSubgroup = "supervisor";

          # Use a closed device policy with explicit allowances. PrivateDevices would
          # hide the host device nodes the VMM and backends require.
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
    })

    (lib.mkIf cfg.agent.frr.enable { services.frr.bgpd.enable = true; })

    (lib.mkIf cfg.agent.nvmeTcp.enable { boot.kernelModules = [ "nvme_tcp" ]; })

    # Mount the optional volume filesystem by stable device reference. No formatting
    # is performed; volumes.required controls whether an absent mount blocks startup.
    (lib.mkIf (builtins.elem "agent" cfg.unitsFor && volumes.device != null) {
      fileSystems.${volumeDir} = {
        device = volumes.device;
        fsType = "ext4";
        # Optional mounts may fall back to the root filesystem.
        options = lib.optional (!volumes.required) "nofail"
          ++ [ "x-systemd.device-timeout=5s" ];
      };
    })
  ];
}
