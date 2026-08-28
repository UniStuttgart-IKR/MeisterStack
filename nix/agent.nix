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

  # The role's config template. The reference for what every key means is
  # config/examples/agent.toml; what is here is only "which value, and why not
  # the example's".
  #
  # The rule this list follows, so that it does not drift into a second
  # unreviewed copy of the binary's defaults: bake a key only if the BINARY
  # requires it, or if this image must deviate — and say why in the second
  # case. Everything the binary defaults is left to the binary, which is the
  # same philosophy controllers.nix states outright ("empty settings = the
  # binaries' built-in defaults").
  defaults = {
    # The one exception, kept on purpose. It equals the binary's own default
    # (default_stop_grace_secs in components/agent/src/config.rs) and so
    # carries no information — but one-context PREPENDS the per-VM keys
    # (node_id, controller_addr) in front of this template, and the rule that
    # makes prepending safe is that the template starts with top-level keys
    # rather than with a [table] header. Leaving one here keeps that property
    # true by construction, and one-context.nix names this key as the reason.
    stop_grace_secs = 30;

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
      db_path = "/var/lib/meisterstack/agent.redb";
      run_dir = "/run/meisterstack/agent";
      image_dir = "/opt/meisterstack/images";
      volume_dir = "/var/lib/meisterstack/volumes";
      cgroup_root = "/sys/fs/cgroup/meisterstack";
    };

    # Required (HypervisorConfig is an enum with no default), and both values
    # deviate from nothing — /opt/meisterstack/bin is where push.sh puts the
    # patched build, and 5000 ms is what the example shows.
    hypervisor.cloud-hypervisor = {
      binary = "/opt/meisterstack/bin/cloud-hypervisor";
      timeout_ms = 5000;
    };

    network = {
      # Required.
      default_bridge = "meister_br0";
      # Optional, and set here where the example leaves it commented out: the
      # agent writes this address onto default_bridge whenever a VM lands on
      # it, which is what gives these nested lab guests a gateway. On a node
      # whose addressing belongs to somebody else, drop this key.
      bridge_addr = "10.42.0.1/24";
    };

    # Empty on purpose rather than absent: these are GPU-less lab nodes, and
    # an empty table says "no device backends configured" out loud in the
    # rendered file instead of leaving a reader to wonder. Optional either
    # way — the agent registers no device driver without a section.
    device = { };
  };
in
{
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
    # BGP/EVPN, nftables for the tap guards. In the image = a stable path
    # (/run/current-system/sw/bin) for the config files, and push.sh has
    # nothing extra to ship.
    environment.systemPackages = with pkgs; [ lvm2 virtiofsd frr nftables ];

    environment.etc."meisterstack/agent.toml".source =
      toml.generate "agent.toml"
        (lib.recursiveUpdate defaults config.meisterstack.agent.settings);

    systemd.tmpfiles.rules = [
      "d /opt/meisterstack/images 0755 root root -"
      "d /var/lib/meisterstack 0755 root root -"
    ];

    systemd.services.meister-agent = {
      description = "MeisterStack agent";
      after = [ "one-context.service" "network-online.target" ];
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
      # Everything except nftables fails later and less clearly than at
      # start-up: at the first VM that needed the backend in question.
      #
      # NOT here, and deliberately: nvidia-smi. The nvrm driver calls it
      # best-effort to warn about persistence mode, and these lab nodes are
      # GPU-less by design; a node with a card gets the NVIDIA packages from
      # its own configuration, not from this role.
      path = with pkgs; [ nftables frr lvm2 virtiofsd qemu-utils util-linux nfs-utils curl ];
      unitConfig = {
        # both must have been pushed before the agent can do anything
        ConditionPathExists = [
          "/opt/meisterstack/bin/meister-agent"
          "/opt/meisterstack/bin/cloud-hypervisor"
        ];
      };
      serviceConfig = {
        ExecStart = "/opt/meisterstack/bin/meister-agent --config /run/meisterstack/agent.toml";
        Restart = "always";
        RestartSec = 2;
        Environment = "RUST_LOG=info";
      };
    };
  };
}
