# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# The log collector. Traces leave this VM over OTLP straight from the
# binaries (nix/one-context.nix, MEISTER_OTLP_ENDPOINT) and metrics are
# SCRAPED off the three metrics ports — so what is left for a collector is
# the third signal, and Alloy is here for that one only.
#
# Why a collector at all, when every binary can already log: because the
# interesting lines on these VMs are not ours. etcd losing a leader,
# cloud-hypervisor refusing a disk, nftables, sshd, the kernel remounting
# read-only — every incident this lab has had was diagnosed in the journal
# next to our lines, not in them. `loki.source.journal` takes the WHOLE
# journal, which is the entire reason to run a collector instead of teaching
# three binaries to push.
#
# Explicitly NOT an OTLP hop: the binaries send spans to Tempo themselves.
# Routing them through Alloy would add a process that can be down between a
# trace and its collector, and buy nothing at this size.
#
# Off unless the deployment asks for it. one-context writes
# /run/meisterstack/alloy.alloy only when MEISTER_LOKI_URL is in the context,
# and the unit's ConditionPathExists reads that file: no variable, no config,
# no Alloy. A VM that says nothing runs exactly what it ran yesterday.
{ pkgs, ... }:
{
  services.alloy = {
    enable = true;
    # A single FILE rather than the module's /etc/alloy default, because this
    # config is rendered per VM at boot (host label, role label, the Loki url
    # itself) and /etc on this image is the nix store. The cost is config
    # reload — the module wires reloadTriggers to `environment.etc` entries,
    # and a store path is not what we point at — which is the right trade for
    # a fleet that gets a new config by rebooting into a new context anyway.
    configPath = "/run/meisterstack/alloy.alloy";
    extraFlags = [
      # The ui and the collector's own scrape endpoint on loopback. The
      # module's default binds 0.0.0.0:12345, and this image already has
      # three unauthenticated metrics ports the lab knows about; a fourth
      # that nobody asked for should not be one of them.
      "--server.http.listen-addr=127.0.0.1:12345"
      # No phone-home. This is a lab VM in someone's thesis, not a
      # deployment anybody needs usage statistics about.
      "--disable-reporting"
    ];
  };

  systemd.services.alloy = {
    # The config does not exist until one-context has read the context drive
    # and rendered it. Without this ordering the condition below is evaluated
    # on a file that is about to appear, and Alloy stays skipped until
    # somebody notices.
    after = [ "one-context.service" ];
    wants = [ "one-context.service" ];
    unitConfig.ConditionPathExists = "/run/meisterstack/alloy.alloy";
  };

  # `alloy fmt`/`alloy validate` on the box, for the same reason etcdctl is in
  # base.nix: the file this unit reads is generated, and the first question
  # about a collector that is not shipping is whether its config parses.
  environment.systemPackages = [ pkgs.grafana-alloy ];
}
