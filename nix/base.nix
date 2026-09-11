# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

# Common base for the control-plane VMs: ssh in, serial console out,
# a writable /opt/meisterstack for push.sh, nothing else. RAM-frugal on
# purpose — the lab hosts are RAM-bound.
{ pkgs, ... }:
{
  networking.useDHCP = false;
  networking.usePredictableInterfaceNames = false; # context addresses eth0
  networking.firewall.enable = false;              # test rig, lab-internal

  # one-context owns this VM's whole network configuration — address, route,
  # hostname AND resolver — because all four come out of the same CONTEXT.
  # resolvconf owns /etc/resolv.conf, and with useDHCP off and no
  # networking.nameservers it writes a file with no nameserver in it at all,
  # AFTER one-context wrote the real one. The result on the fleet was
  # `options edns0` and nothing else: no name resolved anywhere, while
  # ETH0_DNS sat in the context and the server answered on tcp/53.
  #
  # Two owners for one file, and the wrong one won. Found 2026-09-08, by an
  # agent that could not fetch an `image create --from-url` — the road that
  # the missing `curl` had hidden until now.
  networking.resolvconf.enable = false;

  services.openssh = {
    enable = true;
    settings.PermitRootLogin = "prohibit-password";
  };

  # Serial console so `onevm console` works.
  boot.kernelParams = [ "console=ttyS0,115200" "console=tty0" ];

  # push.sh drops the controller binaries and the certificates here; the
  # placeholder dirs exist so the units' ConditionPathExists reads cleanly
  # before the first deploy. Both are OUTSIDE the nix store on purpose — they
  # survive an image swap, and a private key must never travel in a qcow2.
  #
  # pki is 0755 and holds files that are not: ca.crt and the certificates are
  # public by construction, and the secrecy sits on the key files themselves
  # (0600 and owned by the service user, see deploy/push.sh pki).
  systemd.tmpfiles.rules = [
    "d /opt/meisterstack/bin 0755 root root -"
    "d /opt/meisterstack/pki 0755 root root -"
  ];

  # The service account both controllers run as, and the group that reaches
  # the agent's socket. Stage 1 of privilege separation, and only that: no
  # shell, no home, no login — an identity to drop to and a group to put an
  # operator into, nothing else.
  #
  # The AGENT stays root, deliberately: it programs nftables, makes taps and
  # bridges, opens /dev/kvm and hands VFIO devices to guests. What it gives
  # away instead is its socket — `[paths] socket_group = "meister"` in
  # agent.nix — so that `meister agent vm ls` on a node needs a group
  # membership rather than sudo.
  users.groups.meister = { };
  users.users.meister = {
    isSystemUser = true;
    group = "meister";
    description = "MeisterStack control plane";
    shell = "${pkgs.shadow}/bin/nologin";
  };

  environment.systemPackages = with pkgs; [ etcd ]; # etcdctl for checks

  documentation.enable = false;
  nix.enable = false; # image is built, never rebuilt from inside

  system.stateVersion = "25.11";
}
