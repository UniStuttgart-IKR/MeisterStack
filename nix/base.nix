# Common base for the control-plane VMs: ssh in, serial console out,
# a writable /opt/meisterstack/bin for push.sh, nothing else. RAM-frugal on
# purpose — the lab hosts are RAM-bound.
{ pkgs, ... }:
{
  networking.useDHCP = false;
  networking.usePredictableInterfaceNames = false; # context addresses eth0
  networking.firewall.enable = false;              # test rig, lab-internal

  services.openssh = {
    enable = true;
    settings.PermitRootLogin = "prohibit-password";
  };

  # Serial console so `onevm console` works.
  boot.kernelParams = [ "console=ttyS0,115200" "console=tty0" ];

  # push.sh drops the controller binaries here; the placeholder dir exists so
  # the units' ConditionPathExists reads cleanly before the first deploy.
  systemd.tmpfiles.rules = [ "d /opt/meisterstack/bin 0755 root root -" ];

  environment.systemPackages = with pkgs; [ etcd ]; # etcdctl for checks

  documentation.enable = false;
  nix.enable = false; # image is built, never rebuilt from inside

  system.stateVersion = "25.11";
}
