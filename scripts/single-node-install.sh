#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR
#
# single-node-install.sh — the agent and the CLI on one machine that is not
# NixOS, and nothing above them (docs/DEPLOYMENT.md §20).
#
# What it puts where, and why there:
#
#   /opt/meisterstack/bin/           meister, meister-agent, cloud-hypervisor:
#                                    copied, not linked, so that the directory
#                                    they came from (a `nix build` result) can
#                                    go away
#   /usr/local/bin/meister           a link into the above, for PATH
#   /etc/meisterstack/agent.toml     the node's config; it names no controller,
#                                    which is what makes the agent run
#                                    standalone
#   /etc/meisterstack/cli.toml       the CLI's config: one profile `local`, the
#                                    agent's socket, no credential
#   /var/lib/meisterstack/images     where a spec's `base_image` is looked for
#   /var/lib/meisterstack/volumes    the guests' disks and the agent's records
#   /etc/systemd/system/meister-agent.service
#   the group `meister`              who may use the socket besides root;
#                                    --operator puts a user in it
#
# The binaries come from `nix build .#meisterstack-static` (musl, nothing
# from the nix store inside) and `nix build .#cloud-hypervisor-meister-static`,
# made on any machine that has nix, and are handed over as one directory
# (--bin-dir). A cloud-hypervisor the machine already has is taken with
# --hypervisor instead.
#
# It refuses to overwrite a config or a unit that is there (--force says
# otherwise), checks the config it wrote with `meister-agent --check-config`
# before it enables anything, and prints every step. --dry-run prints them
# only. --root DIR writes everything below DIR — the paths inside the
# configs too, like a chroot — and touches no service and no group: that is
# what the test of this script does.
set -euo pipefail

usage() {
  cat <<'USAGE'
usage: single-node-install.sh --bin-dir DIR [options]

  --bin-dir DIR        where meister, meister-agent (and cloud-hypervisor) are
  --hypervisor PATH    a cloud-hypervisor already on this machine, instead of
                       the one in --bin-dir
  --node-id NAME       what the node calls itself (default: this hostname)
  --operator USER      a user who may drive the agent; repeatable
  --bridge NAME        the guests' bridge (default: meister_br0)
  --bridge-addr CIDR   this host's address on that bridge (default: 10.42.0.1/24)
  --no-start           write everything, enable and start nothing
  --force              overwrite configs and the unit that are already there
  --dry-run            say what would be done and do nothing
  --root DIR           put everything below DIR and skip systemd and groups
  -h, --help           this
USAGE
}

die() { echo "single-node-install: $*" >&2; exit 1; }
say() { echo "==> $*"; }

bin_dir=""
hypervisor=""
node_id="$(hostname)"
operators=()
bridge="meister_br0"
bridge_addr="10.42.0.1/24"
start=yes
force=no
dry_run=no
root=""

while [ $# -gt 0 ]; do
  case "$1" in
    --bin-dir) bin_dir="${2:?--bin-dir needs a directory}"; shift 2 ;;
    --hypervisor) hypervisor="${2:?--hypervisor needs a path}"; shift 2 ;;
    --node-id) node_id="${2:?--node-id needs a name}"; shift 2 ;;
    --operator) operators+=("${2:?--operator needs a user}"); shift 2 ;;
    --bridge) bridge="${2:?--bridge needs a name}"; shift 2 ;;
    --bridge-addr) bridge_addr="${2:?--bridge-addr needs an address}"; shift 2 ;;
    --no-start) start=no; shift ;;
    --force) force=yes; shift ;;
    --dry-run) dry_run=yes; shift ;;
    --root) root="${2:?--root needs a directory}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
done

[ -n "$bin_dir" ] || { usage >&2; die "--bin-dir is required"; }
[ -d "$bin_dir" ] || die "$bin_dir is not a directory"
[ -x "$bin_dir/meister" ] || die "$bin_dir has no executable 'meister' (nix build .#meisterstack-static)"
[ -x "$bin_dir/meister-agent" ] || die "$bin_dir has no executable 'meister-agent' (nix build .#meisterstack-static)"
if [ -z "$hypervisor" ]; then
  [ -x "$bin_dir/cloud-hypervisor" ] \
    || die "$bin_dir has no executable 'cloud-hypervisor'; put the result of \`nix build .#cloud-hypervisor-meister-static\` beside the others, or name one with --hypervisor"
fi
if [ -z "$root" ] && [ "$dry_run" = no ] && [ "$(id -u)" != 0 ]; then
  die "this writes to /opt, /etc and /var/lib; run it as root (or with --dry-run to read what it would do)"
fi

# Every path, once, so that --root prefixes all of them or none.
opt="$root/opt/meisterstack/bin"
link="$root/usr/local/bin/meister"
etc="$root/etc/meisterstack"
lib="$root/var/lib/meisterstack"
run_dir="$root/run/meisterstack/agent"
unit="$root/etc/systemd/system/meister-agent.service"
hv_path="${hypervisor:-$opt/cloud-hypervisor}"

# What the machine has to bring: the agent shells out to these
# (drivers/linux-network, components/agent/src/images.rs).
for tool in ip qemu-img curl; do
  command -v "$tool" >/dev/null 2>&1 || echo "note: '$tool' is not on PATH; the agent needs it (bridges and taps, images)" >&2
done
[ -e /dev/kvm ] || echo "note: /dev/kvm is not there; the agent starts, and no guest will" >&2

run() {
  if [ "$dry_run" = yes ]; then echo "    $*"; else "$@"; fi
}

# A file is written whole or not at all, and never over one that is there
# unless --force says so.
write() {
  local path="$1" mode="$2"
  if [ -e "$path" ] && [ "$force" = no ]; then
    echo "    keeping $path (it is there; --force overwrites it)"
    cat >/dev/null
    return 0
  fi
  if [ "$dry_run" = yes ]; then
    echo "    would write $path (mode $mode):"
    sed 's/^/        /'
    return 0
  fi
  local tmp
  tmp="$(mktemp "$(dirname "$path")/.meister.XXXXXX")"
  cat >"$tmp"
  chmod "$mode" "$tmp"
  mv "$tmp" "$path"
  echo "    wrote $path"
}

say "binaries -> $opt"
run install -d -m 0755 "$opt" "$(dirname "$link")"
for b in meister meister-agent; do
  run install -m 0755 "$bin_dir/$b" "$opt/$b"
done
if [ -z "$hypervisor" ]; then
  run install -m 0755 "$bin_dir/cloud-hypervisor" "$opt/cloud-hypervisor"
fi
run ln -sfn "$opt/meister" "$link"

say "directories"
run install -d -m 0755 "$etc" "$lib/images" "$lib/volumes"

say "the group meister, and who is in it"
if [ -n "$root" ]; then
  echo "    (--root: no group is made; the operators would be: ${operators[*]:-nobody})"
else
  run groupadd -f meister
  for u in "${operators[@]:-}"; do
    [ -n "$u" ] || continue
    id "$u" >/dev/null 2>&1 || die "--operator $u: no such user"
    run usermod -aG meister "$u"
  done
fi

say "configs -> $etc"
write "$etc/agent.toml" 0644 <<CONF
# meister-agent on a single node: written by scripts/single-node-install.sh.
# The reference for every key is config/examples/agent.toml in the
# repository; what is here is the standalone shape and nothing else.
#
# No controller_addr and no controller_addrs: with nothing to report to, the
# agent runs standalone and serves its socket, which is what \`meister agent
# vm …\` drives.
node_id = "$node_id"

[paths]
db_path = "$root/var/lib/meisterstack/volumes/agent.redb"
run_dir = "$root/run/meisterstack/agent"
image_dir = "$root/var/lib/meisterstack/images"
volume_dir = "$root/var/lib/meisterstack/volumes"
cgroup_root = "/sys/fs/cgroup/meisterstack"
# Who may talk to the socket besides root. There is no authenticator on it,
# so the group IS the access rule.
socket_group = "meister"

[hypervisor.cloud-hypervisor]
binary = "$hv_path"
timeout_ms = 5000

[network]
default_bridge = "$bridge"
bridge_addr = "$bridge_addr"

# Devices: a card handed to a guest needs a driver section here —
# [device.nvrm] or [device.crosvm-gpu] with the backend binaries, nothing at
# all for [device.vfio]. config/examples/agent.toml has each of them.
CONF

write "$etc/cli.toml" 0644 <<CONF
# The CLI on a single node: written by scripts/single-node-install.sh.
# The CLI reads this file when the person running it has none of their own
# (~/.config/meisterstack/config.toml, or MEISTER_CONFIG).
default_profile = "local"

[profiles.local]
endpoint = "unix://$root/run/meisterstack/agent/agent.sock"
credential = { type = "none" }
CONF

say "the unit -> $unit"
run install -d -m 0755 "$(dirname "$unit")"
write "$unit" 0644 <<CONF
[Unit]
Description=MeisterStack node agent (single node)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$opt/meister-agent --config $etc/agent.toml
Restart=on-failure
RestartSec=2
# The agent stays root: it programs the bridge and the taps, opens /dev/kvm
# and hands VFIO devices to guests. What it gives away is its socket, to the
# group meister (nix/agent.nix says the same for a fleet host).

[Install]
WantedBy=multi-user.target
CONF

say "checking $etc/agent.toml with the agent itself"
if [ "$dry_run" = yes ]; then
  echo "    $opt/meister-agent --check-config --config $etc/agent.toml"
else
  "$opt/meister-agent" --check-config --config "$etc/agent.toml"
fi

if [ -n "$root" ]; then
  say "--root: systemd is not touched; the unit is at $unit"
elif [ "$start" = yes ]; then
  say "enabling and starting meister-agent"
  run systemctl daemon-reload
  run systemctl enable --now meister-agent.service
  say "done. As an operator (after a new login, for the group): meister agent vm ls"
else
  say "done, nothing started: systemctl daemon-reload && systemctl enable --now meister-agent.service"
fi
