#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR
#
# meisterstack-install.sh — MeisterStack on a machine that is not NixOS
# (docs/DEPLOYMENT.md §20). Two shapes, one script:
#
#   single-node   the agent and the CLI on one machine, nothing above them:
#                 a workstation or a lab box that makes guests the way the
#                 fleet does, without a cloud, a cluster or a scheduler
#   cli           the CLI alone, on a machine that talks to a control plane
#                 somewhere else: an operator's laptop, a CI runner, a
#                 jump host
#
# What goes where, and why there:
#
#   /opt/meisterstack/bin/           the binaries, copied and not linked, so
#                                    the directory they came from (a
#                                    `nix build` result) can go away
#   /usr/local/bin/meister           a link into the above, for PATH
#   /etc/meisterstack/cli.toml       the CLI's config for everybody on the
#                                    machine — the CLI takes it when the
#                                    person has none of their own
#   /etc/meisterstack/agent.toml     single-node only: the node's config; it
#                                    names no controller, which is what makes
#                                    the agent run standalone
#   /etc/meisterstack/ca.crt         cli only, with --ca-cert: the control
#                                    plane's CA, so that https:// verifies
#   /var/lib/meisterstack/…          single-node only: images and volumes
#   /etc/systemd/system/meister-agent.service   single-node only
#   the group `meister`              single-node only: who may use the
#                                    socket besides root; --operator puts a
#                                    user in it
#
# What it does NOT write: a credential. A certificate, a key or a token is a
# person's, lives in that person's own config (~/.config/meisterstack/
# config.toml, which wins over the machine's), and is put there by
# `meister login` or by the person — never by a script that runs as root
# for everybody.
#
# The binaries come from `nix build .#meisterstack-static` (musl, nothing
# from the nix store inside) and, for a single node,
# `nix build .#cloud-hypervisor-meister-static`, made on any machine that
# has nix, and are handed over as one directory (--bin-dir).
#
# It refuses to overwrite a config or a unit that is there (--force says
# otherwise), checks the agent config it wrote with `meister-agent
# --check-config` before it enables anything, and prints every step.
# --dry-run prints them only. --root DIR writes everything below DIR — the
# paths inside the configs too, like a chroot — and touches no service and
# no group: that is what `checks.install-script` does with it.
set -euo pipefail

usage() {
  cat <<'USAGE'
usage: meisterstack-install.sh single-node --bin-dir DIR [options]
       meisterstack-install.sh cli         --bin-dir DIR [options]

common
  --bin-dir DIR        where the binaries are (meister; single-node: meister-agent
                       and cloud-hypervisor as well)
  --force              overwrite configs and the unit that are already there
  --dry-run            say what would be done and do nothing
  --root DIR           put everything below DIR and skip systemd and groups
  -h, --help           this

single-node
  --hypervisor PATH    a cloud-hypervisor already on this machine, instead of
                       the one in --bin-dir
  --node-id NAME       what the node calls itself (default: this hostname)
  --operator USER      a user who may drive the agent; repeatable
  --bridge NAME        the guests' bridge (default: meister_br0)
  --bridge-addr CIDR   this host's address on that bridge (default: 10.42.0.1/24)
  --no-start           write everything, enable and start nothing

cli
  --endpoint URL       the control plane: http(s)://host:port. Without it no
                       config is written and the CLI is only put on PATH
  --profile NAME       the profile's name in cli.toml (default: cloud)
  --ca-cert FILE       the CA the endpoint's certificate chains to; copied to
                       /etc/meisterstack/ca.crt and named in the profile
  --oidc ISSUER CLIENT the profile logs in at this identity provider
                       (`meister login --oidc`); without it the profile
                       carries no credential and a person adds their own
USAGE
}

die() { echo "meisterstack-install: $*" >&2; exit 1; }
say() { echo "==> $*"; }

mode="${1:-}"
case "$mode" in
  single-node|cli) shift ;;
  -h|--help|"") usage; [ -n "$mode" ] && exit 0; die "the first argument is the shape: single-node or cli" ;;
  *) usage >&2; die "unknown shape: $mode (single-node or cli)" ;;
esac

bin_dir=""
force=no
dry_run=no
root=""
# single-node
hypervisor=""
node_id="$(hostname 2>/dev/null || echo localhost)"
operators=()
bridge="meister_br0"
bridge_addr="10.42.0.1/24"
start=yes
# cli
endpoint=""
profile="cloud"
ca_cert=""
oidc_issuer=""
oidc_client=""

while [ $# -gt 0 ]; do
  case "$1" in
    --bin-dir) bin_dir="${2:?--bin-dir needs a directory}"; shift 2 ;;
    --force) force=yes; shift ;;
    --dry-run) dry_run=yes; shift ;;
    --root) root="${2:?--root needs a directory}"; shift 2 ;;
    --hypervisor) hypervisor="${2:?--hypervisor needs a path}"; shift 2 ;;
    --node-id) node_id="${2:?--node-id needs a name}"; shift 2 ;;
    --operator) operators+=("${2:?--operator needs a user}"); shift 2 ;;
    --bridge) bridge="${2:?--bridge needs a name}"; shift 2 ;;
    --bridge-addr) bridge_addr="${2:?--bridge-addr needs an address}"; shift 2 ;;
    --no-start) start=no; shift ;;
    --endpoint) endpoint="${2:?--endpoint needs a url}"; shift 2 ;;
    --profile) profile="${2:?--profile needs a name}"; shift 2 ;;
    --ca-cert) ca_cert="${2:?--ca-cert needs a file}"; shift 2 ;;
    --oidc) oidc_issuer="${2:?--oidc needs an issuer}"; oidc_client="${3:?--oidc needs a client id}"; shift 3 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
done

[ -n "$bin_dir" ] || { usage >&2; die "--bin-dir is required"; }
[ -d "$bin_dir" ] || die "$bin_dir is not a directory"
[ -x "$bin_dir/meister" ] || die "$bin_dir has no executable 'meister' (nix build .#meisterstack-static)"
if [ "$mode" = single-node ]; then
  [ -x "$bin_dir/meister-agent" ] || die "$bin_dir has no executable 'meister-agent' (nix build .#meisterstack-static)"
  if [ -z "$hypervisor" ]; then
    [ -x "$bin_dir/cloud-hypervisor" ] \
      || die "$bin_dir has no executable 'cloud-hypervisor'; put the result of \`nix build .#cloud-hypervisor-meister-static\` beside the others, or name one with --hypervisor"
  fi
  [ -z "$endpoint$ca_cert$oidc_issuer" ] || die "--endpoint, --ca-cert and --oidc belong to the cli shape; a single node's CLI talks to its own agent"
else
  [ -z "$hypervisor" ] && [ ${#operators[@]} -eq 0 ] || die "--hypervisor and --operator belong to the single-node shape"
  if [ -n "$ca_cert" ]; then
    [ -f "$ca_cert" ] || die "--ca-cert $ca_cert is not a file"
    [ -n "$endpoint" ] || die "--ca-cert needs --endpoint: a CA is named in a profile, and a profile has an endpoint"
    case "$endpoint" in https://*) ;; *) die "--ca-cert only makes sense for an https:// endpoint, and $endpoint is not one" ;; esac
  fi
  [ -z "$oidc_issuer" ] || [ -n "$endpoint" ] || die "--oidc needs --endpoint"
fi
if [ -z "$root" ] && [ "$dry_run" = no ] && [ "$(id -u)" != 0 ]; then
  die "this writes to /opt, /etc and /var/lib; run it as root (or with --dry-run to read what it would do)"
fi

# Every path, once, so that --root prefixes all of them or none.
opt="$root/opt/meisterstack/bin"
link="$root/usr/local/bin/meister"
etc="$root/etc/meisterstack"
lib="$root/var/lib/meisterstack"
unit="$root/etc/systemd/system/meister-agent.service"
hv_path="${hypervisor:-$opt/cloud-hypervisor}"

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
run install -d -m 0755 "$opt" "$(dirname "$link")" "$etc"
run install -m 0755 "$bin_dir/meister" "$opt/meister"
if [ "$mode" = single-node ]; then
  run install -m 0755 "$bin_dir/meister-agent" "$opt/meister-agent"
  if [ -z "$hypervisor" ]; then
    run install -m 0755 "$bin_dir/cloud-hypervisor" "$opt/cloud-hypervisor"
  fi
fi
run ln -sfn "$opt/meister" "$link"

# --- cli: the profile of a control plane elsewhere --------------------------
if [ "$mode" = cli ]; then
  if [ -z "$endpoint" ]; then
    say "no --endpoint: the CLI is on PATH and no config was written. A profile is one file:"
    echo "    ~/.config/meisterstack/config.toml, or $etc/cli.toml for everybody (config/examples/cli.toml has the shapes)"
    exit 0
  fi
  ca_line=""
  if [ -n "$ca_cert" ]; then
    say "the control plane's CA -> $etc/ca.crt"
    run install -m 0644 "$ca_cert" "$etc/ca.crt"
    ca_line="ca_cert    = \"$etc/ca.crt\""
  fi
  if [ -n "$oidc_issuer" ]; then
    credential="credential = { type = \"oidc\", issuer = \"$oidc_issuer\", client_id = \"$oidc_client\" }"
    how="log in with \`meister login --oidc\`; the session lands in the person's own config directory"
  else
    credential="credential = { type = \"none\" }"
    how="a person adds their credential in ~/.config/meisterstack/config.toml, which wins over this file"
  fi
  say "config -> $etc/cli.toml"
  write "$etc/cli.toml" 0644 <<CONF
# The CLI on this machine: written by scripts/meisterstack-install.sh.
# The CLI reads this file when the person running it has none of their own
# (~/.config/meisterstack/config.toml, or MEISTER_CONFIG); a person's file
# wins, and that is where a credential belongs. config/examples/cli.toml in
# the repository has every shape a profile can take.
default_profile = "$profile"

[profiles.$profile]
endpoint   = "$endpoint"
$ca_line
$credential
CONF
  say "done. \`meister --version\`; then: $how"
  exit 0
fi

# --- single-node: the agent, standalone, and the CLI at its socket ---------
# What the machine has to bring: the agent shells out to these
# (drivers/linux-network, components/agent/src/images.rs).
for tool in ip qemu-img curl; do
  command -v "$tool" >/dev/null 2>&1 || echo "note: '$tool' is not on PATH; the agent needs it (bridges and taps, images)" >&2
done
[ -e /dev/kvm ] || echo "note: /dev/kvm is not there; the agent starts, and no guest will" >&2

say "directories"
run install -d -m 0755 "$lib/images" "$lib/volumes"

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
# meister-agent on a single node: written by scripts/meisterstack-install.sh.
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
# The CLI on a single node: written by scripts/meisterstack-install.sh.
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
