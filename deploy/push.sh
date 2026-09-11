#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR
#
# "test-run" — the fast deploy: cargo build (static musl) -> rsync into the
# VMs -> restart. Measured 6-8s end to end against the lab. Binaries live in
# /opt/meisterstack/bin, OUTSIDE /nix/store, so a "deploy" (new image /
# nixos-rebuild switch) never touches them — only a full re-instantiation
# replaces the disk, then run this once more.
#
#   deploy/push.sh all          # agents, then cluster, then cloud
#   deploy/push.sh              # both controller tiers: cluster, then cloud
#   deploy/push.sh cloud        # just one tier
#   deploy/push.sh pki          # certificates, same road, same order
#   MEISTER_ENV=deploy/env.lab deploy/push.sh
#
# The certificates travel this way for the same reason the binaries do: a
# private key must never sit in a qcow2 — an image gets copied, shared and
# stored in a datastore — so it lives in /opt/meisterstack/pki, outside the
# nix store, and the baked template points at it. Survives an image swap,
# does NOT survive a re-instantiation: then push pki, then push all.
#
# Every tier takes a LIST of addresses. Both tiers have been HA since M4.6, and
# a push that reaches one replica of three leaves the other two on the old
# binary — which is why this prints, at the end, exactly which host got what.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${MEISTER_ENV:-$SCRIPT_DIR/env}"
[ -f "$ENV_FILE" ] || { echo "no env file at $ENV_FILE — cp deploy/env.example deploy/env and fill it in"; exit 1; }
# shellcheck source=/dev/null
. "$ENV_FILE"

# The plural names are the real ones. The singular ones are what env files
# written before the tiers became HA still say, and they keep working.
CLOUD_IPS="${MEISTER_CLOUD_IPS:-${MEISTER_CLOUD_IP:-}}"
CLUSTER_IPS="${MEISTER_CLUSTER_IPS:-${MEISTER_CLUSTER_IP:-}}"
AGENT_IPS="${MEISTER_AGENT_IPS:-}"

# m51-initrd carries the virtio core modules every M5.1 network proof needs.
# It used to be missing from this list, so a freshly re-instantiated agent
# could not run those tests until somebody copied it across by hand.
GUEST_FILES="${MEISTER_GUEST_FILES:-vmlinux.elf tiny-initrd tiny-volume.raw m51-initrd}"

ONLY="${1:-both}"          # all | both | cloud | cluster | agents | pki
TARGET=x86_64-unknown-linux-musl
# MEISTER_SSH_STRICT=no: throwaway VMs (lab re-instantiation) get fresh host
# keys every time — skip pinning entirely instead of failing on the change.
if [ "${MEISTER_SSH_STRICT:-yes}" = no ]; then
    SSH_OPTS=(-i "${MEISTER_SSH_KEY/#\~/$HOME}" -p "${MEISTER_SSH_PORT:-22}" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)
else
    SSH_OPTS=(-i "${MEISTER_SSH_KEY/#\~/$HOME}" -p "${MEISTER_SSH_PORT:-22}" -o StrictHostKeyChecking=accept-new)
fi

PUSHED=()

push() {
    local name=$1 ip=$2 bin="meister-${1}-controller"
    echo "==> $bin -> $ip"
    rsync -e "ssh ${SSH_OPTS[*]}" --progress \
        "$SCRIPT_DIR/../target/$TARGET/release/$bin" \
        "$MEISTER_SSH_USER@$ip:/opt/meisterstack/bin/$bin.new"
    # atomic swap + restart; ConditionPathExists turns true on first deploy
    ssh "${SSH_OPTS[@]}" "$MEISTER_SSH_USER@$ip" \
        "mv /opt/meisterstack/bin/$bin.new /opt/meisterstack/bin/$bin \
         && chmod +x /opt/meisterstack/bin/$bin \
         && systemctl restart $bin.service \
         && systemctl --no-pager --lines=3 status $bin.service | head -5"
    PUSHED+=("$name  $ip")
}

# Agent VMs get the agent binary, the static musl cloud-hypervisor and the
# tiny nested-guest assets. MEISTER_AGENT_IPS is a space-separated list in
# deploy/env; MEISTER_GUEST_ASSETS points at kernel/initrd/volume sources.
push_agent() {
    local ip=$1
    echo "==> agent stack -> $ip"
    rsync -L -e "ssh ${SSH_OPTS[*]}" \
        "$SCRIPT_DIR/../target/$TARGET/release/meister-agent" \
        "$SCRIPT_DIR/../bin/cloud-hypervisor-musl" \
        "$MEISTER_SSH_USER@$ip:/opt/meisterstack/bin/"
    ssh "${SSH_OPTS[@]}" "$MEISTER_SSH_USER@$ip" \
        "cd /opt/meisterstack/bin \
         && mv -f cloud-hypervisor-musl cloud-hypervisor \
         && chmod +x meister-agent cloud-hypervisor"
    if [ -n "${MEISTER_GUEST_ASSETS:-}" ]; then
        # A missing asset is a warning, not the end of the run: not every lab
        # holds every guest image, and dying here would leave the binary
        # already swapped and the service already restarted.
        local have=() miss=() f
        for f in $GUEST_FILES; do
            if [ -e "$MEISTER_GUEST_ASSETS/$f" ]; then
                have+=("$MEISTER_GUEST_ASSETS/$f")
            else
                miss+=("$f")
            fi
        done
        [ ${#miss[@]} -eq 0 ] || echo "    warning: not in $MEISTER_GUEST_ASSETS, skipped: ${miss[*]}"
        [ ${#have[@]} -eq 0 ] || rsync -L -e "ssh ${SSH_OPTS[*]}" \
            "${have[@]}" "$MEISTER_SSH_USER@$ip:/opt/meisterstack/images/"
    fi
    ssh "${SSH_OPTS[@]}" "$MEISTER_SSH_USER@$ip" \
        "systemctl restart meister-agent.service; \
         systemctl --no-pager --lines=2 status meister-agent.service | head -4"
    PUSHED+=("agent   $ip")
}

# --- certificates ----------------------------------------------------------
#
# What a host gets is decided HERE and not in the config template, and that is
# the whole design: a serving certificate and an identity are different files
# on every VM, and one image bakes one template for all of them. So the push
# gives the right file a FIXED name — serving.crt, identity.crt — and the
# template names the fixed one. A certificate that landed on the wrong host
# then fails at the handshake, with a name in the message, rather than at
# rendering time with nothing to look at.
#
#   every cloud replica    ca.crt, serving.crt/.key   (= <hostname>.*)
#                          plus identity.*            (= system-cloud-<name>.*)
#                          plus secrets.key           (= secrets.key)
#   every cluster replica  the same, plus identity.*  (= system-cluster-<name>.*)
#                          plus secrets.key           (= secrets.key)
#   every agent            ca.crt, identity.*         (= system-node-<node_id>.*)
#
# secrets.key is the ONE file that is the same on two tiers and is not a
# certificate: the cloud seals a Secret's values with it and the cluster opens
# them, because the cluster is what hands a node its cloud-init. It goes
# nowhere near an agent — a node is handed the plaintext over its session and
# has no use for the key.
#
# The cloud's identity is the newest of the four and the one that reads oddly:
# the three replicas of a cloud share ONE certificate, where three agents get
# three. That is the point of it — what it authorizes is a replica reading
# from its sibling, and which of the three answered is not a question worth
# authorizing against.
#
# The names on the left of the "=" are what meister-ca writes (tools/meister-ca).
PKI_DIR="${MEISTER_PKI_DIR:-/mnt/vmstore/MeisterStack/labpki}"

remote() { ssh "${SSH_OPTS[@]}" "$MEISTER_SSH_USER@$1" "$2"; }

# The identity a host answers to, asked of the host itself rather than kept in
# a second list that can drift from the context. node_id IS the hostname
# (nix/one-context.nix), and cluster_name is what the context wrote into the
# rendered config at boot.
remote_hostname() { remote "$1" 'cat /proc/sys/kernel/hostname'; }
remote_cluster()  { remote "$1" 'sed -n "s/^cluster_name *= *\"\(.*\)\"/\1/p" /run/meisterstack/cluster.toml'; }
remote_cloud()    { remote "$1" 'sed -n "s/^cloud_name *= *\"\(.*\)\"/\1/p" /run/meisterstack/cloud.toml'; }

# The secrets key, where there is one. OPTIONAL and deliberately so: a fleet
# that has never made a Secret has no key, and demanding one would break every
# `push.sh pki` written before this. A fleet that HAS one gets it on both
# controller tiers or on neither — half of it is a cloud that seals what no
# cluster can open.
secrets_key() {
    [ -f "$PKI_DIR/secrets.key" ] || return 0
    src+=("$PKI_DIR/secrets.key")
    dst+=("secrets.key")
}

push_pki() {
    local role=$1 ip=$2 host cluster cloud stage
    host="$(remote_hostname "$ip" | tr -d '\r\n')"
    [ -n "$host" ] || { echo "$ip: cannot read its hostname"; exit 1; }
    echo "==> pki -> $host ($role, $ip)"

    # source path -> the fixed name it gets on the host
    local -a src=("$PKI_DIR/ca.crt") dst=("ca.crt")
    case "$role" in
        cloud|cluster)
            src+=("$PKI_DIR/$host.crt" "$PKI_DIR/$host.key")
            dst+=("serving.crt" "serving.key") ;;
    esac
    case "$role" in
        cloud)
            # `cloud_name` is rendered from the context like `cluster_name` is
            # one tier down, and a config written before it existed has none:
            # the default is what the binary defaults to, so an old fleet
            # keeps working and gets `system-cloud-cloud.*`.
            cloud="$(remote_cloud "$ip" | tr -d '\r\n')"
            [ -n "$cloud" ] || cloud="cloud"
            src+=("$PKI_DIR/system-cloud-$cloud.crt" "$PKI_DIR/system-cloud-$cloud.key")
            dst+=("identity.crt" "identity.key")
            secrets_key ;;
        cluster)
            cluster="$(remote_cluster "$ip" | tr -d '\r\n')"
            [ -n "$cluster" ] || { echo "    $host: no cluster_name in /run/meisterstack/cluster.toml — has the context run?"; exit 1; }
            src+=("$PKI_DIR/system-cluster-$cluster.crt" "$PKI_DIR/system-cluster-$cluster.key")
            dst+=("identity.crt" "identity.key")
            secrets_key ;;
        agent)
            src+=("$PKI_DIR/system-node-$host.crt" "$PKI_DIR/system-node-$host.key")
            dst+=("identity.crt" "identity.key") ;;
    esac

    # A host with nothing to give it is an ERROR with its name, never a quiet
    # skip: a fleet where one node was silently left without a certificate is
    # a fleet whose cluster will never see that node again, and the push would
    # have looked exactly like a good one.
    local i missing=()
    for i in "${!src[@]}"; do [ -f "${src[$i]}" ] || missing+=("${src[$i]}"); done
    if [ ${#missing[@]} -gt 0 ]; then
        echo "    $host: missing in $PKI_DIR:"
        printf '      %s\n' "${missing[@]}"
        echo "      meister-ca is idempotent — generating the missing identity adds it"
        exit 1
    fi

    # Staged under the fixed names first, so one rsync carries the set and
    # each file lands atomically under the name the template expects.
    #
    # -r because the source is a DIRECTORY: without it rsync prints "skipping
    # directory ." and copies nothing, and the chown below is then the first
    # thing that notices. The other rsync calls in this file name their files
    # one by one and need no such flag.
    stage="$(mktemp -d)"
    for i in "${!src[@]}"; do cp -L "${src[$i]}" "$stage/${dst[$i]}"; done
    rsync -r -e "ssh ${SSH_OPTS[*]}" "$stage/" "$MEISTER_SSH_USER@$ip:/opt/meisterstack/pki/"
    rm -rf "$stage"

    # Owner meister and 0600 on the keys, and that pair is not a matter of
    # taste: pki::pem::check_permissions (shared/pki/src/pem.rs) refuses ANY
    # group or other bit on a private key, so root:meister 0640 would be a
    # hard start-up error rather than a careful compromise. The controllers
    # run as meister and read their key as its owner; the agent runs as root
    # and reads it as root does.
    remote "$ip" '
        set -e
        cd /opt/meisterstack/pki
        chown meister:meister ./*.key
        chmod 0600 ./*.key
        chmod 0644 ./*.crt
        ls -l'
    PUSHED+=("pki $(printf '%-8s' "$role") $ip  $host  ${dst[*]}")
}

# pki builds nothing — it moves files that already exist — and restarts
# nothing either: B3's order is `push.sh pki` and then `push.sh all`, and it
# is the binary push that restarts. A restart from here would hit a fleet
# whose PKI is half distributed, which is the failure the order exists to
# avoid.
if [ "$ONLY" = pki ]; then
    [ -d "$PKI_DIR" ] || { echo "no pki directory at $PKI_DIR — set MEISTER_PKI_DIR"; exit 1; }
    [ -f "$PKI_DIR/ca.crt" ] || { echo "no ca.crt in $PKI_DIR — is this a meister-ca directory?"; exit 1; }
    [ -n "$AGENT_IPS$CLUSTER_IPS$CLOUD_IPS" ] || { echo "no hosts listed in $ENV_FILE"; exit 1; }

    # Same order as the binaries, for a stronger reason: a cluster that asks
    # for client certificates before its agent has one never sees that agent
    # again. agents -> cluster -> cloud.
    for ip in $AGENT_IPS;   do push_pki agent   "$ip"; done
    for ip in $CLUSTER_IPS; do push_pki cluster "$ip"; done
    for ip in $CLOUD_IPS;   do push_pki cloud   "$ip"; done

    echo "==> done — ${#PUSHED[@]} host(s)"
    [ ${#PUSHED[@]} -eq 0 ] || printf '    %s\n' "${PUSHED[@]}"
    echo "    no unit was restarted — deploy/push.sh all does that"
    exit 0
fi

echo "==> building ($TARGET)"
# rustls/ring compile C for the musl target (since M4.5) — plain cargo has no
# musl cc on this host, so borrow one from this flake's own shell.
#
# `.#musl` and not `nix shell nixpkgs#pkgsCross...`: the shell carries the
# three variables `cc` and cargo read (CC_, AR_ and the LINKER, each spelled
# with the target in it), and the linker was the one the old line here did NOT
# set — which is why the lab ended up exporting store paths by hand on
# 2026-09-10. Store paths move on a `nix gc`; the shell does not.
#
# `git+file://` and not the bare path: a bare path copies the whole working
# tree into the store, `target/` and all, and that is gigabytes for a shell
# that needs none of it. The dirty tree is still what is read, so an
# uncommitted flake.nix is the flake.nix this uses.
build() {
    if command -v x86_64-unknown-linux-musl-gcc >/dev/null 2>&1 || ! command -v nix >/dev/null 2>&1; then
        cargo build --release --target "$TARGET" "$@"
    else
        nix develop "git+file://$(cd "$SCRIPT_DIR/.." && pwd)#musl" \
            -c cargo build --release --target "$TARGET" "$@"
    fi
}
case "$ONLY" in
    all)     build -p meister-agent -p meister-cluster-controller -p meister-cloud-controller ;;
    both)    build -p meister-cluster-controller -p meister-cloud-controller ;;
    cloud)   build -p meister-cloud-controller ;;
    cluster) build -p meister-cluster-controller ;;
    agents)  build -p meister-agent ;;
    *) echo "usage: push.sh [all|both|cloud|cluster|agents|pki]"; exit 1 ;;
esac

need() { [ -n "$2" ] || { echo "$1 is empty in $ENV_FILE"; exit 1; }; }

# The order is not cosmetic and not negotiable (M4.6): the new binary goes to
# the BOTTOM tier first, so a controller can never issue a command the tier
# below it does not understand yet. agents -> cluster -> cloud.
case "$ONLY" in
    all|agents)
        need MEISTER_AGENT_IPS "$AGENT_IPS"
        for ip in $AGENT_IPS; do push_agent "$ip"; done ;;
esac
case "$ONLY" in
    all|both|cluster)
        need MEISTER_CLUSTER_IPS "$CLUSTER_IPS"
        for ip in $CLUSTER_IPS; do push cluster "$ip"; done ;;
esac
case "$ONLY" in
    all|both|cloud)
        need MEISTER_CLOUD_IPS "$CLOUD_IPS"
        for ip in $CLOUD_IPS; do push cloud "$ip"; done ;;
esac

# Say what was reached. A push that silently covers 2 of 12 hosts reads
# exactly like one that covered all of them.
echo "==> done — ${#PUSHED[@]} host(s)"
[ ${#PUSHED[@]} -eq 0 ] || printf '    %s\n' "${PUSHED[@]}"
