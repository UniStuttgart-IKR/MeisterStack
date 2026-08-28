#!/usr/bin/env bash
# "test-run" — the fast deploy: cargo build (static musl) -> rsync into the
# VMs -> restart. Measured 6-8s end to end against the lab. Binaries live in
# /opt/meisterstack/bin, OUTSIDE /nix/store, so a "deploy" (new image /
# nixos-rebuild switch) never touches them — only a full re-instantiation
# replaces the disk, then run this once more.
#
#   deploy/push.sh all          # agents, then cluster, then cloud
#   deploy/push.sh              # both controller tiers: cluster, then cloud
#   deploy/push.sh cloud        # just one tier
#   MEISTER_ENV=deploy/env.lab deploy/push.sh
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

ONLY="${1:-both}"          # all | both | cloud | cluster | agents
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

echo "==> building ($TARGET)"
# rustls/ring compile C for the musl target (since M4.5) — plain cargo has no
# musl cc on this host, so borrow one from nixpkgs, exactly like the CH musl
# build in get_patched_binaries.sh does.
build() {
    if command -v x86_64-unknown-linux-musl-gcc >/dev/null 2>&1 || ! command -v nix >/dev/null 2>&1; then
        cargo build --release --target "$TARGET" "$@"
    else
        nix shell nixpkgs#pkgsCross.musl64.stdenv.cc -c bash -c \
            "export CC_x86_64_unknown_linux_musl=x86_64-unknown-linux-musl-gcc \
                    AR_x86_64_unknown_linux_musl=x86_64-unknown-linux-musl-ar \
             && cargo build --release --target $TARGET $*"
    fi
}
case "$ONLY" in
    all)     build -p meister-agent -p meister-cluster-controller -p meister-cloud-controller ;;
    both)    build -p meister-cluster-controller -p meister-cloud-controller ;;
    cloud)   build -p meister-cloud-controller ;;
    cluster) build -p meister-cluster-controller ;;
    agents)  build -p meister-agent ;;
    *) echo "usage: push.sh [all|both|cloud|cluster|agents]"; exit 1 ;;
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
