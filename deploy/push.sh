#!/usr/bin/env bash
# "test-run" — the fast deploy: cargo build (static musl) -> rsync into the
# VMs -> restart. Measured 6-8s end to end against the lab. Binaries live in
# /opt/meisterstack/bin, OUTSIDE /nix/store, so a "deploy" (new image /
# nixos-rebuild switch) never touches them — only a full re-instantiation
# replaces the disk, then run this once more.
#
#   deploy/push.sh              # both controllers
#   deploy/push.sh cloud        # just one
#   MEISTER_ENV=deploy/env.lab deploy/push.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${MEISTER_ENV:-$SCRIPT_DIR/env}"
[ -f "$ENV_FILE" ] || { echo "no env file at $ENV_FILE — cp deploy/env.example deploy/env and fill it in"; exit 1; }
# shellcheck source=/dev/null
. "$ENV_FILE"

ONLY="${1:-both}"          # both | cloud | cluster | agents
TARGET=x86_64-unknown-linux-musl
# MEISTER_SSH_STRICT=no: throwaway VMs (lab re-instantiation) get fresh host
# keys every time — skip pinning entirely instead of failing on the change.
if [ "${MEISTER_SSH_STRICT:-yes}" = no ]; then
    SSH_OPTS=(-i "${MEISTER_SSH_KEY/#\~/$HOME}" -p "${MEISTER_SSH_PORT:-22}" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)
else
    SSH_OPTS=(-i "${MEISTER_SSH_KEY/#\~/$HOME}" -p "${MEISTER_SSH_PORT:-22}" -o StrictHostKeyChecking=accept-new)
fi

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
        rsync -L -e "ssh ${SSH_OPTS[*]}" \
            "$MEISTER_GUEST_ASSETS"/vmlinux.elf \
            "$MEISTER_GUEST_ASSETS"/tiny-initrd \
            "$MEISTER_GUEST_ASSETS"/tiny-volume.raw \
            "$MEISTER_SSH_USER@$ip:/opt/meisterstack/images/"
    fi
    ssh "${SSH_OPTS[@]}" "$MEISTER_SSH_USER@$ip" \
        "systemctl restart meister-agent.service; \
         systemctl --no-pager --lines=2 status meister-agent.service | head -4"
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
    both)    build -p meister-cloud-controller -p meister-cluster-controller ;;
    cloud)   build -p meister-cloud-controller ;;
    cluster) build -p meister-cluster-controller ;;
    agents)  build -p meister-agent ;;
    *) echo "usage: push.sh [cloud|cluster|agents]"; exit 1 ;;
esac

if [ "$ONLY" = agents ]; then
    [ -n "${MEISTER_AGENT_IPS:-}" ] || { echo "MEISTER_AGENT_IPS is empty in $ENV_FILE"; exit 1; }
    for ip in $MEISTER_AGENT_IPS; do push_agent "$ip"; done
else
    [ "$ONLY" != cluster ] && push cloud   "$MEISTER_CLOUD_IP"
    [ "$ONLY" != cloud ]   && push cluster "$MEISTER_CLUSTER_IP"
fi
echo "==> done"
