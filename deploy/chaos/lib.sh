#!/usr/bin/env bash
# Shared plumbing for the chaos harness. Sourced by every other script here.
# Nothing in this directory changes product code; it only pokes the lab.
CHAOS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$CHAOS_DIR/../.." && pwd)"
OUT="${CHAOS_OUT:-$CHAOS_DIR/out}"
mkdir -p "$OUT"

. "$REPO/deploy/env"

SSH=(ssh -i "$HOME/.ssh/id_ed25519" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
     -o ConnectTimeout=6 -o BatchMode=yes -o LogLevel=ERROR)

CLOUD_IPS="${MEISTER_CLOUD_IPS}"
CLUSTER_IPS="${MEISTER_CLUSTER_IPS}"
AGENT_IPS="${MEISTER_AGENT_IPS}"
ALL_IPS="$CLOUD_IPS $CLUSTER_IPS $AGENT_IPS"

# cluster-1 replicas vs the single cluster-2 (env keeps them in one list)
CLUSTER1_IPS="10.128.1.104 10.128.1.110 10.128.1.111"
CLUSTER2_IPS="10.128.1.105"

r() { local ip=$1; shift; "${SSH[@]}" "root@$ip" "$@"; }

# fan out one command over a list, prefixing each line with the ip
fan() {
    local list=$1; shift
    local ip
    for ip in $list; do
        r "$ip" "$@" 2>&1 | sed "s/^/$ip  /"
    done
}

ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# one finding = one line in findings.txt
finding() {  # finding <id> <what> <seed> <sentence>
    printf '%s\t%s\t%s\tseed=%s\t%s\n' "$(ts)" "$1" "$2" "$3" "$4" >> "$OUT/findings.txt"
}
