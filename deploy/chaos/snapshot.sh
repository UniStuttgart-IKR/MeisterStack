#!/usr/bin/env bash
# Step 0 of the chaos brief: freeze the binary the fleet runs today, so the
# way back is a file copy and not a rebuild of a commit nobody wrote down.
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
for ip in $ALL_IPS; do
    echo "== $ip"
    r "$ip" 'cd /opt/meisterstack/bin || exit 1
        for b in meister-cloud-controller meister-cluster-controller meister-agent; do
            [ -f "$b" ] || continue
            cp -a "$b" "$b.pre-chaos"
            echo "  frozen $b $(md5sum <"$b" | cut -c1-12)"
        done' 2>&1 | sed 's/^/  /'
done
