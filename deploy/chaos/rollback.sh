#!/usr/bin/env bash
# The way back. snapshot.sh froze the binary the fleet ran before the chaos
# rollout as <binary>.pre-chaos on every host; this puts it back and restarts.
#
#   deploy/chaos/rollback.sh back     # to the pre-chaos binary
#   deploy/chaos/rollback.sh forward  # to the binary in target/ (= deploy/push.sh all)
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
DIR="${1:-back}"

if [ "$DIR" = forward ]; then
    exec "$REPO/deploy/push.sh" all
fi

n=0
for ip in $ALL_IPS; do
    out=$(r "$ip" 'cd /opt/meisterstack/bin || exit 1
        rc=1
        for b in meister-cloud-controller meister-cluster-controller meister-agent; do
            [ -f "$b.pre-chaos" ] || continue
            # rename, never cp: the file is running, and a cp into it is
            # "Text file busy". push.sh writes .new then renames, for this reason.
            cp -a "$b.pre-chaos" "$b.new" && chmod +x "$b.new" \
                && mv -f "$b.new" "$b" || exit 1
            u=$b; [ "$b" = meister-agent ] && u=meister-agent
            systemctl restart "$u" && echo "restored $b $(md5sum <"$b" | cut -c1-12)" && rc=0
        done
        exit $rc' 2>&1)
    rc=$?
    echo "$ip  $out"
    [ $rc -eq 0 ] && n=$((n+1))
done
echo "==> rolled back on $n host(s)"
[ "$n" -eq 12 ] || { echo "NOT twelve — stop and look"; exit 1; }
