#!/usr/bin/env bash
# The matrix of chaos-extrem-brief.md § 4, in the order § 4 asks for: the
# cells the thesis needs first, so a run that is cut short is still a result.
#
#   ./run-matrix.sh            # everything, skipping cells already on disk
#   ./run-matrix.sh --from 4   # start at group 4
#   ./run-matrix.sh --only 1   # just group 1
#
# Resumable on purpose: a cell whose JSON is already in out/ is skipped, so an
# aborted run continues where it stopped instead of re-measuring six hours.
# Every cell lifts its own shaping; this lifts everything again between cells,
# because "the next cell measured the previous cell's qdisc" is the one way to
# get a whole matrix of plausible, wrong numbers.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
OUT=out
FROM=0; ONLY=""
while [ $# -gt 0 ]; do
    case "$1" in
        --from) FROM=$2; shift 2 ;;
        --only) ONLY=$2; FROM=$2; shift 2 ;;
        *) echo "unknown: $1"; exit 2 ;;
    esac
done

cell() {   # cell <group> <link> <cond> <load> <seed> [n]
    local g=$1 link=$2 cond=$3 load=$4 seed=$5 n=${6:-20}
    [ "$g" -lt "$FROM" ] && return 0
    [ -n "$ONLY" ] && [ "$g" != "$ONLY" ] && return 0
    local tag="${link}x${cond}x${load}"
    if [ -f "$OUT/matrix-${tag}-${seed}.json" ]; then
        echo "== skip $tag seed=$seed (already on disk)"
        return 0
    fi
    echo "== $(date +%T) group $g: $tag seed=$seed n=$n"
    timeout 3600 python3 ./matrix.py --link "$link" --cond "$cond" --load "$load" \
        --seed "$seed" --n "$n" 2>&1 | tail -3
    python3 -c "import ops; ops.unshape_all()" >/dev/null 2>&1
}

# the control row: the same load with nothing on the wire, so every cell below
# has something to be compared against
cell 0 A none w1 4713 20
cell 0 A none w3 4732
cell 0 A none w2 4740 10

# 1. A x {L200,P5,D} -- how fast does the cluster notice a node is gone
cell 1 A L200 w1 4714 20
cell 1 A P5   w1 4715 20
cell 1 A D    w1 4716 20
cell 1 A L200 w5 4717
cell 1 A P5   w5 4718
cell 1 A D    w5 4719

# 2. C x {L200,P5,D} -- the same question one level up, plus the voice
cell 2 C L200 w1 4720 20
cell 2 C P5   w1 4721 20
cell 2 C D    w1 4722 20
cell 2 C L200 w5 4723
cell 2 C P5   w5 4724
cell 2 C D    w5 4725

# 3. etcd: a minority under latency, and a majority gone
cell 3 E1 L200 w1 4726 20
cell 3 E1 P5   w1 4727 20
cell 3 E2 D    w1 4728 20

# 4. the router, on whichever node actually holds it (link G)
cell 4 G L200 w3 4729
cell 4 G P5   w3 4730
cell 4 G D    w3 4731

# 5. the tenant overlay
cell 5 V P5   w1 4733 10
cell 5 V L200 w1 4734 10

# 6. the API as a client sees it
cell 6 R L1000 w1 4735 10
cell 6 R P20   w1 4736 10

# 7. volumes under a bad wire
cell 7 A L200 w2 4739 10

# 8. drain
cell 8 A L200 w4 4737
cell 8 A P5   w4 4738

echo "== $(date +%T) matrix done"
python3 -c "import ops; print('final unshape:', len(ops.unshape_all()), 'targets')"
column -t -s$'\t' "$OUT/matrix.txt" 2>/dev/null | tail -40
