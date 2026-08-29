#!/usr/bin/env bash
# Health check for the control-plane VMs: reachable, etcd healthy, units known.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${MEISTER_ENV:-$SCRIPT_DIR/env}"
[ -f "$ENV_FILE" ] || { echo "no env file at $ENV_FILE — cp deploy/env.example deploy/env"; exit 1; }
# shellcheck source=/dev/null
. "$ENV_FILE"

if [ "${MEISTER_SSH_STRICT:-yes}" = no ]; then
    SSH_OPTS=(-i "${MEISTER_SSH_KEY/#\~/$HOME}" -p "${MEISTER_SSH_PORT:-22}" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5)
else
    SSH_OPTS=(-i "${MEISTER_SSH_KEY/#\~/$HOME}" -p "${MEISTER_SSH_PORT:-22}" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5)
fi
rc=0

check() {
    local name=$1 ip=$2
    echo "== $name ($ip)"
    if ! ping -c1 -W2 "$ip" >/dev/null 2>&1; then echo "  UNREACHABLE"; rc=1; return; fi
    ssh "${SSH_OPTS[@]}" "$MEISTER_SSH_USER@$ip" '
        echo "  host: $(hostname)  role: $(cat /run/meister-role 2>/dev/null || echo "<none>")"
        etcdctl endpoint health 2>&1 | sed "s/^/  etcd: /"
        etcdctl put meister-check ok >/dev/null && etcdctl get meister-check --print-value-only | sed "s/^/  etcd rw: /"
        for u in meister-cloud-controller meister-cluster-controller; do
            printf "  %s: %s\n" "$u" "$(systemctl is-active $u 2>/dev/null)"
        done
        df -h /var/lib/etcd | tail -1 | awk "{print \"  etcd disk: \" \$1 \" \" \$5 \" used\"}"
    ' || { echo "  SSH FAILED"; rc=1; }
}

# An agent VM has no etcd and no controllers — what matters is the agent
# unit, its session, nested virt, and that its VMs are actually processes.
check_agent() {
    local ip=$1
    echo "== agent ($ip)"
    if ! ping -c1 -W2 "$ip" >/dev/null 2>&1; then echo "  UNREACHABLE"; rc=1; return; fi
    ssh "${SSH_OPTS[@]}" "$MEISTER_SSH_USER@$ip" '
        echo "  host: $(hostname)  role: $(cat /run/meister-role 2>/dev/null || echo "<none>")"
        printf "  meister-agent: %s\n" "$(systemctl is-active meister-agent 2>/dev/null)"
        if journalctl -u meister-agent --since "-2 min" --no-pager 2>/dev/null | grep -q "controller session failed"; then
            echo "  session: FAILING (see journalctl -u meister-agent)"
        else
            echo "  session: ok"
        fi
        [ -e /dev/kvm ] && echo "  /dev/kvm: present" || echo "  /dev/kvm: MISSING"
        echo "  vm processes: $(ps -C cloud-hypervisor --no-headers 2>/dev/null | wc -l)"
        free -m | awk "/^Mem:/ {print \"  ram: \" \$3 \"/\" \$2 \" MiB used\"}"
    ' || { echo "  SSH FAILED"; rc=1; }
}

# Lists, like push.sh reads them: both tiers have been HA since M4.6, and a
# check that looks at one replica of three reports a fleet it has not seen.
# The singular names are what env files written before that still say, and
# they keep working -- reading them unguarded under `set -u` is what made this
# script die on line one of its actual work.
CLOUD_IPS="${MEISTER_CLOUD_IPS:-${MEISTER_CLOUD_IP:-}}"
CLUSTER_IPS="${MEISTER_CLUSTER_IPS:-${MEISTER_CLUSTER_IP:-}}"

for ip in $CLOUD_IPS;   do check cloud   "$ip"; done
for ip in $CLUSTER_IPS; do check cluster "$ip"; done
for ip in ${MEISTER_AGENT_IPS:-}; do check_agent "$ip"; done

# Say what was reached. A check that silently looked at two of twelve hosts
# reads exactly like one that looked at all of them.
n=0
for ip in $CLOUD_IPS $CLUSTER_IPS ${MEISTER_AGENT_IPS:-}; do n=$((n + 1)); done
echo "==> checked $n host(s)"
exit $rc
