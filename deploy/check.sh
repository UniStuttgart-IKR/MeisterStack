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
        # A session is not "has one ever failed", it is "does one hold NOW" —
        # and the two were the same question here until 2026-09-10, when a
        # rollout reported all five agents FAILING while the cluster listed
        # all five ready. A push restarts the agent, the first dial races the
        # controller that is restarting too, and those failures sit in any
        # window wide enough to be useful.
        #
        # The agent writes three lifecycle lines — `dialling controller`
        # before every attempt, `controller session failed` or `controller
        # session ended` when one is over — and says nothing more while a
        # session holds (components/agent/src/lib.rs, dial_forever). So the
        # LAST of the three is the state, and the count in the window is the
        # context: one failure at boot and a redial loop are the same line
        # and read very differently to a person.
        # No window at all, therefore: the AGE of that last line is the
        # answer. A dial that is going to fail says so within a second or
        # two, so a `dialling` line that has stood for a quarter of a minute
        # is a session that holds — while a redial loop leaves a failure as
        # the last line almost all of the time, and a fresh dial the rest.
        # Any window ("failures in the last two minutes") counts the past;
        # this counts the present.
        sess_line="$(journalctl -u meister-agent -b --no-pager -o short-unix 2>/dev/null \
            | grep -E "dialling controller|controller session failed|controller session ended" \
            | tail -1)"
        sess_at="${sess_line%%.*}"
        sess_age=$(( $(date +%s) - ${sess_at:-0} ))
        case "$sess_line" in
            "") echo "  session: none yet (no dial in this boot)" ;;
            *"dialling controller"*)
                if [ "$sess_age" -ge 15 ]; then
                    echo "  session: ok (haelt seit ${sess_age}s)"
                else
                    echo "  session: dialling (seit ${sess_age}s — noch keine Aussage)"
                fi ;;
            *"controller session failed"*)
                echo "  session: FAILING (letzter Fehlschlag vor ${sess_age}s)" ;;
            *)  echo "  session: FAILING (Sitzung vor ${sess_age}s beendet, keine neue)" ;;
        esac
        [ -e /dev/kvm ] && echo "  /dev/kvm: present" || echo "  /dev/kvm: MISSING"
        echo "  vm processes: $(ps -C cloud-hypervisor --no-headers 2>/dev/null | wc -l)"
        free -m | awk "/^Mem:/ {print \"  ram: \" \$3 \"/\" \$2 \" MiB used\"}"
        # The conditions the agent reports as Node.status.conditions[], read
        # here at their source.
        #
        # Why here and not from the API: this script has no client, no
        # profile and no certificate — it ssh-es into hosts. What it CAN do is
        # ask the same three questions the agent asks about itself, spelled
        # with the same three words, so that a green check.sh and a green
        # `node ls` mean the same thing.
        #
        # This is the position the mini-chaos run cost three hours: agent-1a
        # was `active`, its session was `ok`, this script said green, and
        # every command it was given failed with "Previous I/O error".
        conditions=""
        db="$(grep -oP "db_path\s*=\s*\"\K[^\"]+" /etc/meisterstack/agent.toml 2>/dev/null)"
        state="$(dirname "${db:-/var/lib/meisterstack/agent.redb}")"
        free_kb="$(df -Pk "$state" 2>/dev/null | awk "NR==2 {print \$4}")"
        # 256 MiB: a volume is at least 1 GiB and a snapshot copies one, so
        # this is not "can it work" but "is it already out" — the state that
        # wedged the store.
        [ -n "$free_kb" ] && [ "$free_kb" -lt 262144 ] && conditions="$conditions DiskPressure"
        if journalctl -u meister-agent -b --since "-5 min" --no-pager 2>/dev/null \
             | grep -q "Previous I/O error"; then
            conditions="$conditions StoreUnhealthy"
        fi
        cg="$(grep -oP "cgroup_root\s*=\s*\"\K[^\"]+" /etc/meisterstack/agent.toml 2>/dev/null)"
        cg="${cg:-/sys/fs/cgroup}"
        if [ -d "$cg" ] && [ "$(stat -f -c %T "$cg" 2>/dev/null)" != cgroup2fs ]; then
            conditions="$conditions CgroupUnusable"
        fi
        if [ -n "$conditions" ]; then
            echo "  conditions:$conditions  <- this node is UP AND UNUSABLE"
            exit 3
        fi
        echo "  conditions: none"
    ' || { rc_agent=$?; [ "$rc_agent" = 3 ] || echo "  SSH FAILED"; rc=1; }
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
