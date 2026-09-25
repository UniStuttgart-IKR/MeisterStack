#!/usr/bin/env bash
# Check selected source/documentation assumptions without building or starting services.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

pass=0
fail=0
ok()   { printf '  ok   %s\n' "$1"; pass=$((pass + 1)); }
bad()  { printf '  FAIL %s\n' "$1"; shift; for l in "$@"; do printf '       %s\n' "$l"; done; fail=$((fail + 1)); }

echo
echo "A. smoke.sh greppt auf Felder, die es gibt"

# Compare smoke-test field references with the agent observation structure.
# This does not validate the CLI command paths or the field values.
OBSERVED="components/agent/src/reconcile/observe.rs"
fields="$(sed -n '/^pub struct Observed {/,/^}/p' "$OBSERVED" \
          | sed -n 's/^ *pub \([a-z_][a-z0-9_]*\):.*/\1/p')"
if [ -z "$fields" ]; then
    bad "Observed-Struktur in $OBSERVED gefunden" \
        "sed hat keine Felder geliefert — ist die Struktur umbenannt worden?"
else
    missing=""
    for used in $(grep -o 'observe_has "\$[A-Z]*" [a-z_]*' scripts/smoke.sh | awk '{print $NF}' | sort -u); do
        grep -qx "$used" <<<"$fields" || missing="$missing $used"
    done
    if [ -n "$missing" ]; then
        bad "jedes observe_has-Feld steht in Observed" \
            "nicht in $OBSERVED:$missing" \
            "vorhanden: $(tr '\n' ' ' <<<"$fields")"
    else
        ok "jedes observe_has-Feld steht in Observed"
    fi
fi

echo
echo "B. Die Lizenz-Aussagen in docs/ stimmen mit dem Baum"

# Check the declared license and Rust SPDX headers.
declared="$(sed -n 's/^license = "\(.*\)"$/\1/p' Cargo.toml | head -1)"
if [ "$declared" = "TODO_LICENSE" ] || [ -z "$declared" ]; then
    bad "Cargo.toml nennt eine echte Lizenz" "license = \"${declared:-<fehlt>}\""
else
    ok "Cargo.toml nennt eine echte Lizenz ($declared)"
fi

total_rs="$(find . -name '*.rs' -not -path './target/*' | wc -l)"
with_spdx="$(grep -rl 'SPDX-License-Identifier' --include='*.rs' . | wc -l)"
if [ "$total_rs" -ne "$with_spdx" ]; then
    bad "jede .rs traegt einen SPDX-Header" "$with_spdx von $total_rs"
else
    ok "jede .rs traegt einen SPDX-Header ($with_spdx)"
fi

# Reject selected German present-tense claims about the former license placeholder.
claims=()
while IFS= read -r line; do
    [ -n "$line" ] && claims+=("$line")
done < <(grep -rn 'TODO_LICENSE' docs/ 2>/dev/null | grep -E 'sagt|steht|traegt|trägt|weiterhin')
if [ "${#claims[@]}" -gt 0 ]; then
    bad "kein docs/-Text behauptet TODO_LICENSE als heutigen Zustand" "${claims[@]}"
else
    ok "kein docs/-Text behauptet TODO_LICENSE als heutigen Zustand"
fi

echo
echo "C. config/ ignoriert, wohin die Dev-Configs zeigen"

# CLI profile paths are relative to config/. Ignore generated token and key directories.
for d in data pki; do
    if git check-ignore -q "config/$d/probe"; then
        ok "config/$d/ ist git-ignoriert"
    else
        bad "config/$d/ ist git-ignoriert" \
            "config/.gitignore deckt $d/ nicht ab"
    fi
done

# The agent development database is outside config/, under the root data directory.
db="$(sed -n 's/^db_path = "\(.*\)"$/\1/p' config/agent.dev.toml)"
case "$db" in
    ../*) ok "agent.dev.toml zeigt aus config/ heraus ($db)" ;;
    *)    bad "agent.dev.toml zeigt aus config/ heraus" \
              "db_path = \"$db\" — dann gehoert die Begruendung in" \
              "config/.gitignore nachgezogen" ;;
esac

echo
printf '%d ok, %d fail\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
