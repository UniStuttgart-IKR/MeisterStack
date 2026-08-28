#!/usr/bin/env bash
# MeisterStack — Drift-Wache fuer Doku, Configs und Skripte
#
# Dieses Repo hat ein wiederkehrendes Problem, und es ist nicht der Code: die
# Doku und die Hilfsskripte behaupten Dinge ueber den Code, die einmal
# gestimmt haben. Der R1-Audit hat 20 doc-drift-Befunde gezaehlt, und die
# teuersten davon waren die stillen — ein Smoke-Test, der auf ein
# umbenanntes Feld greppt und als echter FAIL aussieht, oder ein Status-
# dokument, das eine erledigte Aufgabe als offen fuehrt.
#
# Was hier steht, sind genau die Behauptungen, die schon einmal falsch
# waren, jede als eine Zeile, die gegen den Code prueft statt gegen eine
# andere Doku. Kein Ersatz fuer `cargo test` — eine Ergaenzung fuer die
# Aussagen, die ausserhalb von Rust liegen und die der Compiler deshalb
# nicht halten kann.
#
#   scripts/check-docs.sh        # Exit 0 = alles konsistent
#
# Laeuft ohne Build, ohne Netz und ohne Root.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

pass=0
fail=0
ok()   { printf '  ok   %s\n' "$1"; pass=$((pass + 1)); }
bad()  { printf '  FAIL %s\n' "$1"; shift; for l in "$@"; do printf '       %s\n' "$l"; done; fail=$((fail + 1)); }

echo
echo "A. smoke.sh greppt auf Felder, die es gibt"

# observe_has <vm> <feld> greppt die JSON-Antwort von `agent observe`. Deren
# Felder sind die von `Observed` in reconcile.rs. Ein Name, den es dort nicht
# gibt, meldet sich als FAIL des Lifecycle-Teils und sieht damit aus wie ein
# kaputter Agent statt wie ein veralteter Test.
OBSERVED="components/agent/src/reconcile.rs"
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

# Der Platzhalter license = "TODO_LICENSE" ist seit 6917c8a weg und alle
# .rs tragen den SPDX-Header. Drei Statusdokumente haben das monatelang
# anders behauptet; diese Pruefung ist der Grund, dass es nicht wieder
# auseinanderlaeuft.
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

# Die Doku darf den Platzhalter noch ZITIEREN (als Chronik), aber nicht als
# heutigen Zustand behaupten. Die Trennlinie ist mechanisch: eine Zeile, die
# TODO_LICENSE enthaelt UND ein Praesens-Verb ("sagt", "steht", "traegt"),
# ist eine Behauptung ueber jetzt.
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

# Relative Pfade loesen sich gegen das Verzeichnis der CONFIG-Datei auf
# (agent/src/config.rs::load, cli/src/config.rs::resolve_path). Fuer
# config/cli.dev.toml heisst das: ca_cert = "data/..." ist config/data/, und
# `meister login` legt Schluessel nach config/pki/ ab, weil die Profile kein
# mtls-Credential nennen. Beide Verzeichnisse tragen Material, das nie in
# die History darf — Schluessel im Fall von pki/.
for d in data pki; do
    if git check-ignore -q "config/$d/probe"; then
        ok "config/$d/ ist git-ignoriert"
    else
        bad "config/$d/ ist git-ignoriert" \
            "config/.gitignore deckt $d/ nicht ab"
    fi
done

# Der Agent legt seinen Baum NICHT unter config/ an: agent.dev.toml sagt
# ../data, und das ist relativ zu config/ das <repo>/data der Wurzel-
# .gitignore. Eine Begruendung in config/.gitignore, die etwas anderes
# behauptet, war der Fund, der diese Zeile hier ausgeloest hat.
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
