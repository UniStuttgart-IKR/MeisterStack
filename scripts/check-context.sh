#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR
#
# MeisterStack — Render-Test fuer nix/one-context.nix
#
# Die teuersten Fehler dieses Repos lagen nicht im Rust, sondern in der einen
# Stelle, an der eine Config entsteht: one-context stellt die per-VM-Werte VOR
# das gebackene Template (Top-Level-Keys) und haengt Sektionen DAHINTER an. Ein
# [table]-Header an der falschen Seite verschluckt die Keys der jeweils anderen
# — einmal in jede Richtung passiert, einmal davon einen halben Tag lang.
#
# Dieser Test faehrt GENAU den Skripttext, der ins Image geht: er schneidet ihn
# aus nix/one-context.nix heraus, lenkt jeden absoluten Pfad in ein temporaeres
# Wurzelverzeichnis um und laesst ihn gegen die ECHTEN gerenderten Templates
# laufen. Danach wird jede der drei Dateien mit einem TOML-Parser gelesen: eine
# Datei, in der ein Key in der falschen Table gelandet ist, faellt damit auf,
# und eine, die gar nicht mehr parst, erst recht.
#
#   scripts/check-context.sh     # Exit 0 = alles konsistent
#
# Braucht nix (fuer die Templates), bash und python3. Kein Netz, kein Root,
# keine VM. Fasst nichts ausserhalb von $(mktemp -d) an — die Pfadwache unten
# haelt genau das nach.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

pass=0
fail=0
ok()  { printf '  ok   %s\n' "$1"; pass=$((pass + 1)); }
bad() { printf '  FAIL %s\n' "$1"; shift; for l in "$@"; do printf '       %s\n' "$l"; done; fail=$((fail + 1)); }

# --- 1. den Skripttext herausschneiden -------------------------------------
# Nix-Escapes zurueck nach bash: ''${x} ist im Nix-String das literale ${x},
# und ''' ist das literale ''. Beides muss weg, sonst laeuft der Text nicht.
BODY="$T/one-context.sh"
python3 - "$ROOT/nix/one-context.nix" "$BODY" <<'PY' || exit 1
import sys
src, dst = sys.argv[1], sys.argv[2]
s = open(src, encoding="utf-8").read()
try:
    i = s.index("script = ''") + len("script = ''")
    j = s.index("\n    '';", i)
except ValueError:
    sys.exit("cannot find the `script = ''...''` block in " + src)
body = s[i:j].replace("''${", "${").replace("'''", "''")
open(dst, "w", encoding="utf-8").write(body)
PY

echo
echo "A. die Pfadwache: jeder absolute Pfad ist bekannt und umgelenkt"

# Was der Skripttext anfassen darf, und wohin es hier zeigt. Ein Pfad, der hier
# nicht steht, wuerde beim Testlauf das ECHTE System treffen — deshalb ist ein
# unbekannter Pfad ein FAIL und kein Hinweis. Kommt einer dazu, gehoert er in
# diese Liste UND in die sed-Umlenkung darunter, in einem Zug.
KNOWN=(
    /dev/null                      # render_config: leere Override-Liste
    /dev/disk/by-label/CONTEXT     # das Kontext-Laufwerk
    /proc/sys/kernel/hostname      # node_id, und SET_HOSTNAME schreibt hierhin
    /etc/meisterstack               # die gebackenen Templates (nur gelesen)
    /etc/resolv.conf               # ETH0_DNS
    /etc/static/hosts              # der gebackene Teil von /etc/hosts
    /etc/hosts                     # MEISTER_HOSTS zeigt ihn auf /run um
    /root/.ssh                     # SSH_PUBLIC_KEY
    /run/meisterstack              # die gerenderten Configs
    /run/meister-role              # was diese VM laut Kontext ist
    /run/one-context               # der Mountpoint des Kontext-Laufwerks
    /context.sh                    # relativ zu $mnt, kein eigener Pfad
    //                             # aus http://$ip:2380 und ${x// /}
)
unknown=()
while read -r p; do
    for k in "${KNOWN[@]}"; do
        case "$p" in "$k"*) continue 2;; esac
    done
    unknown+=("$p")
done < <(grep -vE '^\s*#' "$BODY" | grep -oE '/[A-Za-z0-9._/@-]+' | sort -u)

if [ ${#unknown[@]} -eq 0 ]; then
    ok "kein unbekannter absoluter Pfad in one-context.nix"
else
    bad "one-context.nix fasst Pfade an, die dieser Test nicht umlenkt" \
        "${unknown[@]}" \
        "-> in KNOWN und in die Umlenkung aufnehmen, sonst trifft der Test das echte System"
    echo; echo "abgebrochen: $fail FAIL"; exit 1
fi

# --- 2. umlenken und die Umgebung stellen ----------------------------------
sed -i \
    -e "s#/etc/meisterstack#$T/etc/meisterstack#g" \
    -e "s#/run/meisterstack#$T/run/meisterstack#g" \
    -e "s#/run/one-context#$T/run/one-context#g" \
    -e "s#/run/meister-role#$T/run/meister-role#g" \
    -e "s#/dev/disk/by-label/CONTEXT#$T/context.dev#g" \
    -e "s#/proc/sys/kernel/hostname#$T/hostname#g" \
    -e "s#/etc/resolv.conf#$T/resolv.conf#g" \
    -e "s#/etc/static/hosts#$T/static-hosts#g" \
    -e "s#/etc/hosts#$T/hosts#g" \
    -e "s#/root/.ssh#$T/root/.ssh#g" \
    "$BODY"

# mount/umount/systemctl/ip tun hier nichts: das Kontext-"Laufwerk" ist eine
# Datei, die schon am Mountpoint liegt, und gestartet wird in diesem Test
# nichts. seq/sleep bleiben echt — die Warteschleife laeuft dann gar nicht,
# weil das Geraet sofort existiert.
mkdir -p "$T/bin"
for stub in mount umount systemctl ip; do
    printf '#!/bin/sh\nexit 0\n' > "$T/bin/$stub"
    chmod +x "$T/bin/$stub"
done
export PATH="$T/bin:$PATH"

echo
echo "B. die Templates, die das Image wirklich baeckt"

mkdir -p "$T/etc/meisterstack"
tmpl_ok=1
# Die drei Rollen-Templates und die zwei Auth-Fragmente der Cloud. Die
# Fragmente sind keine Templates: sie werden nicht gerendert, sondern von
# render_cloud_auth angehaengt (nix/controllers.nix sagt, warum die
# [auth]-Tabelle der Cloud nicht gebacken werden KANN).
for name in cloud cluster agent cloud-auth-mtls cloud-auth-oidc; do
    attr=".#nixosConfigurations.control-plane.config.environment.etc.\"meisterstack/$name.toml\".source"
    if p="$(nix build --no-link --print-out-paths "$attr" 2>/dev/null)"; then
        install -m 0644 "$p" "$T/etc/meisterstack/$name.toml"
    else
        tmpl_ok=0
        bad "$name.toml aus der flake bauen" "nix build $attr"
    fi
done
[ "$tmpl_ok" = 1 ] && ok "alle drei Rollen-Templates und beide Auth-Fragmente gebaut"
[ "$tmpl_ok" = 1 ] || { echo; echo "abgebrochen: $fail FAIL"; exit 1; }

# --- Helfer ----------------------------------------------------------------
# tomlget <datei> <pfad.mit.punkten> -> Wert, oder "<absent>". Ein Parse-Fehler
# ist ein Fehler des Tests, nicht ein leerer Wert: er kommt mit Text zurueck.
tomlget() {
    python3 - "$1" "$2" <<'PY'
import sys, tomllib
path, key = sys.argv[1], sys.argv[2]
try:
    with open(path, "rb") as fh:
        doc = tomllib.load(fh)
except Exception as e:                       # noqa: BLE001 - der Text ist das Ergebnis
    print("<parse-error: %s>" % e)
    sys.exit(0)
cur = doc
for part in key.split("."):
    if not isinstance(cur, dict) or part not in cur:
        print("<absent>")
        sys.exit(0)
    cur = cur[part]
print(cur)
PY
}

# render <name> <kontextzeilen...> — ein kompletter Lauf in frischem Zustand
render() {
    local name=$1; shift
    rm -rf "$T/run" "$T/hostname"
    mkdir -p "$T/run/one-context"
    echo "agent-1a" > "$T/hostname"
    : > "$T/context.dev"
    printf '%s\n' "$@" > "$T/run/one-context/context.sh"
    bash "$BODY" > "$T/$name.log" 2>&1
}

# renders_without_context — der Zweig ohne Kontext-Laufwerk
render_bare() {
    rm -rf "$T/run" "$T/hostname" "$T/context.dev"
    mkdir -p "$T/run"
    echo "agent-1a" > "$T/hostname"
    bash "$BODY" > "$T/bare.log" 2>&1
}

# render_planned <name> <gebackene Zeilen...> — ein PLAN-Knoten: kein
# Kontext-Laufwerk, die gebackene Datei ist der ganze Kontext (nix/roles.nix).
render_planned() {
    local name=$1; shift
    rm -rf "$T/run" "$T/hostname" "$T/context.dev"
    mkdir -p "$T/run" "$T/etc/meisterstack"
    echo "box" > "$T/hostname"
    printf '%s\n' "$@" > "$T/etc/meisterstack/context.env"
    bash "$BODY" > "$T/$name.log" 2>&1
    rm -f "$T/etc/meisterstack/context.env"
}

# render_planned_ctx <name> <gebacken> -- <kontext> — beide Wege gleichzeitig,
# fuer die eine Frage, die dabei zaehlt: wer gewinnt.
render_planned_ctx() {
    local name=$1; shift
    local baked=() ctx=() cur=baked
    for arg in "$@"; do
        if [ "$arg" = "--" ]; then cur=ctx; continue; fi
        if [ "$cur" = baked ]; then baked+=("$arg"); else ctx+=("$arg"); fi
    done
    rm -rf "$T/run" "$T/hostname"
    mkdir -p "$T/run/one-context" "$T/etc/meisterstack"
    echo "box" > "$T/hostname"
    : > "$T/context.dev"
    printf '%s\n' "${baked[@]}" > "$T/etc/meisterstack/context.env"
    printf '%s\n' "${ctx[@]}" > "$T/run/one-context/context.sh"
    bash "$BODY" > "$T/$name.log" 2>&1
    rm -f "$T/etc/meisterstack/context.env"
}

expect() { # <was> <erwartet> <ist>
    if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "erwartet: $2" "ist:      $3"; fi
}

# grepfor <was> <muster> <datei> [kontextzeilen...] — fuer die Dateien, die
# kein TOML sind (die Alloy-Config, die gebaute Unit). Als Funktion und nicht
# als `grep && ok || bad`, weil das genau die Form ist, die shellcheck zu
# Recht anmeckert: das C in A && B || C laeuft auch, wenn A wahr war.
grepfor() {
    local what=$1 pattern=$2 file=$3; shift 3
    if grep -qE "$pattern" "$file"; then ok "$what"; else bad "$what" "$@"; fi
}

echo
echo "C. ohne Kontext-Laufwerk: die Templates kommen unveraendert durch"

render_bare
expect "cloud.toml traegt metrics_listen aus dem Template" \
    "0.0.0.0:9100" "$(tomlget "$T/run/meisterstack/cloud.toml" metrics_listen)"
expect "cloud.toml traegt kein advertise_api" \
    "<absent>" "$(tomlget "$T/run/meisterstack/cloud.toml" advertise_api)"
expect "agent.toml bekommt node_id aus dem Hostnamen" \
    "agent-1a" "$(tomlget "$T/run/meisterstack/agent.toml" node_id)"
expect "agent.toml behaelt [paths] run_dir" \
    "/run/meisterstack/agent" "$(tomlget "$T/run/meisterstack/agent.toml" paths.run_dir)"
expect "agent.toml traegt den Pfad zur Node-Identitaet" \
    "/opt/meisterstack/pki/identity.crt" \
    "$(tomlget "$T/run/meisterstack/agent.toml" controller_cert)"
# D2: ohne dieses Paar ist `Sibling.tls` None, waehrend `serves_tls` seit
# Image 58 true ist -- jeder Forward zwischen Cloud-Replicas scheitert dann an
# "is https and this one has no client certificate", und `vm logs` antwortet
# auf einer von drei. Der Cluster hatte es immer, die Cloud nie.
expect "cloud.toml traegt das Identitaetspaar fuer den Forward zur Schwester" \
    "/opt/meisterstack/pki/identity.crt" \
    "$(tomlget "$T/run/meisterstack/cloud.toml" identity_cert)"
expect "cloud.toml traegt den passenden Schluessel" \
    "/opt/meisterstack/pki/identity.key" \
    "$(tomlget "$T/run/meisterstack/cloud.toml" identity_key)"
expect "cluster.toml behaelt seines" \
    "/opt/meisterstack/pki/identity.crt" \
    "$(tomlget "$T/run/meisterstack/cluster.toml" cloud_cert)"

echo
echo "D. MEISTER_ADVERTISE_API gesetzt: beide Controller-Rollen bekommen ihn"

render adv \
    'MEISTER_ROLE=cluster' \
    'MEISTER_CLUSTER_NAME=cluster-1' \
    'MEISTER_CLOUD_ADDRS=10.128.1.103:50050,10.128.1.112:50050' \
    'MEISTER_ADVERTISE_API=10.128.1.104:3001'

expect "cluster.toml traegt advertise_api" \
    "10.128.1.104:3001" "$(tomlget "$T/run/meisterstack/cluster.toml" advertise_api)"
expect "cloud.toml traegt advertise_api (b880844 gab der Cloud den Schluessel)" \
    "10.128.1.104:3001" "$(tomlget "$T/run/meisterstack/cloud.toml" advertise_api)"
expect "cluster.toml behaelt cluster_name daneben" \
    "cluster-1" "$(tomlget "$T/run/meisterstack/cluster.toml" cluster_name)"
expect "cluster.toml behaelt metrics_listen aus dem Template" \
    "0.0.0.0:9101" "$(tomlget "$T/run/meisterstack/cluster.toml" metrics_listen)"
expect "cloud_addrs bleibt eine Liste" \
    "['10.128.1.103:50050', '10.128.1.112:50050']" \
    "$(tomlget "$T/run/meisterstack/cluster.toml" cloud_addrs)"
# Der eigentliche Grund, warum die Prepend-Regel zaehlt: das Template endet
# seit A3 auf eine [auth]-Table. Landeten die per-VM-Keys dahinter, waeren sie
# auth.advertise_api und auth.cluster_name -- unbekannte Schluessel, und damit
# ein Startfehler durch deny_unknown_fields statt einer stillen Fehlkonfig.
expect "cluster.toml: [auth] chain ueberlebt das Prepend" \
    "['mtls']" "$(tomlget "$T/run/meisterstack/cluster.toml" auth.chain)"
expect "cluster.toml: advertise_api ist NICHT in [auth] gelandet" \
    "<absent>" "$(tomlget "$T/run/meisterstack/cluster.toml" auth.advertise_api)"
expect "cloud.toml: [auth] chain ueberlebt das Prepend" \
    "['mtls']" "$(tomlget "$T/run/meisterstack/cloud.toml" auth.chain)"
expect "cluster.toml: client_ca aus dem Template" \
    "/opt/meisterstack/pki/ca.crt" \
    "$(tomlget "$T/run/meisterstack/cluster.toml" client_ca)"


# Die Prepend-Regel, im Klartext und nicht nur ueber den Parser: jeder
# per-VM-Key steht VOR dem ersten [table]-Header. Steht er dahinter, ist er
# ein Key IN dieser Table und der Parser findet ihn oben nicht mehr -- was der
# Test darueber schon gezeigt haette, aber nicht so, dass man den Grund sieht.
first_table="$(grep -n '^\[' "$T/run/meisterstack/cluster.toml" | head -1 | cut -d: -f1)"
adv_line="$(grep -n '^advertise_api' "$T/run/meisterstack/cluster.toml" | head -1 | cut -d: -f1)"
if [ -z "$first_table" ]; then
    ok "cluster.toml hat (noch) keinen [table]-Header, Prepend-Regel trivial erfuellt"
elif [ -n "$adv_line" ] && [ "$adv_line" -lt "$first_table" ]; then
    ok "advertise_api steht vor dem ersten [table]-Header (Zeile $adv_line < $first_table)"
else
    bad "advertise_api steht nicht vor dem ersten [table]-Header" \
        "advertise_api: Zeile ${adv_line:-<fehlt>}, erste Table: Zeile $first_table"
fi
# MEISTER_CLOUD_NAME: der Gegenpart von MEISTER_CLUSTER_NAME eine Etage
# hoeher. Er benennt die CLOUD und nicht die Replica -- alle drei tragen
# denselben Wert, weil es der Name in ihrem gemeinsamen
# system:cloud:<name>-Zertifikat ist.
render cloudname \
    'MEISTER_ROLE=cloud' \
    'MEISTER_CLOUD_NAME=lab' \
    'MEISTER_ADVERTISE_API=10.128.1.103:3000'
expect "cloud.toml traegt cloud_name" \
    "lab" "$(tomlget "$T/run/meisterstack/cloud.toml" cloud_name)"
expect "cloud_name ist NICHT in [auth] gelandet" \
    "<absent>" "$(tomlget "$T/run/meisterstack/cloud.toml" auth.cloud_name)"
expect "cloud.toml behaelt advertise_api daneben" \
    "10.128.1.103:3000" "$(tomlget "$T/run/meisterstack/cloud.toml" advertise_api)"
# Und der Cluster bekommt ihn NICHT: eine Cloud und ein Cluster koennen
# gleich heissen, und cluster_name in einer cloud.toml waere ein unbekannter
# Schluessel und damit ein Startfehler.
expect "cluster.toml bekommt kein cloud_name" \
    "<absent>" "$(tomlget "$T/run/meisterstack/cluster.toml" cloud_name)"

render nocloudname 'MEISTER_ROLE=cloud'
expect "ohne die Variable: keine Zeile, kein leerer Wert" \
    "<absent>" "$(tomlget "$T/run/meisterstack/cloud.toml" cloud_name)"


echo
echo "E. MEISTER_ADVERTISE_API nicht gesetzt: keine Zeile, kein leerer Wert"

render noadv \
    'MEISTER_ROLE=cluster' \
    'MEISTER_CLUSTER_NAME=cluster-1'

expect "cluster.toml traegt kein advertise_api" \
    "<absent>" "$(tomlget "$T/run/meisterstack/cluster.toml" advertise_api)"
expect "cloud.toml traegt kein advertise_api" \
    "<absent>" "$(tomlget "$T/run/meisterstack/cloud.toml" advertise_api)"
expect "cluster_name kommt trotzdem an" \
    "cluster-1" "$(tomlget "$T/run/meisterstack/cluster.toml" cluster_name)"

echo
echo "F. die zwei Telemetrie-Variablen: alle DREI Rollen, oder es ist kein Trace"

# Ein `vm create` kreuzt Cloud, Cluster und Agent. Bekaeme eine der drei
# Rollen den Endpunkt nicht, waere das Ergebnis kein halber Trace, sondern
# drei zusammenhanglose -- deshalb prueft dieser Abschnitt alle drei Dateien
# aus EINEM Lauf und nicht nur die Rolle, die diese VM startet.
render telemetry \
    'MEISTER_ROLE=cluster' \
    'MEISTER_CLUSTER_NAME=cluster-1' \
    'MEISTER_ADVERTISE_API=10.128.1.104:3001' \
    'MEISTER_OTLP_ENDPOINT=http://10.128.10.35:4317' \
    'MEISTER_LOG_FORMAT=json'

for role in cloud cluster agent; do
    expect "$role.toml traegt otlp_endpoint" \
        "http://10.128.10.35:4317" \
        "$(tomlget "$T/run/meisterstack/$role.toml" otlp_endpoint)"
    expect "$role.toml traegt log_format" \
        "json" "$(tomlget "$T/run/meisterstack/$role.toml" log_format)"
done

# Dieselbe Prepend-Regel wie bei advertise_api, und hier zaehlt sie doppelt:
# das Cluster-Template endet auf [auth], also waere ein angehaengtes
# otlp_endpoint der Schluessel auth.otlp_endpoint -- unbekannt, und damit ein
# Startfehler durch deny_unknown_fields.
expect "cluster.toml: otlp_endpoint ist NICHT in [auth] gelandet" \
    "<absent>" "$(tomlget "$T/run/meisterstack/cluster.toml" auth.otlp_endpoint)"
expect "cluster.toml: [auth] chain steht neben der Telemetrie" \
    "['mtls']" "$(tomlget "$T/run/meisterstack/cluster.toml" auth.chain)"
expect "agent.toml: [paths] ueberlebt das Prepend der Telemetrie" \
    "/run/meisterstack/agent" \
    "$(tomlget "$T/run/meisterstack/agent.toml" paths.run_dir)"
expect "agent.toml: node_id steht weiter daneben" \
    "agent-1a" "$(tomlget "$T/run/meisterstack/agent.toml" node_id)"

echo
echo "G. keine Telemetrie-Variablen: keine Zeile, kein leerer Wert"

# Ein leerer String waere hier schlimmer als gar nichts: otlp_endpoint = ""
# ist fuer den Exporter eine Adresse, und log_format = "" ist ein Startfehler.
render notelemetry 'MEISTER_ROLE=agent'

for role in cloud cluster agent; do
    expect "$role.toml traegt kein otlp_endpoint" \
        "<absent>" "$(tomlget "$T/run/meisterstack/$role.toml" otlp_endpoint)"
    expect "$role.toml traegt kein log_format" \
        "<absent>" "$(tomlget "$T/run/meisterstack/$role.toml" log_format)"
done

echo
echo "H. die Append-Regel in Gegenrichtung: [network.vxlan] haengt hinten an"

render vxlan \
    'MEISTER_ROLE=agent' \
    'MEISTER_CONTROLLER_ADDRS=10.128.1.104:50051,10.128.1.110:50051' \
    'MEISTER_VXLAN_UPLINK=eth0' \
    'MEISTER_VXLAN_MTU=1450'

expect "agent.toml: [network.vxlan] uplink" \
    "eth0" "$(tomlget "$T/run/meisterstack/agent.toml" network.vxlan.uplink)"
expect "agent.toml: [network.vxlan] mtu" \
    "1450" "$(tomlget "$T/run/meisterstack/agent.toml" network.vxlan.mtu)"
expect "agent.toml: default_bridge aus dem Template ueberlebt den Append" \
    "meister_br0" "$(tomlget "$T/run/meisterstack/agent.toml" network.default_bridge)"
expect "agent.toml: node_id bleibt Top-Level" \
    "agent-1a" "$(tomlget "$T/run/meisterstack/agent.toml" node_id)"
expect "agent.toml: controller_addrs bleibt eine Liste" \
    "['10.128.1.104:50051', '10.128.1.110:50051']" \
    "$(tomlget "$T/run/meisterstack/agent.toml" controller_addrs)"

echo
echo "H2. das abgegebene Interface: [network.provider] haengt genauso hinten an"

# Die Maschinen-Aussage aus 6k. Per Kontext, weil zwoelf VMs aus derselben
# qcow2 kommen und nur zwei davon eine NIC abgeben.
render physnets \
    'MEISTER_ROLE=agent' \
    'MEISTER_CONTROLLER_ADDRS=10.128.1.104:50051' \
    'MEISTER_VXLAN_UPLINK=eth0' \
    'MEISTER_PHYSNETS=ext=eth1'

expect "agent.toml: [network.provider] physnets" \
    "{'ext': 'eth1'}" \
    "$(tomlget "$T/run/meisterstack/agent.toml" network.provider.physnets)"
expect "agent.toml: [network.vxlan] daneben ueberlebt" \
    "eth0" "$(tomlget "$T/run/meisterstack/agent.toml" network.vxlan.uplink)"
expect "agent.toml: default_bridge aus dem Template ueberlebt beide Appends" \
    "meister_br0" "$(tomlget "$T/run/meisterstack/agent.toml" network.default_bridge)"

# Zwei Netze in einem Wert, und Leerzeichen um das Komma sind erlaubt: der
# Wert wird von Hand in ein ONE-Template getippt, und ONE schreibt ihn
# gequotet in die context.sh.
render physnets2 \
    'MEISTER_ROLE=agent' \
    'MEISTER_CONTROLLER_ADDRS=10.128.1.104:50051' \
    'MEISTER_PHYSNETS="ext=eth1, dmz=eth2"'

expect "agent.toml: zwei Physnets in einem Wert" \
    "{'ext': 'eth1', 'dmz': 'eth2'}" \
    "$(tomlget "$T/run/meisterstack/agent.toml" network.provider.physnets)"

# Kein Wert heisst KEIN Abschnitt. Ein leeres [network.provider] waere ein
# Abschnitt ohne seinen Pflichtschluessel und damit ein Startfehler statt
# "diese Maschine gibt nichts ab" -- der Unterschied ist die ganze Semantik.
render nophysnets \
    'MEISTER_ROLE=agent' \
    'MEISTER_CONTROLLER_ADDRS=10.128.1.104:50051'

expect "agent.toml: ohne MEISTER_PHYSNETS kein [network.provider]" \
    "<absent>" \
    "$(tomlget "$T/run/meisterstack/agent.toml" network.provider.physnets)"

# Und Unsinn im Wert kostet den Eintrag, nicht den Abschnitt und nicht den
# Start: eine Zeile ohne = ist kein Paar.
render badphysnet \
    'MEISTER_ROLE=agent' \
    'MEISTER_CONTROLLER_ADDRS=10.128.1.104:50051' \
    'MEISTER_PHYSNETS=eth1'

expect "agent.toml: ein Eintrag ohne = rendert keinen Abschnitt" \
    "<absent>" \
    "$(tomlget "$T/run/meisterstack/agent.toml" network.provider.physnets)"

echo
echo "H3. die Ankuendigung: [network.bgp] und seine Nachbarn"

# Der zweite Teil derselben Maschinen-Aussage. FRR laeuft im Image
# (services.frr.bgpd, nix/agent.nix); was dieser Knoten sagt, steht hier.
render bgp \
    'MEISTER_ROLE=agent' \
    'MEISTER_CONTROLLER_ADDRS=10.128.1.104:50051' \
    'MEISTER_PHYSNETS=ext=eth1' \
    'MEISTER_BGP_ASN=65001' \
    'MEISTER_BGP_ROUTER_ID=10.128.1.10' \
    'MEISTER_BGP_NEIGHBORS="10.128.0.1=65000, 10.128.0.2=65000"'

expect "agent.toml: [network.bgp] asn" \
    "65001" "$(tomlget "$T/run/meisterstack/agent.toml" network.bgp.asn)"
expect "agent.toml: [network.bgp] router_id" \
    "10.128.1.10" "$(tomlget "$T/run/meisterstack/agent.toml" network.bgp.router_id)"
expect "agent.toml: beide Nachbarn, in der Reihenfolge des Werts, mit ihrer asn" \
    "[{'address': '10.128.0.1', 'remote_asn': 65000}, {'address': '10.128.0.2', 'remote_asn': 65000}]" \
    "$(tomlget "$T/run/meisterstack/agent.toml" network.bgp.neighbors)"
expect "agent.toml: [network.provider] daneben ueberlebt den dritten Append" \
    "{'ext': 'eth1'}" \
    "$(tomlget "$T/run/meisterstack/agent.toml" network.provider.physnets)"

# Ohne Peers ist der Abschnitt trotzdem richtig: eine Maschine, die auf ihre
# Nachbarn wartet, ist ein Zustand und kein Fehler.
render bgpnopeers \
    'MEISTER_ROLE=agent' \
    'MEISTER_CONTROLLER_ADDRS=10.128.1.104:50051' \
    'MEISTER_BGP_ASN=65001' \
    'MEISTER_BGP_ROUTER_ID=10.128.1.10'

expect "agent.toml: [network.bgp] ohne Nachbarn" \
    "65001" "$(tomlget "$T/run/meisterstack/agent.toml" network.bgp.asn)"
expect "agent.toml: und dann steht keine Nachbarliste da" \
    "<absent>" "$(tomlget "$T/run/meisterstack/agent.toml" network.bgp.neighbors)"

# Ein halber Abschnitt waere ein Startfehler und kein "kein BGP": asn ohne
# router_id rendert nichts und sagt es.
render bgphalf \
    'MEISTER_ROLE=agent' \
    'MEISTER_CONTROLLER_ADDRS=10.128.1.104:50051' \
    'MEISTER_BGP_ASN=65001'

expect "agent.toml: asn ohne router_id rendert keinen Abschnitt" \
    "<absent>" "$(tomlget "$T/run/meisterstack/agent.toml" network.bgp.asn)"

render nobgp \
    'MEISTER_ROLE=agent' \
    'MEISTER_CONTROLLER_ADDRS=10.128.1.104:50051'

expect "agent.toml: ohne MEISTER_BGP_ASN kein [network.bgp]" \
    "<absent>" "$(tomlget "$T/run/meisterstack/agent.toml" network.bgp.asn)"

echo
echo "I. der Log-Sammler: die gerenderte Alloy-Config parst wirklich"

# Der Grund, das hier zu pruefen und nicht erst auf der VM: diese Datei
# entsteht per Heredoc in einem Shell-Skript, und ein Alloy mit kaputter
# Config startet nicht -- was auf zwoelf Hosts gleichzeitig auffaellt und
# nirgends vorher. `alloy validate` ist derselbe Parser, den die Unit fahren
# wird, aus demselben Paket, das das Image baeckt.
render alloy \
    'MEISTER_ROLE=agent' \
    'MEISTER_CONTROLLER_ADDRS=10.128.1.104:50051' \
    'MEISTER_LOKI_URL=http://10.128.10.34:3100/loki/api/v1/push'

CFG="$T/run/meisterstack/alloy.alloy"
if [ ! -f "$CFG" ]; then
    bad "MEISTER_LOKI_URL gesetzt -> alloy.alloy gerendert" "$CFG fehlt"
else
    ok "MEISTER_LOKI_URL gesetzt -> alloy.alloy gerendert"

    # Die zwei Labels, die eine Zeile in Loki ueberhaupt adressierbar machen.
    # host kommt aus dem Hostnamen und NICHT aus env("HOSTNAME"): eine
    # systemd-Unit erbt kein HOSTNAME, und env() waere dort der leere String
    # -- die ganze Flotte unter host="" ist ein stiller Ausfall.
    grepfor "alloy.alloy traegt den Hostnamen als Literal" \
        'host = "agent-1a"' "$CFG" "$(grep labels "$CFG")"
    grepfor "alloy.alloy traegt die Rolle aus dem Kontext" \
        'role = "agent"' "$CFG" "$(grep labels "$CFG")"
    grepfor "alloy.alloy traegt die Loki-URL aus dem Kontext" \
        'url = "http://10\.128\.10\.34:3100/loki/api/v1/push"' "$CFG" "$(grep url "$CFG")"

    alloy_pkg="$(nix build --no-link --print-out-paths \
        '.#nixosConfigurations.control-plane.config.services.alloy.package' 2>/dev/null)"
    if [ -z "$alloy_pkg" ] || [ ! -x "$alloy_pkg/bin/alloy" ]; then
        bad "das Alloy des Images bauen" \
            "nix build .#nixosConfigurations.control-plane.config.services.alloy.package"
    else
        if out="$("$alloy_pkg/bin/alloy" validate "$CFG" 2>&1)"; then
            ok "alloy validate: die gerenderte Config ist gueltig"
        else
            bad "alloy validate: die gerenderte Config ist gueltig" "$out"
        fi
        # Kanonisch formatiert, damit ein Diff auf der VM ein echter Diff ist
        # und kein Leerzeichen.
        if "$alloy_pkg/bin/alloy" fmt "$CFG" 2>/dev/null | diff -q - "$CFG" > /dev/null; then
            ok "alloy fmt: das Heredoc schreibt kanonisches Alloy"
        else
            bad "alloy fmt: das Heredoc schreibt kanonisches Alloy" \
                "$("$alloy_pkg/bin/alloy" fmt "$CFG" 2>/dev/null | diff - "$CFG" | head -20)"
        fi
    fi
fi

# Ohne Variable keine Datei -- und das ist der ganze Schalter, denn die Unit
# haengt mit ConditionPathExists an genau diesem Pfad.
render noalloy 'MEISTER_ROLE=agent'
if [ -f "$T/run/meisterstack/alloy.alloy" ]; then
    bad "ohne MEISTER_LOKI_URL wird nichts gerendert" \
        "$T/run/meisterstack/alloy.alloy existiert trotzdem"
else
    ok "ohne MEISTER_LOKI_URL wird nichts gerendert"
fi

# Und die Verdrahtung selbst: Unit und Renderer muessen denselben Pfad
# meinen. Zwei Dateien, eine Zeichenkette -- die Sorte Drift, die erst im Lab
# auffaellt, als "Alloy ist skipped und keiner weiss warum".
unit="$(nix build --no-link --print-out-paths \
    '.#nixosConfigurations.control-plane.config.systemd.units."alloy.service".unit' 2>/dev/null)"
if [ -z "$unit" ] || [ ! -f "$unit/alloy.service" ]; then
    bad "die alloy.service aus der flake bauen" "nix build ...systemd.units.\"alloy.service\".unit"
else
    grepfor "alloy.service haengt an genau der gerenderten Datei" \
        '^ConditionPathExists=/run/meisterstack/alloy\.alloy$' "$unit/alloy.service" \
        "$(grep -i condition "$unit/alloy.service")"
    grepfor "alloy.service liest genau die gerenderte Datei" \
        'ExecStart=.*/alloy run /run/meisterstack/alloy\.alloy' "$unit/alloy.service" \
        "$(grep ExecStart "$unit/alloy.service")"
    grepfor "alloy.service startet nach one-context" \
        '^After=.*one-context\.service' "$unit/alloy.service" \
        "$(grep '^After=' "$unit/alloy.service")"
fi

echo
echo "I2. /etc/hosts: die Namen, die diese Flotte ohne dns aufloesen muss"

# Warum es die Variable gibt: Kanidms Issuer, sein origin, jede
# oauth2-Redirect-URL und der Name im Serving-Zertifikat sind EIN Name
# (nix/addons.nix), und ein Lab hat kein dns. Warum es hier geprueft wird:
# /etc/hosts ist ein Symlink in den Store, und ein Schreiben DURCH den
# Symlink trifft ein read-only Dateisystem -- der Fehler, der auf zwoelf VMs
# gleichzeitig auffaellt und nirgends vorher.
hosts_fixture() {
    printf '127.0.0.1 localhost\n::1 localhost\n127.0.0.2 nixos\n' > "$T/static-hosts"
    ln -sfn "$T/static-hosts" "$T/hosts"
}

# Der Wert traegt Leerzeichen und Kommata, also steht er in Anfuehrungszeichen
# -- so schreibt OpenNebula eine context.sh, und ohne sie waere die zweite
# Haelfte der Zeile ein Kommando statt eines Wertes.
hosts_fixture
render hosts \
    'MEISTER_ROLE=cloud' \
    'MEISTER_HOSTS="10.128.1.103 meister-cloud-a.lab, 10.128.1.112 meister-cloud-b.lab"'

if [ ! -f "$T/run/meisterstack/hosts" ]; then
    bad "MEISTER_HOSTS gesetzt -> die Datei unter /run entsteht" \
        "$T/run/meisterstack/hosts fehlt"
else
    ok "MEISTER_HOSTS gesetzt -> die Datei unter /run entsteht"
    grepfor "der gebackene Teil bleibt: localhost geht nicht verloren" \
        '^127\.0\.0\.1 localhost$' "$T/run/meisterstack/hosts" \
        "$(head -3 "$T/run/meisterstack/hosts")"
    grepfor "der erste Eintrag steht drin" \
        '^10\.128\.1\.103 meister-cloud-a\.lab$' "$T/run/meisterstack/hosts" \
        "$(tail -3 "$T/run/meisterstack/hosts")"
    grepfor "der zweite Eintrag steht drin, ohne fuehrendes Leerzeichen" \
        '^10\.128\.1\.112 meister-cloud-b\.lab$' "$T/run/meisterstack/hosts" \
        "$(tail -3 "$T/run/meisterstack/hosts")"
    # Der eigentliche Punkt: der Store wurde NICHT beschrieben.
    if [ "$(readlink "$T/hosts")" = "$T/run/meisterstack/hosts" ]; then
        ok "/etc/hosts zeigt auf die Datei unter /run (der Store bleibt unberuehrt)"
    else
        bad "/etc/hosts zeigt auf die Datei unter /run" \
            "zeigt auf: $(readlink "$T/hosts" || echo '<kein Symlink>')"
    fi
    if grep -q meister-cloud-a "$T/static-hosts"; then
        bad "der gebackene Teil wird nicht angefasst" "$T/static-hosts wurde beschrieben"
    else
        ok "der gebackene Teil wird nicht angefasst"
    fi
fi

# Ohne die Variable bleibt /etc/hosts, was NixOS daraus gemacht hat.
hosts_fixture
render nohosts 'MEISTER_ROLE=agent'
if [ -e "$T/run/meisterstack/hosts" ]; then
    bad "ohne MEISTER_HOSTS wird nichts umgehaengt" "$T/run/meisterstack/hosts existiert trotzdem"
elif [ "$(readlink "$T/hosts")" != "$T/static-hosts" ]; then
    bad "ohne MEISTER_HOSTS wird nichts umgehaengt" \
        "/etc/hosts zeigt auf: $(readlink "$T/hosts")"
else
    ok "ohne MEISTER_HOSTS wird nichts umgehaengt"
fi

echo
echo "J. die [auth]-Tabelle der Cloud: mit Issuer und ohne"

# Warum das hier und nicht im Image steht: `chain` mit "oidc" ohne
# [auth.oidc] ist ein Startfehler, `issuer` ist ein PFLICHTFELD (also waere
# ein gebackenes [auth.oidc] ohne Issuer ein Parse-Fehler), und ein Append
# kann keine [table] neu definieren. Also rendert one-context die ganze
# Tabelle -- und dieser Abschnitt ist der Beweis, dass beide Zweige gueltiges
# TOML mit den richtigen Werten ergeben.
render oidc \
    'MEISTER_ROLE=cloud' \
    'MEISTER_ADVERTISE_API=10.128.1.103:3000' \
    'MEISTER_OIDC_ISSUER=http://10.128.10.31:8080/realms/meisterstack'

CLOUD="$T/run/meisterstack/cloud.toml"
expect "mit Issuer: die Kette nennt mtls UND oidc" \
    "['mtls', 'oidc']" "$(tomlget "$CLOUD" auth.chain)"
expect "mit Issuer: der Issuer landet in [auth.oidc], nicht daneben" \
    "http://10.128.10.31:8080/realms/meisterstack" \
    "$(tomlget "$CLOUD" auth.oidc.issuer)"
expect "mit Issuer: client_id aus dem gebackenen Fragment" \
    "meister-cli" "$(tomlget "$CLOUD" auth.oidc.client_id)"
# Die audience kommt seit Kanidm aus dem Kontext, nicht mehr aus dem Fragment:
# Keycloaks Audience-Mapper schrieb "meister", Kanidm schreibt den Namen des
# Clients und hat gar keinen Mapper. Ohne die Variable bleibt es der Wert, den
# das Image vorher gebacken hat -- ein Image-Tausch unter dem heutigen Kontext
# aendert also nichts.
expect "mit Issuer, ohne MEISTER_OIDC_AUDIENCE: der alte gebackene Wert" \
    "['meister']" "$(tomlget "$CLOUD" auth.oidc.audience)"
expect "mit Issuer: username_claim aus dem gebackenen Fragment" \
    "preferred_username" "$(tomlget "$CLOUD" auth.oidc.username_claim)"
# Das Prepend muss neben dem Append weiter stimmen: die per-VM-Keys stehen
# vorn, die [auth]-Tabelle hinten, und keiner faellt in den anderen.
expect "mit Issuer: advertise_api bleibt Top-Level" \
    "10.128.1.103:3000" "$(tomlget "$CLOUD" advertise_api)"
expect "mit Issuer: client_ca aus dem Template ueberlebt" \
    "/opt/meisterstack/pki/ca.crt" "$(tomlget "$CLOUD" client_ca)"
expect "mit Issuer: metrics_listen aus dem Template ueberlebt" \
    "0.0.0.0:9100" "$(tomlget "$CLOUD" metrics_listen)"

# Die Lab-CA fuer den Provider. Ohne sie prueft der Client gegen die
# oeffentlichen Wurzeln -- richtig fuer einen echten Provider, falsch fuer
# einen, den tools/meister-ca signiert hat.
expect "mit Issuer: ohne MEISTER_OIDC_CA steht kein ca_cert da" \
    "<absent>" "$(tomlget "$CLOUD" auth.oidc.ca_cert)"

render oidcaud \
    'MEISTER_ROLE=cloud' \
    'MEISTER_OIDC_ISSUER=https://box.lab.example:8443/oauth2/openid/meister-cli' \
    'MEISTER_OIDC_AUDIENCE=meister-cli'
expect "mit MEISTER_OIDC_AUDIENCE: der Name des Kanidm-Clients" \
    "['meister-cli']" "$(tomlget "$CLOUD" auth.oidc.audience)"
expect "mit MEISTER_OIDC_AUDIENCE: client_id kommt weiter aus dem Fragment" \
    "meister-cli" "$(tomlget "$CLOUD" auth.oidc.client_id)"

render oidcca \
    'MEISTER_ROLE=cloud' \
    'MEISTER_OIDC_ISSUER=https://10.128.10.31:8443/realms/meisterstack' \
    'MEISTER_OIDC_CA=/opt/meisterstack/pki/ca.crt'

expect "mit MEISTER_OIDC_CA: ca_cert landet in [auth.oidc]" \
    "/opt/meisterstack/pki/ca.crt" "$(tomlget "$CLOUD" auth.oidc.ca_cert)"
expect "mit MEISTER_OIDC_CA: der Issuer steht weiter daneben" \
    "https://10.128.10.31:8443/realms/meisterstack" \
    "$(tomlget "$CLOUD" auth.oidc.issuer)"
expect "mit MEISTER_OIDC_CA: die Kette nennt weiter beide Links" \
    "['mtls', 'oidc']" "$(tomlget "$CLOUD" auth.chain)"

# Eine CA ohne Issuer rendert nirgends -- [auth.oidc] entsteht ja nicht. Das
# still zu schlucken saehe aus wie ein Provider, dem nicht vertraut wird,
# also sagt one-context es auf der Konsole.
render caonly \
    'MEISTER_ROLE=cloud' \
    'MEISTER_OIDC_CA=/opt/meisterstack/pki/ca.crt'

expect "CA ohne Issuer: es entsteht kein [auth.oidc]" \
    "<absent>" "$(tomlget "$CLOUD" auth.oidc)"
grepfor "CA ohne Issuer: one-context warnt auf der Konsole" \
    'MEISTER_OIDC_CA is set but MEISTER_OIDC_ISSUER is not' "$T/caonly.log" \
    "$(cat "$T/caonly.log")"

render nooidc \
    'MEISTER_ROLE=cloud' \
    'MEISTER_ADVERTISE_API=10.128.1.103:3000'

expect "ohne Issuer: die Kette ist ['mtls'] wie heute" \
    "['mtls']" "$(tomlget "$CLOUD" auth.chain)"
expect "ohne Issuer: es gibt gar kein [auth.oidc]" \
    "<absent>" "$(tomlget "$CLOUD" auth.oidc)"
expect "ohne Issuer: advertise_api bleibt Top-Level" \
    "10.128.1.103:3000" "$(tomlget "$CLOUD" advertise_api)"

# Der teuerste Fehler, den dieser Abschnitt sonst durchliesse: ein Schluessel
# im gebackenen Fragment, den es in OidcConfig nicht gibt. tomllib faende ihn
# gueltig, serde nicht -- deny_unknown_fields macht daraus einen Startfehler
# auf allen drei Cloud-Replicas gleichzeitig, und zwar erst im Lab. Also
# werden die gerenderten Schluessel gegen die Struktur im Rust geprueft, wie
# check-docs.sh es fuer Observed tut.
# Der Pfad ist mit dem Struktur-Schnitt gewandert (rest.rs -> rest/guard.rs);
# was hier zaehlt, ist die Datei, in der OidcConfig und build_chain stehen.
REST="shared/controller-api/src/rest/guard.rs"
oidc_fields="$(sed -n '/^pub struct OidcConfig {/,/^}/p' "$REST" \
               | sed -n 's/^ *pub \([a-z_][a-z0-9_]*\):.*/\1/p')"
rendered_keys="$(python3 - "$T/etc/meisterstack/cloud-auth-oidc.toml" <<'KEYS'
import sys, tomllib
with open(sys.argv[1], "rb") as fh:
    doc = tomllib.load(fh)
for k in doc.get("auth", {}).get("oidc", {}):
    print(k)
KEYS
)"
if [ -z "$oidc_fields" ]; then
    bad "OidcConfig in $REST gefunden" "sed hat keine Felder geliefert - umbenannt?"
elif [ -z "$rendered_keys" ]; then
    bad "das oidc-Fragment traegt Schluessel" "cloud-auth-oidc.toml hat kein [auth.oidc]"
else
    # Nicht `unknown`: das ist oben in der Pfadwache ein Array, und eine
    # Zeichenkette unter demselben Namen ist genau der Fehler, den shellcheck
    # SC2178 nennt.
    unknown_keys=""
    for k in $rendered_keys; do
        grep -qx "$k" <<<"$oidc_fields" || unknown_keys="$unknown_keys $k"
    done
    if [ -n "$unknown_keys" ]; then
        bad "jeder gebackene [auth.oidc]-Schluessel ist ein Feld von OidcConfig" \
            "nicht in $REST:$unknown_keys" \
            "vorhanden: $(tr '\n' ' ' <<<"$oidc_fields")"
    else
        ok "jeder gebackene [auth.oidc]-Schluessel ist ein Feld von OidcConfig"
    fi
    # Und der Schluessel, den MEISTER_OIDC_CA rendert, muss es auch sein. Er
    # kommt aus dem Kontext statt aus dem Fragment, faellt also nicht unter
    # die Schleife darueber -- und ein Startfehler waere derselbe.
    if grep -qx "ca_cert" <<<"$oidc_fields"; then
        ok "ca_cert (aus MEISTER_OIDC_CA) ist ein Feld von OidcConfig"
    else
        bad "ca_cert (aus MEISTER_OIDC_CA) ist ein Feld von OidcConfig" \
            "nicht in $REST" "vorhanden: $(tr '\n' ' ' <<<"$oidc_fields")"
    fi
    # issuer ist Pflichtfeld und darf deshalb genau NICHT im Fragment stehen:
    # ein gebackenes [auth.oidc] ohne Issuer waere ein Parse-Fehler auf jeder
    # VM, die nie einen bekommt. Er kommt aus dem Kontext, oder die Tabelle
    # entsteht gar nicht.
    for k in issuer audience; do
        if grep -qx "$k" <<<"$rendered_keys"; then
            bad "das Fragment traegt KEIN $k" "$k steht im gebackenen Fragment"
        else
            ok "das Fragment traegt KEIN $k (es kommt aus dem Kontext)"
        fi
    done
fi

# Und die zwei Namen der Kette muessen Namen sein, die build_chain kennt.
for link in mtls oidc; do
    grepfor "build_chain kennt den Kettennamen \"$link\"" \
        "^ *\"$link\" =>" "$REST" "kein match-Arm fuer \"$link\" in build_chain"
done

# Und der Cluster bleibt, was er war: dieselbe Kette, gebacken, ohne oidc --
# build_chain lehnt [auth.oidc] an diesem Tier ausdruecklich ab.
expect "der Cluster behaelt seine gebackene Kette" \
    "['mtls']" "$(tomlget "$T/run/meisterstack/cluster.toml" auth.chain)"
expect "der Cluster bekommt kein [auth.oidc]" \
    "<absent>" "$(tomlget "$T/run/meisterstack/cluster.toml" auth.oidc)"

echo
echo "K. der gebackene Kontext: ein Plan-Knoten ohne Kontext-Laufwerk"

# nix/roles.nix backt /etc/meisterstack/context.env, one-context liest sie
# BEVOR es das Laufwerk sucht. Das ist der ganze zweite Weg in dieselben
# Module: eine Kiste aus dem Plan, oder ein fremder NixOS-Host, bekommt exakt
# dieselben Dateien wie eine OpenNebula-VM -- nur die Quelle der Variablen ist
# eine andere.
render_planned planned \
    'MEISTER_ROLE=cloud,cluster,agent,addons' \
    'MEISTER_CLUSTER_NAME=box' \
    'MEISTER_CLOUD_NAME=box' \
    'MEISTER_CLOUD_ADVERTISE_API=10.0.0.10:3000' \
    'MEISTER_CLUSTER_ADVERTISE_API=10.0.0.10:3001' \
    'MEISTER_CONTROLLER_ADDRS=10.0.0.10:50051' \
    'MEISTER_OIDC_ISSUER=https://box.lab.example:8443/oauth2/openid/meister-cli'

expect "ohne Laufwerk: cluster_name kommt aus der gebackenen Datei" \
    "box" "$(tomlget "$T/run/meisterstack/cluster.toml" cluster_name)"
expect "ohne Laufwerk: cloud_name kommt aus der gebackenen Datei" \
    "box" "$(tomlget "$T/run/meisterstack/cloud.toml" cloud_name)"
expect "ohne Laufwerk: node_id bleibt der Hostname" \
    "box" "$(tomlget "$T/run/meisterstack/agent.toml" node_id)"
expect "ohne Laufwerk: der Issuer landet in [auth.oidc]" \
    "https://box.lab.example:8443/oauth2/openid/meister-cli" \
    "$(tomlget "$T/run/meisterstack/cloud.toml" auth.oidc.issuer)"

# Die zwei Adressen, die frueher eine Variable teilen mussten. Auf einer Kiste
# mit beiden Rollen kann ein Wert nicht fuer beide stimmen -- die Ports sind
# verschieden -- und genau diese Kiste ist laut Katalog der Normalfall.
expect "cloud.toml: advertise_api ist der CLOUD-Port" \
    "10.0.0.10:3000" "$(tomlget "$T/run/meisterstack/cloud.toml" advertise_api)"
expect "cluster.toml: advertise_api ist der CLUSTER-Port" \
    "10.0.0.10:3001" "$(tomlget "$T/run/meisterstack/cluster.toml" advertise_api)"

echo
echo "L. MEISTER_ROLE ist eine Komma-Liste"

grepfor "vier Rollen aus einer Liste landen in /run/meister-role" \
    '^cloud cluster agent addons$' "$T/run/meister-role" \
    "ist: $(cat "$T/run/meister-role" 2>/dev/null)"

render all_shorthand 'MEISTER_ROLE=all'
grepfor "all = alle vier" '^cloud cluster agent addons$' "$T/run/meister-role" \
    "ist: $(cat "$T/run/meister-role" 2>/dev/null)"

# `both` ist, was die zwoelf Lab-VMs und jedes vor heute geschriebene Template
# sagen. Es bedeutet weiter dasselbe.
render both_shorthand 'MEISTER_ROLE=both'
grepfor "both = cloud cluster, wie bisher" '^cloud cluster$' "$T/run/meister-role" \
    "ist: $(cat "$T/run/meister-role" 2>/dev/null)"

render one_role 'MEISTER_ROLE=agent'
grepfor "eine Rolle bleibt eine Rolle" '^agent$' "$T/run/meister-role" \
    "ist: $(cat "$T/run/meister-role" 2>/dev/null)"

echo
echo "M. gebacken und Kontext zugleich: der Kontext gewinnt"

# Der Plan sagt, was die Kiste sein SOLL; der Kontext sagt, wo sie
# tatsaechlich gebootet wurde. Das zweite ist die staerkere Aussage -- sonst
# koennte man eine Flotte nie umhaengen, ohne sie neu zu bauen.
render_planned_ctx override \
    'MEISTER_ROLE=cluster' \
    'MEISTER_CLUSTER_NAME=aus-dem-plan' \
    'MEISTER_OTLP_ENDPOINT=http://10.0.0.10:4317' \
    -- \
    'MEISTER_ROLE=cluster' \
    'MEISTER_CLUSTER_NAME=aus-dem-kontext'

expect "der Kontext ueberschreibt den Plan" \
    "aus-dem-kontext" "$(tomlget "$T/run/meisterstack/cluster.toml" cluster_name)"
expect "was der Kontext nicht nennt, bleibt der Plan" \
    "http://10.0.0.10:4317" \
    "$(tomlget "$T/run/meisterstack/cluster.toml" otlp_endpoint)"

echo
echo "==> $pass ok, $fail FAIL"
[ "$fail" -eq 0 ]
