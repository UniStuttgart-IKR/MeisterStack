#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
# SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR
#
# MeisterStack — Trockenlauf fuer `deploy/push.sh pki`
#
# Der Push entscheidet, WELCHE Datei auf einem Host den festen Namen
# serving.crt bzw. identity.crt bekommt. Das ist die Stelle, an der ein
# Zertifikat auf dem falschen Host landen kann, und im Lab merkt man das erst
# am Handshake -- auf zwoelf produktiven VMs.
#
# Also hier: eine erfundene Flotte in einem Temp-Verzeichnis, ssh und rsync als
# Stubs im PATH, und danach die Frage, ob jeder Host genau die Dateien unter
# genau den Namen hat, die ihm gehoeren. Kein SSH, kein Lab, kein Root.
#
#   scripts/check-push-pki.sh    # Exit 0 = alles konsistent
#
# Was die Stubs NICHT pruefen koennen: chown auf `meister` (dafuer braucht es
# Rechte, die ein Test nicht hat) und die Uebertragung selbst. Die Modi sind
# echt -- chmod laeuft.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

pass=0
fail=0
ok()  { printf '  ok   %s\n' "$1"; pass=$((pass + 1)); }
bad() { printf '  FAIL %s\n' "$1"; shift; for l in "$@"; do printf '       %s\n' "$l"; done; fail=$((fail + 1)); }

# --- die erfundene Flotte ---------------------------------------------------
# Zwei Agents, zwei Cluster-Replicas (verschiedene Cluster!), eine Cloud. Die
# zwei Cluster sind der Punkt: identity.* kommt aus dem cluster_name und nicht
# aus dem Hostnamen, also muss ein Lauf beide auseinanderhalten.
FLEET="$T/fleet"
declare -A HOSTNAME=(
    [10.0.0.6]=agent-1a
    [10.0.0.7]=agent-2a
    [10.0.0.4]=cluster-1a
    [10.0.0.5]=cluster-2a
    [10.0.0.3]=cloud-a
)
declare -A CLUSTER_OF=(
    [10.0.0.4]=cluster-1
    [10.0.0.5]=cluster-2
)
# Die Cloud heisst anders als ihr Host, genau wie ein Cluster: identity.* der
# Cloud kommt aus cloud_name, nicht aus dem Hostnamen.
declare -A CLOUD_OF=(
    [10.0.0.3]=lab
)
for ip in "${!HOSTNAME[@]}"; do
    mkdir -p "$FLEET/$ip/opt/meisterstack/pki" "$FLEET/$ip/run/meisterstack"
    echo "${HOSTNAME[$ip]}" > "$FLEET/$ip/hostname"
    if [ -n "${CLUSTER_OF[$ip]:-}" ]; then
        printf 'cluster_name = "%s"\nmetrics_listen = "0.0.0.0:9101"\n' \
            "${CLUSTER_OF[$ip]}" > "$FLEET/$ip/run/meisterstack/cluster.toml"
    fi
    if [ -n "${CLOUD_OF[$ip]:-}" ]; then
        printf 'cloud_name = "%s"\nmetrics_listen = "0.0.0.0:9100"\n' \
            "${CLOUD_OF[$ip]}" > "$FLEET/$ip/run/meisterstack/cloud.toml"
    fi
done

# --- das erfundene PKI-Verzeichnis ------------------------------------------
# Jede Datei traegt ihren eigenen Namen als Inhalt. Damit ist "welche Quelle
# wurde zu welchem Ziel" hinterher ablesbar, statt nur "eine Datei ist da".
PKI="$T/labpki"
mkdir -p "$PKI"
make_pem() { echo "$1" > "$PKI/$1"; }
make_pem ca.crt
for h in agent-1a agent-2a cluster-1a cluster-2a cloud-a; do
    case "$h" in
        cluster-*|cloud-*) make_pem "$h.crt"; make_pem "$h.key" ;;
    esac
done
for n in agent-1a agent-2a; do make_pem "system-node-$n.crt"; make_pem "system-node-$n.key"; done
for c in cluster-1 cluster-2; do make_pem "system-cluster-$c.crt"; make_pem "system-cluster-$c.key"; done
for c in lab; do make_pem "system-cloud-$c.crt"; make_pem "system-cloud-$c.key"; done
# Der eine Schluessel, der auf ZWEI Tiers gehoert und kein Zertifikat ist.
make_pem secrets.key

# --- ssh und rsync als Stubs ------------------------------------------------
# push.sh ruft beide in genau zwei Formen auf:
#   ssh   <opts...> user@ip "<kommando>"        -> letztes Argument = Kommando
#   rsync -e "ssh ..." <quelle>/ user@ip:<pfad> -> letztes Argument = Ziel
mkdir -p "$T/bin"
cat > "$T/bin/ssh" <<STUB
#!/usr/bin/env bash
# Letztes Argument ist das Kommando, das davor das Ziel.
cmd="\${!#}"
dest="\${@:(-2):1}"
ip="\${dest#*@}"
root="$FLEET/\$ip"
[ -d "\$root" ] || { echo "stub-ssh: unknown host \$ip" >&2; exit 255; }
# Pfade in die erfundene Wurzel umlenken, chown/chgrp neutralisieren: ein Test
# darf keine Datei einer Gruppe uebereignen, die es hier nicht gibt.
cmd="\${cmd//\\/opt\\/meisterstack/\$root/opt/meisterstack}"
cmd="\${cmd//\\/run\\/meisterstack/\$root/run/meisterstack}"
cmd="\${cmd//\\/proc\\/sys\\/kernel\\/hostname/\$root/hostname}"
exec bash -c "chown() { :; }; chgrp() { :; }; \$cmd"
STUB
cat > "$T/bin/rsync" <<STUB
#!/usr/bin/env bash
dest="\${!#}"
src="\${@:(-2):1}"
ip="\${dest#*@}"; ip="\${ip%%:*}"
path="\${dest#*:}"
root="$FLEET/\$ip"
[ -d "\$root" ] || { echo "stub-rsync: unknown host \$ip" >&2; exit 255; }
# Wie das echte rsync: ein Verzeichnis als Quelle braucht -r (oder -a), sonst
# wird es uebersprungen und NICHTS kopiert -- exit 0, ohne Fehler. Genau das
# hat der erste Lauf gegen die echte Flotte getan, und dieser Stub hat es
# nicht nachgestellt, weil er stumpf kopiert hat.
if [ -d "\$src" ]; then
  case " \$* " in
    *" -r "*|*" -a "*|*" -rL "*|*" -av "*) ;;
    *) echo "skipping directory ."; exit 0 ;;
  esac
fi
mkdir -p "\$root\$path"
cp -a "\$src". "\$root\$path" 2>/dev/null || cp -a "\$src" "\$root\$path"
STUB
chmod +x "$T/bin/ssh" "$T/bin/rsync"
export PATH="$T/bin:$PATH"

# --- die env-Datei, die push.sh liest ---------------------------------------
cat > "$T/env" <<ENV
MEISTER_CLOUD_IPS="10.0.0.3"
MEISTER_CLUSTER_IPS="10.0.0.4 10.0.0.5"
MEISTER_AGENT_IPS="10.0.0.6 10.0.0.7"
MEISTER_SSH_USER=root
MEISTER_SSH_KEY=$T/nokey
MEISTER_SSH_STRICT=no
ENV

run_push() { MEISTER_ENV="$T/env" MEISTER_PKI_DIR="$PKI" ./deploy/push.sh pki > "$T/$1.log" 2>&1; }

echo
echo "A. der ganze Lauf: jeder Host bekommt genau das Seine"

run_push full
rc=$?
if [ $rc -eq 0 ]; then
    ok "push.sh pki laeuft durch (exit 0)"
else
    bad "push.sh pki bricht ab (exit $rc)" "$(tail -20 "$T/full.log")"
fi

# have <ip> <datei> <erwarteter inhalt>
have() {
    local ip=$1 file=$2 want=$3 p="$FLEET/$1/opt/meisterstack/pki/$2"
    if [ ! -f "$p" ]; then
        bad "${HOSTNAME[$ip]}: $file fehlt"
        return
    fi
    local got; got="$(cat "$p")"
    if [ "$got" = "$want" ]; then
        ok "${HOSTNAME[$ip]}: $file <- $want"
    else
        bad "${HOSTNAME[$ip]}: $file kommt aus der falschen Quelle" "erwartet: $want" "ist:      $got"
    fi
}

# absent <ip> <datei>
absent() {
    local ip=$1 file=$2
    if [ -e "$FLEET/$1/opt/meisterstack/pki/$2" ]; then
        bad "${HOSTNAME[$ip]}: $file sollte hier nicht liegen"
    else
        ok "${HOSTNAME[$ip]}: kein $file, richtig so"
    fi
}

have 10.0.0.6 ca.crt       ca.crt
have 10.0.0.6 identity.crt system-node-agent-1a.crt
have 10.0.0.6 identity.key system-node-agent-1a.key
absent 10.0.0.6 serving.crt
have 10.0.0.7 identity.crt system-node-agent-2a.crt

have 10.0.0.4 ca.crt       ca.crt
have 10.0.0.4 serving.crt  cluster-1a.crt
have 10.0.0.4 serving.key  cluster-1a.key
have 10.0.0.4 identity.crt system-cluster-cluster-1.crt
have 10.0.0.5 serving.crt  cluster-2a.crt
have 10.0.0.5 identity.crt system-cluster-cluster-2.crt

have 10.0.0.3 ca.crt      ca.crt
have 10.0.0.3 serving.crt cloud-a.crt
have 10.0.0.3 serving.key cloud-a.key
# Aus cloud_name und nicht aus dem Hostnamen: die drei Replicas einer Cloud
# teilen sich diese eine Identitaet. Eine Cloud ohne cloud_name in der
# gerenderten Config faellt auf "cloud" zurueck, wie das Binary auch.
have 10.0.0.3 identity.crt system-cloud-lab.crt
have 10.0.0.3 identity.key system-cloud-lab.key
# secrets.key auf BEIDEN Controller-Tiers und auf keinem Agenten: die Cloud
# versiegelt, der Cluster oeffnet, und ein Knoten bekommt den Klartext ueber
# seine Session und hat fuer den Schluessel keine Verwendung.
have 10.0.0.3 secrets.key secrets.key
have 10.0.0.4 secrets.key secrets.key
have 10.0.0.5 secrets.key secrets.key
absent 10.0.0.6 secrets.key
absent 10.0.0.7 secrets.key

echo
echo "B. die Reihenfolge: agents, dann cluster, dann cloud"

order="$(grep -o '^==> pki -> [a-z0-9-]* ([a-z]*' "$T/full.log" | sed 's/.*(//' | tr '\n' ' ')"
if [ "$order" = "agent agent cluster cluster cloud " ]; then
    ok "agents -> cluster -> cloud ($order)"
else
    bad "die Reihenfolge stimmt nicht" "ist: $order" \
        "ein Cluster, der Client-Zertifikate verlangt, bevor sein Agent eines hat, sieht ihn nie wieder"
fi

echo
echo "C. die Rechte: 0600 auf den Schluesseln, 0644 auf den Zertifikaten"

key_modes="$(find "$FLEET" -name '*.key' -exec stat -c '%a' {} + | sort -u | tr '\n' ' ')"
crt_modes="$(find "$FLEET" -name '*.crt' -exec stat -c '%a' {} + | sort -u | tr '\n' ' ')"
if [ "$key_modes" = "600 " ]; then
    ok "jeder private Schluessel ist 0600"
else
    bad "ein privater Schluessel ist nicht 0600" "gefundene Modi: $key_modes" \
        "pki::pem::check_permissions lehnt JEDES Gruppen- oder Other-Bit ab"
fi
if [ "$crt_modes" = "644 " ]; then
    ok "jedes Zertifikat ist 0644"
else
    bad "ein Zertifikat ist nicht 0644" "gefundene Modi: $crt_modes"
fi

echo
echo "D. ein Host ohne Datei ist ein Fehler mit seinem Namen, kein stiller Skip"

rm -f "$PKI/system-node-agent-2a.key"
rm -rf "$FLEET/10.0.0.7/opt/meisterstack/pki"
mkdir -p "$FLEET/10.0.0.7/opt/meisterstack/pki"
run_push missing
rc=$?
if [ $rc -ne 0 ]; then
    ok "push.sh pki bricht ab (exit $rc)"
else
    bad "push.sh pki laeuft durch, obwohl eine Datei fehlt"
fi
if grep -q "agent-2a" "$T/missing.log" && grep -q "system-node-agent-2a.key" "$T/missing.log"; then
    ok "die Meldung nennt den Host UND die fehlende Datei"
else
    bad "die Meldung nennt nicht beides" "$(tail -10 "$T/missing.log")"
fi
if [ -z "$(ls -A "$FLEET/10.0.0.7/opt/meisterstack/pki")" ]; then
    ok "auf dem Host liegt nichts Halbes"
else
    bad "der abgebrochene Lauf hat halbe Dateien hinterlassen" \
        "$(ls -A "$FLEET/10.0.0.7/opt/meisterstack/pki")"
fi

echo
echo "==> $pass ok, $fail FAIL"
[ "$fail" -eq 0 ]
