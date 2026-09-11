#!/usr/bin/env bash
# MeisterStack Agent — CLI Smoke Tests
#
# Teil A/B brauchen weder Hardware noch Root: alle geprüften Fehler entstehen
# vor dem Provisionieren (into_spec -> catalog.validate -> check_exclusive_devices).
# Teil C (SMOKE_FULL=1) bootet echte VMs und braucht Image + cloud-hypervisor.
#
#   ./smoke.sh
#   SMOKE_FULL=1 SMOKE_SPEC=./specs/minimal.json ./smoke.sh
#   DEBUG=1 ./smoke.sh          # zeigt jedes generierte Spec-File
#
# Env:
#   MEISTER        Pfad zur CLI            (default: ./target/debug/meister)
#   SOCK           Agent-Socket            (default: /tmp/run/meisterstack/agent.sock)
#   MEISTER_CONFIG CLI-Config              (optional, sonst --endpoint)
#   SMOKE_VFIO_PCI PCI-Adresse aus [[device.managed]] (default: 0000:23:00.0)
 
set -uo pipefail
 
MEISTER="${MEISTER:-./target/debug/meister}"
SOCK="${SOCK:-/tmp/run/meisterstack/agent.sock}"
SMOKE_VFIO_PCI="${SMOKE_VFIO_PCI:-0000:23:00.0}"
TMP="$(mktemp -d)"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT
 
pass=0; fail=0
red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
 
if [ -n "${MEISTER_CONFIG:-}" ]; then
  CLI=("$MEISTER")
else
  CLI=("$MEISTER" --endpoint "unix://$SOCK")
fi
cli() { "${CLI[@]}" "$@"; }
 
# ok <name> -- <cmd...>   (cmd darf auch eine Shell-Funktion sein)
ok() {
  local name="$1"; shift; [ "${1:-}" = "--" ] && shift
  local out rc
  out="$("$@" 2>&1)"; rc=$?
  if [ $rc -eq 0 ]; then green "  ok   $name"; pass=$((pass+1))
  else red "  FAIL $name"; printf '       %s\n' "$out"; fail=$((fail+1)); fi
}
 
# nok <name> <substring> -- <cmd...>   : muss failen UND die Meldung enthalten
nok() {
  local name="$1" want="$2"; shift 2; [ "${1:-}" = "--" ] && shift
  local out rc
  out="$("$@" 2>&1)"; rc=$?
  if [ $rc -eq 0 ]; then
    red "  FAIL $name (unerwartet erfolgreich)"; printf '       %s\n' "$out"; fail=$((fail+1))
  elif ! grep -qF -- "$want" <<<"$out"; then
    red "  FAIL $name (Meldung passt nicht)"
    printf '       erwartet: %s\n       bekommen: %s\n' "$want" "${out//$'\n'/ }"; fail=$((fail+1))
  else
    green "  ok   $name"; pass=$((pass+1))
  fi
}
 
# spec <name> [devices-json] [nics-json] [vcpus] [extra-toplevel-json]
#   -> schreibt das File und echoed den Pfad
spec() {
  local name="$1"
  local devices="${2:-}" nics="${3:-}" vcpus="${4:-}" extra="${5:-}"
  # ACHTUNG: Defaults NICHT über ${x:-[{}]} setzen — Bash beendet die
  # Expansion am ersten '}' und liefert '[{' + ']}' als Textrest.
  [ -z "$devices" ] && devices='[]'
  [ -z "$nics"    ] && nics='[{}]'
  [ -z "$vcpus"   ] && vcpus='1'
 
  local f="$TMP/$name.json"
  cat >"$f" <<EOF
{
  "vcpus": $vcpus,
  "memory_mib": 256,
  "boot": { "kind": "direct_kernel", "kernel": "vmlinux", "cmdline": "console=ttyS0" },
  "volumes": [ { "size_bytes": 1048576 } ],
  "nics": $nics,
  "devices": $devices$extra
}
EOF
  if [ "${DEBUG:-0}" = "1" ]; then cat "$f" >&2; fi
  echo "$f"
}
 
# --- Helfer, damit ok/nok keine verschachtelten `bash -c` brauchen ---
healthz()      { curl -sf --unix-socket "$SOCK" http://localhost/healthz | grep -q ok; }
create()       { cli agent vm create -f "$1"; }
ls_has()       { cli -o json agent vm ls | grep -q "$1"; }
ls_health_ok() { cli agent vm ls | awk -v id="$1" '$1==id && $4=="ok"' | grep -q .; }
# ACHTUNG: der zweite Parameter ist ein FELDNAME aus `Observed`
# (components/agent/src/reconcile.rs). Ein Name, den es dort nicht gibt,
# meldet sich als echter FAIL des Lifecycle-Teils und nicht als Tippfehler
# im Test — genau so ueberlebte `devices_alive` hier den Umbenennen-Commit
# 0613553 (devices_alive -> backends_alive). scripts/check-docs.sh haelt
# die Namen darum gegen die Struktur im Code.
observe_has()  { cli -o json agent observe "$1" | grep -q "$2"; }
reconcile_is() { cli agent reconcile "$1" | grep -q "$2"; }
 
# ---------------------------------------------------------------- A: Preflight
echo
echo "A. Preflight"
 
[ -x "$MEISTER" ] || { red "  CLI nicht gefunden: $MEISTER  (cargo build)"; exit 1; }
[ -S "$SOCK" ]    || { red "  Kein Agent-Socket: $SOCK  (meister-agent --config config/agent.dev.toml)"; exit 1; }
 
ok "healthz antwortet" -- healthz
ok "ls läuft (table)"  -- cli agent vm ls
ok "ls läuft (json)"   -- cli -o json agent vm ls
 
# Selbsttest: der Generator muss gültiges JSON liefern, sonst testen wir nur ihn
ok "spec-generator liefert gültiges json" -- \
  python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$(spec selftest)"
 
# ---------------------------------------------------- B: Validierung ohne Boot
echo
echo "B. Spec-Validierung (kein Provisioning)"
 
nok "unbekannter Driver" "is not configured on this node" -- \
  create "$(spec unknown_driver '[{"driver":"nope","partition":"mediated"}]')"
 
nok "unbekanntes Profil" "has no profile" -- \
  create "$(spec unknown_profile '[{"partition":"mediated","profile":"gibtsnicht"}]')"
 
nok "vfio ohne pci_address" "requires params.pci_address" -- \
  create "$(spec vfio_noparams '[{"driver":"vfio","partition":"exclusive"}]')"
 
nok "vfio mit kaputter pci_address" "invalid pci_address" -- \
  create "$(spec vfio_badaddr '[{"driver":"vfio","partition":"exclusive","params":{"pci_address":"nicht-hex"}}]')"
 
nok "dieselbe pci_address zweimal im Spec" "requested twice" -- \
  create "$(spec vfio_dupe "[{\"driver\":\"vfio\",\"partition\":\"exclusive\",\"params\":{\"pci_address\":\"$SMOKE_VFIO_PCI\"}},{\"driver\":\"vfio\",\"partition\":\"exclusive\",\"params\":{\"pci_address\":\"$SMOKE_VFIO_PCI\"}}]")"
 
nok "unbekannte partition" "unknown partition type" -- \
  create "$(spec bad_partition '[{"partition":"halbgar"}]')"
 
nok "vcpus = 0" "vcpus must be greater than zero" -- \
  create "$(spec vcpu0 '' '' 0)"
 
nok "unbekanntes Feld im Spec" "unknown field" -- \
  create "$(spec junk '' '' '' ', "quatsch": true')"
 
nok "desired = Absent bei create" "not a valid creation target" -- \
  create "$(spec absent '' '' '' ', "desired": "Absent"')"
 
echo '{ not json' > "$TMP/broken.json"
nok "kaputtes JSON -> lokal abgefangen" "not valid json" -- create "$TMP/broken.json"
 
# Rückwärtskompatibilität: der serde-Alias muss weiter greifen
nok "driver_name-Alias wird gelesen" "is not configured on this node" -- \
  create "$(spec alias '[{"driver_name":"nope","partition":"mediated"}]')"
 
GHOST="00000000-0000-4000-8000-000000000000"
nok "inspect unbekannte VM" "404"           -- cli agent vm get "$GHOST"
nok "observe unbekannte VM" "404"           -- cli agent observe "$GHOST"
nok "ungültige UUID"        "invalid vm id" -- cli agent vm get "keine-uuid"
 
# ------------------------------------------------------- C: Lifecycle (opt-in)
if [ "${SMOKE_FULL:-0}" != "1" ]; then
  echo
  echo "C. Lifecycle übersprungen (SMOKE_FULL=1 SMOKE_SPEC=... zum Aktivieren)"
else
  echo
  echo "C. Lifecycle (bootet echte VMs)"
 
  SPEC="${SMOKE_SPEC:?SMOKE_SPEC muss auf ein bootfähiges Spec-File zeigen}"
  VM="$(cli -o json agent vm create -f "$SPEC" | grep -o '"id"[^,}]*' | cut -d'"' -f4)"
  if [ -z "$VM" ]; then
    red "  FAIL create lieferte keine id"; fail=$((fail+1))
  else
    green "  vm: $VM"
    cleanup() { cli --yes agent vm rm "$VM" >/dev/null 2>&1; rm -rf "$TMP"; }
 
    ok  "ls listet die VM"          -- ls_has "$VM"
    ok  "health-Spalte = ok"        -- ls_health_ok "$VM"
    ok  "observe hat backends_alive" -- observe_has "$VM" backends_alive
    ok  "reconcile konvergiert"     -- reconcile_is "$VM" None
 
    ok  "stop"  -- cli agent stop "$VM" --grace 5
    sleep 6
    ok  "start" -- cli agent start "$VM"
    sleep 2
 
    # Exklusiv-Konflikt braucht eine zweite existierende VM -> hier statt Teil B
    if grep -q '"vfio"' "$SPEC" 2>/dev/null; then
      nok "pci-Adresse doppelt vergeben" "already assigned to vm" -- create "$SPEC"
    fi
 
    ok  "destroy" -- cli --yes agent vm rm "$VM"
    sleep 1
    nok "nach destroy weg" "404" -- cli agent vm get "$VM"
    cleanup() { rm -rf "$TMP"; }
  fi
fi

# --------------------------------------------------------- D: nvrm (opt-in)
# Bootet eine vGPU-VM über den nvrm-Treiber. Braucht einen NVIDIA-Host mit
# passendem Treiber, gebaute Leandro-Binaries und ein bootfähiges Spec
# (z. B. /mnt/vmstore/MeisterStack/specs/nvrm-4q.json).
# WICHTIG: nvrm-VMs nie im Guest rebooten — der virtio-Reset beendet den
# Backend und die VM landet in Quarantäne; stop/start ist der Weg.
if [ "${SMOKE_NVRM:-0}" != "1" ]; then
  echo
  echo "D. nvrm übersprungen (SMOKE_NVRM=1 SMOKE_NVRM_SPEC=... zum Aktivieren)"
else
  echo
  echo "D. nvrm (bootet eine vGPU-VM)"

  NSPEC="${SMOKE_NVRM_SPEC:?SMOKE_NVRM_SPEC muss auf ein nvrm-Spec-File zeigen}"
  NVM="$(cli -o json agent vm create -f "$NSPEC" | grep -o '"id"[^,}]*' | cut -d'"' -f4)"
  if [ -z "$NVM" ]; then
    red "  FAIL create lieferte keine id"; fail=$((fail+1))
  else
    green "  vm: $NVM"
    sleep 3
    ok  "health-Spalte = ok"        -- ls_health_ok "$NVM"
    ok  "observe hat backends_alive" -- observe_has "$NVM" backends_alive
    ok  "reconcile konvergiert"     -- reconcile_is "$NVM" None

    # Admission: dasselbe Spec nochmal muss am max_instance-Limit scheitern,
    # solange das Profil nur eine Instanz erlaubt — sonst läuft es durch und
    # wird hier wieder abgeräumt.
    if [ "${SMOKE_NVRM_EXPECT_LIMIT:-0}" = "1" ]; then
      nok "zweite Instanz am Limit abgelehnt" "already active" -- create "$NSPEC"
    fi

    ok  "destroy" -- cli --yes agent vm rm "$NVM"
    sleep 1
    nok "nach destroy weg" "404" -- cli agent vm get "$NVM"
  fi
fi

# ------------------------------------------------------------------ Ergebnis
echo
if [ "$fail" -eq 0 ]; then green "$pass ok, 0 fehlgeschlagen"; exit 0
else red "$pass ok, $fail fehlgeschlagen"; exit 1; fi

