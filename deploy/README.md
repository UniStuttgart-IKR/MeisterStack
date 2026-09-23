<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR
-->

# Deployment

Vier Formen, von der kleinsten zur groessten. Alle vier bauen auf
denselben NixOS-Modulen auf; was sich unterscheidet, ist nur, wer der
Maschine sagt, was sie ist.

| Form | wofuer | wie |
|---|---|---|
| **Prozesse** | Entwicklung auf dem eigenen Rechner, drei Binaries nebeneinander | `config/*.dev.toml`, `scripts/smoke.sh`. Ein eigener kleiner Brief folgt. |
| **Eine VM** | einen Knoten einmal wirklich booten sehen, ohne Blech | `nixos-rebuild build-vm --flake .#box`, dann `./result/bin/run-*-vm` |
| **Kiste plus Knoten** | der Normalfall: 1-5 Maschinen im Labor | `fleet.toml`, `meister-deploy` — siehe `config/examples/one-box/README.md` |
| **Eine Flotte** | 1-70 Maschinen, gemischte Hardware, aus dem eigenen Repo | `meister-deploy init`, dann `resolve` -> `build` -> `plan` -> `apply` — das Runbook ist `docs/DEPLOYMENT.md` |

## Der Plan

Eine Datei, `fleet.toml`, beschreibt die Flotte. **Abgeleitet wird sie
nur noch an einer Stelle** (seit meister-deploy v1): `nix/lib/inventory.nix`
liest Schema 2 und leitet jeden Deploymentwert ab; `meister-deploy` liest
dieselbe Datei nur fuer ihre Gestalt (`inventory`, `validate`). Was beide
noch teilen, ist die Praezedenz defaults < group < host, und der Check
`inventory-parity` vergleicht ihre Antworten dafuer. `nix/fleet.nix` und
`scripts/check-fleet.sh` sind damit weg.

Was **abgeleitet** und nie zweimal getippt wird: die etcd-Peers und das
Bootstrap-Token je Raft-Gruppe, `cluster_name` und `cloud_name`, die
`controller_addrs` der Agents, die `cloud_addrs` der Cluster, beide
`advertise_api`, die Scrape-Liste und der OIDC-Issuer. Ein Plan sagt, wer
zu welcher Gruppe gehoert; die Adressen folgen.

## Die Verben

Abgelesen an `tools/meister-deploy/src/main.rs`. Die **Effektklasse** ist die
des Werkzeugs selbst (`run::Effect`): `--offline` laesst nur `offline` durch,
`--dry-run` nur `offline` und `read` — beides sind Eigenschaften des
Programms und keine Zusage in Prosa. **Exit** ist 0 = ja, 1 = es hat nicht
funktioniert, 2 = es hat funktioniert und die Antwort ist nein (ein Plan, der
etwas nicht anfassen will; ein Lauf, der auf einen Provider wartet).

| Verb | Effektklasse | `--dry-run` | `--offline` | Exit |
|---|---|---|---|---|
| `init <dir>` | local-write | listet die Dateien, schreibt nichts | – | 0/1 |
| `inventory [--json]` | offline | – | – | 0/1 |
| `validate [--nix] [--manifest <f>]` | offline (mit `--nix`: nix-eval) | – | – | 0/1 |
| `resolve --out m.json [--from f] [--dev] [--hosts …]` | nix-eval + local-write | zeigt die Kommandozeile, schreibt nichts | verweigert | 0/1 |
| `build --manifest m.json --out r.json [--sign-key …]` | build + local-write | zeigt die Derivationen | verweigert | 0/1 |
| `image --release r.json --host <id> --kind installer\|disk\|direct-boot` | build | zeigt die Kommandozeile | verweigert | 0/1 |
| `install --plan p.json --release r.json --host <id> --approve destructive=<plan_id>` | build (Medium) + local-write | druckt das Blatt, baut nichts | verweigert | 0/1/2 |
| `plan --release r.json --select <expr> [--kind upgrade\|bootstrap\|install]` | read + local-write | fragt die Hosts, schreibt nichts | Schnappschuss-frei, `provisional`, nur nach stdout | 0/2 |
| `apply --plan p.json --release r.json [--resume <run>] [--takeover <run>]` | target-write | schaut, prueft, nennt die Schritte — keine Sperre, kein Journal | – | 0/1/2 |
| `status` / `check --release r.json [--suite readiness]` | read | – | antwortet aus dem letzten Schnappschuss | 0/2 |
| `report --run <id>` | offline (liest das Zustandsverzeichnis) | – | – | 0/1 |
| `verify --release r.json --suite vm-lifecycle\|gpu\|rdma --approve verify=<release_id>` | target-write (Ledger, echte Gaeste, Cleanup) | listet die Schritte | verweigert | 0/1/2 |
| `keys enroll <host> --fingerprint SHA256:…` | read + local-write | zeigt den Schluessel, schreibt nicht | verweigert | 0/1 |
| `keys csr --host <id> --kind identity\|serving [--as <tier>]` | target-write (der Schluessel entsteht am Ziel) | zeigt das Subjekt | – | 0/1 |
| `keys issue --host <id> --kind node\|cluster\|cloud\|serving` | key (offline, nur diese Maschine) | zeigt das Subjekt | – | 0/1 |
| `keys revoke --serial <s>\|--host <id>\|--refresh --release r.json` | key + read + local-write, danach ein Plan | zeigt die zwei CA-Kommandos | – | 0/1/2 |
| `keys rotate --host <id> --kind identity\|serving --release r.json` | key + target-write (der neue Schluessel entsteht am Ziel), danach ein Plan | zeigt, was vorbereitet wuerde | – | 0/1/2 |
| `keys import --from <dir> --map <host>=<stem> --manifest m.json` | key + local-write (offline) | zeigt, was wohin ginge | – | 0/1 |
| `retire <host> --release r.json` | key + local-write, danach ein Plan an die uebrigen Hosts | zeigt die CA-Kommandos, schreibt nichts | – | 0/1/2 |
| `gc --keep N [--older-than 14] [--observations N] [--runs]` | local-write (nur GC-Wurzeln) | nennt die Releases | – | 0/1 |
| `schema <art>` | offline | – | – | 0/1 |

Genehmigt wird ausschliesslich mit `--approve <klasse>=<plan_id>`; ein
globales `--force` gibt es nicht, und eine Freigabe nennt den Plan, fuer den
sie gilt. `meister deploy …` ruft dasselbe Binary auf, wenn es neben der CLI
oder im PATH liegt.

### Warum `push` ein Programm ist und keine Schleife

Weil die Reihenfolge zaehlt und weil dazwischen gewartet werden muss.
Agents zuerst, dann Cluster, dann Clouds, dann Addons — der untere Tier
zuerst, damit ein Controller nie einen Befehl gibt, den die Etage darunter
noch nicht versteht. Und **innerhalb einer Raft-Gruppe ein Knoten nach dem
anderen**: drei gleichzeitig neugestartete etcd-Mitglieder sind ein Cluster
ohne Quorum, und der Neustart dauert vier Sekunden. Der naechste wird erst
angefasst, wenn der letzte wieder gesund ist (Unit aktiv, Session ok, bei
Controllern etcd-Member healthy). Kommt einer nicht zurueck, bricht die
Gruppe ab, und der Satz sagt, wie viele nicht mehr angefasst wurden.

## Ein fremder Host

Ein Host mit eigener NixOS-Konfiguration — NVIDIA, Mellanox, ein Kernel,
eine auf dem Blech erzeugte `hardware-configuration.nix` — soll nichts
davon aufgeben muessen, um Knoten dieser Flotte zu sein. Also importiert
er die Module und sagt, was er ist:

```nix
{
  inputs.meisterstack.url = "github:UniStuttgart-IKR/MeisterStack";

  outputs = { nixpkgs, meisterstack, ... }: {
    nixosConfigurations.mine = nixpkgs.lib.nixosSystem {
      modules = [
        ./hardware-configuration.nix
        meisterstack.nixosModules.default
        {
          meisterstack.roles = [ "cloud" "cluster" ];
          meisterstack.cloud.settings.listen_api = "0.0.0.0:3000";
        }
      ];
    };
  };
}
```

`examples/fleet/foreign-flake/` ist genau das, und `nix flake check`
evaluiert es — der Export kann also nicht unbemerkt aufhoeren, allein zu
stehen. Ein Host, der in einem Inventar steht, braucht das nicht von Hand:
`meisterstack.lib.mkFleet` baut sein Modul aus dem `[[host]]`-Eintrag, und
`(mkFleet {…}).hostModules.<id>` ist genau diese Datei als Wert.

Die Zertifikate kommen in keinem Fall aus dem Nix-Store: sie werden von der
Plan-Aktion `deliver-secret` nach `meisterstack.pki.dir` gelegt (`apply`
fuehrt sie aus), und bis dahin bleiben die Units sichtbar uebersprungen.

## Von der leeren Platte zur laufenden Flotte

Zwoelf Zeilen, und jede davon laeuft so in `nix/tests/bootstrap.nix` —
`checks.vm-bootstrap-fleet` ist dieser Ablauf gegen zwei leere virtuelle
Platten.

```
meister-deploy resolve --repo . --out m.json                 # das Manifest dieses Baums
meister-deploy build --manifest m.json --sign-key keys/signing.sec --out r.json
meister-deploy plan --release r.json --select all --kind install --out p-install.json
meister-deploy install --plan p-install.json --release r.json --host box \
    --approve destructive=<plan_id>                          # baut das Medium, druckt das Blatt
#   Medium booten. Auf der Konsole der Maschine:
#     meister-install confirm --host box --disk <serial>
#   Die letzte Zeile ist   HOST KEY FINGERPRINT  SHA256:…
meister-deploy keys enroll box --fingerprint SHA256:…        # known_hosts, ausser Band geprueft
meister-deploy keys csr --host box --kind identity --as cluster --manifest m.json
meister-deploy keys issue --host box --kind cluster --manifest m.json
meister-deploy plan --release r.json --select all --kind bootstrap --out p-boot.json
meister-deploy apply --plan p-boot.json --release r.json --approve singleton=<plan_id> …
meister-deploy check --release r.json                        # Exit 0 = die Flotte ist, was sie sein soll
```

Danach ist ein Update dieselbe Strecke ohne die ersten fuenf Zeilen:
`resolve` -> `build` -> `plan` -> `apply`. Ein Host mit
`boot = "direct"` haelt bei einem Kernelwechsel an (`provider-reboot`): der
Lauf endet mit Exit 2, einer JSON-Zeile mit Kernel, Initrd und
Kommandozeile, und geht nach `apply --resume <run-id>` weiter, sobald der
Provider die Maschine damit gestartet hat.

### nixos-anywhere als Alternative

**nixos-anywhere** installiert dieselben Systeme ohne Medium: es kexect
einen NixOS-Installer auf eine Kiste, die schon irgendein Linux mit SSH
faehrt, partitioniert mit demselben disko-Layout
(`install.layout` im Inventar) und installiert
`.#nixosConfigurations.<id>`. Der Rest des Vertrags bleibt danach
unveraendert: `keys enroll` mit dem Fingerprint, den die Maschine zeigt,
dann `plan --kind bootstrap` und `apply`.

Was es nicht tut, und weshalb hier trotzdem ein Medium gebaut wird:

* Es prueft **keine Datentraegerfreigabe**. `meister-install confirm`
  loest die Serial aus `lsblk -J` auf, vergleicht sie mit der im Inventar,
  besteht auf Eindeutigkeit (zwei Platten mit derselben Serial sind ein
  Abbruch) und zeigt Groesse, Modell und Umfang, bevor irgendetwas
  formatiert wird. nixos-anywhere bekommt ein Ziel genannt und glaubt es.
* Es hinterlaesst **keine Installationsmarke**.
  `/etc/meister-install/installed.json` ist der Grund, dass ein zweites
  Booten desselben Mediums die Platte in Ruhe laesst, bis jemand
  `--reinstall` sagt.
* Es setzt eine **SSH-Verbindung voraus**, die es schon gibt — und damit
  einen Host, dem man bereits vertraut. Das Medium braucht das nicht: der
  Fingerprint kommt von der Konsole, und `keys enroll` ist die Stelle, an
  der die Flotte ihn annimmt.

Fuer eine Kiste, die ohnehin schon erreichbar ist und deren Platte niemand
anders beansprucht, ist nixos-anywhere der kuerzere Weg. Fuer eine leere
Maschine, an der jemand steht, ist es das Medium.

## Die Kontext-Flotte (OpenNebula) — nicht mehr hier

Zwoelf VMs des Labs booten ein generisches Image und rendern ihre
Konfigurationsdateien beim Boot aus einem Kontext. Dieses Repo hat davon
seit M5B fast nichts mehr: `nix/appliance.nix`, `nix/context.nix`,
`deploy/push.sh`, `deploy/check.sh`, `deploy/one-template.example` und
`examples/fleet/lab.toml` liegen in

    ~/git/meisterstack-lab/legacy/

zusammen mit ihrem Rendertest (`check-context.sh`, 140 Pruefungen) und dem
Paritaetsbeleg, dass das Bild dort **dieselbe Ableitung** ist wie das, das
hier gebaut wurde (72 Units, je derselbe Store-Pfad). Der Weg von dort
hierher ist eine Migration und steht in `docs/DEPLOYMENT.md`, Abschnitt
"Migrating the context fleet".

Was hier bleibt, und mit Absicht: **`nixosModules.provider-opennebula`**.
Das Medium eines Providers zu LESEN ist nicht dasselbe wie
Konfigurationsdateien beim Boot zu rendern, und eine verwaltete Maschine
kann das erste ohne das zweite wollen — sie wird auf OpenNebula
instanziiert und bekommt ihre Adresse von dort. Der Leser parst
`context.sh` mit einem `KEY='value'`-Grammar und einer Allowlist von sechs
Schluesseln, sourct nie und nimmt kein `MEISTER_*` vom Medium: was eine
Maschine IST, steht im Inventar.

Ebenfalls hier: `deployment = "context"` im Inventar ist weiter ein
gueltiger Wert. Ein solcher Host steht in `inventory`, hat aber kein
Toplevel im Manifest, und ein Plan weist ihn mit einem Satz ab, der auf den
Push im Lab-Repo zeigt. Das ist die ehrliche Antwort: dieses Werkzeug
bedient ihn nicht.

Der musl-Build braucht einen musl-Cross-GCC (`ring` uebersetzt C fuer das
Ziel), und den gibt es hier als Shell: `nix develop .#musl`. Die statischen
Binaries selbst kommen aber aus Nix und nicht mehr aus dieser Shell:
`nix build .#meisterstack-static` (sieben Binaries) und
`nix build .#cloud-hypervisor-meister-static` (cloud-hypervisor + ch-remote,
static-pie) — das ist, was der Push im Lab-Repo nimmt.


## Ohne root

Der Agent laeuft als root, und das bleibt der Default. Fuer einen reinen
Rechenknoten — ein PoC- oder Benchmark-Knoten — gibt es daneben ein Profil:

```nix
meisterstack.agent.unprivileged = true;          # User=meister
meisterstack.agent.capabilities = [ "CAP_NET_ADMIN" ];   # der Default
```

Die Unit wird damit zu `User=meister`, `Group=meister`, mit den
Geraetegruppen `kvm video render input`, `Delegate=cpu cpuset io memory pids`
und `DelegateSubgroup=supervisor`, `AmbientCapabilities=` aus der Option und
`DeviceAllow=` statt `PrivateDevices=`. `cgroup_root` ist dann die cgroup der
Unit, nicht `/sys/fs/cgroup/meisterstack`. Es bleibt eine **System-Unit**:
nur `system.slice` fuehrt `cpuset`, eine User-Session nie — ein Agent unter
`user@.service` koennte `cgroup_cpuset` also nicht durchsetzen.

**Ein PoC-Knoten kann kein LVM, kein NFS, kein NVMe-oF und kein vfio; der
Agent sagt beim Start, was fehlt.** Ein Treiber, dessen Bedarf fehlt, wird
nicht registriert — und was ein Knoten nicht gebaut hat, behauptet er nicht
in seinem Hello, also platziert der Scheduler solche Arbeit nie dort. Dazu
eine WARN-Zeile je Treiber und die NodeCondition `Unprivileged` auf jedem
Herzschlag.

Der Bedarf, gemessen (2026-09-16, Kernel 7.2.4; je Zeile die Operation, an
der es haengt):

| Treiber | braucht | woran es haengt |
|---|---|---|
| `cloud-hypervisor` | `/dev/kvm` | Gruppe `kvm` (udev-Regel `0660 root:kvm`) — **keine** Capability |
| `filesystem` | nichts | Dateien und `qemu-img` |
| `input` (`fifo`) | nichts | eine Named Pipe, die der Treiber selbst anlegt |
| `input` (`evdev`) | Gruppe `input` | `open("/dev/input/eventN")` |
| `crosvm-gpu` | Gruppen `render`/`video` | `open("/dev/dri/renderD*")` |
| `linux` (Taps, Bridges, VXLAN, nft-Tap-Guard) | `CAP_NET_ADMIN` | `TUNSETIFF`, rtnetlink `RTM_NEWLINK`, `nft -f -` |
| Tenant-**Router** | `CAP_SYS_ADMIN` | `unshare(CLONE_NEWNET)` + Bind-Mount unter `/run/netns` — `CAP_NET_ADMIN` genuegt dafuer **nicht** |
| `nfs` | `CAP_SYS_ADMIN` | `mount(2)` (ueber `mount.nfs`) |
| `lvm-thin` | `CAP_SYS_ADMIN` **und** `CAP_DAC_OVERRIDE` | `/dev/mapper/control` ist `0600 root:root`, `/run/lock/lvm` root-only |
| `nvmeof` | `CAP_SYS_ADMIN` **und** `CAP_DAC_OVERRIDE` | `nvme connect` nach `/dev/nvme-fabrics` (`0600 root:root`) |
| `vfio` | `CAP_SYS_ADMIN` **und** `CAP_DAC_OVERRIDE` | die Bindung an `vfio-pci` per sysfs; `/dev/vfio/vfio` selbst ist `0666` |
| `nvrm` | Gruppen `video`/`render` | die NVIDIA-Geraeteknoten; die mdev-Seite schreibt sysfs und braucht dann dasselbe wie `vfio` |

`CAP_SYS_ADMIN` in `capabilities` ist kein Mittelweg: capabilities(7) sagt
ueber sie "It can plausibly be called 'the new root'". Ein Knoten, der LVM,
NFS, NVMe-oF oder vfio braucht, laeuft als root und sagt das.

Drei Saetze, die unabhaengig von diesem Profil gelten und die man kennen
muss, bevor man es fuer eine Haertung haelt:

1. **Die Gruppe `meister` am Agent-Socket ist root-aequivalent.** Wer am
   Socket eine VM anlegen darf, waehlt Image-Pfade, virtiofs-Shares und
   Geraete; auf einem Knoten, dessen Agent root ist, ist das root. Jeder
   Referenzstack sagt dasselbe ueber seine Gruppe — Docker: "The `docker`
   group grants root-level privileges to the user."; libvirt ueber
   `libvirt-sock`: "A connection to this socket gives the client privileges
   that are equivalent to having a root shell."; Incus: "Anyone added to
   this group will have full control over Incus." Erst wenn auch der VMM
   unprivilegiert ist (Stufe 3), ist die Socket-Gruppe weniger als root.
2. **vhost-user ist keine Isolationsgrenze.** QEMU: "There is not considered
   to be security boundary between QEMU and the vhost-user & vfio-user
   backends."; cloud-hypervisor: "Cloud Hypervisor gives vhost-user devices
   complete control over the guest." `nvrm`, `input` und `crosvm-gpu` muessen
   also **mit** dem VMM unprivilegiert werden, sonst kauft ein
   unprivilegierter VMM fuer eine Display-VM nichts.
3. **Der cloud-hypervisor-API-Socket ist eine Vertrauensgrenze, und Landlock
   schuetzt ihn nicht.** CHs Threat Model: "These interfaces are considered
   trusted. For instance, Cloud Hypervisor does not prevent an API client
   from telling Cloud Hypervisor to access /proc/self/mem and thus overwrite
   its own memory." und "it does not prevent access to AF_UNIX sockets". Die
   Rechte auf `<run_dir>/vms/<vm>.sock` sind also unsere Arbeit.

Zwei Dinge, die ein solcher Knoten sonst noch anders macht: die Sektion
`[volume.nvmeof]` steht im Rollen-Template dieser Flotte und wird auf einem
`unprivileged`-Knoten **nicht** registriert (der Knoten sagt es beim Start und
auf jedem Herzschlag; wer die Meldung nicht will, nimmt die Sektion per
`meisterstack.agent.settings` heraus), und `[network.provider]` ist dort kein
sinnvoller Schluessel, weil ein Router `CAP_SYS_ADMIN` braucht.

## Spaeter: `meister-deploy discover <host>`

Ein Verb, das es noch nicht gibt. Es wuerde per SSH **nur lesen** (`lspci`,
`ip -j link`, `lsblk -J`) und einen Vorschlagsblock fuer den Plan drucken:
die Uplink-NIC, die Platte fuer den Thin-Pool, die VFIO-Adressen, die
RDMA-NIC. Ein Mensch uebernimmt daraus, was stimmt. Die Wahrheit bleibt der
Plan — ein Werkzeug, das sich seine Konfiguration von der Maschine holt,
kann nie sagen, dass die Maschine falsch ist.

## Stufe 3: der VMM laeuft nicht als der Agent

Ein Schluessel, `vmm_user` in `meisterstack.agent.settings`:

```toml
vmm_user = "meister-vmm"
```

**Fehlt er, aendert sich nichts.** Jeder Knoten, der heute laeuft, laeuft
danach genauso: cloud-hypervisor und die vhost-user-Backends sind Kinder des
Agenten mit den Rechten des Agenten, und die Live-Migration geht wie bisher.

Ist er gesetzt, gilt:

| Wer | laeuft als | hat |
|---|---|---|
| Agent | root (bzw. `meister` + `CAP_NET_ADMIN`) | Taps, Bridges, VXLAN, `nft`, cgroups, LVM/NFS/NVMe-oF, vfio-Bindung |
| cloud-hypervisor | `meister-vmm` | `/dev/kvm` (Gruppe `kvm`), Landlock, seccomp, **keine** Capability — gemessen: `CapEff: 0000000000000000` |
| `vhost-user-nvrm`, `vhost-user-input`, `crosvm` (gpu) | `meister-vmm` | dasselbe |
| `virtiofsd` | der Agent | es setzt Eigentuemer im Share; es bleibt privilegiert und wird per `--sandbox=namespace` eingehegt |

Der Nutzer muss vor dem Agentenstart existieren, und er darf **nicht** in der
Gruppe am Agent-Socket (`[paths] socket_group`) sein. Ein Knoten mit einem
`vmm_user`, den es nicht gibt, startet nicht und sagt den Namen.

### Was der Rollout dafuer bereitstellen muss

* Den Nutzer, ohne Shell, in der Gruppe `kvm` — und je Knoten `video`,
  `render` (fuer `crosvm-gpu`) bzw. `input` (fuer das `evdev`-Profil).
  Geraete kommen ueber **Gruppen**, nicht ueber Dateideskriptoren: das ist
  die Antwort der Referenzstudie und die von Kata.
* **Alles, was der VMM oeffnet, muss fuer ihn erreichbar sein — samt
  Ausfuehrungsbit auf jedem Elternverzeichnis.** Der uid-Wechsel passiert vor
  dem `exec`, also braucht schon das Binary selbst ein `x` fuer ihn. Der
  erste Messlauf starb genau daran: `EACCES` beim `exec` eines
  cloud-hypervisor unter einem `0700`-Heimatverzeichnis. Auf einem Knoten
  sind das `/opt/meisterstack/bin`, das Image-Verzeichnis und das
  Volume-Verzeichnis.
* `CAP_SETUID` und `CAP_SETGID` fuer den Agenten, wenn er nicht root ist. Ein
  Agent ohne sie bekommt beim ersten VM-Start einen Satz, der genau das sagt.
* Ein Agent, der nicht root ist, muss zusaetzlich **in der Gruppe des
  VMM-Nutzers** sein: die Dateien der VM gehoeren danach dem VMM. Die
  Richtung ist Absicht und nur diese: der Agent tritt der Gruppe des VMM bei,
  nie umgekehrt.

### Die drei Saetze, die die Rechnung bestimmen

**1. Die Gruppe am Agent-Socket ist root-aequivalent, solange der VMM root
ist.** Wer am Socket eine VM anlegen darf, waehlt Image-Pfade, virtiofs-Shares
und Geraete auf einem Knoten, dessen Agent root ist. Drei Stacks sagen
denselben Satz ueber ihre eigene Gruppe: Docker — "The `docker` group grants
root-level privileges to the user."; libvirt — "A connection to this socket
gives the client privileges that are equivalent to having a root shell.";
Incus — "Anyone added to this group will have full control over Incus." Erst
`vmm_user` macht diese Gruppe zu weniger als root.

**2. vhost-user ist keine Isolationsgrenze.** QEMU: "There is not considered
to be security boundary between QEMU and the vhost-user & vfio-user
backends." Cloud Hypervisor: "Cloud Hypervisor gives vhost-user devices
complete control over the guest." Deshalb wechseln `nvrm`, `input` und
`crosvm-gpu` **mit** dem VMM den Nutzer und nicht nach ihm — ein
unprivilegierter VMM neben einem root-Backend ist ein root-VMM mit
Zwischenschritt.

**3. Der API-Socket des VMM ist eine Vertrauensgrenze, und Landlock schuetzt
ihn nicht.** Cloud Hypervisors Threat Model: "These interfaces are considered
trusted. For instance, Cloud Hypervisor does not prevent an API client from
telling Cloud Hypervisor to access /proc/self/mem and thus overwrite its own
memory." Und: "The sandbox only prevents access to resources subject to
Landlock access controls. For instance, it does not prevent access to AF_UNIX
sockets." Die Rechte auf `<run_dir>/vms/<vm>.sock` sind also Arbeit dieses
Stacks. Sie sind `0770`, Eigentuemer und Gruppe der VMM-Nutzer —
cloud-hypervisor macht die Datei selbst mit `umask(0o077)`, und der Agent
oeffnet sie danach genau der einen Gruppe, weil er sonst seine eigene VM
nicht mehr faehrt.

### Was Stufe 3 kostet

**Keine Live-Migration fuer VMs mit NICs.** Der Tap kommt als
Dateideskriptor, und cloud-hypervisor v53 kann Deskriptoren nicht ueber eine
Migration tragen: die Config reist als JSON, `fds` wird beim Empfaenger
absichtlich zu `-1` ("FDs in 'NetConfig' won't be deserialized as they are
most likely invalid now"), und `vm.receive-migration` hat keinen Kanal fuer
neue — `net_fds` gibt es nur an `vm.restore`. Gemessen: der Empfaenger bricht
ab, derselbe Aufbau ohne NIC wandert fehlerfrei. Der Agent verweigert so eine
Migration darum mit einem Satz, statt den Gast draussen sterben zu lassen.
Ein Knoten, der live migrieren muss, laesst `vmm_user` weg.

**Kein Hot-Plug eines Datei-Volumes aus einem Verzeichnis, das die
Landlock-Regeln nicht nennen.** Genannt sind das Run-, das Image- und das
Volume-Verzeichnis plus das Verzeichnis jedes Volumes, das die VM beim
Anlegen schon hatte. Eine VM, die ihr erstes `lvm-thin`- oder
`nvmeof`-Volume (`/dev/mapper/...`, `/dev/nvme...`) heiss anhaengt, bekommt
`Permission denied`. Das ist Landlocks Modell und kein Versehen: ein Ruleset
laesst sich nach `restrict_self` nicht erweitern.

## Die Optionen des Moduls

Erzeugt aus den Modulen selbst (`nix build .#module-options`,
`scripts/module-options.sh` schreibt die Tabelle hierher). Wer die Tabelle
von Hand aendert, aendert sie am naechsten Lauf wieder zurueck.

<!-- BEGIN module-options -->

| Option | Typ | Default | Was sie bedeutet |
|---|---|---|---|
| `meisterstack.addons.fqdn` | string | `"nixos"` | The name this box is reached under. It is the Kanidm origin, the issuer, the name in the serving certificate and the host in every oauth2 redirect url at once — so it is a NAME and not an address, it has to resolve on every machine that logs in, and `meister-deploy keys init` has to have signed it. |
| `meisterstack.addons.retention` | string | `"7d"` | How long Prometheus keeps series. A lab box, not an archive. |
| `meisterstack.addons.scrapeTargets` | list of string | `[ ]` | The `meister` scrape job, one entry per node AND role: a box with two roles has two metrics listeners (9100 cloud, 9101 cluster, 9102 agent). nix/fleet.nix derives this from the plan; the lab's twelve vms are twelve targets, not thirty-six. |
| `meisterstack.agent.capabilities` | list of string | `[ "CAP_NET_ADMIN" ]` | The capabilities an unprivileged agent holds — both its ambient set (so that `nft`, `ip` and the VMM it spawns inherit them) and its bounding set (so that the list is the whole truth and not a floor). Only read when `meisterstack.agent.unprivileged` is true. The default is the one capability that buys something a node cannot work around: `CAP_NET_ADMIN`, which is exactly enough for taps, bridges, VXLAN and the tap guard, and exactly not enough for anything else (measured). An empty list is a node with no networking at all — legal, and then a VM with a NIC cannot run there. `CAP_SYS_ADMIN` in this list is not a middle ground: capabilities(7) says of it "It can plausibly be called 'the new root'". A node that needs LVM, NFS, NVMe-oF or vfio should run the agent as root and say so, rather than pretend. The list exists because the next lane needs two more: the VMM-as- `meister-vmm` step (`design/privilege-separation.md`, stage 3) adds `CAP_SETUID CAP_SETGID`, since dropping to another user is itself a privilege. |
| `meisterstack.agent.frr.enable` | boolean | `an agent node runs it` | Whether FRR itself runs beside the agent, and not only the package. `vtysh` is a CLIENT: it talks to the daemons over their vty sockets in /run/frr, so a node that has the binary and no daemon answers every call with "failed to connect to any daemons" — which is exactly what `[network.bgp]` would have got. The package alone was what this image had, and manacor showed the other half of the same gap from the outside: no announcement, so the routed /29 had to be reached by a static route somebody typed. bgpd is the only daemon named. zebra and staticd are started by the module whatever is asked for, and they are the two the driver needs beside it — zebra holds the routing table vtysh writes into. No `config` is given: what this node says to its peers is the AGENT's to render (drivers/linux-network/src/frr.rs writes a fragment and `vtysh -f` merges it), and a second author of the same configuration is how two halves start disagreeing about what is announced. On by default on an agent node, and it costs a node with no `[network.bgp]` one idle daemon: the appliance image is generic and the section arrives at BOOT from the context (MEISTER_BGP_*), so a daemon that were conditional on build-time knowledge would be missing on exactly the machines that turn out to need it. A managed node whose plan names no BGP can turn it off. |
| `meisterstack.agent.imageDir` | string | `"/opt/meisterstack/images"` | Where this node keeps the guest images it has been handed. The default is the APPLIANCE's answer and is what it has always been: on that road images arrive next to the binaries, both pushed into /opt/meisterstack by `meister-deploy legacy context-push`, and moving them would move a directory the push writes. A MANAGED host has no push (nix/managed.nix sets `/var/lib/meisterstack/images`): nothing writes into its filesystem by hand any more, and the FHS answer for state a service owns is /var/lib — which is where `meisterstack.pki.dir` and the volume records already live. Named as an option rather than derived from the profile so that a node with its images on a separate block can say so in one line. |
| `meisterstack.agent.inputBackend` | null or string | `null` | Path to upstream vhost-device-input; null disables the input driver. Each device uses profile "evdev" and params.evdev to select a host /dev/input/eventN node. The backend user needs read access to that node. Set settings.device.input.socket_timeout_ms to override the 5000 ms startup timeout. The package is supplied separately. |
| `meisterstack.agent.nvmeTcp.enable` | boolean | `an agent node loads it` | Whether `nvme_tcp` is loaded at boot for the NVMe-oF attacher. `nvme` reads the topology out of /sys/class/nvme BEFORE it opens /dev/nvme-fabrics, and that directory does not exist until nvme_core is loaded. On a node with no PCIe nvme disk — every VM in this lab — nothing has loaded it, so the very first thing the driver does dies with "Failed to scan topology: No such file or directory" and never reaches the connect that would have autoloaded the module. Measured on agent-2b: the same discover succeeds the moment nvme_tcp is in. nvme_tcp and not nvme_fabrics: it depends on the other two and pulls them in, and tcp is the transport this fleet's fabric speaks. A host with an RDMA card wants nvme_rdma beside it, which is a fact about that host's hardware and belongs in that host's own configuration. |
| `meisterstack.agent.physnets` | attribute set of string | `{ }` | The interfaces this node gives away to provider networks, by the name of the network each of them reaches. Empty (the default) is a node that gives none away: it still runs VMs and still carries tenant overlays, it is simply no candidate for a tenant router. A non-empty attrset renders `[network.provider] physnets` into the config template, and the agent then makes one bridge per provider network (`meister-px-<name>`, so a name has four characters), puts the interface in it, and claims `network/gateway:<name>` in its Hello. The tier above places routers only where that claim is. The interface must carry NO address: an address there is somebody still using the interface, and the agent refuses to start rather than put a router on a network the host is also on. This is per NODE and not per role, which is why it is its own option rather than a line in `settings` — a fleet plan says it per machine, and a machine that has no spare NIC says nothing. |
| `meisterstack.agent.rdma.enable` | boolean | `false, and the inventory turns it on for a host whose hardware.nics declares rdma` | Whether this machine carries the user-space tools of an RDMA fabric: `rping` and `ibv_devinfo` out of rdma-core, `ib_send_lat` and `ib_write_bw` out of perftest. It is what `meister-deploy verify --suite rdma` drives, over ssh, one end of a declared pair at a time. Without it that suite finds no binary on the host and says `skipped` with the sentence — never `pass`, because a fabric nobody could measure is not a fabric that works. Off by default and turned on by the inventory for a host whose `hardware.nics[].rdma` is true: a card is a fact about a machine, and the inventory is where the facts about machines are written down. |
| `meisterstack.agent.rdma.packages` | list of package | `[ pkgs.rdma-core (pkgs.callPackage ./packages/perftest.nix { }) ]` | The packages `rdma.enable` puts on the machine. An option rather than a constant because the two builds are not equivalent everywhere: a Mellanox estate has MLNX_OFED, whose `ib_write_bw` is the one its support contract talks about, and an operator who replaces this list gets their own without a fork. The suite names the binaries and not the packages, so anything that provides `rping`, `ibv_devinfo`, `ib_send_lat` and `ib_write_bw` on `PATH` does. |
| `meisterstack.agent.settings` | TOML value | `{ }` | Agent config template overrides, merged over the role defaults above. Free-form TOML: nothing here validates a key, the agent does that at start-up with deny_unknown_fields. config/examples/agent.toml is the reference for what may go in it, and config/examples/hardened/agent.toml for a node that is not on a lab switch. node_id and controller_addr are NOT settable here ON AN APPLIANCE — there the context renderer writes them into <configDir>/agent.toml at boot from the hostname and the context, and a key in both places would be a duplicate TOML key and a parse error. On a managed host they are not written at boot but BAKED (`meisterstack.agent.generated`, from nix/lib/render.nix), and this option still wins over them: there is one file, written once, and naming a key twice in it is not possible. |
| `meisterstack.agent.unprivileged` | boolean | `false` | Run the agent as the user `meister` with exactly the capabilities in `meisterstack.agent.capabilities`, instead of as root. The default is false and stays false: root is what every node in this fleet has been, and the agent's behaviour as root does not change. What such a node can still do, all of it measured on 2026-09-16: boot guests (`/dev/kvm` through the group `kvm`), `filesystem` volumes, and — with the default `CAP_NET_ADMIN` — every tap, bridge, VXLAN and nftables tap guard it makes today. What it cannot do, and says so at start-up, one sentence per driver: `lvm-thin` and `vfio` (CAP_SYS_ADMIN *and* CAP_DAC_OVERRIDE), `nfs` (CAP_SYS_ADMIN for mount(2)), `nvmeof` (the same, plus a root-owned /dev/nvme-fabrics), and a tenant router (CAP_SYS_ADMIN for `unshare(CLONE_NEWNET)` — a tap needs CAP_NET_ADMIN, a router does not stop at it). A driver whose need is missing is not registered, so this node claims none of that in its Hello and the scheduler places none of it here. This is a PROFILE for a compute-only node, not a hardening pass for the fleet: `deploy/README.md`, section "Ohne root", says what falls away, and in particular that the group `meister` on the agent socket is root-equivalent either way. |
| `meisterstack.agent.vmm.package` | package | `pkgs.cloud-hypervisor-meister` | The hypervisor this node's agent starts guests with: cloud-hypervisor with this repository's patch series (nix/packages/cloud-hypervisor.nix says why it is not nixpkgs' own). Read only where `meisterstack.binDir` is derived from a package — an appliance has its hypervisor pushed into /opt/meisterstack/bin — and joined with `meisterstack.package` into one directory there, because the agent's unit names both programs in `binDir`. |
| `meisterstack.agent.volumes.device` | null or string | `"/dev/disk/by-label/meister-volumes"` | The block this node keeps its guests' disks on, mounted at /var/lib/meisterstack/volumes. `null` keeps them on the root disk. A guest's disks are the one thing on an agent that is BIG and that must outlive an image swap — the root disk of these lab VMs is 3.4 GiB with a 2.2 GiB image on it, so a single provisioned volume fills it. By LABEL rather than by device name in the default, because which slot a disk lands in is not a promise anybody made: /dev/vdb quietly became sda+vda twice in the lab, and etcd lived on the root disk without saying so. |
| `meisterstack.agent.volumes.required` | boolean | `false` | Whether the agent may run WITHOUT that block. False (the default) mounts it `nofail`: a node whose disk was not attached comes up and keeps its volumes on the root disk, which is the honest degraded state and not an emergency shell — and what the lab has done since the block existed. True is the other answer, for a node whose disks are its job: no `nofail`, and the agent unit REQUIRES the mount. A node that silently provisions onto its root disk fills it and then fails at the worst moment, and "the volume block is not here" is a sentence worth stopping for. |
| `meisterstack.binDir` | string | `"/opt/meisterstack/bin"` | The directory every unit of this stack takes its binaries from: `ExecStart`, the `ConditionPathExists` that keeps a unit visibly skipped until they are there, and the hypervisor path in the agent's config all read this one option. The default is where a push has always put them — outside the nix store, so that an image swap does not touch them. A host whose binaries come from a package points this at that package's `bin` instead; the condition is then satisfied by construction, which is the honest reading of "the binary is part of this system". |
| `meisterstack.cloud.settings` | TOML value | `{ }` | cloud-controller config, same shape and same rules; see config/examples/cloud.toml. This is the one tier with a public port, so config/examples/hardened/cloud.toml is worth reading before any deployment that is reachable from outside the lab. NOT `auth`: this tier's whole [auth] table is appended by the context renderer (nix/context.nix) at boot (see cloudAuthMtls/cloudAuthOidc above and the reason it has to be one owner). A key here would be a duplicate [auth] table and a parse error on the VM. The values live in cloudAuthOidc; the issuer comes from MEISTER_OIDC_ISSUER — and on a managed host, where there is no renderer, by `meisterstack.cloud.generated` at build time. |
| `meisterstack.cluster.settings` | TOML value | `{ }` | cluster-controller config, merged OVER the role defaults above (so a deployment that sets one key keeps the rest). Free-form TOML: nothing here validates a key, the binary does that at start-up with deny_unknown_fields. config/examples/cluster.toml is the reference for every key it takes, and config/examples/hardened/cluster.toml for a control plane that is not on a lab switch. Empty (the default) = the role defaults above and, for everything they do not name, the binary's own — which are the lab topology. cluster_name, cloud_addr and cloud_addrs are normally left out here and written by the context renderer from the context instead — a key in both places would be a duplicate TOML key. |
| `meisterstack.configDir` | string | `"/run/meisterstack"` | The directory the units read their `--config` from. The default is where a boot-time renderer writes the completed files: such an image bakes a TEMPLATE under /etc/meisterstack, and the per-machine values — node id, controller addresses, the cloud's whole [auth] table — are only known once the machine has booted somewhere. This flake has no such renderer any more (M5B); the one the lab's twelve context VMs boot is in `~/git/meisterstack-lab/legacy/nix/context.nix`. A managed host has no renderer and no context: Nix knows every one of those values at build time, writes the complete file into /etc and points this option at it. Then the config a unit reads is part of the system generation, which is what makes a rollback a rollback. |
| `meisterstack.context.defaults` | attribute set of string | `{ }` | MEISTER_* variables baked as defaults for the context renderer. Anything a provider's context can say, a configuration can say here instead — and the context, being the thing that knows where this machine was actually booted, wins over it. On a managed host this attrset is the WHOLE input: there is no provider and no cd, `nix/lib/render.nix` turns it into the complete config files at build time, and nothing overrides it afterwards. Secrets do not belong here: this file is in the nix store and the store is world-readable. Certificates and keys travel with `meister-deploy keys push`, as they always have. |
| `meisterstack.context.enable` | boolean | `false` | Whether this machine renders its config files at BOOT, from a context. A renderer sets it by being imported; this flake ships none any more (M5B), so on a host of this flake it is always false and what reads it is the refusal in nix/managed.nix. It is read rather than set: the two auth fragments of the cloud exist only where something appends them, and `nix/managed.nix` refuses to be combined with a renderer — a host whose config files are complete at build time must not have a second author for them at boot. |
| `meisterstack.context.providerScript` | strings concatenated with "\n" | `""` | Shell run before anything else reads this machine's context: a provider's chance to say where the machine was actually booted. Empty (the default) is a machine whose whole context is what its configuration bakes. `nixosModules.provider-opennebula` is the one implementation today, and it is deliberately NOT part of `nixosModules.default`: a reader that knows how to mount a CONTEXT cd is a reader nobody else can use. Two modules run it, and never both on one host. On an appliance the boot renderer (nix/context.nix) runs it in the middle of rendering, because there the provider's values are an INPUT to the config files. On a managed host there is no renderer — the config files are part of the system generation — and `meister-provider-context.service` (nix/services.nix) runs the same script for the one thing that is still the provider's to say: the machine's address, its route, its resolver, its hostname and the operator's key. What it may do is set MEISTER_* variables and configure the interface it owns. What it must not do is render a config file. |
| `meisterstack.data.label` | string | `"etcd-data"` | The filesystem label of this box's data block. The default is the lab's historical one and mounts only /var/lib/etcd, exactly as before. Any other value mounts /var/lib/meister-data instead and puts etcd under `etcd/` and the addons under `addons/` there. The label is IN the filesystem (`mkfs.ext4 -L <label>`), so it survives an image swap and a bus surprise alike. |
| `meisterstack.etcd.clusterToken` | string | `"meisterstack"` | Bootstrap token. Two tiers bootstrapping on one network must not share it — it is what keeps a cloud member from joining a cluster's Raft. |
| `meisterstack.etcd.enable` | boolean | `a controller tier runs one` | Whether this machine runs the etcd its controller talks to. The default is "yes if it carries a controller role": each tier's etcd is private to its controller (Oakestra-style), so an agent-only node has no reason to run one — and a host that imports these modules without naming a role gets no database it did not ask for. The appliance image is every tier at once (`meisterstack.unitsFor`), so there this is on, exactly as it has always been. |
| `meisterstack.etcd.member` | string | `"nixos"` | Which entry of `peers` this VM is. |
| `meisterstack.etcd.peers` | attribute set of string | `{ }` | Member name -> IP of every etcd member of this tier, this VM included. Empty (the default) keeps the single loopback member. Three members tolerate one loss; two do not tolerate any, so an even count buys nothing. |
| `meisterstack.install.hasEsp` | boolean | `false` | Whether the disk layout of this host makes an EFI system partition. Set by the layout (`templates/operator/disko/single-nvme.nix` says `true`, `disko/single-direct.nix` says `false`), read by the inventory module, and never guessed: a `boot = "uefi"` host whose layout makes no ESP would install systemd-boot nowhere and come back from its first reboot with no way to start, and a `boot = "direct"` host with an ESP would carry a partition nothing ever writes to. The default is `false`, which is the safe direction: a host that names no layout at all has no ESP this flake knows about, and only a `boot = "uefi"` host with an `install` table is held to it. |
| `meisterstack.managed.enable` | boolean | `false` | Whether this host is deployed to by `meister-deploy`: its closure is copied in, staged, activated and confirmed from the outside. Off by default, because importing a module should not turn a machine into a deployment target behind its owner's back — the appliance profile is the other way round, and the difference is that an image is built for one purpose and a host is not. |
| `meisterstack.managed.keepGenerations` | positive integer, meaning >0 | `3` | How many system generations besides the running and the booted one this host keeps. Nothing on the machine acts on this number: automatic gc is off here (a host must not collect the closure somebody is about to roll back to), and the helper that does the collecting — `meister-activate gc` — is part of M2. Until then this is a declared intent that the manifest carries and no code reads. It is listed as open in the M1 report rather than left looking finished. |
| `meisterstack.managed.substituters` | list of string | `[ ]` | Binary caches this host may fetch from. Empty (the default) is a host that is only ever pushed to: `nix copy --to ssh-ng://` carries the whole closure, and a target that fetches from nowhere cannot be surprised by what somebody else put in a cache. |
| `meisterstack.managed.trustedPublicKeys` | list of string | `[ ]` | The signing keys whose closures this host accepts. REQUIRED when `enable` is on, and the assertion below says so. Measured, not assumed (M0 probe S12): with `require-sigs = true` a `nix copy --to ssh-ng://root@host` of an UNSIGNED closure is refused — "cannot add path … because it lacks a signature by a trusted key" — even though root is a trusted user. Being trusted is not being signed. The old `ssh://` store would take it, and that is exactly the guarantee `require-sigs` exists for, so the answer is to sign (`meister-deploy build --sign-key`) rather than to widen the target. |
| `meisterstack.observability.enable` | boolean | `a machine that runs a role collects its journal` | Whether this machine runs the log collector beside its units. The default is "yes, if this machine runs any of our units at all": the interesting lines on these VMs are not ours — etcd losing a leader, the VMM refusing a disk, the kernel remounting read-only — and it is the WHOLE journal that gets shipped, which is the entire reason to run a collector rather than teach three binaries to push. It still costs nothing on a machine that names no Loki: without a rendered config the unit's ConditionPathExists is not met and Alloy stays skipped. A managed host turns this off by default, and that is a gap rather than a decision: its config file would have to be baked at build time the way its TOML files are, and that is not built yet. |
| `meisterstack.package` | package | `pkgs.meisterstack` | The package the units of this stack take their binaries from. Read only where `meisterstack.binDir` is derived from it — which is what nix/managed.nix does. A host that is not managed by this flake may get its binaries pushed into /opt/meisterstack/bin instead, and then this option is never forced. That is also why the default may be a package that the operator's nixpkgs does not have: a foreign host importing `nixosModules.default` without the overlay is a perfectly good host, as long as it says where its binaries are. |
| `meisterstack.pki.dir` | string | `"/opt/meisterstack/pki"` | Where this machine's certificates and private keys live. The names in it are FIXED — `ca.crt`, `serving.crt`, `serving.key`, `identity.crt`, `identity.key` — because a serving certificate and an identity differ per host while one config template serves them all. Outside the nix store on purpose, in both profiles: a private key must never travel in an image, and the store is world-readable. The private keys belong to the user that reads them (`meister`, mode 0600). systemd credentials are NOT an option here: `LoadCredential` hands the unit a `root:root 0440` file with an ACL, and all three of this project's key loaders refuse a mode with group bits in it (`shared/pki/src/pem.rs`, `shared/proto/src/lib.rs`, `components/cli/src/config.rs`). Measured in a VM, M0 probe S11. |
| `meisterstack.ports` | attribute set of attribute set of (signed integer or string) | `{ agent = { metrics = 9102; migration = "49000-49099"; }; cloud = { api = 3000; grpc = 50050; metrics = 9100; }; cluster = { api = 3001; grpc = 50051; metrics = 9101; }; etcd = { client = 2379; peer = 2380; }; }` | The ports this stack listens on, per role — to be READ, not set. No firewall rule is written by these modules, and that is the point: a host's firewall belongs to the host, and a service module that opens a port decides something host-global behind its owner's back. So the numbers are published here instead, and an operator's own `networking.firewall` can name them: networking.firewall.allowedTCPPorts = with config.meisterstack.ports; [ cloud.api cloud.grpc etcd.peer ]; Which of them this module actually sets: the three `metrics` listeners (controllers.nix, agent.nix), the agent's `migration` RANGE, and etcd's two (nix/etcd.nix — `client` is bound to loopback and is here for completeness, `peer` is the one that crosses the network). `api` and `grpc` are the binaries' own defaults, written down because a plan derives addresses from them (`MEISTER_CLOUD_ADDRS`, `MEISTER_CONTROLLER_ADDRS`) and an operator opening a hole needs the number in one place. The addons role is not in this list: its six services bring their own nixpkgs modules and their own listeners, and `meisterstack.addons` is where they are configured. |
| `meisterstack.provider.opennebula.device` | string | `"/dev/disk/by-label/CONTEXT"` | The medium. OpenNebula labels its context iso CONTEXT, and the label is what makes it findable whatever bus it lands on — which slot a disk gets is not a promise anybody made. Read by the strict reader only. The legacy one has the path in it, because it is frozen. |
| `meisterstack.provider.opennebula.interface` | string | `"eth0"` | The interface the context's ETH0_* values configure — `eth0`, because the appliance turns predictable interface names off and the context speaks of ETH0. Read by the strict reader only. |
| `meisterstack.provider.opennebula.mode` | one of "strict", "legacy" | `"strict"` | Which reader gets the medium. `strict` parses `context.sh` with a `KEY='value'` grammar and an allowlist of six keys (ETH0_IP, ETH0_MASK, ETH0_GATEWAY, ETH0_DNS, SET_HOSTNAME, SSH_PUBLIC_KEY), validates every value before it is used, and takes NO MEISTER_* variable off the medium: what this machine is comes from its plan. Anything else on the medium is named in the journal and dropped. `legacy` sources the file as root. It exists because the twelve VMs of the context fleet boot through it today; `nix/appliance.nix` is what turns it on, and both leave together (L3). |
| `meisterstack.provider.opennebula.network` | boolean | `true` | Whether the provider configures that interface at all. ONE owner per interface. If this host names a static address for it (`networking.interfaces.<if>.ipv4.addresses`), the provider must not write a second one on top: two owners for one file is how the fleet lost every name it could resolve on 2026-09-08 (nix/appliance.nix tells that story), and an address is the same kind of thing. The assertion below refuses that combination in `strict` mode and warns about it in `legacy`, where it is today's behaviour and a rollout is not the place to change two things at once. Turning it off keeps the rest: hostname and ssh key still come from the medium, because those are not the interface. |
| `meisterstack.provider.opennebula.waitSeconds` | unsigned integer, meaning >=0 | `30` | How long to wait for the medium to appear, and only on a machine that expects one: a host whose MEISTER_ROLE is already baked does not wait at all, because it would be waiting for something that is not coming. Read by the strict reader only. |
| `meisterstack.roles` | list of (one of "cloud", "cluster", "agent", "addons") | `[ ]` | Which roles this machine runs. Empty (the default) is the generic appliance image: every unit ships, and MEISTER_ROLE in the context decides at boot which of them starts. A non-empty list is baked as that variable's default, so a machine with no context still knows what it is — and a context may still override it. On every host that is not that image, this list is also what decides which UNITS are built at all (`meisterstack.unitsFor`): a cloud is not a machine with an agent unit that happens to be stopped. `both` and `all` are MEISTER_ROLE shorthands and not values here: a configuration that knows its roles at build time can name them. |

<!-- END module-options -->
