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
| **Die Kontext-Flotte** | OpenNebula, zwoelf VMs, drei Tiers | dasselbe generische Image fuer alle, `MEISTER_ROLE` im Kontext — siehe unten |

## Der Plan

Eine Datei, `fleet.toml`, beschreibt die Flotte. Sie wird zweimal
gelesen: von Nix (`nix/fleet.nix`, damit `nix build` ohne Rust auskommt)
und von `meister-deploy` (damit `plan`, `keys` und `check` ohne Nix
auskommen). `scripts/check-fleet.sh` misst, dass beide dasselbe sagen.

Was **abgeleitet** und nie zweimal getippt wird: die etcd-Peers und das
Bootstrap-Token je Raft-Gruppe, `cluster_name` und `cloud_name`, die
`controller_addrs` der Agents, die `cloud_addrs` der Cluster, beide
`advertise_api`, die Scrape-Liste und der OIDC-Issuer. Ein Plan sagt, wer
zu welcher Gruppe gehoert; die Adressen folgen.

```
meister-deploy plan            # die Tabelle: was ist, und was sollte sein
meister-deploy image <knoten>  # raw-efi fuer diese Kiste (oder `generic`, oder `all`)
meister-deploy keys init       # CA, Zertifikate, die drei Geheimnisse
meister-deploy keys push       # unter die festen Namen, Agents zuerst
meister-deploy push            # rollen: Agents, Cluster, Clouds, Addons
meister-deploy check           # Units, Sessions, Platten — und was die API sagt
meister-deploy render <knoten> # der Knoten als importierbares Nix-Modul
```

`meister deploy …` ruft dasselbe Binary auf, wenn es neben der CLI oder
im PATH liegt. Jeder Aufruf sagt, was er tut, bevor er es tut; `--dry-run`
sagt es und tut es nicht.

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
stehen. Statt die Rollen von Hand zu setzen, kann der Host auch die Datei
importieren, die `meister-deploy render <knoten>` schreibt: dieselben
Optionswerte, die `mkNode` fuer diesen Knoten setzen wuerde, als reine
Funktion des Plans und byteidentisch bei gleichem Plan. Sie enthaelt keine
Hardware, keinen Bootloader, kein Dateisystem und keine Adresse — das
gehoert dem Host.

Die Zertifikate kommen in keinem Fall aus dem Nix-Store: `keys push` legt
sie nach `/opt/meisterstack/pki`, und bis dahin bleiben die Units sichtbar
uebersprungen.

## Erstinstallation ohne `dd`

`nix build .#image-<knoten>` und `dd` ist der kurze Weg, wenn die Platte
erreichbar ist. Ist sie es nicht, ist **nixos-anywhere** die dokumentierte
Alternative: es kexect einen NixOS-Installer auf eine Kiste, die schon
irgendein Linux mit SSH faehrt, partitioniert mit disko und installiert
`.#nixosConfigurations.<knoten>` — dasselbe System, das auch im Image
liegt, also aendert sich am Plan nichts. Was fehlt, ist ein
disko-Layout; der Plan traegt heute nur `disk` und `data`, nicht die
Partitionierung. Deshalb steht hier ein Absatz und kein Output.

`.#iso-<knoten>` ist der dritte Weg: dasselbe System als Installer-ISO,
fuer eine Kiste, an der man mit einem Stick steht.

## Die Kontext-Flotte (OpenNebula)

Zwoelf VMs, ein generisches Image, `MEISTER_ROLE` im Kontext. Der Plan
dafuer ist `examples/fleet/lab.toml`; die Knoten haben dort **kein**
`disk`, weil ihre Platte aus einem registrierten Image kam und der
VM-Lebenszyklus OpenNebula gehoert (Tofu, spaeter). Fuer solche Knoten
heisst `push`: rsync der Binaries nach `/opt/meisterstack/bin` und ein
Unit-Restart — genau das, was `deploy/push.sh` seit M1 tut.

**`push.sh` und `check.sh` bleiben**, bis `meister-deploy` sie im Lab
einmal wirklich ersetzt hat. Sie koennen zwei Dinge, die das Werkzeug
heute nicht kann: die Gast-Assets mitschieben (`MEISTER_GUEST_ASSETS`) und
den musl-Build anstossen. Bis dahin sind sie die Wahrheit fuer die
Kontext-Flotte, und `meister-deploy` ist es fuer alles andere.

Der musl-Build braucht einen musl-Cross-GCC (`ring` uebersetzt C fuer das
Ziel), und den gibt es hier als Shell: `nix develop .#musl` — oder gar nichts
tun, `push.sh` betritt sie selbst, wenn der Compiler nicht schon auf dem PATH
liegt. Die Shell setzt genau die drei Variablen, die `cc` und cargo lesen
(`CC_`, `AR_`, `CARGO_TARGET_..._LINKER`, je mit dem Ziel im Namen); sie bringt
kein Rust mit, denn das ist das der Maschine. Ein nativer Bau in ihr ist
derselbe Bau wie ausserhalb.

Beide lesen `deploy/env`; `meister-deploy` liest dieselben Variablen
(`MEISTER_SSH_KEY`, `MEISTER_SSH_PORT`, `MEISTER_SSH_STRICT`), also
bedeutet `. deploy/env` vor dem einen dasselbe wie vor dem anderen.

Was eine Maschine ueber sich selbst sagt und nicht ueber ihre Rolle, geht
denselben Weg — per Kontext, weil dieselbe qcow2 zwoelfmal instanziiert
wird und die Maschinen sich unterscheiden:

| Kontextschluessel | Beispiel | Wirkung |
|---|---|---|
| `MEISTER_VXLAN_UPLINK` / `MEISTER_VXLAN_MTU` | `eth0`, `1450` | `[network.vxlan]` im `agent.toml` |
| `MEISTER_PHYSNETS` | `ext=eth1` oder `"ext=eth1, dmz=eth2"` | `[network.provider] physnets` — die Interfaces, die diese Maschine abgibt, mit dem Namen des Provider-Netzes davor. Das Interface darf KEINE Adresse tragen, sonst startet der Agent nicht. Kein Wert heisst kein Abschnitt und damit kein Gateway-Slot; die Nix-Option daneben ist `meisterstack.agent.physnets` und ist die Antwort fuer eine Flotte, die ihre Maschinen im Plan stehen hat. |
| `MEISTER_BGP_ASN` / `MEISTER_BGP_ROUTER_ID` | `65001`, `10.128.1.10` | `[network.bgp]` — dieser Knoten spricht BGP und kuendigt an, was er traegt (`/32` je Floating IP eines Gastes hier, und die Praefixe seiner Router). Beide oder keiner: ein halber Abschnitt ist ein Startfehler. Die `router_id` wird gesetzt und nicht FRR ueberlassen, das sonst die hoechste Adresse der Kiste nimmt — auf einem Knoten voller Bruecken und Taps die des zuletzt gebauten Gastes. |
| `MEISTER_BGP_NEIGHBORS` | `10.128.0.1=65000` oder `"10.128.0.1=65000, 10.128.0.2=65000"` | Die Peers, `<adresse>=<asn>`. Leer ist erlaubt: der Abschnitt steht, `frr` laeuft, angekuendigt wird an niemanden. Ohne `MEISTER_BGP_ASN` wirkungslos. |

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
| `meisterstack.agent.inputBackend` | null or string | `null` | Where `vhost-user-input` is on this node, or null (the default) for a node that does not serve virtio-input. cloud-hypervisor has no virtio-input device of its own, so the keyboard and the mouse of a guest come from a backend beside the VMM — Leandro's `vhost-user-input`, the second one of the display rig. The PACKAGE is not in this repo and is not built by this flake: it is a path, pushed to the node like the patched cloud-hypervisor beside it, and naming it here is what makes the agent register the driver and claim `input/fifo` and `input/evdev` in its Hello. A path and not a bool, for the reason the hypervisor binary is one: an image that carried the backend would make every node claim a device it may not have, and a node that has it in another place has to be able to say so. The two profiles come with the backend and need no configuration: `fifo` takes `type code value` lines from a named pipe the driver makes beside the socket, which is how a test presses a key with no human; `evdev` forwards one host `/dev/input/eventN`, named per device in `params.evdev`. A node that wants a longer patience than the driver's 5000 ms sets `settings.device.input.socket_timeout_ms` beside this. |
| `meisterstack.agent.physnets` | attribute set of string | `{ }` | The interfaces this node gives away to provider networks, by the name of the network each of them reaches. Empty (the default) is a node that gives none away: it still runs VMs and still carries tenant overlays, it is simply no candidate for a tenant router. A non-empty attrset renders `[network.provider] physnets` into the config template, and the agent then makes one bridge per provider network (`meister-px-<name>`, so a name has four characters), puts the interface in it, and claims `network/gateway:<name>` in its Hello. The tier above places routers only where that claim is. The interface must carry NO address: an address there is somebody still using the interface, and the agent refuses to start rather than put a router on a network the host is also on. This is per NODE and not per role, which is why it is its own option rather than a line in `settings` — a fleet plan says it per machine, and a machine that has no spare NIC says nothing. |
| `meisterstack.agent.settings` | TOML value | `{ }` | Agent config template overrides, merged over the role defaults above. Free-form TOML: nothing here validates a key, the agent does that at start-up with deny_unknown_fields. config/examples/agent.toml is the reference for what may go in it, and config/examples/hardened/agent.toml for a node that is not on a lab switch. node_id and controller_addr are NOT settable here — one-context writes them into /run/meisterstack/agent.toml at boot from the hostname and the OpenNebula context, and a key in both places would be a duplicate TOML key and a parse error. |
| `meisterstack.agent.unprivileged` | boolean | `false` | Run the agent as the user `meister` with exactly the capabilities in `meisterstack.agent.capabilities`, instead of as root. The default is false and stays false: root is what every node in this fleet has been, and the agent's behaviour as root does not change. What such a node can still do, all of it measured on 2026-09-16: boot guests (`/dev/kvm` through the group `kvm`), `filesystem` volumes, `input` with the `fifo` profile, and — with the default `CAP_NET_ADMIN` — every tap, bridge, VXLAN and nftables tap guard it makes today. What it cannot do, and says so at start-up, one sentence per driver: `lvm-thin` and `vfio` (CAP_SYS_ADMIN *and* CAP_DAC_OVERRIDE), `nfs` (CAP_SYS_ADMIN for mount(2)), `nvmeof` (the same, plus a root-owned /dev/nvme-fabrics), and a tenant router (CAP_SYS_ADMIN for `unshare(CLONE_NEWNET)` — a tap needs CAP_NET_ADMIN, a router does not stop at it). A driver whose need is missing is not registered, so this node claims none of that in its Hello and the scheduler places none of it here. This is a PROFILE for a compute-only node, not a hardening pass for the fleet: `deploy/README.md`, section "Ohne root", says what falls away, and in particular that the group `meister` on the agent socket is root-equivalent either way. |
| `meisterstack.cloud.settings` | TOML value | `{ }` | cloud-controller config, same shape and same rules; see config/examples/cloud.toml. This is the one tier with a public port, so config/examples/hardened/cloud.toml is worth reading before any deployment that is reachable from outside the lab. NOT `auth`: this tier's whole [auth] table is appended by one-context at boot (see cloudAuthMtls/cloudAuthOidc above and the reason it has to be one owner). A key here would be a duplicate [auth] table and a parse error on the VM. The values live in cloudAuthOidc; the issuer comes from MEISTER_OIDC_ISSUER. |
| `meisterstack.cluster.settings` | TOML value | `{ }` | cluster-controller config, merged OVER the role defaults above (so a deployment that sets one key keeps the rest). Free-form TOML: nothing here validates a key, the binary does that at start-up with deny_unknown_fields. config/examples/cluster.toml is the reference for every key it takes, and config/examples/hardened/cluster.toml for a control plane that is not on a lab switch. Empty (the default) = the role defaults above and, for everything they do not name, the binary's own — which are the lab topology. cluster_name, cloud_addr and cloud_addrs are normally left out here and written by one-context from the OpenNebula context instead — a key in both places would be a duplicate TOML key. |
| `meisterstack.context.defaults` | attribute set of string | `{ }` | MEISTER_* variables baked as defaults for one-context. Anything the OpenNebula context can say, a configuration can say here instead — and the context, being the thing that knows where this machine was actually booted, wins over it. Secrets do not belong here: this file is in the nix store and the store is world-readable. Certificates and keys travel with `meister-deploy keys push`, as they always have. |
| `meisterstack.data.label` | string | `"etcd-data"` | The filesystem label of this box's data block. The default is the lab's historical one and mounts only /var/lib/etcd, exactly as before. Any other value mounts /var/lib/meister-data instead and puts etcd under `etcd/` and the addons under `addons/` there. The label is IN the filesystem (`mkfs.ext4 -L <label>`), so it survives an image swap and a bus surprise alike. |
| `meisterstack.etcd.clusterToken` | string | `"meisterstack"` | Bootstrap token. Two tiers bootstrapping on one network must not share it — it is what keeps a cloud member from joining a cluster's Raft. |
| `meisterstack.etcd.member` | string | `"nixos"` | Which entry of `peers` this VM is. |
| `meisterstack.etcd.peers` | attribute set of string | `{ }` | Member name -> IP of every etcd member of this tier, this VM included. Empty (the default) keeps the single loopback member. Three members tolerate one loss; two do not tolerate any, so an even count buys nothing. |
| `meisterstack.roles` | list of (one of "cloud", "cluster", "agent", "addons") | `[ ]` | Which roles this machine runs. Empty (the default) is the generic image: every unit ships, and MEISTER_ROLE in the OpenNebula context decides at boot which of them starts. A non-empty list is baked as that variable's default, so a machine with no context still knows what it is — and a context may still override it. `both` and `all` are MEISTER_ROLE shorthands and not values here: a configuration that knows its roles at build time can name them. |

<!-- END module-options -->
