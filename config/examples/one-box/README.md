<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR
-->

# Eine Kiste, vier Knoten

Der Normalfall: eine Bare-Metal-Kiste ist Cloud-Controller,
Cluster-Controller, Addons (Kanidm, Garage, Prometheus, Loki, Tempo,
Grafana) **und** Knoten, daneben ein paar Kisten, die nur Knoten sind.
HA und OpenNebula sind die Option nach oben, nicht der Anfang.

Der ganze Aufbau, in zehn Zeilen:

```bash
cp examples/fleet/one-box.toml fleet.toml   # 1. Plan schreiben: Adressen,
$EDITOR fleet.toml                          #    Platten, Domain anpassen
git add fleet.toml                          #    (ein Flake sieht nur, was in git ist)
nix flake check                             # 2. Plan pruefen
meister-deploy keys init                    # 3. CA, Zertifikate, drei Geheimnisse
meister-deploy image all --copy /var/tmp    # 4. je Knoten ein raw-efi-Image
sudo dd if=/var/tmp/meisterstack-one-box-box-*.img of=/dev/nvme0n1 bs=4M status=progress
                                            # 5. auf die Platte, je Kiste einmal
#    booten, dann von hier aus:
meister-deploy keys push                    # 6. Zertifikate auf die Kisten
meister-deploy check                        # 7. Units, Sessions, /dev/kvm, etcd
```

Das war es. Was danach noch von Hand kommt, steht unten.

## Was in `fleet.toml` geaendert werden muss

| Zeile | warum |
|---|---|
| `[fleet] domain` | Kanidm braucht einen **Namen**, keine Adresse: Origin, Issuer, jede Redirect-URL und das Serving-Zertifikat sind derselbe Name. `<knoten>.<domain>` muss auf jeder Maschine aufloesen, die sich anmeldet — DNS-Eintrag oder `/etc/hosts`. |
| `[fleet] ca` | wo `meister-ca` sein Verzeichnis hat. **Nie im Image**, nie im Repo. |
| `address` je Knoten | die Adresse, unter der die Kiste erreichbar ist |
| `disk` je Knoten | die Zielplatte fuer `dd`. `lsblk` **vorher**. |
| `data` auf der Box | die zweite Platte: etcd und der Zustand der sechs Dienste. Ohne sie leben beide auf der Rootplatte und ein Image-Tausch nimmt sie mit. |
| `modules` je Knoten | eigene Nix-Dateien: NVIDIA, Mellanox, Kernel-Optionen, eine `hardware-configuration.nix`. Pfade relativ zur Plan-Datei. |

Adressen, `[defaults] prefix` und `gateway` entscheiden, ob die Kisten
statisch konfiguriert werden oder per DHCP hochkommen. Ohne `prefix`:
DHCP, und die Adresse im Plan ist die, die reserviert wurde.

## Die zweite Platte, einmal

Der Datenblock wird nicht formatiert — ein Werkzeug, das eine Platte
formatiert, die es nicht angelegt hat, ist ein Werkzeug, das irgendwann
die falsche formatiert. Einmal, auf der Box, nach dem ersten Boot:

```bash
lsblk                                       # welche Platte ist es wirklich
mkfs.ext4 -L meister-data /dev/nvme1n1      # das LABEL ist der Vertrag
reboot
```

Das Label steht **im** Dateisystem, ueberlebt also einen Image-Tausch und
eine Umsortierung der Geraete — beides ist im Lab schon passiert, und
beim zweiten Mal lag etcds Zustand still auf der Rootplatte.

## Die vier Konten, einmal

Kanidm legt Gruppen, Konten und die beiden OAuth2-Clients selbst an
(`nix/addons.nix`). Was es **nicht** kann, ist ein Passwort setzen — dafuer
gibt es keine API. Also einmal je Mensch, auf der Box:

```bash
kanidm login -D idm_admin                   # Passwort: /opt/meisterstack/pki/addons-admin
kanidm person credential create-reset-token silas
```

Der Link, den das druckt, wird im Browser geoeffnet. Danach:

```bash
meister login --oidc                        # siehe die Einschraenkung unten
meister user create silas --tenant ops --role admin
```

> **Device Grant:** Kanidm 1.10 unterstuetzt RFC 8628 nicht (der Code
> steht hinter einem Cargo-Feature, das nixpkgs nicht baut, und die
> Dokumentation kennt ihn nur als Entwurf). Bis die CLI einen zweiten Weg
> hat — Authorization Code + PKCE mit Redirect auf `localhost` — ist der
> Weg hinein das Break-Glass-Zertifikat aus `keys init`:
> `meister --profile root user create ...`.

## Was diese Kiste danach ist

| Dienst | Adresse |
|---|---|
| Cloud-API (mTLS, spaeter OIDC) | `https://<box>:3000` |
| Cluster-API | `https://<box>:3001` |
| Kanidm | `https://<box>.<domain>:8443` |
| Grafana | `http://<box>:3080` — **nicht** 3000: das ist die Cloud-API, und auf einer Kiste mit beiden Rollen kann nur einer der beiden dort liegen. Grafana ist der, dessen Port nirgends sonst aufgeschrieben steht. |
| Prometheus / Loki / Tempo | `:9090`, `:3100`, `:4317` |
| Garage S3 | `:3900`, Admin `:3903` |

## Weiter

- `deploy/README.md` — die vier Formen des Deployments und die
  Optionstabelle des Moduls
- `meister-deploy plan` — was die Flotte gerade wirklich ist
- `meister-deploy push` — der naechste Stand, Gruppe fuer Gruppe
