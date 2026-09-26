# Configuration

Start with [component examples](../config/examples/) or
[mTLS examples](../config/examples/hardened/README.md).
[Development fixtures](../config/README.md) use checkout paths and lab addresses.
TOML configures processes/backends; API resources hold workloads and tenant policy.

## Loading and validation

- Controller command-line options override the file. Agent configuration requires
  node identity, paths, hypervisor, and default network settings.
- Relative paths resolve against the selected file's directory. PEM settings name files.
- `--check-config --config <file>` validates types, combinations, and names without
  listeners or runtime databases. Devices, helpers, privileges, mounts, and peers
  still need runtime checks.
- Examples: `# ` prose, `#key` disabled settings. Optional top-level keys must
  precede tables. Examples are tested combinations, not exhaustive schemas.
- [Nix](NIX.md) renders the same types from defaults, generated values, and role settings.

Sources: [agent](../components/agent/src/config.rs),
[cloud](../components/cloud-controller/src/main.rs),
[cluster](../components/cluster-controller/src/main.rs).

## Identities, addresses, and credentials

| Setting | Contract |
| --- | --- |
| `node_id` | Stable agent identity, unique within the cluster. |
| `cluster_name`, `cloud_name` | Logical identity shared by replicas. |
| `listen_api` / `advertise_api` | REST bind / reachable sibling forwarding address. Unspecified binds cannot serve as advertised destinations. |
| `listen_session` | gRPC listener for the lower tier. |
| `controller_addrs`, `cloud_addrs` | Upstream replicas; nonempty list overrides singular setting. Rendezvous order, bounded dials. Agent → cluster → cloud. |
| `https://` | Enables session TLS. PEM paths with `http://` still give plaintext. |
| `tls_cert`, `tls_key` | Controller serving pair for REST and sessions. |
| `client_ca` | Client-certificate trust anchor. |
| Agent `controller_*`, cluster `cloud_*` | Outbound session trust and identity; subjects must match Hello. |
| Cloud `identity_cert`, `identity_key` | Sibling forwarding identity. |
| Signing CA | Optional; without it CSRs can be recorded but not issued. |
| `secrets_key` | Shared 32-byte controller key. Replacing it does not rotate stored ciphertext. |

No configured authenticators means unrestricted anonymous access. Explicit chains
require their inputs. Cloud User records authorize ordinary users; cluster rejects
ordinary users. Private keys require no group/other permissions.
See [Security](SECURITY.md) for subjects, roles, and machine/break-glass access.

## Agent resources and host integration

| Area | Contract / requirement |
| --- | --- |
| Persistence | Database and disks need the same lifetime. `run_dir`: runtime/sockets; `image_dir`: base images; `volume_dir`: local volumes. Shared images do not share volumes; catalogue entries do not distribute bytes. |
| Local API | Unix socket, default `0600`. `socket_group` grants full administration without tenant authentication. Nix selects `meister`, under `/run/meisterstack/agent`. |
| Multiple agents | Separate node IDs, databases, runtime directories, cgroup roots. Explicitly allocate devices/storage/network ownership. |
| Capacity/pinning | `capacity_vcpus` / `capacity_mem_mib` only lower reported capacity; `cgroup_cpuset` enforces CPU placement. |
| Backends | Filesystem volumes default on; other sections enable/advertise capabilities. Device parameters: defaults < profile < VM. `vfio` allowlist: `[[device.managed]]`. |
| Overlay | Separate VXLAN bridges. Participating nodes must agree on multicast/EVPN. Provider interfaces must have no host IP. |
| Floating guard | Keep `guarded_ranges` aligned with cloud pools; sessions do not distribute the full pool catalogue. |
| Connectivity | Migration, metrics, VXLAN, BGP, and storage may need inbound ports. Nix metrics are unauthenticated; host firewall remains operator-owned. |
| Migration deadlines | Agent watchdog ceilings must exceed cluster transfer deadline. Timeout alone does not prove teardown safe. |

References: [agent example](../config/examples/agent.toml), [Storage](STORAGE.md),
[Networking](NETWORKING.md), [Nix ports](NIX.md#network-and-state-defaults),
[Observability](OBSERVABILITY.md), [Migration limits](MIGRATION.md).

## Controller scheduling and resources

| Setting / mechanism | Contract |
| --- | --- |
| etcd prefixes | Separate per tier; one etcd deployment can host both. Cross-tier exchange uses sessions. |
| Placement | Cloud selects cluster; cluster selects node. Configured strategy: `first-fit`. |
| Admission | Reported capacity × factor − all bound claims, including Pending. CPU default `4.0`; memory default/maximum `1.0`. Placement budgets, not free-memory measurements; other eligibility filters still apply. |
| Cluster `retry` | Failed-VM backoff: 10 s doubling to 5 min. `none` disables; count limits attempts. Quarantined requires intervention. |
| Cloud `vni_base` | Monotonic tenant VNI floor; implementation maximum `99999`. |
| `routed_pools` | Automatic subnet allocation ranges. Floating pools, tenant quotas, users, VMs remain API resources. |

References: [API](API.md), [Control plane](CONTROL_PLANE.md).

## CLI profiles and OIDC sessions

| Selection | Precedence / behavior |
| --- | --- |
| Config | `--config` / `MEISTER_CONFIG`; existing `$XDG_CONFIG_HOME/meisterstack/config.toml` or `~/.config/meisterstack/config.toml`; `/etc/meisterstack/cli.toml`. Files are selected, not merged. |
| Profile | `--profile` → `MEISTER_PROFILE` → `default_profile`. |
| Endpoint | `--endpoint` / `MEISTER_ENDPOINT` override address, retaining profile settings. |
| Credential override | `MEISTER_TOKEN` replaces profile credential. |
| Credential types | None, token file, environment, command, mTLS pair, OIDC. |
| HTTPS trust | Explicit controller `ca_cert` required; OIDC has a separate optional provider CA. |
| OIDC flow | Authorization code + PKCE when discovery supports it; device fallback. Later commands refresh saved sessions. |
| Default token path | `<selected config directory>/oidc/<profile>.json`. System profile therefore uses `/etc/meisterstack/oidc`, normally unwritable by ordinary users. |

For interactive OIDC, use a per-user profile or explicit private `tokens` path.
Copy required endpoint/trust settings; the system profile is not merged. Example
`~/.config/meisterstack/config.toml`:

```toml
default_profile = "cloud"
[profiles.cloud]
endpoint = "https://cloud.example.net:3000"
ca_cert = "/etc/meisterstack/ca.crt"
credential = { type = "oidc", issuer = "https://idp.example.net", client_id = "meisterstack" }
```

Login establishes identity; the cloud still requires a User unless controlled
provisioning is enabled. Sources: [CLI config](../components/cli/src/config.rs),
[CLI reference](CLI.md).
