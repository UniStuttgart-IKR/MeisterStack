# Technology stack

Versions are pinned or constrained in [Cargo.lock](../Cargo.lock),
[Cargo.toml](../Cargo.toml) and [flake.lock](../flake.lock). This table explains their
roles without maintaining a second version list.

| Technology | Role in MeisterStack |
| --- | --- |
| Rust, Cargo | Runtime services, CLI, drivers and shared contracts |
| Tokio | Async tasks, I/O, timers and synchronization |
| Axum, Hyper | REST APIs, local HTTP transport and console connections |
| Tonic, Prost | Bidirectional controller sessions and protobuf messages |
| Serde, Schemars | Persisted JSON resources, TOML config and API schemas |
| etcd | Controller resource storage, revision comparisons and watches |
| redb | Agent records, owned handles and migration receipts |
| Cloud Hypervisor, KVM | VM processes and virtualization |
| vhost-user backends | Out-of-process device services, including input and GPU paths |
| Linux netlink, namespaces, nftables | Interfaces, overlays, routing and packet policy |
| cgroup v2, Unix credentials, VFIO | Resource controls, process identity and PCI assignment |
| Filesystem, NFS, NVMe-oF drivers | Storage provisioning or import and attachment |
| rustls, ring, rcgen | TLS, signing and certificate handling |
| OIDC, JWT/JWK handling | Human login and bearer-token validation |
| tracing, OpenTelemetry, Prometheus | Structured logs, traces and scraped metrics |
| Nix, NixOS | Build inputs, packages, service modules and host composition |

The agent API traits isolate backend-specific behavior. A dependency being present
does not mean its feature is enabled or its hardware is available. See
[drivers](DRIVERS.md), [Nix](NIX.md) and [testing](TESTING.md).
