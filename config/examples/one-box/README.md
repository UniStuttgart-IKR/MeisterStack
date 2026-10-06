<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR
-->

# One-box deployment

A one-box fleet combines cloud, cluster, agent, and optional addon roles on one
machine. Additional agents can join the same cluster. Use meister-deploy's
schema-2 one-box inventory (`examples/fleet/one-box.toml` there) as a topology
example and its operator template (`templates/operator/`) for the deployment
repository. See [Deployment](../../../docs/DEPLOYMENT.md) for installation and
rollout commands and [Nix integration](../../../docs/NIX.md) for module behavior.

Set stable host identities, management addresses, the disk layout, persistence,
SSH fingerprints, trusted binary-cache keys, and host hardware modules. The
addons role requires a domain whose name matches the identity provider's serving
certificate and origin. The inventory only configures a management interface
when `static = true`; otherwise the host or provider supplies its address.

Persistent VM records, volumes, etcd, and addon state need storage that survives
the intended update or reinstall. Runtime modules mount configured devices but
do not format them. An optional missing data disk may leave state on the root
filesystem, so establish and verify the layout before depending on it.

The addon module provisions Kanidm groups, sample accounts, and OAuth2 clients.
Complete each person's credential setup through Kanidm administration. These
groups do not create MeisterStack User resources or grant API roles; a cloud
administrator creates the corresponding users unless controlled OIDC provisioning
is enabled. The CLI supports authorization code with PKCE and a device-grant
fallback; see [Configuration](../../../docs/CONFIGURATION.md).

| Service | Default endpoint |
| --- | --- |
| Cloud API | `https://<box>:3000` |
| Cluster API | `https://<box>:3001` |
| Kanidm | `https://<box>.<domain>:8443` |
| Grafana | `http://<box>:3080` |
| Prometheus | `http://<box>:9090` |
| Loki | `http://<box>:3100` |
| Tempo OTLP | TCP `4317` / `4318` |
| Garage S3 / admin | TCP `3900` / `3903` |

Restrict internal and unauthenticated endpoints with the host's network policy.
Combining roles reduces availability to that machine's lifetime; the addon
example also uses local state and single-node object-store replication.
