# mTLS deployment examples

These files configure a cloud API for user access, internal controller session
ports, and certificate authentication. Replace the example addresses, identities,
and PEM paths before use. See [Configuration](../../../docs/CONFIGURATION.md)
and [Security](../../../docs/SECURITY.md) for the authentication and loading rules.

| Endpoint | Example binding | Access |
| --- | --- | --- |
| Cloud REST | `0.0.0.0:3000` | TLS and an identity accepted by the cloud. |
| Cloud session | `10.128.1.103:50050` | Internal cluster-to-cloud mTLS. |
| Cluster REST | `127.0.0.1:3001` | Machine or break-glass operator identity, optionally through an SSH tunnel. |
| Cluster session | `10.128.1.104:50051` | Internal agent-to-cluster mTLS. |
| Agent API | `<run_dir>/agent.sock` | Local filesystem permissions; no tenant authentication. |

The cluster rejects ordinary user certificates because it has no user directory.
Users call the cloud, which resolves their User record on each request. A
certificate's issuer trust and its authorization are separate checks.

The agent's control-plane session is outbound, but enabled migration, metrics,
VXLAN, BGP, and storage functions can require inbound connectivity. Restrict
those ports to the appropriate networks. These examples do not configure a host
firewall. The local socket defaults to `0600`; configuring `socket_group` grants
members full local administration.

Serving certificate SANs must cover every name or address clients dial. Session
URLs must use `https://`: PEM settings alone do not enable TLS. Private keys must
have no group or other permission bits. Relative paths resolve against the
configuration file's directory.

The explicit `auth.chain = ["mtls"]` requires the client CA and leaves no bearer
bootstrap route. Issue the initial break-glass administrator identity through
the operator's CA workflow. Later certificate requests still need an accepted
identity and, with auto-approval disabled, explicit approval. The cloud example
includes a signing CA key; deployments that keep signing offline should remove
that runtime responsibility when adapting the configuration.

Floating-pool ranges and `routed_pools` must remain synchronized with agent
`guarded_ranges`.
Overlay discovery mode and upstream routing also require site configuration;
see [Networking](../../../docs/NETWORKING.md).
