# Security boundaries

Credentials establish identity. Authorization, tenant ownership, and node isolation
remain separate checks.

## Authentication and directory grants

| Case | Behavior |
| --- | --- |
| Default chain | Configured mechanisms in order: mTLS, OIDC, static bearer. First success wins; hard rejection stops traversal. |
| Explicit unconfigured mechanism | Startup error. |
| Enabled chain, no accepted credential | HTTP 401. |
| No authenticators | Unrestricted anonymous access, independently of serving TLS. |
| Development bearer | Defaults to the masters group; bypasses ordinary role checks. |
| Session listener | Configured chain requires mTLS; incomplete TLS is rejected. |
| Ordinary cloud user | Role/tenant read from current User record on every request. Certificate groups and token claims cannot replace it. Unknown/deleted users are refused. |
| Ordinary cluster user | Refused: cluster has no human directory, even for certificates claiming an admin group. |
| OIDC provisioning | Off by default. When enabled: configured claim must name an existing tenant; creates Member only. |
| `whoami` | Returns this endpoint's resolved grant. |

Sources: [auth chain](../shared/controller-api/src/auth.rs),
[directory guard](../shared/controller-api/src/rest/guard.rs),
[OIDC adapter](../shared/controller-api/src/oidc.rs),
[sessions](../shared/controller-api/src/grpc.rs).

## Roles, tenants and peer identities

Role order: Viewer < Member < Operator < Admin. Resource policy precedes object scope.

| Resource class | Read | Write |
| --- | --- | --- |
| User/Tenant directory, certificate approval | Admin | Admin |
| CSR creation/read | Viewer | Viewer; another user's identity requires additional authority |
| Infrastructure | Viewer | Operator |
| Tenant resources | Viewer | Member |
| Tenant-operated resources, including routers/migrations | Viewer | Operator |

- Viewers/Members read their tenant and public images. Operators read across
  tenants, but ordinary tenant writes still require their own tenant ownership.
- Admin and approved system paths bypass object scoping. Missing ownership is
  not public access; list filters cannot widen scope.
- `system:<kind>:<name>` session identities must match Hello kind/name. Machine
  credentials do not automatically grant general REST access.
- Exact same-tier sibling identities can read and perform limited forwarded writes:
  cluster node updates, node migration commands, cloud migration creation.
  Those writes also require `x-meister-forwarded`; the marker is not a credential.
  Masters is the explicit break-glass exception.

Sources: [policy](../shared/controller-api/src/auth.rs),
[forwarding](../shared/controller-api/src/forward.rs),
[ownership](../shared/controller-api/src/resources/mod.rs).

## PKI and OIDC

- Keys are generated locally; CSRs prove possession. Signers control subject,
  usage, validity, and extensions. User certificates are client-only.
- **CSR dry-run limit:** auto-approved creation signs and updates User history
  before dry-run checking, potentially issuing a usable certificate without a
  stored CSR. Explicit approval separately refuses dry-run.
  [CSR handler](../components/cloud-controller/src/api/csrs.rs).
- Unix key loading rejects group/other permissions. Secret-file creation uses
  `0600`, but overwriting an existing file does not tighten its mode.
- REST TLS permits an absent client certificate for later bearer authentication;
  presented certificates still undergo trust/validity checks.

| Revocation / OIDC setting | Contract |
| --- | --- |
| CRL startup | Configured list must load. |
| CRL reload | Every 30 s; invalid, unreadable, lower-numbered, or changed same-number replacements retain the last accepted list. Session paths also enforce peer checks. |
| Provider requests | HTTPS discovery/JWKS; 15 s limit. Explicit CA bundle replaces public roots. |
| JWT algorithms | Configured asymmetric set; defaults RS256/ES256. Reject unsigned, HMAC, unsupported critical extensions. |
| JWT claims | Signature, exact issuer, allowed audience, required expiry, optional not-before; 60 s clock allowance. |
| Username | Defaults to `sub`; reserved `system:` names refused. |
| JWKS startup | Asynchronous. Fetch completion can report readiness even for an empty, unusable key set. |
| Unknown key ID | Reject token; request background refresh, at most once/minute. |
| Scheduled refresh | Hourly; failed fetch retains previous keys. |
| CLI login | PKCE authorization code where supported; device fallback and token refresh. See [configuration](CONFIGURATION.md#cli-profiles-and-oidc-sessions). |

Sources: [signing](../shared/pki/src/ca.rs), [CSR](../shared/pki/src/csr.rs),
[PEM](../shared/pki/src/pem.rs), [TLS](../shared/pki/src/tls.rs),
[CRL](../shared/controller-api/src/auth.rs), [JWT](../shared/oidc/src/jwt.rs),
[cache](../shared/oidc/src/cache.rs), [discovery](../shared/oidc/src/discovery.rs),
[device flow](../shared/oidc/src/device.rs).

## Secrets, console tickets and quotas

| Mechanism | Contract / limit |
| --- | --- |
| Secret encryption | AES-256-GCM; KEK is 32 raw bytes or 64 hex characters; fresh nonce per value. AAD binds kind/name/data key, excluding tenant and UID. |
| Secret reads | Return key names, not stored values. One external KEK; no envelope-key or rotation protocol. |
| Secret delivery | Ciphertext mirrored to clusters sharing the KEK; cluster decrypts cloud-init values for VM commands and guest materialization. Sessions, memory, and node files still contain plaintext. |
| Console tickets | URL/caller-bound, 30 s, single-use leased etcd records. Conditional deletion serializes redemption; no public ticket listing. Stream/WebSocket adapters share session transport. |
| Tenant quotas | VM count, vCPU, memory; omitted limits unlimited. Usage includes terminating objects. |
| Pool quotas | Separate volume-size and address quotas. Floating defaults: private pool 4, public pool 0. Concurrent admission needs [fences](API.md#store-and-admission). |

Current console limits:

- Cloud ConsoleOpen identifies a VM only by name. Cluster lookup omits cloud UID
  and ownership checks: a same-named local VM can be selected after refused cloud
  creation. [Cloud entry](../components/cloud-controller/src/api/vms.rs).
- Cluster sibling console forwarding uses plain HTTP without sibling TLS
  credentials; authenticated TLS siblings cannot be reached through that path.
  [Cluster forwarding](../components/cluster-controller/src/cloud.rs).

Sources: [encryption](../shared/controller-api/src/secrets.rs),
[Secret type](../shared/controller-api/src/resources/secret.rs),
[protocol](../shared/proto/proto/control.proto),
[tickets](../shared/controller-api/src/tickets.rs),
[quotas](../shared/controller-api/src/quota.rs),
[address allocation](../shared/controller-api/src/floating.rs).

## Node-side boundaries

| Boundary | Enforcement / limit |
| --- | --- |
| Image conversion | Regular raw/self-contained qcow2; reject backing/external data files; pass inspected format explicitly. Dedicated-user systemd sandbox constrains writes, devices, capabilities, sockets, and resources. Does not hide every readable host path or eliminate input mutation between inspection/conversion. |
| VMM credentials | Preserve configured device groups; switch GID/UID before exec. |
| PID checks | Match VM identity before adoption/signaling; no pidfd or atomic check-and-signal guarantee. |
| Storage | Backend ownership differs from attachment. Release/forget cannot substitute for destructive deprovision. |
| Migration | Durable attempt evidence establishes ownership; see [Migration](MIGRATION.md) and [resource lifecycle](RESOURCE_LIFECYCLE.md). |

Sources: [images](../shared/agent-api/src/base_image.rs),
[VMM user](../shared/agent-api/src/vmm_user.rs), [PIDs](../shared/agent-api/src/pid.rs),
[storage](../shared/agent-api/src/storage.rs).
