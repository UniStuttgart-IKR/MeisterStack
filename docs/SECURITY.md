# Security boundaries

Authentication, authorization, tenant ownership and node isolation are separate
checks. A credential establishes an identity; it does not by itself establish a
role, a tenant or ownership of a resource.

## Authentication and directory grants

Controllers build an ordered authenticator chain from configuration. The default
order is mTLS, OIDC, then static bearer, retaining configured mechanisms. An
explicitly requested but unconfigured mechanism is a startup error. The first
successful authenticator supplies the identity; a hard rejection stops the chain.
An enabled chain that recognizes no credential returns 401.

With no authenticators configured, requests are anonymous and unrestricted. TLS
and authentication are independent settings. The static development bearer token
is a break-glass credential: its identity belongs to the masters group and bypasses
ordinary role checks. Session listeners require mTLS in a configured authentication
chain; incomplete TLS configuration is rejected.

Ordinary users are authorized through the cloud's current User directory entry.
The middleware reads role and tenant there for each request. Certificate groups
and OIDC claims do not replace that grant. A valid credential for a deleted or
unknown user is refused. Cluster controllers have no human directory and refuse
ordinary human identities, including certificates carrying an admin group; they do
not retain stale user privileges from those certificate claims.

Optional OIDC first-login provisioning is disabled by default. When enabled, it
requires a configured tenant claim naming an existing tenant and creates a Member
grant. Identity-provider role-like claims do not grant administrator access.
`whoami` exposes the grant actually resolved by the endpoint.

Sources: [authenticator chain](../shared/controller-api/src/auth.rs),
[directory middleware and configuration](../shared/controller-api/src/rest/guard.rs),
[OIDC identity adapter](../shared/controller-api/src/oidc.rs),
[session authentication](../shared/controller-api/src/grpc.rs).

## Roles, tenants and peer identities

Roles are ordered Viewer, Member, Operator, Admin. The shared policy first checks
the operation's resource class, then handlers check the particular object's owner.

| Resource class | Minimum read role | Minimum write role |
| --- | --- | --- |
| User/Tenant directory and certificate approval | Admin | Admin |
| Certificate request creation/read | Viewer | Viewer; acting for another user requires additional authority |
| Infrastructure | Viewer | Operator |
| Tenant resources | Viewer | Member |
| Tenant-operated resources, including routers and migrations | Viewer | Operator |

For tenant-scoped objects, Viewers and Members read their own tenant's objects and
public images. Operators can read across tenants, but ordinary tenant writes still
require ownership in their own tenant. Admin and approved system paths bypass
object scoping. Missing tenant ownership is not public access. A list filter is
only a filter; it cannot widen the caller's scope.

Machine identities use `system:<kind>:<name>`. A session certificate must be allowed
to speak for the kind and name in Hello. A node identity cannot claim a cluster or
another node. Machine credentials do not automatically grant general REST access.
An exact sibling identity of the same tier can read and can perform a narrow set
of forwarded writes: cluster node updates, node migration commands and cloud
migration creation. The `x-meister-forwarded` marker is required for those writes
but grants nothing without the matching credential. The masters group remains the
explicit break-glass exception.

Sources: [policy tables and object scope](../shared/controller-api/src/auth.rs),
[forwarding](../shared/controller-api/src/forward.rs),
[resource ownership](../shared/controller-api/src/resources/mod.rs).

## PKI and OIDC

Client keys are generated locally; a CSR contains the public key and proof of
possession. The signer controls the issued subject, usage and validity instead of
trusting requested privileges or extensions. User certificates are client-only.
With CSR auto-approval enabled, the create handler currently signs and updates
User certificate history before checking dry-run. A preview can therefore issue
a usable certificate without storing its CSR. Explicit approval has a separate
dry-run refusal; see [controller CSR handling](../components/cloud-controller/src/api/csrs.rs).

Private-key loading rejects group- or world-readable files on Unix. The shared
secret writer creates new files with mode 0600; it does not tighten permissions on
an existing destination.

The REST TLS handshake can accept a connection without a client certificate so
bearer authentication can run later. A presented certificate still undergoes trust
and validity checks. Configured revocation lists must load successfully at startup.
The loader checks for changes every 30 seconds; unreadable, invalid or rolled-back
replacements leave the last accepted list in force. A lower CRL number, or changed
content at the same number, is refused. Session paths also apply their configured
peer checks; TLS and application authorization serve different purposes.

OIDC uses HTTPS discovery and JWKS retrieval. A configured CA bundle replaces the
public root set for provider requests. Requests have a 15-second limit. Verification
allows configured asymmetric algorithms, defaults to RS256 and ES256, and rejects
unsigned tokens, HMAC algorithms and unsupported critical header extensions. It
verifies the signature, exact issuer, an allowed audience, required expiry and
optional not-before time with a 60-second allowance. The username claim defaults
to `sub`; reserved `system:` names are refused.

The key cache starts asynchronously. Authentication remains degraded until usable
keys arrive. An unknown key ID is refused and requests a background refresh, limited
to once per minute; scheduled refresh also runs hourly. Fetch failures preserve
previous keys. The CLI supports the device flow and refresh tokens through the
same OIDC crate.

Sources: [certificate signing](../shared/pki/src/ca.rs),
[CSR handling](../shared/pki/src/csr.rs),
[PEM files](../shared/pki/src/pem.rs),
[TLS configuration](../shared/pki/src/tls.rs),
[CRL loader](../shared/controller-api/src/auth.rs),
[JWT validation](../shared/oidc/src/jwt.rs),
[key cache](../shared/oidc/src/cache.rs),
[provider discovery](../shared/oidc/src/discovery.rs),
[device flow](../shared/oidc/src/device.rs).

## Secrets, console tickets and quotas

Secret values are encrypted with AES-256-GCM before entering etcd. The configured
KEK is 32 raw bytes or 64 hexadecimal characters. Each value has a fresh nonce;
authenticated associated data binds it to its resource kind, object name and data
key. It does not include the tenant or object UID. The API returns key names without
returning stored values. The KEK lives outside etcd; this implementation uses one
configured key rather than an envelope-key or rotation protocol.

Cloud-managed secrets are mirrored as ciphertext to clusters using the same KEK.
The cluster decrypts a referenced value when constructing agent cloud-init data.
That resolved value then travels in the VM command and is materialized for the
guest. Protecting etcd ciphertext does not remove the need to secure sessions,
controller memory and node-side files.

Browser consoles can use a 30-second, single-use ticket tied to one URL and caller.
Tickets live in leased etcd records shared across replicas. Spending one uses a
conditional deletion, so concurrent consumers cannot both succeed. Tickets are not
exposed as a listable public resource. Raw stream and WebSocket console adapters
ultimately use the same session transport.

Two current console limits weaken that boundary. Cloud ConsoleOpen carries only
a VM name; the cluster lookup does not check the cloud UID or ownership marker.
A same-named local VM can therefore be selected after a cloud CreateVm was refused.
The cluster's sibling console hop also uses plain TCP HTTP without sibling TLS
credentials, so it cannot connect to an authenticated TLS sibling. These differ
from the ownership checks on ordinary cloud resource commands and the configured
TLS transport used by logs. See [cloud console entry](../components/cloud-controller/src/api/vms.rs)
and [cluster console forwarding](../components/cluster-controller/src/cloud.rs).

Tenant quotas limit VM count, vCPU count and memory; omitted limits are unlimited.
Usage is derived from live resource objects, including objects still terminating.
Storage pools impose their own per-tenant volume-size quotas, and floating pools
have separate address quotas. Default floating allowance is four addresses for a
private pool and zero for a public pool. Allocation and admission must account for
concurrent writers; see [store admission](API.md#store-and-admission).

Sources: [secret encryption](../shared/controller-api/src/secrets.rs),
[secret type](../shared/controller-api/src/resources/secret.rs),
[session secret mirror](../shared/proto/proto/control.proto),
[tickets](../shared/controller-api/src/tickets.rs),
[quota calculations](../shared/controller-api/src/quota.rs),
[floating allocation](../shared/controller-api/src/floating.rs).

## Node-side boundaries

Image inspection and conversion accept regular raw or self-contained qcow2 files,
reject backing files and external data files, and pass the inspected format
explicitly to conversion. The qemu-img processes run through a systemd sandbox
under a dedicated user, with constrained writable paths, devices, capabilities,
sockets and resource limits. This is an execution boundary around an untrusted
image parser; it is not a guarantee that every host-readable path is hidden or that
an externally mutable input cannot change between inspection and conversion.

VMM credentials retain configured supplementary device groups, then switch GID and
UID before exec. Recorded PIDs are checked against VM identifiers before adoption
or signaling. That check reduces PID-reuse mistakes but is not a pidfd or an atomic
check-and-signal operation. Storage handles separate ownership of backend bytes
from a node attachment; release and forget must not be substituted with destructive
deprovisioning. Migration ownership needs durable attempt evidence, described in
[Migration](MIGRATION.md) and [resource lifecycle](RESOURCE_LIFECYCLE.md).

Sources: [base-image boundary](../shared/agent-api/src/base_image.rs),
[VMM credentials](../shared/agent-api/src/vmm_user.rs),
[PID checks](../shared/agent-api/src/pid.rs),
[storage contract](../shared/agent-api/src/storage.rs).
