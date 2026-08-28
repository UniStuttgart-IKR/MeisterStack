// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Shared control-plane API: the K8s-style object envelope, the typed
//! resources of both tiers, the etcd-backed store, and the plugin traits
//! (scheduler first). Both controllers build on this crate; the design is
//! docs/design/control-plane.md.

pub mod auth;
pub mod command;
pub mod events;
pub mod floating;
pub mod grpc;
pub mod heartbeat;
pub mod lifecycle;
pub mod mirror;
pub mod object;
pub mod quota;
pub mod requeue;
pub mod resources;
pub mod rest;
pub mod scheduler;
pub mod store;
pub mod vni;

pub use auth::{
    Attempt, AuthChain, AuthRequest, Authenticated, Authenticator, BearerAuthenticator,
    GROUP_ADMINS, GROUP_CLUSTERS, GROUP_MASTERS, GROUP_MEMBERS, GROUP_NODES, Identity,
    MtlsAuthenticator, Rejected, Role, Scope, Verb, classify, permits, permits_object,
};
pub use command::{Ack, Peer, Pending};
pub use heartbeat::{HEARTBEAT_TIMEOUT_SECS, expired as heartbeat_expired};
pub use lifecycle::{Lifecycle, lifecycle_command};
pub use mirror::{Observation, observe};
pub use object::{ANNOTATION_TRACEPARENT, Metadata, Object, Resource};
pub use requeue::{RequeueConfig, RequeuePolicy};
pub use resources::{
    API_VERSION, CertificateSigningRequest, Cluster, ClusterCapacity, ClusterSpec, ClusterStatus,
    Counter, CounterSpec, CsrCondition, CsrConditionType, CsrSpec, CsrStatus,
    DEFAULT_QUOTA_PRIVATE, DEFAULT_QUOTA_PUBLIC, DEFAULT_ROUTED_PREFIX_LEN, Event, EventSpec,
    EventType, FloatingIp, FloatingIpSpec, FloatingIpStatus, FloatingPool, FloatingPoolSpec,
    FloatingPoolStatus, Image, ImageFormat, ImagePhase, ImageSpec, ImageStatus, IssuedCertificate,
    LABEL_CLOUD_UID, LABEL_MANAGED_BY, MANAGED_BY_CLOUD, Node, NodeCapacity, NodeSpec, NodeStatus,
    RoutedSubnet, RoutedSubnetSpec, RoutedSubnetStatus, RunStrategy, SIGNER_USER_CLIENT, Tenant,
    TenantQuota, TenantSpec, TenantStatus, TenantUsage, User, UserSpec, UserStatus, Vm, VmPhase,
    VmSpec, VmStatus,
};
pub use rest::{
    ApiError, AuthState, Caller, CallerRole, CallerTenant, PeerCerts, SpecUpdate,
    apply_spec_update, check_envelope, conflict, forbidden, guard, invalid, serve,
};
pub use scheduler::{
    Candidate, Capacity, DevicePolicy, FirstFit, Overcommit, PendingReason, PendingTally,
    Scheduler, SchedulerConfig, deduct, pending_reason, pending_reason_of,
};
pub use store::{EtcdStore, PassTrigger, StoreError};
