// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Shared control-plane API: the K8s-style object envelope, the typed
//! resources of both tiers, the etcd-backed store, and the plugin traits
//! (scheduler first). Both controllers build on this crate; the design is
//! docs/design/control-plane.md.

pub mod auth;
pub mod command;
pub mod drain;
pub mod events;
pub mod floating;
pub mod forward;
pub mod grpc;
pub mod heartbeat;
pub mod lifecycle;
pub mod mirror;
pub mod network;
pub mod object;
pub mod oidc;
pub mod quota;
pub mod requeue;
pub mod resources;
pub mod rest;
pub mod scheduler;
pub mod secrets;
pub mod store;
pub mod stuck;
pub mod tickets;
pub mod vm_spec;
pub mod vni;
pub mod websocket;

pub use auth::{
    Attempt, AuthChain, AuthRequest, Authenticated, Authenticator, BearerAuthenticator, Class,
    GROUP_ADMINS, GROUP_CLOUDS, GROUP_CLUSTERS, GROUP_MASTERS, GROUP_MEMBERS, GROUP_NODES,
    GROUP_OPERATORS, GROUP_VIEWERS, Identity, MtlsAuthenticator, OwnPeer, Rejected, Role, Scope,
    Verb, class_of, classify, least_role, permits, permits_object,
};
pub use command::{Ack, CANNOT_SERVE, Peer, Pending, Refusal, Refused};
pub use heartbeat::{HEARTBEAT_TIMEOUT_SECS, expired as heartbeat_expired};
pub use lifecycle::{
    Holder, Lifecycle, lifecycle_command, not_stopped_enough, released_while_unknown,
    stopped_enough, unknown_needs_its_holder,
};
pub use mirror::{Observation, addresses_with, observe};
pub use network::{
    GATEWAY_CHASSIS, MeisterNetwork, NetworkBackend, NetworkConfig, RouterOutcome, RouterPlan,
    RouterSink, active_node, cut_external_addr, gateway_candidates, nat_rules, plan_nodes,
    router_load,
};
pub use object::{
    ANNOTATION_CLOUD_GENERATION, ANNOTATION_DRY_RUN, ANNOTATION_TRACEPARENT, Metadata, NameShape,
    Object, Resource,
};
pub use oidc::{GROUP_OIDC, GROUP_OIDC_TENANT_PREFIX, OidcAuthenticator, claimed_tenant};
pub use requeue::{RequeueConfig, RequeuePolicy};
pub use resources::{
    API_VERSION, AccessMode, CLASS_ROUTER, CLASS_VM, CertificateSigningRequest, Cluster,
    ClusterCapacity, ClusterSpec, ClusterStatus, Counter, CounterSpec, CsrCondition,
    CsrConditionType, CsrSpec, CsrStatus, DEFAULT_QUOTA_PRIVATE, DEFAULT_QUOTA_PUBLIC,
    DEFAULT_QUOTA_STORAGE_GIB, DEFAULT_ROUTED_PREFIX_LEN, Draining, Evacuating, Evacuation,
    EvacuationStep, Event, EventSpec, EventType, FloatingIp, FloatingIpSpec, FloatingIpStatus,
    FloatingPool, FloatingPoolSpec, FloatingPoolStatus, Image, ImageFormat, ImageNodeState,
    ImagePhase, ImagePhaseKind, ImageReason, ImageSpec, ImageStatus, IssuedCertificate,
    LABEL_CLOUD_UID, LABEL_MANAGED_BY, Locality, MANAGED_BY_CLOUD, MachineProfile, NatKind,
    NatRule, Node, NodeCapacity, NodeCondition, NodeConditionType, NodeSpec, NodeStatus,
    NodeSummary, PoolAtCluster, PoolDisagreement, PoolPointer, ProviderNetwork,
    ProviderNetworkSpec, ProviderNetworkStatus, Refusal as VmRefusal, RoutedSubnet,
    RoutedSubnetSpec, RoutedSubnetStatus, Router, RouterPhase, RouterPhaseKind, RouterReason,
    RouterSpec, RouterStatus, RunStrategy, SIGNER_USER_CLIENT, Secret, SecretSpec, StayReason,
    StayingVm, StoragePool, StoragePoolPhase, StoragePoolPhaseKind, StoragePoolReason,
    StoragePoolSpec, StoragePoolStatus, Tenant, TenantQuota, TenantSpec, TenantStatus, TenantUsage,
    Ticket, TicketBearer, TicketSpec, User, UserSpec, UserStatus, VOLUME_RELEASE_FINALIZER, Vm,
    VmAddress, VmAddressKind, VmMigration, VmMigrationPhase, VmMigrationPhaseKind,
    VmMigrationReason, VmMigrationSpec, VmMigrationStatus, VmPhase, VmPhaseKind, VmPlacement,
    VmReason, VmSilence, VmSpec, VmStatus, Volume, VolumeAttachmentStatus, VolumeMode, VolumePhase,
    VolumePhaseKind, VolumeReason, VolumeSnapshot, VolumeSnapshotPhase, VolumeSnapshotPhaseKind,
    VolumeSnapshotReason, VolumeSnapshotSpec, VolumeSnapshotStatus, VolumeSpec, VolumeStatus,
    accepts_class, cluster_accepts, frozen_vm_shape, grows_only, live_migration_refusal,
    new_volume, new_volume_snapshot, same_tenancy, second_open_is_a_migration, settle_image,
    settle_storage_pool, unbind_only, vm_shape_unchanged,
};
pub use resources::{
    ImagePhaseWire, ImageReported, RouterPhaseWire, RouterReported, StoragePoolPhaseWire,
    StoragePoolReported, UNSTAMPED, VmMigrationPhaseWire, VmMigrationReported, VmPhaseWire,
    VmReported, VolumePhaseWire, VolumeReported, VolumeSnapshotPhaseWire, VolumeSnapshotReported,
};
pub use rest::{
    ApiConfig, ApiError, ApiResource, AuthState, Caller, CallerRole, CallerTenant, DISCOVERY_PATH,
    DryRun, ListQuery, Mutability, Owned, PeerCerts, Removal, Removed, SCHEMAS_PATH, Selector,
    SpecUpdate, apply_merge_patch, apply_spec_update, assert_tables_match_schemas,
    carry_generation, check_envelope, check_owned, conflict, cors, discovery, discovery_document,
    forbidden, guard, invalid, invalid_field, merge_patch, patch_with_retry, readiness, removed,
    schema_document, schema_has_field, schema_of, serve, statuses,
};
pub use scheduler::{
    Candidate, CandidateKind, Capacity, DevicePolicy, FirstFit, NodeDemand, Overcommit,
    PendingReason, PendingTally, Scheduler, SchedulerConfig, Spread, VolumeBinding, feasible,
    feasible_for_volumes, narrow_allowed, pending_reason, pending_reason_of, preferred,
    preferred_for_volumes, selector_for, selects, spend, volume_nodes_unusable,
    volume_pending_reason,
};
pub use store::{EtcdStore, PassTrigger, StoreError};
pub use stuck::{
    STUCK_AFTER_PENDING, STUCK_AFTER_PROVISIONING, STUCK_AFTER_UNKNOWN, stuck, stuck_after,
};
