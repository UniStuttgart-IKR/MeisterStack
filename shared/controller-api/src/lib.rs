// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Silas Müller <github@silasmueller.de>
// SPDX-FileCopyrightText: 2026 Universität Stuttgart, IKR

//! Shared controller resource types, REST contracts and etcd persistence.
//!
//! Both controller tiers use the object envelope, typed resources, authorization
//! policy and scheduler traits defined here. See `docs/API.md` and
//! `docs/CONTROL_PLANE.md` for their integration.

pub mod address_space;
pub mod auth;
pub mod capacity;
pub mod command;
pub mod deletion;
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
pub use command::{Ack, CANNOT_SEND, CANNOT_SERVE, Peer, Pending, Refusal};
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
    API_VERSION, AccessMode, CLASS_ROUTER, CLASS_VM, CapacityReservation, CapacityReservationSpec,
    CertificateSigningRequest, Claimant, Cluster, ClusterCapacity, ClusterSpec, ClusterStatus,
    Counter, CounterSpec, CsrCondition, CsrConditionType, CsrSpec, CsrStatus,
    DEFAULT_QUOTA_PRIVATE, DEFAULT_QUOTA_PUBLIC, DEFAULT_QUOTA_STORAGE_GIB,
    DEFAULT_ROUTED_PREFIX_LEN, Draining, Evacuating, Evacuation, EvacuationStep, Event, EventSpec,
    EventType, FloatingIp, FloatingIpSpec, FloatingIpStatus, FloatingPool, FloatingPoolSpec,
    FloatingPoolStatus, HandDownRefused, HandedDown, Image, ImageFormat, ImageNodeState,
    ImagePhase, ImagePhaseKind, ImageReason, ImageSpec, ImageStatus, IssuedCertificate,
    LABEL_CLOUD_UID, LABEL_MANAGED_BY, Locality, MANAGED_BY_CLOUD, MachineProfile, NatKind,
    NatRule, Node, NodeCapacity, NodeCondition, NodeConditionType, NodeSpec, NodeStatus,
    NodeSummary, PoolAtCluster, PoolDisagreement, PoolPointer, ProviderNetwork,
    ProviderNetworkSpec, ProviderNetworkStatus, Refusal as VmRefusal, RoutedSubnet,
    RoutedSubnetSpec, RoutedSubnetStatus, Router, RouterPhase, RouterPhaseKind, RouterReason,
    RouterSpec, RouterStatus, RunStrategy, SIGNER_USER_CLIENT, STALE_PLACEMENT_AFTER_SECS, Secret,
    SecretSpec, StayReason, StayingVm, StoragePool, StoragePoolPhase, StoragePoolPhaseKind,
    StoragePoolReason, StoragePoolSpec, StoragePoolStatus, Tenant, TenantQuota, TenantSpec,
    TenantStatus, TenantUsage, Ticket, TicketBearer, TicketSpec, UNPLACED_CARRIED_MAX, User,
    UserSpec, UserStatus, VOLUME_RELEASE_FINALIZER, Vm, VmAddress, VmAddressKind, VmMigration,
    VmMigrationPhase, VmMigrationPhaseKind, VmMigrationReason, VmMigrationSpec, VmMigrationStatus,
    VmPhase, VmPhaseKind, VmPlacement, VmReason, VmSilence, VmSpec, VmStatus, Volume,
    VolumeAttachmentStatus, VolumeMode, VolumePhase, VolumePhaseKind, VolumeReason, VolumeSnapshot,
    VolumeSnapshotPhase, VolumeSnapshotPhaseKind, VolumeSnapshotReason, VolumeSnapshotSpec,
    VolumeSnapshotStatus, VolumeSpec, VolumeStatus, accepts_class, cluster_accepts,
    first_bound_digest, frozen_vm_shape, grows_only, live_migration_refusal, new_volume,
    new_volume_snapshot, orphaned_reservations, same_tenancy, second_open_is_a_migration,
    settle_image, settle_storage_pool, unbind_only, vm_shape_unchanged,
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
    carry_generation, check_envelope, check_owned, claim_not_taken_back, conflict, cors, discovery,
    discovery_document, forbidden, guard, invalid, invalid_field, merge_patch, patch_with_retry,
    readiness, removed, schema_document, schema_has_field, schema_of, serve, statuses,
};
pub use scheduler::{
    Candidate, CandidateKind, Capacity, DevicePolicy, FirstFit, Hosted, NodeDemand, NodeRoom,
    Overcommit, PendingReason, PendingTally, Scheduler, SchedulerConfig, Spread, VolumeBinding,
    bound_on, feasible, feasible_for_volumes, free_on, hold, hosted_on, narrow_allowed, node_rooms,
    pending_reason, pending_reason_of, preferred, preferred_for_volumes, reservation_holds,
    reserved_on, selector_for, selects, spend, unplaced_demand, volume_nodes_unusable,
    volume_pending_reason,
};
pub use store::{EtcdStore, Fence, PassTrigger, StoreError};
pub use stuck::{
    STUCK_AFTER_PENDING, STUCK_AFTER_PROVISIONING, STUCK_AFTER_UNKNOWN, stuck, stuck_after,
};
