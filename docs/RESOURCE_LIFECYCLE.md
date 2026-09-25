# Resource cleanup: ownership and incomplete work

This document describes local cleanup checks implemented for overlays, local
anti-spoofing rules and VM volumes. Migration has a separate
[ownership and recovery contract](MIGRATION.md). These guarantees are local to an
agent; they do not establish distributed fencing for shared storage.

## Network ownership

An empty VM inventory alone does not establish that an overlay is unused. An
overlay can belong to a router even when no VM on this node uses it. Both explicit
last-VM cleanup and startup sweeping therefore pass through the same Linux driver
guard before deleting a VXLAN device or its bridge:

1. The agent checks VM ownership. Unreadable VM records prevent overlay sweeping.
2. The driver reads persisted router records from the configured gateway state
   directory. A router's VNI protects its overlay across driver and agent restarts.
   An unreadable router record or failed directory read refuses deletion.
3. The driver reads the bridge's kernel ports. Any port except this overlay's own
   VXLAN tunnel prevents deletion, including router veths, VM taps and unknown ports.

The port check also protects a partially created router whose record has not yet
been committed. Router commands and VM teardown share the agent operations lock;
startup sweeping runs before the command service. External link manipulation does
not participate in that lock. There is no atomic kernel transaction spanning the
inventory check and both link deletions, so this is not fencing against an external
network manager. Conservative retention can leave unused overlays until a later
sweep or explicit operator action.

Anti-spoofing cleanup has a similar completeness requirement. The startup tap list
is built from every raw VM row. If any row cannot be decoded, the agent skips the
filter reaper entirely. It must not present a partial list as a complete inventory:
the omitted row might describe a running guest whose rules still protect the host.
Readable records retain the normal cleanup behavior. A storage read error propagates
instead of authorizing removal.

## Volume deletion versus attachment

`Volumes::deprovision` and `Volumes::forget` acquire the same `ops` mutex used by
local VM creation, controller VM commands and reconciliation. They hold it across
the holder check, backend call and final record update. The lock belongs inside
these methods so that callers cannot accidentally separate the check from the
destructive operation.

If attachment wins the lock, it commits the VM record before deletion can inspect
holders. Deletion then refuses. If deletion wins, it leaves a handle-free `Gone`
record, or removes the record for `forget`. A later referenced attach refuses the
missing handle or missing record. Unreadable VM rows continue to count as possible
holders, as do recorded inline handles awaiting attachment.

This serializes operations within the running agent. It does not introduce a
distributed storage lease or a durable deletion protocol for a backend operation
that can outlive an agent crash. Long backend calls can hold the existing global
VM operations lock for their duration.

## Inline volume acquisition and rollback

The persisted VM specification records which inline disks the VM intends to own.
The runtime record now also has `unattached_volumes`, a list of volume handles:

```text
persist VM specification
    -> provision inline disk
    -> persist returned handle in unattached_volumes
    -> attach disk
    -> atomically record attachment and remove unattached handle
```

Each successful attachment is committed separately. An error on a later disk must
not hide attachments already acquired. A retry reuses a saved unattached handle
instead of provisioning another disk.

Teardown deprovisions saved unattached handles and only removes them from the record
after success. A failed delete retains the VM row and handle for another attempt,
including after reopening the redb store. If a crash interrupted provision before
the handle was committed, teardown probes the inline disk by its persisted ID and
specification. A found handle is saved before deletion; a failed probe retains the
record. Referenced disks are excluded from this recovery path because the VM does
not own their bytes.

This relies on the storage driver's `probe` and idempotent `deprovision` contracts.
It does not make an arbitrary driver's partially successful `attach` transactional.
The driver remains responsible for failed attachment side effects, and teardown's
existing process termination behavior remains relevant.

## Persistence compatibility

The new JSON field defaults to an empty list, so records from older agents remain
readable. Persisted specifications allow the new cleanup path to probe an older
incomplete inline provisioning attempt. No protobuf or storage schema migration is
required for this field. Router ownership uses the existing router record format.

Older agents ignore `unattached_volumes` and do not implement the recovery path.
Resolve incomplete provisioning and cleanup before downgrading; decoding JSON
successfully is not a guarantee that an older binary preserves the same ownership
contract. Configuration must continue to provide the driver and backend namespace
that created the resource.

## Executable evidence and limits

| Property | Deterministic regression test |
| --- | --- |
| Persisted router ownership and corrupt router inventory | `router_ownership_preserves_an_overlay_across_driver_restart` |
| Remaining bridge consumers | `any_remaining_router_or_vm_port_blocks_overlay_removal` |
| Incomplete tap inventory | `a_corrupt_vm_record_cannot_remove_its_anti_spoofing_rules` |
| Attachment wins against delete and forget | `deletion_rechecks_holders_after_waiting_for_vm_creation` |
| Attach failure, restart, failed cleanup, restart, successful retry | `an_inline_attach_failure_remains_reclaimable_after_restart` |
| Missing handle and failed backend probe | `a_crash_before_inline_handle_commit_is_recovered_by_probe` |
| Restarted attachment reuses the original disk | `a_restarted_attach_reuses_the_persisted_inline_handle` |

Network tests use persisted router fixtures and synthetic netlink attributes; they
do not demonstrate live namespace connectivity. Volume tests use real temporary
redb files, explicit future polling for the lock ordering, and injected backend
failures. Reopening a database tests process restart semantics, not power-loss
durability. For thesis evaluation, report these limits separately from live network,
VMM and storage experiments.

## Remaining cleanup gaps

The review found that some teardown paths continue to inline-volume deletion after
failed detach or process termination. Adopted backend termination can acknowledge
SIGTERM without waiting for exit. These paths must not be treated as proof that all
writers stopped. Controller router inventory handling can also mistake undecodable
records for absence and request removal; the local overlay guards above do not
repair that upstream decision. See [agent](AGENT.md), [storage](STORAGE.md) and
[networking](NETWORKING.md) for the affected mechanisms. No fixes to those paths
are part of this documentation revision.
