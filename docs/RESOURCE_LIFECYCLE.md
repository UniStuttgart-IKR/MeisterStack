# Resource ownership and cleanup

Local guards preserve ownership through incomplete work. They do not provide
shared-storage leases or distributed fencing. Migration has a separate
[contract](MIGRATION.md).

## Network cleanup

Overlay deletion requires all three checks:

1. VM inventory is readable and no VM owns the overlay.
2. Persisted router inventory is readable and no router owns its VNI.
3. Kernel bridge ports contain no consumer other than the overlay's VXLAN tunnel.

- Router records preserve ownership across agent/driver restart.
- Port checks retain partly created routers before their record is committed.
- VM/router commands share the operations lock; startup sweeps precede command service.
- External network managers do not take that lock. Inventory and link deletion are
  not one kernel transaction; conservative retention can leave unused overlays.
- Tap-filter reaping uses raw VM rows. Any undecodable row skips reaping; read errors
  propagate. A partial inventory must not remove a live guest's source guard.

Sources: [Linux driver](../drivers/linux-network/src/lib.rs),
[router ownership](../drivers/linux-network/src/router.rs),
[agent startup](../components/agent/src/lib.rs).

## Volume deletion and attachment

`Volumes::deprovision` and `forget` hold the shared `ops` mutex across holder check,
backend operation and record update.

| Lock winner | Result |
| --- | --- |
| Attach | Persisted VM holder causes later deletion to refuse |
| Deprovision | Handle-free Gone record causes later referenced attach to refuse |
| Forget | Missing local record causes later referenced attach to refuse |
| Unreadable VM row / unattached inline handle | Treat as possible ownership; do not authorize deletion |

This protects operations in one agent process. Backend work surviving a crash needs
separate recovery evidence; long calls also hold the global operations lock.
Source: [volume operations](../components/agent/src/volumes.rs).

## Inline provisioning recovery

```text
persist VM spec → provision disk → persist unattached handle → attach
                → persist attachment and remove unattached handle
```

- Commit each attachment separately; a later failure must retain earlier handles.
- Retry reuses `unattached_volumes` instead of provisioning a second disk.
- Cleanup removes a saved handle only after successful deprovision.
- Crash before handle persistence: probe by persisted disk ID/spec, save the recovered
  handle, then delete. Probe failure retains ownership.
- Referenced disks are excluded: the VM does not own their data.
- Driver probe/idempotence and failed-attach cleanup remain required contracts.

Sources: [provision volumes](../components/agent/src/provision/volumes.rs),
[teardown](../components/agent/src/provision/teardown.rs),
[record types](../components/agent/src/types.rs).

## Compatibility and open gaps

- `unattached_volumes` defaults empty for legacy JSON. No protobuf change is required.
- Older agents ignore this field. Resolve incomplete cleanup before downgrade and
  retain the driver/backend namespace needed to interpret existing handles.
- Current teardown can delete inline data after detach/process-stop failure.
- Adopted backend stop can return after SIGTERM without waiting for exit.
- Controller router listing can skip corrupt records and misclassify reported
  routers as orphans. Local overlay guards do not repair that upstream decision.

See [agent](AGENT.md), [drivers](DRIVERS.md) and [networking](NETWORKING.md).
These defects are documented for later fixes.

## Regression map

| Property | Test |
| --- | --- |
| Router ownership / corrupt inventory | `router_ownership_preserves_an_overlay_across_driver_restart` |
| Remaining bridge users | `any_remaining_router_or_vm_port_blocks_overlay_removal` |
| Incomplete tap inventory | `a_corrupt_vm_record_cannot_remove_its_anti_spoofing_rules` |
| Attach/delete interleaving | `deletion_rechecks_holders_after_waiting_for_vm_creation` |
| Attach failure + restart + cleanup retry | `an_inline_attach_failure_remains_reclaimable_after_restart` |
| Crash before handle save | `a_crash_before_inline_handle_commit_is_recovered_by_probe` |
| Reuse saved handle | `a_restarted_attach_reuses_the_persisted_inline_handle` |

Tests use persisted fixtures, synthetic netlink attributes, temporary redb and
injected driver results. They do not establish live connectivity, process-exit
semantics or power-loss durability. See [testing](TESTING.md).
