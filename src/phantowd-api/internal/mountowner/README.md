# Internal mount owner

`mountowner` is an internal M3.4 lifecycle prototype. It is not constructed by
normal product code, is not wired to the storage broker or service startup, and
has no HTTP/RPC surface. Its current real mount driver and qualification helper
exist only in `qemu_linux.go` (`qemu && linux`) and refuse machines other than
the disposable Versatile PB guest.

## Contract

- A private, one-use `Qualification` carries a transient trusted source tuple
  and a pinned `mountguard.Root`; it is not serialized or accepted from a
  request. Qualification verifies the source and captures an existing empty,
  non-mount-root target before any mount operation.
- `Owner` binds one fixed driver, observer and root opener at construction. It
  performs one bind mount, then requires the target to have a new unique mount
  ID while matching the qualified filesystem's inode, device, type, writable
  state and kernel-checked UUID before issuing a lease.
- `Owner.ObserveMountedVolume` revalidates that same live identity while holding
  the lifecycle lock and returns a process-local, non-serializable tuple for
  this one volume. It does not grant a lease or assert discovery completeness;
  an aggregate storage provider must prove its complete scope separately.
- `MountedVolumeSet` holds every member Owner lock in canonical target order,
  revalidates every member and returns no partial evidence. Duplicate logical
  IDs, filesystem UUIDs, mount IDs or device numbers are rejected. Its
  generation advances when any member tuple or Owner generation changes. A
  snapshot is complete only relative to the immutable roster supplied at
  construction; the current constructor is used by host tests and a one-volume
  QEMU fixture, not product discovery.
- `MountedVolumeSet.Acquire` takes that same all-owner lock set, obtains a
  complete fresh observation and retains one child lease per roster member
  before releasing any lock. If a member fails revalidation, already acquired
  leases are rolled back and no partial group authority is returned; cleanup
  uncertainty quarantines the affected Owner. `MountedVolumeSetLease` routes
  directory opens by roster ID and closes every tracked descriptor when the
  group lease is closed. Drain blocks new opens while existing group leases
  keep every member from unmounting.
- A `Lease` opens existing directories only through the pinned mountguard.
  Returned `O_PATH` handles are tracked by the Owner and revoked when identity
  verification fails. They cannot read file contents. Draining denies new
  leases and new opens; outstanding leases must close before unmount.
- Unmount revalidates the mounted identity, closes the pinned root descriptor,
  calls the fixed unmount operation once, and succeeds only if the target has
  returned to its exact pre-mount identity and is empty. Keeping the pinned
  mount descriptor open during `umount` produced `EBUSY` in QEMU, so release is
  deliberately ordered after the last pre-unmount verification.
- Any uncertain mount/unmount result, changed identity, or failed postcondition
  transitions to `review-required`. The Owner blocks further access and does
  not retry or implicitly clean up. `Close` never unmounts.
- `ServiceHandoff` is a Linux-only internal prototype. It requires an empty,
  root-owned mode-0711 directory under `/run/phantowd/service-handoff`; every
  ancestor must be root-owned, searchable by service identities and not
  group/other writable. It pins the handoff root and retains one lease for the
  complete fixed roster. Each cloned mount tree is created from the qualified
  `O_PATH` source descriptor with `open_tree`/`move_mount`, then checked for a
  distinct mount ID and matching filesystem identity. Opaque path bindings
  are issued only while the source roster, root pathname and clone identities
  still match. Teardown is explicit and may be called only after consumers
  stop; it unmounts a clone once and only while its exact mount identity still
  matches. It never falls back to source path resolution or lazy unmount.

The state machine and Linux fake-driver tests are in `owner_linux.go` and
`owner_linux_test.go`. The QEMU-only integration runs real bind mounts from the
fixed synthetic ext2 fixture into private `/run` directories. It covers the
normal lease/drain/unmount sequence, an overmount with handle revocation, lost
mount/unmount results, and a mismatched filesystem. The M4.4 QEMU fixture also
clones the mount from its qualified descriptor into the protected service
pathname, holds the full roster lease, replaces the source anchor and verifies
that the service pathname remains on the original clone while the Owner and
handoff enter review. It then explicitly detaches the exact clone and tears
down the quarantined synthetic Owner. The local ARMv5 standard smoke and Linux
API/vet checks pass on the current source using the existing read-only
Buildroot cache and temporary overlays. Linux tests exercise multiple
members, drain exclusion, idempotent release and rollback when the second
member changes during acquisition.

The qualification token currently comes only from the QEMU fixture. There is
no production qualifier or production roster source, no EX4-complete mounted-
volume collector, mount-point allocator, durable volume identity, product
service handoff/start/stop integration, or operator review/recovery workflow.
The prototype does not stop pathname-consuming daemons when the source Owner
enters review; a cloned handoff path can remain accessible until the future
service owner stops consumers and explicitly closes it. Passing QEMU tests
does not qualify physical EX4 disks or authorize mounting user media.

See [M3.4 roadmap acceptance](../../../../ROADMAP.md#m3-complete-storage-discovery-and-volume-lifecycle) and the private
dated evidence records in `doc/sources/m34-owner-lifecycle-local-qemu-2026-09-30.md`
and `doc/sources/m34-owner-mounted-evidence-local-qemu-2026-09-30.md`.
