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
  root-owned `root:<service-gid>` mode-0710 directory under
  `/run/phantowd/service-handoff`; every ancestor must be root-owned,
  searchable by the fixed service identity and not group/other writable. Only
  the configured service group can traverse the handoff root. A fixed internal
  `ServiceShare` list names each share ID, volume ID, relative directory and
  read-only intent. Whole-volume `.`, invalid paths, duplicate IDs and
  ancestor/descendant overlaps on one volume are rejected. Each root is opened
  through the pinned volume lease and cloned with `open_tree`/`move_mount`, then
  checked for a distinct mount ID and matching filesystem identity. Clones get
  `nosuid,nodev,noexec`; requested read-only clones receive `MOUNT_ATTR_RDONLY`
  before attach and are verified afterward. Opaque bindings carry the selected
  share root and source evidence; teardown is explicit and only detaches a
  clone whose exact mount identity still matches. No path-based fallback or
  lazy unmount is used.

  This is a share-scoped pathname view, not a complete authorization boundary.
  Consumers remain in the host mount namespace and may reach the original
  volume anchor if its Unix metadata allows; writes there can bypass a
  read-only clone. Every process in one fixed handoff group can traverse all
  roots in that handoff. The prototype does not provision service accounts or
  file-level ACLs and must not be treated as production share authorization.
- `ServiceRuntime` is the internal coordinator for one fixed handoff and one
  fixed `processowner.Set`. `Start` mounts, verifies the complete binding set,
  starts all consumers and verifies storage again after readiness. `Observe`
  checks storage before process state; source loss causes one process-set stop
  before handoff close. If stop is uncertain, the handoff lease remains held
  for review and no cleanup retry or restart occurs. `Stop` follows the same
  stop-before-close order. The caller must poll `Observe` at a bounded cadence;
  there is no monitor goroutine or automatic restart. Callers must treat the
  handoff and process set as exclusively owned by the runtime after
  construction.

The state machine and Linux fake-driver tests are in `owner_linux.go` and
`owner_linux_test.go`. The QEMU-only integration runs real bind mounts from the
fixed synthetic ext2 fixture into root-controlled `/run` paths. It covers the
normal lease/drain/unmount sequence, an overmount with handle revocation, lost
mount/unmount results, and a mismatched filesystem. The M4.4 QEMU fixture now
clones one declared `media` subtree, proves a sibling marker is absent from the
clone, and confirms a read-only write fails with `EROFS`. It holds the full
roster lease, replaces the source anchor and verifies that the service pathname
remains on the original clone while the Owner and handoff enter review. A fixed
BusyBox consumer as UID/GID 1000 reads the marker; a separate UID/GID 65534
probe is denied, and runtime construction rejects a process set without the
configured handoff group. On source loss the child stops before the exact clone
is detached. The fixture does not prove the original anchor is unreachable to
the child; subtree and read-only access remain bypassable until a private
service mount namespace exists. A host fake-process test verifies that an
uncertain stop leaves the handoff open and is not retried. Windows API tests,
ARMv5 cross-compilation, Linux API/vet and the local one-boot ARMv5 standard
smoke pass with existing read-only Buildroot inputs and a temporary overlay. A
focused MD v1.0 fixture also passes; its two-volume M3.5 test was separated
because that guest intentionally has no independent healthy ext2 volume. Linux
tests exercise multiple members, drain exclusion, idempotent release and
rollback when the second member changes during acquisition.

The separate internal `IsolatedServiceRuntime` exclusively claims one prepared
handoff for **one static non-root process**, not a process Set or Samba daemon.
The handoff is that process's grant-only root: a bounded census rejects any
undeclared root entry, symlink or missing share. After verifying the complete
roster, it pins the root and launches the fixed `processowner.IsolatedOwner`.
Direct handoff teardown returns busy while this pin is retained. Normal stop
confirms process/group reap before closing launch descriptors, releasing the
root pin, detaching clones and returning the roster lease. Source loss follows
the same stop-before-release ordering and remains quarantined; uncertainty
retains resources and is not retried. The caller must still poll `Observe`.

Local ARMv5 QEMU now composes that path using one disposable ext2 filesystem,
one UID/GID1000 static probe and a read-only `public` grant. The probe reads the
marker, cannot open either original volume anchor, `/private`, `/proc`, `/dev`
or leaked FDs, and gets `EROFS` on writes. It verifies distinct mount namespaces,
busy close while live, normal stop/reap and clone removal, then source-anchor
substitution with stop/reap and retained review/no restart. Host census,
immutable-input/exclusive-owner and race tests pass. This does not change the
ordinary `ServiceRuntime`'s host-path bypass limitation described above.

There are no approved runtime files, dynamic-library/interpreter manifests,
multi-process isolated Set, per-client Samba identity/ACL profile or kernel NFS
authority in this increment. It is fixture-only, not installed by product init,
and exposes no HTTP/RPC operation. The helper's presence in a copied QEMU image
is not Buildroot package installation or product authorization.

## QEMU-only declared-share pins

`WithQEMUNativeMountedSet` adds only a fixed synthetic roster for the disposable
Samba overlay. It refuses host/missing-observer execution and checks the exact
ARM model, explicit fixture cmdline, tmpfs context, device/source binding,
16 MiB size, protected ext4 mount and UUID before construction. Logical anchors
use a scoped protected tmpfs overlay over the read-only image; verified child
teardown precedes overlay removal and original-anchor identity restoration.
Uncertainty retains mounts for guest disposal, never lazy-unmount recovery.
Actual ARMv5 admission matches Plan-derived roots with the SAME native identity
Owner and verifies fresh evidence, caller closure and retained-authority gates.
It starts no daemon and is not a production roster or physical-disk qualifier.

`ServiceHandoff.RetainShareRootsQEMU` exclusively retains the original attached
share objects after complete verification. `DuplicateRoots` returns independent
`O_PATH` copies of only those individual declared subdirectories, never the
whole handoff/volume root; it does not reopen source paths. Pins and descriptors
refuse JSON. Lock order is pin, handoff, complete roster, canonical volume Owners.
Direct handoff closure remains busy while the pin exists. Source loss or changed
objects enter sticky review, with no revival after pathname restoration.

This is lifetime preparation, not Samba admission or isolation. The returned
labels are not authority; a future fixed native factory must bind the exact
Plan/root roles and make nonrecursive individual-share mounts inside its private
namespace. Parent-namespace descriptors alone do not prevent traversal outside
the selected subtree. Mutable data/ACLs must not inherit immutable-code rules.

The trusted consumer must prove descendant stop/reap and copied-input closure
before releasing original pins. Known closure releases once; uncertainty retains
the reservation in review without cleanup retry. The actual ARMv5 launcher guest
covers caller-copy closure, two RO/RW roots, effective non-root write ownership,
kernel `EROFS`, accepted data mutation, gated handoff close, source-loss review,
restoration refusal and final FD equality. No Samba process consumes these roots
yet, and actual uncertain-close fault qualification for this pin remains open.

Host-only input-release characterization now uses actual temporary `O_PATH`
descriptors: a preclosed original preserves reviewed handoff exclusion and
leaves later inputs open; repeated/concurrent calls neither retry nor touch a
test-only replacement. Known closure remains idempotent and fences subsequent
descriptor use. Tagged Linux vet and package race-count3 pass. These tests
exercise rejected teardown bookkeeping without fabricating, admitting or
verifying a healthy mount/roster lease. The behavior already existed; this is
new coverage, not a bug fix, kernel EIO proof or actual mounted QEMU fault
qualification. The latter and durable product recovery remain required.

The qualification token currently comes only from the QEMU fixture. There is
no production qualifier or production roster source, no EX4-complete mounted-
volume collector, mount-point allocator, durable volume identity, product
service handoff/start/stop integration, per-share service ACL matrix,
service-account/group provisioning, automatic source-loss monitor, or operator
review/recovery workflow. The
lower-level `ServiceHandoff` does not stop pathname consumers by itself;
`ServiceRuntime` does so only for the one fixed process set it controls, and
only after its caller invokes `Observe`. Passing QEMU tests does not qualify
physical EX4 disks or authorize mounting user media.

See [M3.4 roadmap acceptance](../../../../ROADMAP.md#m3-complete-storage-discovery-and-volume-lifecycle)
and [implementation status](../../../../IMPLEMENTATION-STATUS.md).
