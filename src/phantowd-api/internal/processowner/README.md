# Internal process owner

`processowner` provides Linux-only owners for foreground process groups and a
fixed, ordered set of such processes. It is not a product service manager and
is not reachable over HTTP or RPC.

The caller supplies a fixed executable, arguments and bounded readiness/stop
timeouts. The owner opens a regular executable without following symlinks,
starts it in its own process group with a minimal environment, captures a
bounded 32 KiB diagnostics tail, and reports `ready` only after the supplied
probe succeeds. The probe must be service-specific, bounded and must not
re-enter the same owner.

`Spec.RunAs` optionally fixes a numeric UID, primary GID and exact
supplementary-group list for the child before exec; `NewSet` copies that
credential tuple and group slice. A nil `RunAs` retains the caller's current
credentials and is not accepted by the storage-backed `ServiceRuntime`.
`ServiceRuntime` also requires every fixed member to be non-root, use reserved
service IDs 1000..60000, and belong to its handoff group. This establishes
process identity and handoff-path traversal only; it does not provision Unix
accounts, groups, or file-level share ACLs.

`Observe` does not start, stop, adopt or restart a process. If a process that
previously reached readiness has exited, observation moves the owner to
`review-required`; a new start is blocked. `Stop` performs bounded graceful
shutdown and may force termination; uncertain or forced cleanup also requires
review. Generation advances only after readiness is confirmed.

`NewSet` constructs private Owners from copied, fixed `MemberSpec` values. It
starts members in declaration order and advances the set generation only when
all readiness probes succeed. If a later member fails, already-ready members
are stopped in reverse order; if the failed member or rollback is uncertain,
the set enters permanent `review-required`. An observed unexpected exit also
quarantines set restart but does not automatically stop healthy peers. An
explicit `Stop` attempts cleanup of every member in reverse order and never
clears review. Set and member snapshots reject JSON serialization. This
provides startup/cleanup coordination only; it does not apply configuration,
hold storage leases, persist state, adopt existing daemons, or decide whether
SMB/NFS may remain partially available.

Diagnostics and snapshots are internal, non-serializable data. Diagnostics
may contain paths or account names and must not be logged or returned to a
network client without a separate redaction boundary. Non-Linux builds return
`ErrUnavailable`.

## Fixed restricted-root child

Linux `NewIsolated` constructs an `IsolatedOwner` around the separate native
launcher. It fixes and copies the spec/credentials once, pins independent
read-only executable/helper and `O_PATH` root descriptors, validates root-owned
non-writable metadata and captures the root mount ID. `Start(ctx)` accepts no
new spec, root, path or backend. The owner starts the pinned helper as root in
its supervised child group; the helper, not Go's multithreaded parent, creates
the private namespace/chroot and removes privileges before executing the
pinned static child. The same PID/group remains owned. Ordinary `New`/`NewSet`
behavior and the existing `ServiceRuntime` remain unchanged.

Before launch, after readiness and during `Observe`, pinned input metadata is
revalidated. Drift permanently requires review; a live child gets one bounded
stop attempt before input release. Restoration cannot clear review or retry
launch. `Close` never stops a process and refuses while any child is still
owned, including uncertain termination. It only releases its descriptors; it
does not unmount, release an external storage lease or prove grant completeness.

The caller must construct the entire trusted root/runtime manifest, hold and
revalidate all storage grants/leases, serialize executable updates, supply a
service-specific readiness check and poll source loss. This adapter does not
create per-service roots, join the existing process Set/runtime, provision
permissions, install a daemon or authorize kernel NFS exports. Static ELF only.
Host tests cover fixed input copying/validation, non-serialization and launch-
input quarantine. The disposable ARMv5 fixture proves actual constructor/
readiness/stop behavior, caller-FD closure, argument/credential mutation,
metadata loss before launch and live root drift. EX4 remains unqualified.

Important Samba boundary: the existing real multi-user QEMU `smbd` fixture
starts with the caller's root identity (`RunAs` is nil), unlike the synthetic
handoff child. Pinned Samba 4.22.11 `source3/smbd/sec_ctx.c` and `uid.c` use
root/context and Unix UID/GID/group switches for impersonation. A fixed UID
with zero capabilities is not evidence for that multi-user ownership model.
Do not replace it with `force user`, shared credentials or permission widening.
The product needs a separately reviewed Samba-specific privilege/runtime
contract; NFS kernel control likewise needs its own typed authority. This
generic non-root helper deliberately does not gain either authority.

The package has no adoption of pre-existing processes, durable state,
automatic recovery, aggregate SMB/NFS configuration lifecycle, last-known-good
configuration transaction, or production startup wiring. Host tests exercise
unexpected exit/quarantine, forced-stop cleanup, failed-start review
persistence, reverse-order set rollback, all-ready set shutdown, immutable
arguments, and member-level quarantine that preserves a healthy peer until
explicit stop. The one-boot ARMv5 QEMU smoke exercises normal ownership of
disposable `smbd`, three controlled BusyBox failure cases, and a two-member
BusyBox Set for successful start/stop, rollback, unexpected exit, peer
preservation and explicit cleanup. All guest fixtures require process groups
to be reaped. They do not simulate a real `smbd` crash or forced termination
of `smbd`.
