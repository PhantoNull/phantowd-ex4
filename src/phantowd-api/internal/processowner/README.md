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

### Single-use regular-stdin capture

`NewCapture` fixes copied arguments/credentials and independently retains one
root-owned executable and one regular `O_RDONLY` stdin descriptor. Inputs must
start at offset zero; devices, directories, pipes, writable descriptors and
oversized inputs are refused. The caller exclusively owns the shared stdin
offset/content and serializes executable updates. Bounded before/after descriptor
digests detect observed drift, including same-size changes within a filesystem
timestamp tick; these are not authenticated release hashes or atomic snapshots.

`Capture(ctx)` has no per-call paths/options. It executes the retained descriptor
once, with a minimal environment, fixed credentials and an owned foreground
process group. Separate stdout/stderr buffers enforce 64 KiB/4 KiB during copy;
stdin is at most 64 KiB and executable observation at most 16 MiB. Normal wait
joins output workers and distinguishes genuine 0..255 ordinary exit codes from
signals; signals expose no report. Cancellation reuses the existing bounded
group cleanup and publishes no result. Failed exec consumes the instance too.
Observed input drift or canceled/uncertain ownership cannot authorize retry.

`Settled` only verifies absence; `Close` releases pins only after verified
absence and never signals/retries a process. Failed descriptor release remains
an error on subsequent Close, without a second close attempt. Constructors and
results are private/non-serializable; value-copied handles are refused.

This is a trusted cooperative foreground-command primitive, not hostile-process
containment, a privilege profile, authenticated runtime closure, restricted root,
device provider or physical SMART authority. Nil credentials retain the caller's
identity, as with `Spec`; product startup never calls this constructor. Native
Linux tests cover bounds, signal/ordinary exits, drift, busy/canceled/forced
cleanup and release uncertainty. The tagged `smartcapture` QEMU adapter runs the
actual static generic-only producer through the SMART coordinator with regular
synthetic traces and an explicitly fake census, including source-change refusal.
No disk/ioctl, HTTP endpoint, scheduler or product service is enabled.

### Retained service and isolated-child adapters

`NewPinnedSet` is a separate internal constructor that copies fixed specs and
duplicates corresponding read-only, root-owned executable descriptors. Start
uses those pins directly rather than reopening a pathname; the constructor
does not verify hashes, loader closure, a manifest or an isolated root.
Its private Set is not exposed. `Close` refuses while any member still owns a
process, including forced/uncertain cleanup; explicit Stop must confirm every
group reaped before descriptors can be released. Review persists and no
automatic restart is added. The retained code-tree Owner in `runtimebundle`
provides stricter fixed-tree/static/non-root composition; existing New/NewSet
and IsolatedOwner behavior is otherwise unchanged.
Native lifecycle tests use the pinned build environment's root-owned `sleep`
and isolated Python3, not its builder-owned Go test executable; this keeps the
root-ownership guard intact while exercising the real non-root builder. Python
is only a disposable host test fixture, not a target runtime dependency.

Linux `NewIsolated` constructs an `IsolatedOwner` around the separate native
launcher. It fixes and copies the spec/credentials once, pins independent
read-only executable/helper and `O_PATH` root descriptors, validates root-owned
non-writable metadata and captures the root mount ID. Root duplication holds
the caller's `os.File` reference through `SyscallConn.Control`: a caller Close that has already begun
is refused even if another active Control keeps the kernel FD alive. This
avoids acquisition from a closing or reused FD number. A deterministic root
constructor regression and the disposable ARMv5 fixture verify the refusal;
no service is started with that invalid root. `Start(ctx)` accepts no
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
