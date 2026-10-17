# Internal process owner

`processowner` provides Linux-only owners for foreground process groups and a
fixed, ordered set of such processes. It is not a product service manager and
is not reachable over HTTP or RPC.

## Failed-start settlement

An absent kernel process group does not by itself mean the original `Cmd.Wait`
has completed: its output-copy goroutines may still be settling. After uncertain
cleanup, Stop keeps the original PID and review until BOTH the original Wait
notification and group absence are verified. A later confirmed Stop may release
the PID but never clears failed-start review or permits automatic restart.

A deterministic Linux fixture holds a real child's output-copy boundary across
forced termination. It proves retained ownership while Wait is pending, then
explicitly observes that SAME Wait and group before requiring PID release. The
older failed-start regression now also observes this precondition rather than
assuming uncertain Stop is completion. The separate test-only observation is
bounded at two seconds and sends no signals or stop retries; product readiness,
stop and drain limits are unchanged. Both cases run three times in the existing
ARMv5 static-owner guest, with no additional boot or wider guest budget.

This reproduces an invalid test assumption, not the exact scheduling cause of
every earlier intermittent host failure or product-service recovery.

## QEMU-only capture cost observation

Only the guarded native Samba constructor enables fixed-size diagnostic storage.
Ordinary CaptureSpec has no timing option, callback or replacement input; default
captures keep a nil pointer and never sample clocks/CPU. The tagged read-only
observer separates input checks, launch, wait-select and post-processing.
Wait-select return is NOT original Wait completion: a separate direct-child
reaped flag requires that exact notification before reading kernel CPU counters.
No process reference, descriptor, identity or output bytes enter the snapshot.
Post includes verification and any internal cancellation/stop work. Metrics do
not establish group absence, server/host CPU or I/O wait; Linux's original-child
wait record can include descendants that child reaped. They never
change execution/settlement, review, retry, result publication or timeouts.
Completed evidence survives Close; copied/canceled/concurrent observers refuse.

## Failed construction ownership

`NewPinnedSet`, executable/read-only input duplication and `NewCapture` preserve
uncertain no-child rollback in package-private opaque error handles. Original
construction/cleanup causes remain reachable through ordinary wrapping. The
caller must retain the original error, not merely its string. No usable partial
set/capture, descriptors, retry/recovery methods or global admission latch are
published. Failed objects are permanently unusable; unattempted inputs stay held.

The acyclic `constructionreview` package classifies these errors across owner
boundaries; its marker is not an execution token or proof of ownership. A nested
retained failure stops unrelated containing cleanup. Fixed QEMU constructors use
the same no-child contract without changing their launcher profiles. A failed
pending-client constructor also clears its unused copied secret.

Actual factory tests inject one specific duplicate's `close -> EIO` in terminal
subprocesses, covering set rollback, regular/executable admission and capture
input admission. They verify the selected duplicate's identity, original causes,
GC retention, no launch/retry, unattempted references and independent construction.
The same tests and a cross-package containing-rollback test run in the existing
static ARM guest. This is controlled syscall failure, not physical EIO, a complete
valid runtime grant, live Capture teardown or all directory/temporary-close faults.

The separate `qemu && linux` `PendingClientQEMU` adapter fixes a single-use
dedicated launcher, read-only root and client descriptors at construction.
It uses distinct stdout/stderr pipes, a copied bounded secret through a fresh
anonymous pipe, fixed descriptor roles and an owned process group. Client OPEN
and CLOSE notices are telemetry, never server/session/object or durability
proofs. Only explicit close is available; there is no write/reopen/retry/restart
operation. Failed start, timeout, forced stop or uncertain closure preserves
review and original pins. Normal reference release requires exit0 and verified
original-group absence; close errors are sticky and retain later references.

Host refusal/parser/command-description/release tests, race tests and ARMv5
cross-compilation pass. The separate private runtimebundle Owner binds and
rechecks the complete client/loader/configuration/bootstrap census. Its focused
ARM fixture now also executes the actual retained client/loader against Samba:
healthy OPEN/CLOSE and independently observed original server worker/session/
tree/local-file identity pass, with verified settlement before release. This
supersedes the earlier constructor-only qualification, not product authority.
The adapter now captures its original proc reference/generation before Wait can
reap it. A one-time private binding duplicates that reference and the validated
server-worker proc, retains both net/mount namespaces and compares complete
bounded FD censuses with a fixed ESTABLISHED TCP dump. Same network namespace,
distinct mount namespaces, original executable, all client UID/GID65534, no
groups/capabilities and no-new-privileges are required. Later checks select no
PID/FD; original socket inode/cookie/principal/endpoints must remain identical.
Actual ARM Samba binding/recheck/CLOSE/stop/FD equality pass. References stay
through both verified stops; uncertainty retains review without retry. Host
controls and the independent TCP descriptor oracle also pass on ARM.
These sequential observations are not atomic or continuous. Adversarial live
drift/uncertain teardown in the new composition, remote handle/request/extent,
pending I/O and product storage/identity composition remain unqualified.
The separate actual ARM peer-exit fixture now verifies concrete connection
refusal after the owned daemon group stops, client quarantine/group absence and
original proc/namespaces/pins retained. A read-only reviewed-state check requires
verified stop, absent original tasks and all original references still open;
missing/copied/busy/canceled/incomplete states refuse. This is not uncertain-stop
qualification, automatic recovery or permission to release reviewed authority.
Ordinary builds/startup, generic launchers and HTTP remain unchanged; see the
[focused client contract](../../../../support/QEMU-FAST-TESTS.md#dedicated-same-open-client-prerequisites-host-and-qemu).

The caller supplies a fixed executable, arguments and bounded readiness/stop
timeouts. The owner opens a regular executable without following symlinks,
starts it in its own process group with a minimal environment, captures a
bounded 32 KiB diagnostics tail, and reports `ready` only after the supplied
probe succeeds. The probe must be service-specific, bounded and must not
re-enter the same owner.

Readiness checks both the original caller and its derived startup deadline
before/after each probe. A late positive probe cannot advance generation:
the candidate takes the same verified failed-start cleanup path, and the
returned `ErrNotReady` retains fixed cancellation/deadline causes without
disclosing the probe's private error. Monotonic deadlines do not depend on
timer delivery. This is a point-in-time admission fence, not preemption of a
blocking callback or a guarantee against cancellation after the final check.
Real-child native/race and ARMv5 tests cover eight late-result combinations;
this separate correction does not identify the intermittent Samba fixture cause.

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
The operation budget starts before code/input admission and covers post-capture
hash checks, not constructor baseline hashing. Cancellation is checked between
hash reads and before digest publication; it cannot interrupt an in-progress
filesystem syscall or private fixture validator. Cancellation before launch
leaves the instance unconsumed and does not by itself quarantine it. Observed
drift and post-launch canceled/uncertain ownership retain review and cannot
authorize retry.

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

### TCP wire prerequisite (QEMU-only)

A private `qemu && linux` decoder accepts only bounded IPv4 ESTABLISHED
SOCK_DIAG multipart observations for the expected sequence/receiver port. It
checks native/network byte orders, mandatory nonzero inode/cookie/endpoints,
duplicate inode/cookie refusal and complete successful DONE. Failed or
interrupted framing permanently discards partial rows. Returned rows are copies.
Limits are 4 KiB per record, 64 KiB per datagram, 256 KiB per dump, 256 sockets
and 32 framed extensions per record; unconsumed extensions confer no authority.

Kernel querying exists only in a test file. Independent Fstat, SO_COOKIE,
getsockname/getpeername and empty SO_BINDTODEVICE observations now check every
fixed identity field against the actual dump, not merely a second dump. Real
same-UID connections to the same server endpoint stay distinct across 32
concurrent queries; closing one pair removes only that pair. Nil/canceled/
expired contexts and cancellation immediately after the real request expose
no rows; successful/refused queries preserve descriptor counts. These fixtures
run on non-root Linux and ARM926 QEMU. They retain no process/socket authority
and do not qualify adversarial mutation or general cancellation timing.
Pure framing/identity/refusal/bound controls and fuzz tests are separate. The optional
[focused runner](../../../../support/QEMU-FAST-TESTS.md#kernel-tcp-wire-prerequisite-not-client-binding)
reuses the pinned builder/base read-only and runs fifteen cases three times.

The separate pure copied-pair matcher consumes bounded completed observations
and two inode observations, never PIDs/paths/descriptors. It requires distinct
original inode/cookie identities and fixed reciprocal loopback1445 endpoints,
rejects missing/reversed/cross-pair/duplicate/foreign or malformed rows, and
publishes no pair after cancellation. Full UID/cookie/endpoint rows are retained
as copied values for continuity comparison. Host/race3 and actual ARMv5 tests
match two same-UID/same-server connections to independent descriptors and
require peer preservation after one pair closes. This does not trust the caller's
inode census, qualify principals, pin processes/namespaces, or bind the actual
SMB client; no method is added to `PendingClientQEMU` or its containing Owner.

This is not an atomic inventory, namespace/process generation binding, retained
socket authority, remote SMB client-handle, request/extent proof or permission
to WRITE. No decoder is wired into the existing Owner, generic launcher,
product startup, HTTP or fault admission. Those boundaries remain separate.

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
