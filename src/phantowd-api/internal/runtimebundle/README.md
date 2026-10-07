<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Internal code-only runtime bundle inspection

`runtimebundle` provides code verification and an internal retained-code Owner
prototype for M4.4, not an approved runtime manifest or installation token. Ordinary
product startup does not call it. It has no HTTP/RPC or JSON input/output.
The separate `qemu && linux` staging prototype below is excluded from ordinary
builds; it does not turn the read-only inspector into a product write service.

The `qemu`-only `SambaPlannedDataDocumentsQEMU` renderer produces seven bounded
configuration documents from one immutable isolated Plan candidate. It preserves
the candidate's granted-only Unix identities and exact RO/RW share sections,
uses the existing native fixture's loopback SMB3 globals and passdb/state paths,
and rejects empty or over-budget output without returning partial documents.
The aggregate budget remains 64 KiB. Rendering performs no I/O, retains no
authority, installs no configuration and changes no native backend. Host tests
cover exact documents, caller independence, refusals and unchanged global bytes.
A focused ARMv5 lifecycle fixture also renders from the actual native Owner and
mounted roster, verifies granted-only output and compares complete documents
after fresh locked evidence compilation. Neither proof starts a Plan-configured
daemon or qualifies the two-role runtime lifecycle. A future
trusted constructor must independently derive expectations, bind the original
mounted share objects and recheck complete admission before starting a daemon.

`RetainPlannedConfigurationQEMU` is a separate inert prototype. It independently
derives expectations from the opaque candidate and retains exact configuration
objects in the same Owner without replacing its management configuration or
mutable state. Complete revalidation includes both roles, and verified process
stop precedes release. The role cannot be replaced and blocks native daemon
startup; it does not acquire storage grants or establish candidate freshness.
Guarded disposable ARMv5 staging proves construction refusals, independent
caller closure, unchanged management observations and normal exact-mount
cleanup. Complete planned-service lifetime and fault qualification remain open.

`NewPlan` privately copies a fixed in-process file/alias roster supplied by a
future trusted build/release owner. It limits the plan to 256 regular files,
1024 bindings, 4096 total nodes, 16 path components and 64 MiB. Files have exact
SHA-256, size and mode 0444 or 0555. Aliases point directly to a declared file;
chains, collisions, ancestor conflicts and noncanonical paths are refused.
It does not infer trust by hashing the tree it is inspecting.

Linux `Inspect` independently duplicates an `O_PATH` root. The complete
code-only tree must be root:root on one kernel-enforced read-only mount, with
unique mount-ID support. It refuses the original `/`, undeclared entries,
remote/FUSE or other unqualified backing types (the fixed code-only roster is
tmpfs, SquashFS and ext-family),
special files, symlink traversal and crossing mounts. Directory traversal and
regular reads use descriptor-relative `openat2` with no weaker fallback.
Only declared aliases are read as text; their exact absolute in-root target
must match the fixed plan. Regular files require exact permissions, single
links, bounded hash reads and stable metadata. The root, every directory and
every regular file must have no access/default POSIX ACL or file-capability
attribute; unsupported attributes are absent, while other query errors refuse.
This code-only rule does not apply to ACLs on separately composed data grants.
Any error returns no partial observation. Non-Linux inspection is unavailable.

The result contains internal counts only, cannot be serialized and holds no
descriptors or leases after return. This is a point-in-time check: privileged
writers through another mount, concurrent configuration updates, active root
replacement and later drift require separate owner serialization, retained
pins and revalidation. A read-only bind does not make other views immutable.
Trusted signature/model binding, ARM ABI and loader qualification, NSS/config,
state/grants/device rules, privilege profiles, construction/activation/recovery
and product wiring remain separate. No user data is read or modified here.
Context cancellation is checked between bounded local reads, not a guarantee
that an arbitrary kernel I/O stall can be interrupted.

## Shared prepared code references

The package-private `prepareRetainedCode` helper captures independent read-only
root/file references and original file/directory/alias metadata for the complete
declared code tree. Static `Owner` now reuses it without changing its static ELF
or non-root execution restrictions. Preparation does not publish execution
authority: the containing constructor must perform the trailing full
revalidation after its other inputs are fixed and before publication/launch.
The extraction preserves the existing census/hash/identity sequence; it does
not replace late pathname checks with early metadata or add a constructor scan.

The containing Owner serializes all access, decides review/stop policy and
establishes complete process-group absence before releasing code references.
After a descriptor-close error, retained code/configuration/state and pinned
process inputs permanently preserve that error, stop subsequent releases and
refuse cleanup retry. The containing Owner remains in review; repeated Close
cannot report success. Confirmed earlier closures stay released. A failed
close does not prove that its descriptor remains open; only unattempted inputs
are guaranteed not to have been released by this cleanup. Linux fault fixtures
use already-closed real files and qualify bookkeeping, not kernel I/O failures
or durable product recovery. Normal static/Samba ARMv5 paths are separately
tested; those positive campaigns are not injected-close-fault qualification.
The helper itself starts no process, mounts nothing, accepts no backend changes
and exports no descriptor or production API. Dynamic code may be inspected and
retained without being authorized for execution by the generic Owner.

The `qemu && linux`-only `ProbeRetainedCodeQEMU` observes the actual prepared
Samba code-only closure under the existing non-root/capability-free fixture
boundary. It checks real dynamic ELF headers, rejection of that daemon by the
generic execution adapter with both non-root and root credentials, caller-descriptor closure,
complete revalidation, canceled observation, release/no further use and stable
descriptor count. It returns counts only after releasing the prepared references;
it is not a retained grant returned to a caller and does not hold code through
the later Samba service. The full Samba-specific Owner must still integrate
these references with protected configuration/state/identity/storage inputs,
supervision and verified service stop. Signature/model/ABI authority remains a
separate gate, not inferred from a fixture dependency manifest.

The QEMU-only `cmd/qemu-runtime-bundle` checks the actual prepared Samba code
tree before fixture configuration/state/share grants are added. A fixed native
test helper creates a private read-only bind, drops every bounding capability
and switches to UID1801 with zero effective/permitted capabilities before the
probe. It never changes the parent mount namespace. The probe checks the real
roster and refuses five altered plans: digest, mode, alias target, omitted
daemon and symlink retyped as file. Cancellation must return no observation.
This fixture manifest is research evidence, not a signed product manifest.

After fixture configuration exists, a separate capability-free QEMU observer
rechecks the unchanged code-only census. Code and service roots are distinct;
fixed read-only executable code views must expose the same descriptor-observed
objects. An actual byte/mode-identical copied-catalog overlay is refused by that
same observer. Config/NSS presence/type is checked separately, not authorized.
These point-in-time references close before later Samba launch; complete dynamic
code/configuration/identity/storage lifetime and race-qualified root construction
remain unimplemented. See the [separate-view profile](../../../../support/SAMBA-RUNTIME-PROFILE.md#qualified-separate-codeservice-views-fixture-only).

A separate fixed root-only QEMU permission regression uses miniature tmpfs
code trees, its own private mount namespace and read-only binds. It reads back
actual kernel ACL bytes and proves Unix modes remain unchanged. An ACL-free
positive control must pass; access/default ACLs on the root and an inner
directory, plus a regular-file access ACL, must return no observation. This
regression is excluded from product builds and does not modify the Samba tree,
data-grant ACLs, parent mount namespace or physical storage.

## Disposable construction prototype

The configuration increment additionally retains seven fixed fixture config/NSS
files through real Samba execution. Its package-private data-only plan has
16-file/64-KiB limits and modes 0400/0444/0600/0644, sharing exact census/hash and
original-object retention but not executable admission. Code `NewPlan` is
unchanged. Read-only/nosuid/nodev/noexec config views are rebuilt after the
nonrecursive service-root bind and verified through actual child objects.
Independent compiled fixture contents define expectations; no filesystem
self-hashing is used. Caller config closure, normal stop, live config-mode drift,
retained review, restoration refusal and verified code/config release pass in
the focused ARMv5 campaign. The containing Owner owns serialization and combined
revalidation; generic static construction cannot configure this private field.
Passdb/state legitimate mutations are separate, not immutable inputs. The
state increment retains the original writable tmpfs root plus its six fixed
root:root0700 role directories. Revalidation checks identity, ownership/mode,
mount and absence of access/default ACLs or capabilities, not content hashes,
ctime/mtime, size or link counts that normal TDB/log writes change. Ordinary
mount IDs are compared only while original open references retain the mount;
the existing immutable-code unique-mount-ID requirement is unchanged.
Actual ARMv5 child views use those same objects and are writable/nosuid/nodev/
noexec. Normal use, live private-directory mode drift, whole-group stop,
retained review, restoration refusal and verified release are exercised.
Generic static construction cannot supply state or gain these privileges.
This is not product renderer/NSS authority, identity revision, storage/state ownership,
race-qualified construction, durable activation or complete firmware validation.
See the [configuration scope](../../../../support/SAMBA-RUNTIME-PROFILE.md#qualified-protected-configuration-lifetime-qemu-only).

The guarded state tracer now independently retains seven read-only directory
FDs at construction. Its fixed bootstrap validates them before effects, clones
their mounts via `open_tree` before namespace isolation and attaches the clones
via `move_mount`, without reopening a source pathname. A mandatory actual
ARMv5 case masks that pathname with an empty child-private tmpfs; real Samba
readiness and same-object writable/nosuid/nodev/noexec views still pass. Input
FDs must be closed before exec, bounded private bootstrap evidence must be
complete/untruncated, and the four lifecycle cases must leak no descriptors.
The public QEMU-only constructor rejects duplicated objects and mixed
filesystems before publication. Fixed probes exercise five invalid last-role
inputs after partial retention, without launching or closing callers. The actual
daemon receives independent inputs after all temporary callers are closed and
the caller's argv/credentials mutated. A frozen-group state-drift case requires
forced-stop review retaining code/config/state until explicit verified release;
restoration never allows restart. Strict final evidence covers these behaviors.
The ordinary static launcher still has no extra-input option. Code/config/data
construction retains fixed fixture paths: this is **not** an atomic whole-root
constructor or qualification of all path-replacement races. Passdb files are
not pinned as immutable objects: their supported mutation/replacement lifecycle
must come from the same real identity authority, not from this directory
tracer. Persistent state, external privileged writers, identity-consumer
composition and storage leases remain required before product activation.
A separate guarded `qemu && linux` constructor now composes complete prepared
code references with the pinned fixed Samba bootstrap and the existing
serialized Owner lifecycle. The actual dynamic daemon is checked against the
retained object. Three mandatory ARMv5 cases cover normal stop, live code-mode
drift and forced stop of a frozen group; restoration refuses restart and review
keeps code references until explicit verified teardown. Generic `NewOwner`
static/non-root restrictions remain unchanged. No descriptors/owner are returned
from the qualification probe. This test-only composition is not the complete
Samba Owner: configuration/identity/state/storage inputs are not yet retained
product authorities. See the [lifetime scope](../../../../support/SAMBA-RUNTIME-PROFILE.md#qualified-dynamic-code-lifetime-qemu-only).

A fixed QEMU-only observation worker independently retains the same seven state
directory objects for a single actual `pdbedit` listing inside the restricted
root. Its source pathname is masked; input FDs close before tool exec. The
containing runtime Owner retains/rechecks the code and protected configuration.
Duplicate late-input refusal, partial cleanup, closure of every temporary caller,
private bounded listing, single-use/closed-handle refusal, verified process-group
absence and release/no-FD-leak pass on ARMv5. Generic `CaptureSpec` has no new
descriptor/action/password option. The private fixed constructor requires the
root VersatilePB fixture and empty regular stdin; product builds exclude it.
This uses synthetic qpwriter, not an identity Owner's native private-group
account. The real credential backend/Owner-derived NSS and mutations/revocation
must still be composed; this probe returns neither a backend nor raw listing.

Its separate prelaunch refusal case uses the same fixed public constructor:
pre-admission cancellation publishes no output and consumes no command; a later
protected directory mode fault returns review, preserves all nine retained
code/input/state descriptors and cannot be revived by mode restoration. Group
absence and explicit close release those references without leakage. The fault
is temporary disposable QEMU state only, not a supported permission change or
a production interface. Credential-worker cancellation after launch and full
forced/uncertain shutdown still require their own qualification.

`Plan.StageQEMU` independently pins source/destination `O_PATH` descriptors.
It requires root credentials, a local read-only source and a freshly empty
root:root 0700 writable tmpfs destination with no ACL/capability attributes.
Only canonical files from the copied plan are opened, with no symlink,
magic-link or cross-mount traversal and no fallback. New directories are 0700;
files are created with `O_EXCL` and mode 0600. Bounded SHA-256 verification runs
during copying, with exact size and stable source metadata. It does not copy
xattrs, source modes/ownership or hardlinks. Only fully verified files receive
their declared 0444/0555 mode. Direct aliases are generated from the plan, never
copied from the source symlink graph. Traversable directory modes are set last.

Any potentially mutating failure includes `ErrStageIncomplete`: discard the
entire disposable tree; no rollback, publication, automatic retry or resume.
Occupied destinations are refused before copying, never cleaned or overwritten.
Exclusive ownership/serialization by the root caller is a prerequisite; this
does not resist another privileged writer or seal every writable view. Success
still requires the separate kernel read-only bind and non-root `Inspect`.

The fixed QEMU fixture now uses this prototype instead of shell `cp`. Actual
guest checks require fresh independent inodes, five refusals (occupied tree,
wrong digest, writable source, canceled context and source symlink) plus dirty
tree re-entry refusal. The failed digest's file remains 0600 and root 0700.
The stager itself has no authenticated manifest, persistent recovery, retained
root ownership, service activation or installable product API.

The generic service launcher and Samba's bounded root profile are unchanged.
Neither this test helper nor probe is installed by a firmware package. Use the
existing [focused Samba wrapper](../../../../support/test-samba-root.ps1);
it reuses read-only cache/base inputs and bounded temporary space, without new
images or persistent volumes. Host tests cover plan copying/budgets/hierarchy,
serialization refusal, writable-root refusal and safe Linux open flags.

## Retained code and static-process Owner

The separate fixed QEMU native-data prerequisite adds two original per-share
`O_PATH` inputs to a NEW runtime after the preceding identity/runtime fixture
fully closes. It validates protected, independent ext-family RO/RW mount roots;
the native helper attaches individual nonrecursive clones and closes inputs
before executing Samba in its restricted root. The original credential workers
receive no data descriptors. Fixed qualification documents are not desired
policy, a complete file-service Plan, or product activation inputs.

Actual ARMv5 SMB transfers prove RW write/read, RO read/write denial, Unix file
ownership, kernel `EROFS` and symlink refusal with no transferred/forbidden file.
Every owned group and descriptor copy settles before caller originals release.
The full local three-campaign lane, Linux race-count3/module vet and Windows
preflight/cross-compile pass. Complete-roster storage pins, the SAME identity
Owner/backend through startup, policy/grant/ACL admission, storage-loss and
uncertain-stop fences, full image/hosted qualification and product wiring remain
open. The exact marker records `complete_storage_identity=false`; do not borrow
continuous lifetime evidence from another fixture.

The separate QEMU-only native composition now retains the same original code,
Owner-derived configuration and writable state through disabled-first account
enrollment and one bounded single-use daemon lifecycle. Its private adapter
duplicates the helper plus twelve input objects; the bootstrap clones originals,
masks source paths, closes escape FDs and runs in a read-only root with caps
`0xdb`/NNP, no proc/dev/run and empty read-only IPC `/tmp`. Only the disposable
guest's loopback is available, not a host listener or data grant.

The official local ARMv5 wrapper verifies real authentication for two distinct
Owner-enrolled accounts, wrong-password refusal, all114 original code views,
protected config/state and verified whole-group stop/reap/no-FD-leak. Credentials
and authentication keep separate 60/20-second phases inside the 180-second guest.
The same fixed backend now also passes idle disable while that daemon remains
owned: same-SID journal, two complete stable-absence inventories, refused new
target login and successful peer login. Start/worker/check/stop operations keep
the private gate individually; no callback or replacement backend runs inside
it. Exactly one complete code/config/state and live-daemon admission brackets
each worker, retaining the existing status/revocation deadlines. Canceled and
duplicate starts, restart after stop and absent/busy authority are refused.
That first idle-only result did not establish active-session coverage.
The newer official local wrapper additionally holds two fixed interactive
clients, observes a complete qualified pair, executes Owner-bound target-only
logoff, requires two complete target-absence inventories and verifies the SAME
peer session/server generation. Fresh target login is denied; the peer remains
usable. The witness is backend-bound/nonserializable; incomplete, foreign or
replaced evidence is refused. All37 driver/seven loader tests, both campaigns,
verified client/daemon group stop/reap, final FD equality and unchanged base
pass; native host/race-count3 checks also pass. No new privilege or data share
is granted. Native status/revocation use fixed4/10-second budgets (ordinary
adapter2/5 unchanged), with independent startup20/idle20/session45 phases,
enrollment60 and guest180. Complete worker admissions are never skipped.
This is not complete image/clean/hosted qualification, data-handle semantics,
continuous identity/storage authority, product root construction or startup.
The generic Owner's static/non-root contract below is unchanged. See the
[native profile](../../../../support/SAMBA-RUNTIME-PROFILE.md#native-same-state-authentication-qemu-only).

A subsequent read-only native-backend probe obtains an identity consumer only
for the exact adapter fixed in `identityowner.OpenWithSMBBackend`. It refuses a
foreign adapter, verifies complete evidence and busy Owner close, then releases
before daemon/client startup and confirms unchanged evidence. The official
38-driver/seven-loader/two-campaign ARMv5 wrapper and root identity race-count3
pass, including every earlier guard. This qualifies a binding prerequisite,
not a continuously retained service lease: that probe adds no runtime callback,
account transition, supervision or product constructor. Never invoke lease
verification from an Owner/runtime gate or silently refresh invalidated tokens.

The separate native live-session fixture now qualifies an explicit
`identityowner.SMB(id).DisableForFileService` successor. It binds to the exact
startup adapter, retains before held-client construction, and transfers only
after complete before/after evidence proves the single authorized disable.
The old token remains invalid, the successor verifies and keeps Owner Close
busy, and the SAME peer session remains usable. Both tokens are discarded only
after independently verified whole daemon/client stop; uncertain stop keeps
retention. The mandatory handoff marker explicitly records `startup_bound=false`
and `service_owner=false`: retention starts AFTER daemon startup, not at a
product constructor. No gate recursion, per-call backend injection, implicit
refresh, new capabilities, storage authority or HTTP surface is introduced.
The official local 39-driver/seven-loader/two-campaign lane passes. Preparation
is independently bounded 20 seconds; live checks 45, enrollment 60 and guest 180
remain fixed. A prior combined 45-second attempt expired at login verification;
an instrumentation-only control passed, so the failure is not represented as
a deterministic runtime defect or a diagnosis of older hosted census failures.

Linux `Plan.NewOwner(ctx, root, specs)` privately duplicates the root and retains
every verified regular file. It copies a fixed set of 1..8 process specifications
and owns their independently pinned executable descriptors. There is no handle
getter, borrowed close authority, backend substitution or path selection at
`Start`. Descriptor duplication uses `SyscallConn.Control`, protecting it from
concurrent caller close/reuse. `Inspect` uses the same safe root duplication.

The initial process adapter accepts only declared **static ELF** executables,
with explicit non-root service credentials (IDs 1000..60000). It executes the
pinned descriptor, not a reopened pathname. This is not the dynamic Samba
adapter: no host loader, root impersonation, namespace, storage grant, NFS
control, configuration or extra capabilities are approved by this constructor.
The original generic/isolated process-owner profiles remain separate.

Before launch, after readiness and during explicit `Observe`, the Owner checks
the complete bounded census/hashes and original metadata/inode/mount identities,
including directories and aliases. A same-byte replacement is not the original
retained object. Drift or an uncertain lifecycle result permanently requires
review and triggers one bounded process-set stop. Restoring inputs does not
clear review or restart. A duplicate Start reports already-running without
stopping healthy processes. Snapshot member slices are independent and JSON
serialization is refused.

`Close(ctx)` explicitly stops and waits for all owned groups before releasing
any code/root pin, even if that accepted teardown context is canceled. Unknown
process ownership blocks all pin release. A later explicit close may verify
earlier termination, without resending signals or clearing review. This is
in-memory ownership only: review is not a durable recovery journal, and a
privileged writer through another mount still requires external serialization.
`Supervise(ctx, interval)` is an explicit blocking operation for an already-ready
static Owner. It holds the same lifecycle gate for its whole accepted lifetime;
concurrent lifecycle calls fail busy. One timer schedules a complete observation
after each fixed idle interval (1 second..1 hour), reset only after that scan
finishes. Drift, unexpected exit or uncertainty stops the set and retains review;
there is no automatic start/restart. A context canceled before admission has no
effect. Accepted cancellation stops before returning, retaining all code pins
until explicit `Close`; uncertain stop remains review. Cancellation during a
scan can require review because observation is incomplete. Stop is bounded by
the existing member budgets, not by ignoring cancellation or clearing ownership.

Revalidation is bounded local I/O, not continuous integrity enforcement or a
guarantee that a kernel stall is interruptible. The idle interval is not a
maximum detection latency: scan/stop time and kernel stalls also matter. No timer
starts at construction/ordinary Start, and no HTTP/product startup calls this
Owner. Non-Linux construction/lifecycle remains unavailable. The prototype's
interval limits do not qualify an EX4 production polling cadence.

`support/test-runtime-owner.ps1` runs its own finite ARMv5 QEMU fixture with a
static test child, private guest mount namespace and tmpfs code tree. It verifies
caller-close survival, immutable spec/snapshot, pinned launch, duplicate Start,
canceled teardown, group reaping, identical-byte inode replacement before
launch, live root drift and permanent review after restoration. The guest also
exercises a child that ignores SIGTERM: forced stop requires review, normal
unmount remains kernel-EBUSY while pins are retained, and only a later explicit
reap verification allows release/unmount without clearing review. These checks
use only the guest's disposable code bind, never a data mount. This separate
120-second guest does not inherit Samba entropy/network readiness waits. It uses
only a read-only cached base/workspace and a 512 MiB disposable tmpfs, removes
the compile cache before copying rootfs, checks base hashes, and creates no
persistent image/volume or physical-device attachment. Full QEMU integration
includes the same fixture and preserves a bounded failure log. The same guest
also covers invalid/stopped/pre-canceled supervision admission, exclusive
lifecycle ownership, accepted cancellation, live code drift, unexpected child
exit and forced-stop review, with kernel group absence and retained mount pins.
Restoring code cannot restart the reviewed Owner.

The same finite guest also schedules two actual mutations at a later file's
hash-read boundary, after the complete census, alias checks and earlier file
hash. It replaces an inner executable directory with identical bytes, or an
alias with an identical target. A separate `Inspect` control still accepts
the declared bytes; a retained Owner refuses the changed original path before
any child starts and restoration cannot clear review. A test-only context
observes the inspector's actual independent read descriptor at offset zero;
it injects no metadata, changes no descriptor offset and adds no production
hook. Required evidence includes both cases and verified Close/root release/
normal unmount before the guest's final success marker. This explains why
early census metadata cannot replace the Owner's trailing pathname identity
checks. It does not prove an atomic snapshot, every possible race or exclusion
of privileged writers, nor justify reducing the production integrity checks.

The separate Samba fixture emits a bounded scan-cost measurement around its
existing positive code-only inspection (no additional scan): file/byte counts
and monotonic elapsed time. Its log validator rejects missing, duplicate,
malformed or over-budget evidence and labels it `qemu-emulation-only`. This
does not measure physical EX4 CPU/I/O, production responsiveness or efficiency
relative to the legacy firmware.

Trusted signed/model/ABI inputs, dynamic Samba-specific composition and
privileges, storage leases, durable recovery and EX4/product qualification
remain open. Passing this prototype does not activate SMB or NFS.
