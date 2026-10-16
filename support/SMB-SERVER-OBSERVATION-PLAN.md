<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# M4.5: retained server-open observation integration plan

## Current scope and remaining work

The variants below are distinct. Existing construction/launch code must not be
mistaken for missing work, or inherited as permission for a different operation.

| Client path | Existing fixture scope | Still not established |
| --- | --- | --- |
| Generic pending client | Complete retained-input Owner; actual OPEN/CLOSE-only execution and server/process/transport observations. The C program opens O_RDWR, but the Owner exposes no WRITE command. | The program's WRITE branch has mock/compile evidence only, not a runtime WRITE qualification. |
| Handle-observer build | WRITE is compiled out; original-handle observations and CLOSE are exercised. It still opens O_RDWR. | A read-only descriptor, original worker OFD duplication or pending-request authority. |
| Separate capture client | O_RDONLY OPEN, two one-byte READs and CLOSE; same-open VFS metadata and selected between-request containment fixtures. | Complete construction/lifetime/uncertain-stop coverage, original OFD/request lease, interrupted server I/O or WRITE. |
| Product service | The above are optional host/disposable-QEMU fixtures, not service startup. | Product state/identity/storage admission, activation, recovery and physical EX4 qualification. |

Source boundaries are in the [generic/handle client](tests/samba-pending-write-fixture.c),
[capture client](tests/samba-server-capture-client-qemu.c) and
[containing Owner](../src/phantowd-api/internal/runtimebundle/pending_client_owner_qemu_linux.go).
Fixture evidence remains commit/profile-specific; see the
[test contracts](QEMU-FAST-TESTS.md) and [current integration gate](../IMPLEMENTATION-STATUS.md).

Next work is read-only constructor/reference-lifetime and late/uncertain-close
fault coverage at the real containing boundary, without fabricated healthy
inputs or replaceable per-call backends. Retain original errors, review and
unattempted references; verify original groups absent before release. Separate
original worker OFD/request and outstanding-I/O semantics must precede a new
reviewed WRITE experiment. No WRITE, new privilege, HTTP or NAS authorization
is created by this plan. The original qualification scopes below are history,
not a list of prerequisites to reimplement.

### Constructor-backed pre-close packet: focused host/ARM tested

The fixed `preclose-input-loss` mode now passes in the optional complete-input
ARM guest. It constructs the real never-started Owner, normally closes one owned
client-code `os.File`, and verifies mismatch/review with the original unattempted
references retained. Repeated close/start/client-close calls refuse; the reviewed
FD count stays stable and an independent descriptor survives. A strong reference
keeps the reviewed Owner until helper-process exit. Init waits for exit zero,
checks the child is reaped and compares bounded parent FD counts (not identities).
All five ordered receipts are mandatory. The original 60-second guest bound and
base checks remain; no SMB client/server executes. This is not kernel EIO,
guaranteed numeric-FD reuse, launched-child teardown or product qualification.
The containing Owner now also retains its first review cause and recorded stop/
release errors. The actual ARM proof requires cause identity across repeated
refusals; host controls cover observation entrypoints and later-cause replacement.
This diagnostic correction does not authorize retry, restart or input release.

The scoped acceptance contract is:

- Construct the real dedicated Owner from qualified original roots, with no
  client launch. Do not fabricate healthy `started`/`settled` state or inject a
  successful replacement adapter.
- In a disposable fixture only, close one fixed owned client-code `os.File`
  before normal close admission. Do not raw-close its numeric FD and risk later
  closing a recycled descriptor. This models observed input loss, not kernel EIO.
- Require refusal and sticky review, unchanged unattempted bootstrap/root pins,
  no restart/retry/release after input loss, and continued usability of unrelated
  independently owned descriptors. Reopening/replacing a closed pin is not
  restoration of the original reference. A copied error field is not this test.
- Keep reviewed originals until disposable process teardown. Reuse and qualify
  the fixed isolated-child pattern where necessary; preserve parent FD equality
  instead of pretending reviewed retention is healthy closure. No new default
  guest, privilege or mutable backend is needed.
- Retain all existing source/base hashes, complete-input proofs and original
  deadlines. Claim only constructor-backed pre-close input-loss containment;
  later close-syscall uncertainty and construction-race coverage remain separate.

## Latest read-only qualification checkpoints

Partial S5 now also covers the fixed parent share mount: binding the SAME
directory at its parent path preserves inode/content but changes unique mount
identity. No-symlink original-root-relative O_PATH metadata fences bracket
worker observations, close temporary observations and never adopt a replacement
share. Actual ARM next-READ refusal/verified groups/sticky originals-review/
restoration refusal/data/base pass. Real directory/symlink/missing controls
must PASS in the pinned guest, not skip. Unsupported WSL host kernels prove
refusal only. Exact eleven-guest union/pinned host/Windows and strict10+136
pass at original bounds. Complete source/device lifetime, uncertain stop,
SDK/construction/OFD/request/S6/S7/full/hosted/product gates remain; a favorable
rerun does not fix prior reliability failures. No NAS/new Docker storage or
new privileges/default CI boot.

Partial S5 adds the fixed parent source-leaf cover after one matched READ.
The old input fence accepted the changed parent alias while the held object
and child remained original; bounded diagnostic70937 proves only that gap,
not a successful subsequent READ. Original4258 refusal failure and50153
60-second diagnostic timeout are preserved. A no-follow parent-relative object
check now brackets worker observations, never reopening/adopting a copy.
Corrected actual ARM39040 and the final source guest refuse the next READ,
settle both groups, retain originals/review and reject work after restoration.
Restored source metadata is checked after stop without clearing review.
That checkpoint's strict input receipts were8+109 for four declared kinds. Complete source/root/
device lifetime, uncertain stop, SDK/construction/OFD/request and S6/S7 remain.
The latest clean focused union now passes all ten guests on identical source
witnesses, with pinned host and Windows checks. Earlier healthy60s failures
remain reliability evidence; twelve parent checks total1.949ms in one measured
guest do not establish the sole cause of variation. The duplicate tracer sweep
experiment was reverted/all DEBUG removed; no timing fix, full/hosted gate
waiver or installation is claimed.

Partial S5 now additionally exercises cancellation of READ collection. A fixed
waiting client variant keeps the original control pipe open without READ ACK;
a joined bounded observer cancels only on 88 original queued bytes. Actual
ARMv5 requires canceled context/review, zero frame/sequence, verified groups
stopped and the queue/original references retained, with refusal on repeated
READ/start/Close and stable reviewed FDs/data/base. Byte count is never decoded
metadata authority or completion. Real-pipe behavioral RED/GREEN, sanitizer,
real-socket refusal controls and strict2+30 pass. This is not interruption of
server I/O, uncertain-stop, pending-WRITE/OFD/request or full S5 qualification.

Partial S5 additionally exercises a separately compiled fixed client that
withholds its READ acknowledgement. Its deliberate refusal sits after the
one-byte read/seek/tuple check; the unchanged normal binary remains separate.
Actual ARMv5 containment returns zero metadata, leaves sequence zero and the
88-byte record unconsumed, verifies both groups stopped and retains originals
in review. Repeated READ/start/Close refuse with stable reviewed FD counts and
unchanged data/base. Only queued byte count is observed, never record contents
or authority. Missing acknowledgement cannot certify client completion; this
is not pending-request/OFD/WRITE, uncertain-stop or full S5 qualification.

Partial S5 now additionally qualifies original module/configuration/receiver
drift after one completed authenticated READ. Separate fixed `-InputDrift`
guests prove zero next frame, verified client/server stop, complete original
retention and READ/start/Close refusal after restoration, with stable reviewed
FD counts and unchanged data/base. Module/configuration copies are byte-identical
RAM path covers, not replacement execution authority. A read-only restored-input
observation deliberately preserves the nested code keeper's review latch;
normal revalidation of that latch was an actual refused diagnostic attempt.
Strict fault receipts require each declared kind (six positive/82 negative).

The original negotiation-only runtime regression now also preserves review
instead of disposing after receiver/code drift. Its observed failure is retained;
the corrected control requires repeated Close refusal, original references and
stable reviewed FD counts, not healthy-release equality. Strict2+67 includes
fatal-log refusals. No global input/queue/bind/READ fence or timer is relaxed.
These are between-request faults only; uncertain stop/cancellation, complete SDK/
construction/OFD/request/S6/S7 and product/hardware gates remain mandatory.

Partial S5 now includes actual original-worker loss **after one completed READ,
before the next request**. The optional `-WorkerExit` lane uses a generation-
bound pidfd, refuses the next READ with a zero frame, proves client/server stop,
retains original object/proc/code/channel pins in sticky review, and refuses
retry/restart/close. A host regression fixes runtime Close's missing early
review refusal. Actual ARMv5 and independent strict fault receipts pass. This
does not qualify interrupted pending I/O, durable reconnect, remaining active
module/config/channel faults or complete S4/S5/SDK/construction/S6/S7.
The existing-state refusal regression now also forbids reviewed disposal and
retains unchanged passdb/code/channel/state references after verified stop.
Its healthy FD equality and retained-fault scopes are distinct, with all five
ordered ARM adapter tests and strict2+41 controls still mandatory. Only a
redundant tracer Observe before the complete dual-lock bind was removed; no
bind/READ/global queue fence or timer was weakened.

The optional capture OPEN lane now qualifies two actual one-byte READs and
kernel-credentialled VFS observations on the original authenticated handle.
Every metadata field matches independent STATUS/client evidence; original
worker generation/executable/endpoint, one O_RDONLY data slot, an O_PATH object
pin, and reciprocal TCP/namespaces are checked with complete original inputs
before/after each READ under both gates. The object pin survives verified stop.
It is **not a duplicate worker OFD or pending-request lease**. Actual ARM CLOSE,
unchanged data/base and FD equality pass within the existing timers; an extra
tracer-only sweep duplicated READ fences and was removed, not relaxed.
Complete SDK/construction/fault coverage, S4/S5 authority and S6/S7 remain open.

## Earlier prerequisites and their original qualification scopes

The capture OPEN lane now also binds and rechecks original client/worker
generations, four retained namespaces and reciprocal kernel TCP pair through
the unchanged connection primitive. Complete input/STATUS/worker fences run
with both Owner gates held in client-first order; rechecks accept no replacement
peer. Actual ARM CLOSE/stop/data/base/FD proofs and host/race/refusal tests pass.
Containment belongs to the public/dual-owner boundary, not its locked helper.
The original worker data-FD and active VFS/FileId/frame/request bridge remain
unqualified; no complete S4/S5, product startup, privilege or timer change.

The current optional OPEN lane adds a fixed STATUS-only helper with unchanged
native12 namespace/chroot/capability/FD boundary. Two independently captured
STATUS observations match the original client session/tree and retained worker
proc/start/parent/group/executable/FD3 plus local-file view. Actual ARM and final
data/FD/base checks pass. Helper settlement and complete original input fences
are mandatory; its exact isolated-network warning is source-verified, not an
arbitrary diagnostic allowance. This is partial S4 observation, not an original
worker data-FD lease, reciprocal TCP/namespace pair, remote FileId/local-object
match or request/frame authority. These are the next integration deliverables.

Historical OPEN/CLOSE checkpoint: **dedicated fixture boundary approved; this
checkpoint did not yet include READ/frame or an independent worker lease**.
Subsequent READ/frame observations are described above; complete OFD/request
authority remains unqualified. The approved boundary covers a
dedicated VFS module/bootstrap in host/disposable VersatilePB QEMU only, retained
original code/socket references through verified stop, with no extra privileges
or generic-launcher widening. No NAS, physical media, HTTP, installed helper or
pending WRITE experiment. Client-launcher approval alone is not server approval.

`support/test-server-capture-open.ps1` now qualifies actual authentication and
one original read-only OPEN/CLOSE in the fixed capture runtime. Complete
independently expected client/bootstrap inputs are retained and revalidated;
original modules/channel, unchanged data and FD equality survive verified
client/server stop. No READ or VFS frame is requested. This supersedes only the
earlier "capture client not executed" gap below: original worker generation,
remote FileId/local-object/transport matching and fault qualification remain
mandatory before a server-open authority or pending-I/O experiment.

`support/test-server-vfs-loader.ps1` now exercises the real pinned Samba loader
and VFS registry at one canonical path. The fixture module deliberately refuses
CONNECT with `ENOTSUP`: no endpoint or sampling path exists yet. Actual ARMv5
loader/ABI/name/duplicate controls and non-root/caps0/NNP execution pass. Six
sensitive SDK/configuration hashes, fixed exports/imports/direct dependencies,
RELRO/NOW and non-executable stack are guarded. This is only **S1's loader
prerequisite**, not a complete SDK/dynamic-closure lease, active-worker bridge or
completed S1/S2. No default campaign or pipeline boot is added.

`support/test-server-observer-context.ps1` adds a **partial S2 context
prerequisite**: a fixed separate bootstrap retains only the validated original
sender at FD3 after isolated-root construction and execs a static context probe.
Actual ARM verifies the root/capability/FD boundary, kernel child credentials and
original references after verified child/group settlement. Endpoint loss and
config-FD leakage refuse. Neither the existing generic/native helper nor the
VFS CONNECT refusal changes. This is not a real smbd bootstrap, complete code/
SDK lease, containing Owner, active worker or S2 completion.

`support/test-server-observer-daemon.ps1` now adds the separately qualified
**partial S2 real-daemon handoff**: fixed single-use adapter, retained sender,
actual pinned smbd executable/FD3 checks, guest-loopback SMB 3.02 NEGOTIATE and
verified whole-group stop before descriptor release. Twelve constructor
refusals run three times in ARM; failed startup immediately retains review
without retry. The existing context fixture shares only the private C boundary;
generic/native/product launchers remain unchanged. No authentication, file OPEN
or active VFS sample is requested. Complete SDK/code/containing authority and
S2–S6 remain unqualified; neither an inherited FD nor NEGOTIATE grants a lease.

The dedicated adapter also checks the original endpoint during discrete Observe
and explicit Stop. A fresh second smbd fixture proves a real sender-option drift:
verified stop, original references retained, restored option still reviewed and
restart refused. This is a **partial S5 endpoint fault**, not continuous
supervision, active worker/module/configuration fault coverage or full S5.

The same optional lane now has a **partial S2 code-input prerequisite**, run
before the daemon: privately retained complete declared code, original fixed
path/mount binding and exact-byte-copy overmount refusal. Actual ARM RED/GREEN,
caller-close independence, foreign-root refusal/FD equality and retained sticky
review after path restoration pass. It is not a live containing Owner; the
observer module, full SDK/bootstrap inputs and channel/process composition are
still required. Original code hashing/census is preserved, not replaced by a
path check. No generic launcher or default boot is changed.

The lane now additionally composes a private single-use runtime retaining the
declared code and independently built bootstrap, fixed configuration, original
mutable-state/share roots, both endpoints and the dedicated daemon adapter.
Actual ARM receiver-option drift and live code-path cover settle real smbd and
keep original references plus review; restoration cannot restart. Healthy
negotiation, proc/executable/FD3 checks, close-before-stop refusal, canceled
cleanup and final parent FD equality pass. This advances partial S2/S5, but is
not complete S1/S2/S4: the observation module/SDK/active producer is absent,
no frames or file OPEN are requested, and actual worker/FileId binding remains
the next deliverable. Current constructors still require construction-race and
complete fault qualification; no default CI, privilege or timer change.

## Deliverable and existing boundaries

`support/test-server-capture-runtime.ps1` now joins independently expected
capture-module/bootstrap code inputs to a separate fixed runtime profile.
The old negotiation-only configuration and launchers stay unchanged. The new
bootstrap uses a fresh stdin pipe for one synthetic nobody account in private
RAM state; its credential helper closes the observer FD and stays in the same
owned group. Any existing passdb or uncertain lookup refuses before mutation.
Actual ARM verifies smbd/NEGOTIATE, original module/channel retention, verified
stop-before-release, existing-state refusal with unchanged TDB and FD equality.
This supersedes "module absent" only for the declared input composition: no
authenticated client, OPEN or frame in that runtime-only lane. The newer OPEN
lane above composes actual authentication/OPEN/CLOSE; all S4
worker/FileId/local-object/namespace/TCP witnesses remain mandatory.

The dedicated `ServerCaptureClientQEMU` process adapter now handles the new
canonical OPEN/max-two-READ/CLOSE notice stream and keeps original process
generation/executable/non-root status checks. Host and ARM parser/refusal tests
and scoped race checks pass; these adapter tests alone are not a server lease.
The separate OPEN lane above now qualifies retained client roots and actual
authentication/OPEN/CLOSE. Successful reads and S4 worker witnesses remain next.

The optional `support/test-server-capture.ps1` now implements a separate fixed
capture module variant. Sync/async read callbacks sample current FSA metadata
without retaining a file pointer and send two ordered frames nonblocking via
FD3; failures, cancellation/overlap, restored inputs and a third sample refuse.
Twenty actual ARM cases use the real registry/tevent/socket transport but
**synthetic open/connection records and a thin local-pread test backend**. They
do not include a real SMB client/worker or grant remote-handle authority.
Sensitive SDK pins and fixed ELF boundaries are checked, not a complete SDK
lease. Next, join this module to the retained runtime and qualify two sequential
one-byte reads only after independently confirmed original client OPEN, then
match kernel sender/worker generation, remote FileId and original local object.
The loader-only module, generic launchers and old campaigns remain unchanged.

`support/test-server-capture-client.ps1` now prepares a separate fixed O_RDONLY
client for that integration. Three mock-positive flows, exact ordered receipts
and 121 refusals pass with ASan/UBSan; the independently compiled ARMv5 PIE has
no mutation accessor imports and depends on the existing source handle reader.
At most two one-byte reads reuse the original context/file, checking its tuple
before reading and after local seek-to-zero. Early explicit CLOSE is allowed;
unknown/third-read commands and uncertain results never retry or reopen.
This compile-only lane does not execute the client; the OPEN lane above now
joins retained code/bootstrap to actual ARM Samba. Original worker and transport
authority remain unqualified. Its new notice protocol is
distinct: do not route it through the old close-only process adapter. Existing
launchers/adapter/configuration and default campaigns stay unchanged.

The next deliverable is an independently qualified bridge from the original
client's remote SMB FileId to the original server worker's still-open local
file. Successful SMB OPEN, copied IDs, STATUS output and transport credentials
are separate observations, not interchangeable authorities.

| Existing component | Reuse | Does not establish |
| --- | --- | --- |
| Retained client Owner and handle reader | Original client process, input closure, handle/session/tree and connection checks | Same server open or a pending request |
| `pendingServerOpenQEMU` | Retained worker proc generation, STATUS and local-object checks | Remote persistent/volatile FileId |
| C server-open reader | Actual Samba types/getters and local descriptor metadata | Active worker lifetime or final CREATE response success |
| Frame decoder/comparator | Fixed 88-byte records, all-field client/STATUS comparison | Trusted producer or channel lifetime |
| Private packet primitive | Original endpoints, sequence, kernel sender credentials and queue refusal | Authenticated Samba user or execution authority |
| Static/native Owners | Serialized admission, review and stop-before-release | An approved observation-module/server profile |

## Source-verified constraints

Pinned Samba 4.22.11 uses VFS interface 50 and the dynamic entry symbol
`samba_init_module`. Its dynamic loader constructs the subsystem path from a
module name and rejects slash-containing names. VFS name normalization alone
does not prove an absolute path will load. Select one fixed canonical module
name/path and verify its actual load in ARM; do not add caller-selected names,
paths, configuration parameters or `LD_PRELOAD`.

`is_fsa` is set before further operations can fail. A successful backend
CREATE return is not a successful final SMB CREATE response. Independently
observe the original client's successful OPEN. SMB2 sets `closing` before
backend CLOSE, so two valid samples must be taken while the original file is
still open; do not weaken the reader's closing refusal to use that callback.
The exact observation trigger remains a design/qualification requirement,
not a claimed completed hook.

The current fixed native bootstrap supplies five configuration and seven
state inputs, plus two share roots in its separate data profile. It closes
all inherited descriptors 3+ before exec and verifies their absence. Preserve
this behavior. A new dedicated server handoff must retain only its explicitly
validated observation endpoint after root construction; do not add a generic
extra-FD switch or relax the existing native bootstrap check.

## Ordered implementation packets, within the approved fixture boundary

1. **S1 — fixed build closure.** Add one fixture-only VFS producer using the
   existing source reader and wire encoder. Independently pin the actual SDK,
   sensitive headers, build flags, resulting module and complete dynamic
   closure. Verify ARMv5 soft-float ABI, canonical loader bindings, expected
   exports/undefined symbols and actual module loading. Review licensing under
   [the project policy](../LICENSE-POLICY.md). Neither an SDK hash nor a
   successful compile is signed product execution authority.
2. **S2 — dedicated descriptor handoff.** Specify a fixed ABI and dedicated
   constructor/bootstrap, excluded from ordinary builds. Independently duplicate
   and validate the original sender endpoint. Keep original receiver/sender
   references in the containing Owner; refuse copies, foreign endpoint roles,
   wrong socket settings and partial construction. Retain all original code,
   configuration, state and share authorities. After exec, only the intended
   endpoint survives: no caller root, device, namespace, code or data escape FD.
   Keep the existing namespace/chroot/NNP/capability boundary, with no added
   capability. Closing caller duplicates must not revoke the Owner's originals.
3. **S3 — active capture.** Choose and test a bounded trigger that observes the
   original still-open FSA structure after independently confirmed client OPEN.
   Validate its membership and current lifetime on every sample, without
   retaining an unguarded C pointer after destruction. Produce exactly two
   ordered records; no reopening, reconnect, retry, pathname-derived replacement
   or filesystem mutation. Full/closed channel or uncertain send fails closed;
   bound work and output without blocking the worker indefinitely.
4. **S4 — containing authority.** Join the original worker proc/start/group,
   executable, namespaces and TCP connection with each packet's kernel sender
   PID and the expected fixed credential mode. Socket creator and worker differ
   after fork; real/effective sender IDs do not identify the Samba account.
   Match every frame field with the original client handle and independent
   STATUS/local-object witness. Recheck originals before/after consumption;
   never replace expected tuples or treat equal caller-supplied metadata as a
   lease. Missing, foreign, duplicate, extra or replayed records require review.
5. **S5 — lifetime/fault refusal.** Qualify worker exit, original-module/config/
   endpoint drift, source alias replacement, canceled collection and uncertain
   closure. Drift/uncertainty stop owned processes once and preserve review plus
   unattempted original references; restoration cannot permit restart/rebind.
   Only verified whole client/server-group settlement permits ordered release.
   Closing a descriptor unsuccessfully does not prove it remains open.
6. **S6 — exact regression union.** Run fast host/refusal/race checks first, then
   the focused actual ARM guest with unchanged original base and strict ordered
   proofs. Preserve existing healthy, peer-stop, retained-handle and native
   campaigns, parent/subprocess FD equality and unchanged synthetic data.
   Declare measured budgets rather than silently increasing original timers.
   No additional default CI boot until the focused contract is qualified;
   complete-image and exact-head hosted checks remain separate.
7. **S7 — pending-I/O admission.** Only after S1–S6 qualify may a later packet
   prove an original request, transfer extent, completion/cache/journal state
   and interruption timing. The bridge alone does not authorize WRITE, durable
   reconnect, recovery or a product service. Hardware/storage/release gates in
   [the roadmap](../ROADMAP.md) remain mandatory.

## Handoff evidence

Each packet reports exact source/artifact identities, real positive and negative
controls, original process/reference lifetimes, cleanup outcome, resource caps
and scope. Keep raw IDs private; public receipts expose redacted proof only.
Never infer successful admission from a timeout, a diagnostic label, a skipped
test, a copied observation or another guest's authority.

The hosted native fresh-login/shared-deadline failure is independent. Do not
use this integration plan to waive that failed gate, skip hashing or authorize
an installation. See [implementation status](../IMPLEMENTATION-STATUS.md),
[runtime contracts](../src/phantowd-api/internal/runtimebundle/README.md) and
[the Samba profile](SAMBA-RUNTIME-PROFILE.md).
