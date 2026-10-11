<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# M4.5: retained server-open observation integration plan

Status: **dedicated fixture boundary approved; partial S1 loader prerequisite;
not an active observer or authorized product startup**. Approval covers a
dedicated VFS module/bootstrap in host/disposable VersatilePB QEMU only, retained
original code/socket references through verified stop, with no extra privileges
or generic-launcher widening. No NAS, physical media, HTTP, installed helper or
pending WRITE experiment. Client-launcher approval alone is not server approval.

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
The client is not yet executed against Samba/in ARM or joined to retained code,
bootstrap, actual worker or transport authority. Its new notice protocol is
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
