<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# M4.5: retained server-open observation integration plan

Status: **proposed, not implemented or authorized for product startup**.
The dedicated server VFS/bootstrap boundary requires an explicit architecture
decision before implementation. Existing client-launcher approval does not
approve a server profile. All initial work is host/disposable VersatilePB QEMU
only; no NAS, physical media, HTTP, installed helper or pending WRITE experiment.

## Deliverable and existing boundaries

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

## Ordered implementation packets, after the boundary decision

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
