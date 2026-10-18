<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Retained policy-operation observation — experimental M1.3b.3

Linux-only private collector over the fixed experimental layout below. It
supplies the existing pure matcher with actual bounded file reads under retained
original locks. It is not product boot wiring, a second store, journal writer,
recovery engine, durable quarantine, consumer lease or service admission.
The selected product direction is current policy plus per-operation bundles.
No NAS installation path, physical medium or product writer is selected; the
experimental layouts below are not a frozen compatibility contract.

The QEMU fixture now obtains intent/base/candidate data from the separate private
preparer and compares its candidate with an actual temporary Store commit. The
receipt used for matcher cases remains invented fixture data, never a preparation
result or proof of a durable operation.
An additional disposable fixture checks the separate
[anchored Store prerequisite](../revisionstore/ANCHORED-STORE.md): exact commit
readback, actual policy-lock exclusion and sticky refusal after late pending
evidence. This does not connect the observer to a writer or authorize recovery.
The same QEMU-only fixture also runs the separate
[disposable transaction protocol](../policytransaction/README.md). Its new
`operation.json` profile requires the separate explicit `OpenBundle` entry;
ordinary `Open` retains its original fixed census and refuses that profile.

```text
trusted-state-root/
  policy/
    nas-services.json       # optional current coherent NAS policy
    .nas-services.pending   # optional metadata-only evidence; always review
  operations/
    intent.json             # optional private schema1 operation record
    receipt.json            # optional private schema1 local-confirmation record
```

`OpenBundle(ctx, root, expectedInstallationID)` instead fixes operations to
optional `operation.json` (maximum896KiB) and metadata-only `.operation.pending`.
Policy names are identical. It reuses the same retained locks, original read-only
files, unique mount/path witnesses, census, watches and cleanup engine, not a
caller-selected codec or per-observation backend. Legacy/mixed names refuse;
there is no layout guessing or migration. Either pending role latches review
before **any** current/bundle data read. The portable private bundle comparison
returns the same six no-action diagnoses and clears temporary decoded bytes.

## Lifetime contract

### Explicit identity namespace profile — M1.2c.8

Root-only `OpenIdentity(ctx, directory)` selects the current native Owner's
dedicated layout, never guesses a policy or credential profile:

```text
identity-root/
  registry/service-accounts.json       # optional current; fixed pending name
  operations/<account-id>/
    identity-operation.json            # optional current; fixed pending name
    smb/smb-operation.json             # optional child/current; fixed pending name
```

Root, registry and operations directories must exist. Retain their actual flocks
in that order, then account directories in lexical ID order and each present
`smb` child immediately after its parent. Lexical order is only lock/IO order;
creation chronology comes from bound registry/journal data. Reuse the domain ID
grammar, not an independent filename parser. Census every directory with fixed
names/types or at most1024 account directories. Unknown, alias, symlink, unsafe
ownership/mode, cross-mount and changed entries refuse. All directories/files
retain original unique mount identities and mutation watches; no layout upgrade.

`ObserveIdentity` feeds the complete original bounded record set to the private
[identity comparison](../identityevidence/README.md), with before/after namespace
and file rechecks under the same mutex. A present-but-empty `smb` child means
unavailable enrollment evidence, not proven absence. Any registry/native/Samba
pending file latches review before **all** content reads. Read-only/no-atime opens,
chunk bounds, private/copied handles and first-uncertain-close retention reuse
the shared engine. Cancellation is checked before each new directory/current
open and metadata-budget step; kernel calls themselves remain non-interruptible.
Constructor never creates/syncs/replays, and restoration cannot resume review.

The4MiB metadata budget includes all current bytes and account names before file
content reads; original individual limits remain. The maximal syntactic roster
can require2051 retained directories and2049 current files, plus watch/temporary
descriptors. No process limit is raised and resource exhaustion refuses; that
worst case is **not** qualified on EX4 or the complete product process. Product
resource budgeting/FD limits and larger-roster qualification remain gates.

This is a diagnostic lifetime, not Owner construction/handoff, live Unix/passdb/
session observation, durable review, whole-appliance startup or permission to
initialize missing state. Full constructor/temporary-close/watch, namespace/
mount/read/cancel/fault coverage, actual writer/restart/media provenance, product
role/consumer composition and physical/release qualification remain required.
Existing policy/credential profiles, Owner recovery and HTTP stay unchanged.

Pinned native tagged vet/scoped units/race3 and nine-family receipt controls pass.
Positive native root lifecycle explicitly SKIP for the non-root test profile.
Native controls test active-roster aliasing, domain naming/root refusal, canceled
directory acquisition and a single controlled dynamic pre-close refusal;
they do not qualify all constructor/close/watch or kernel-EIO outcomes. Actual
standard ARM smoke executes eight cases twice: valid, missing registry, empty
enrollment child, three pending roles, observed/restored file replacement and
malformed registry. Six actual locks, copied/wrong methods, pending zero-read,
ordinary exact bytes/stat/atime and FD-balanced known-name disposal pass at the
unchanged shared15s/guest240s/outer360s bounds, alongside all prior assertions.
No new default guest or producer work. Those six-directory/four-current fixture
rosters are not the maximal1024-account descriptor/namespace qualification.

### Explicit credential-state profiles — M1.2c.6

`OpenAdministratorCredentials(ctx, directory)` and root-only
`OpenCHAPCredentials(ctx, directory)` select one existing dedicated role, not
the policy/history layout. The fixed names are `accounts.json` /
`.accounts.pending` (4KiB) or `chap-secrets.json` / `.chap-secrets.pending`
(256KiB). No caller supplies a decoder or changes the profile between reads.
The shared retained engine holds the original directory and actual writer-lock,
original no-atime/read-only file, unique mount/path identity, bounded complete
census and file/directory watches. Old policy profiles remain unchanged.

`ObserveCredentials` returns private missing/valid kind and exact uint64 revision
only; generic JSON refuses and ordinary formatting contains no account, verifier,
SecretRef or material. The original strict schema decoders are reused, without
KDF/authentication work. Canonical setup-only account v1 is interpreted as revision1
without changing its bytes; this is not import of WD credentials. Missing is not
pristine or enrollment permission, and valid bytes do not establish credential
entropy, policy-reference coverage or consumer/boot readiness.

Pending metadata latches review before **any** content read. Malformed state,
replacement, read/cancellation uncertainty and restored changes cannot yield a
partial diagnosis or resume the lifetime. Wrong-profile methods/copies refuse.
Close releases references only; uncertainty retains the existing no-retry/error
ownership contract. No create, sync, promotion, deletion, owner construction,
provisioning, secret consumption, session grant, recovery or product wiring.

These are separate diagnostic lifetimes, not continuity from a prior writer or
a complete startup coordinator. In particular, the ordinary credential Store/Owner
constructors establish sync boundaries and must not be used as read-only probes.
See the [whole-state ownership map](../../../../STATE-OWNERSHIP.md). Full constructor,
temporary-close/watch, namespace/fault coverage, supported-media and product
composition qualification remain required.

Pinned native vet/scoped units/race3 and strict seven-family receipt controls pass;
positive full native Open/Observe lifecycles explicitly skip without mandatory
unique mount IDs. The actual standard ARM smoke exercises both profiles with
valid, absent, pending, replaced/restored and malformed state (ten cases twice
across API restart). It checks the actual directory-lock exclusion, copied/wrong
entrypoints, no pending content reads, unchanged ordinary bytes/stat/atime and
verified FD-balanced disposal. Two exact new receipts and all prior assertions
are required at the unchanged shared15s/guest240s/outer360s limits. No extra lane,
producer experiment, physical disk or persistent Docker resource is introduced.

### Explicit session/history profile — M1.2c.5

`OpenSessionHistory(ctx, root, expectedInstallationID, exactCheckpoint)` selects
three fixed child directories: `policy`, `operations`, `policy-session`. The
four original directory flocks remain held in root/policy/operations/session
order, with original files, unique mount/path identities, complete censuses and
file/directory mutation watches. The checkpoint is validated and privately copied.
All directories must exist; optional missing records yield incomplete DATA,
never pristine/boot permission. No directory or record is initialized/synced.

`policy-session` allows only `epoch.json` (strict12KiB experimental envelope) and
metadata-only `.epoch.pending`. Policy and operation names/limits remain those of
OpenHistory. The4MiB raw metadata budget includes checkpoint/current/journal and
all operation bundles before reading, in addition to the decoded joined bounds.
Any of the three pending roles latches review before **any** content read. No
pending bytes are opened, promoted, deleted or recovered by the observer.

Use `ObserveSession`, which supplies the complete named bundle set and original
journal/current bytes to the strict joined matcher under the same mutex. The
opening must bind the exact checkpoint, not a coherent later suffix. All reads
are bounded/no-atime/read-only and bracketed by original-object/namespace checks.
Malformation, drift, read error or in-flight cancellation returns no partial kind
and retains review; restoration/new context cannot resume the lifetime.

This is an explicit fourth profile, not layout autodetection: legacy Open,
OpenBundle and OpenHistory retain their two-child census and refuse the new role.
Observe rejects this profile; ObserveSession rejects other profiles, without
poisoning a healthy lifetime. Close uses the actual retained roster, stops at
first uncertainty and never writes a closure, clears evidence or opens a writer.
An uncertain constructor result retains the same reviewed-handle/error contract.

Portable strict-journal/named-history bridge tests and pinned native vet/scoped
units/race3 pass. Native positive full lifecycles skip without unique mount IDs,
not positive lifecycle/race qualification. Close-only native controls additionally
cover all eight file/directory positions of a synthetic two-operation session
roster, with both pre-close and post-close/recycled-FD errors. That does not
qualify actual Open/Observe there, larger rosters, constructors or kernel EIO.

Actual standard ARM smoke repeats10 cases across API restart: closed/open/missing
journal, policy/history/session pending, restored file replacement, malformed
journal, restored session-directory bind mount and read error. Four actual locks,
copied/wrong-profile refusal, owned checkpoint, sticky review/zero reads for
pending, known-name disposal and FD balance are checked. Ordinary cases preserve
exact bytes and selected complete stat metadata including atime. Two exact new
receipts and every older assertion are mandatory at unchanged15s fixture/240s
guest/360s outer limits; no extra default lane or persistent Docker resource.

These observations use invented declarations in fresh tmpfs layouts, not actual
writer/reboot/power-loss evidence. No HTTP/product startup, existing-state writer
admission, trusted checkpoint provenance/succession, full product roles/consumers,
durable review/reconciliation, physical medium or release qualification follows.
Complete constructor/temporary-close/watch and larger-roster faults remain gates.

### Explicit multi-operation history profile

`OpenHistory(ctx, root, expectedInstallationID, exactCheckpoint)` fixes a third
experimental profile: `operations/<operation-ID>.json`, with at most16 records
and optional metadata-only `.history.pending`. Policy names are unchanged.
Basenames must contain a nonzero128-bit lowercase hexadecimal ID which matches
the strictly decoded intent. Unknown/mixed names refuse; no autodetection occurs.
Lexical enumeration is only deterministic IO order, not operation chronology.

The constructor validates and copies an independently trusted exact checkpoint;
it never derives one from these records. Caller mutation after construction
cannot change it. Its origin, provisioning and rollback resistance remain
external prerequisites. Before content reads, the complete metadata census
enforces the4MiB aggregate wire budget including checkpoint/current/records,
plus existing individual limits. Pending metadata suppresses all content reads.

The same retained directory locks, confined original files, unique mount
identities, watches and serialized before/after rechecks feed the private named
bundle/history matcher. Changed namespace/content or invalid name/content binding
latches review; restoring the source does not resume observations. Close uses
the captured variable-length file roster, stopping at the first uncertainty and
retaining unattempted references. The owned checkpoint is cleared only after
verified normal closure. This is not an existing-state writer or service lease.

The standard ARM fixture uses two successive nonempty three-protocol operations,
actual Store exclusion, checkpoint-copy independence, pending zero-read and
name/object/namespace refusal,16/17 record bounds and aggregate budget refusal.
Six file/directory close positions for that two-record profile each run controlled
pre-close and post-close errors with exact recycled-FD protection. These12 cases
do not qualify all possible larger rosters, constructor/watch-close faults,
kernel EIO, power loss or physical media. The constructor-only16-record case
tests the census limit, not validity of its synthetic record contents.
Two exact history-filesystem receipts across the original API restart are
mandatory alongside all existing smoke proofs; no additional CI guest is added.

### Shared retained lifetime

`Open(ctx, root, expectedInstallationID)` captures trusted in-process inputs;
neither HTTP nor an operation supplies role names, ownership, codec or backend.
Parents, provisioning, a suitable local filesystem and cooperating writers are
external prerequisites. The expected ID is an assertion, not provenance or
protection against cloned/restored state. The experimental layout is not an
approved product state bundle or complete future publication namespace.

Retain owned0700 root/policy/operations directories and their exclusive flocks
in that order. The **actual policy-directory flock** excludes the existing Store;
a root/sibling flock alone cannot do so. Require complete unique kernel mount
identity (`STATX_MNT_ID_UNIQUE`), no fallback to a recyclable ID or inode/device
equality. Open descendants with `openat2` no-symlink/no-magic-link/no-cross-mount
resolution. Independently recheck the original absolute root path against the
held root and unique mount; a path witness never replaces the original lock.
Trusted ancestors must remain stable; this is not an all-history namespace monitor.

Completely census the bounded fixed names. Retain original owned0600 single-link
regular current/record objects, with no-atime/nonblocking/read-only opens. Zero
and excessive present documents refuse; failed reads never become absent.
Use bounded read-at chunks and compare held/named identities before and after
the pure match. Retain directory AND file mutation watches: any event, loss or
overflow refuses further observations. Pending publication is metadata-only;
no bytes are read, promoted, deleted or adopted when it exists.

`Observe` serializes complete fresh reads, clears owned temporary byte buffers
best-effort, and returns only the existing redacted diagnosis. Every kind grants
**no action**, including matching local confirmation. Cancellation before admission
does not poison the lifetime; drift, in-flight cancellation/read uncertainty or
invalid content latches review. Errors contain only fixed classes and standard
`ctx.Err()`, never private cause text. Byte/chunk limits cannot interrupt a blocked
kernel filesystem call. Copies/zero handles refuse; formatting and generic JSON
do not transfer or disclose authority. Malicious in-process code/root is excluded.

`Close` serves no consumers. First uncertainty is terminal: preserve remaining
originals and metadata, never retry a raw descriptor. A failed close does not
prove that its kernel lock survived. Uncertain constructor cleanup may return
a nonnil reviewed handle **with an error** to preserve unattempted originals;
callers must not treat that as a successful open. No instance state is a durable
quarantine or proof of earlier fsync returns, browser receipt or first enrollment.

## Verification and remaining gates

The WSL kernel used for native checks lacks unique mount identity: it verifies
unsupported refusal, not the positive filesystem lifecycle. Positive unit cases
are explicitly skipped there, not counted as passed. Native Windows does not
execute this Linux-only package. Separate actual ARMv5 Linux6.18 QEMU fixtures
exercise all six diagnoses using a nonempty three-protocol policy, repeated
actual-Store exclusion and lock release, stable FD counts, four self-bind mount
substitutions, nine unsafe layouts, pending/write-close/cancel/read/watch faults,
private/copied handles,12 concurrent reads and controlled close uncertainty.
Injected faults are not physical EIO or kernel-close qualification.

The existing standard boot additionally checks all eleven retained file/directory
close positions (six legacy, five bundle), with both controlled pre-close failure
and successful real close followed by an invented failure: 22 cases per API
lifetime. The latter atomically allocates a duplicate at the released FD number,
never overwriting another owner. Repeated Close/Observe must perform no later
close, publish no diagnosis, retain remaining original references/metadata and
locks, and leave that replacement readable. Known fixture-only disposal restores
the FD baseline without retrying a completed close. Native tagged units/race
exercise Close over synthetic descriptors without claiming Open admission on WSL;
actual ARM cases use the real supported Open/OpenBundle constructors. Two exact
new receipts across API restart are required alongside every original proof.
Constructor faults, watch-close errors, kernel/media EIO and complete lifecycle
race/ownership/durability qualification remain separate. Product code is unchanged.

The standard guest requires two exact filesystem receipts across API restart;
host controls reject missing/one/duplicate/lookalike receipts. The observer is
read-only, but its QEMU fixture creates/disposes synthetic tmpfs files, takes
self-bind mounts and probes the actual Store only on those temporary files.
No new guest stage, persistent image/volume, HTTP route or NAS operation is added.

The explicit bundle profile additionally passes actual ARMv5 observations after
28 real SIGKILLs in the existing optional media guest. Original pre-loss references
bracket its fresh diagnostic lifetime; policy/root exclusions, exact metadata
including atime, repeated diagnoses, pending refusal and normal closure are
independently checked. Its standard ARM fixture checks all six kinds, zero reads
for either pending role, injected read/cancel faults, sticky restored drift and
profile refusal. These do not automatically transfer every legacy fault test to
the new profile, qualify physical media or establish uninterrupted writer locks.

A separate eight-case media test now verifies the same reader on a fixed32MiB
synthetic ext4 filesystem remounted read-only: six kinds plus both pending roles,
unchanged original bytes/statx/atime, actual policy/root exclusion and FD baseline.
This is not product boot admission, qualified physical placement or power loss.

Still required: complete constructor/read/close/watcher fault and race campaigns,
explicit atime/content/ownership/bounds qualification on supported media,
independent writer-process and namespace history tests, product namespace and
filesystem/provisioning decisions, one-attempt publication, reconciliation and
complete boot admission. See the [design](../policyevidence/COLLECTOR-DESIGN.md)
and [recovery requirements](../revisionstore/RECOVERY-DESIGN.md). This prototype
does not satisfy those later gates or make the firmware installable.
