<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Disposable operation protocols — experimental M1.3c

This package tests an actual **base/intent → policy → local receipt** sequence,
not a deployable state store. Its private writer is compiled only with `qemu &&
linux`. Its fixture writer entry accepts invented policy data and creates
a new owned tmpfs directory (or the sealed synthetic ext4 fixture below);
there is no existing-state writer opener, HTTP route,
service consumer, NAS operation or product installation path.

The portable codec is an internal experimental format, **not** an approved
product compatibility contract. The selected product direction is current policy
plus per-operation bundles, not immutable generations/manifest. This selects the
protocol family, not physical placement/provisioning or a frozen on-disk schema.
Existing policy adapters remain unchanged. A separate fixed-profile
read-only collector can inspect this experimental bundle; it cannot adopt it
into a writer or authorize recovery.

## Anchored multi-operation history prerequisite

`MatchBundleHistoryObservation` reuses the strict experimental bundle decoder
and `policyevidence.MatchHistory` to compare a complete supplied set with an
independently trusted exact policy checkpoint and the observed current policy.
Enumeration order is irrelevant. Duplicate operation IDs, forks, gaps, foreign
installation, altered exact bytes and unconfirmed interior operations refuse a
coherent-chain result. An uncertain tail retains its existing diagnostic kind;
matching local declarations never prove past sync return or browser delivery.

Validate every present record before diagnosis: missing evidence must not hide
malformed later input. Invalid inputs return no partial diagnosis; known
contradictions take precedence over missing evidence. Generic JSON and formatting
remain private. No caller buffers are mutated or retained in a returned result.

The complete inspection is bounded to16 operations and4MiB, including checkpoint,
current and supplied records. Both wire and decoded inputs are bounded. These
are memory/processing bounds, **not** a product retention policy: never drop
records, delete evidence or replace the checkpoint to fit them. Completeness,
checkpoint origin, pending-file exclusion, protected filesystem enumeration,
rollback resistance and retention/reconciliation remain trusted-owner work.

The explicit Linux `policyevidencefs.OpenHistory` prerequisite now supplies a
bounded complete protected census under the original locks and an owned caller
checkpoint. `MatchNamedBundleHistoryObservation` additionally binds each fixed
experimental basename to its decoded operation ID without disclosing the tuple.
This does not establish checkpoint origin, historical completeness, rollback
resistance, writer admission or a product-compatible on-disk namespace.

Host/race controls cover these boundaries and byte mutations. The existing
standard ARM smoke requires two exact synthetic history receipts across its
original intentional API restart; no extra guest or persistent write is added.
This does not turn the one-operation disposable writer into a product store.

## Bounded successive-operation prototype

A separate private QEMU/Linux mode creates fresh tmpfs state with the same
original root/policy locks and a retained history-directory lock. It never opens
existing state or upgrades a read-only Observer. The old one-operation mode and
its crash profiles keep their original contracts; `execute` refuses this new mode.

Each operation has its own canonical operation-ID JSON file. Publication uses
one fixed exclusive pending name, full write/file sync/close, confined rename and
directory sync, followed by exact readback of the original published inode.
Initial publication is no-replace; only that operation's intent may become its
matching local confirmation. Confirmed files retain original read-only/no-atime
descriptors, metadata and individual watches for the entire writer lifetime.
They are never overwritten by the next operation. Fresh history observations
read those actual retained files, check exact bytes and the anchored chain.
Captured identity/mode/owner/link/size/mtime/ctime are rechecked; this is not
a complete xattr/ACL/atime witness or a physical-media guarantee.

The child directory's watcher is not reset or drained indiscriminately around
owned writes. Each publication requires the exact five directory events for
pending create/modify/write-close and a cookie-paired pending-to-record move.
Extra, missing, reordered, foreign-name or immutable-file events require review.
Unsupported/coalescing behavior outside this experimental kernel/filesystem
profile fails closed. This does not identify event authors or exclude malicious
root/noncooperating same-UID writers; exclusive provisioning/cooperation remain
prerequisites. The journal borrows its parent's lifetime; unique root mount/path
and root watch authority are supplied by the enclosing constructor, not the
standalone child primitive tested natively.

A successful local operation advances the owned exact base and permits a distinct
next revision. A stale concurrent proposal fails before effects. Any admitted
error/cancellation fences the **whole** root lifetime, including when confirmed
bytes survived. Another context, operation ID or restored source never bypasses
review. Count16 and the4MiB aggregate checkpoint/current/encoded-record budget
are checked before effects; reaching capacity does not prune or rebase history.
No history retention/recovery policy is implied by these prototype bounds.

The current fixture checks two operations, original Store-lock exclusion, one
concurrent winner, unchanged original first record, cancellation after intent/
policy/receipt, a real policy commit followed by an injected error, immutable
write-open detection, repeated no-effect refusal and FD-balanced verified
closure/disposal. Native real-file primitive controls include16/17 records and
watch-enrollment failure. The latter reproduced a closed-original roster retry;
enrolling the new pin before retiring the old one fixes that path. Controlled
errors are not kernel EIO, complete close-fault coverage or power loss.

This prototype is **not covered automatically** by the older one-operation
SIGKILL/syscall/ext4 campaigns below. Its separate process-loss qualification is
described next. Still required: interruption/restart on supported media, constructor/
temporary-close/watcher races, worst-case memory/time bounds, independent product
checkpoint provenance, durable review and authorized reconciliation. There is no
product constructor, consumer lease, HTTP save or persistent EX4 placement.

### History process-loss qualification — M1.3c.2d

A constructor-bound, copied closed profile can stop only the **second** operation
at seven actual success boundaries for intent/policy/confirmation: an actual
eight-byte write, complete write, file sync, file close, before/after rename and
directory sync. No operation/HTTP selector exists. A returning gate poisons the
affected lifetime, never successful publication. The policy profile is separately
sealed to revision3; the older factory still accepts only revisions1/2.

Native actual-file controls cover14 returning journal gates and seven third-policy
gates, first-operation preservation, copied profiles and no retry. The actual ARM
media lane additionally executes21 real SIGKILL cases through the runtime history
reader, not a simulated error or a clean process return. A first bounded gate
follows locally successful operation1; the parent captures original directories
and the confirmed first record before acknowledging any second effect. A second
gate binds the same root/PID/challenge and selected syscall boundary. One bounded
buffered reader preserves both frames and any prefetched duplicate/trailing bytes.

Parent independently verifies actual child flocks, planned SIGKILL/reaping and
unchanged first-record original bytes plus full captured statx including atime.
Original references bracket the actual read-only history reader after death.
Pending yields review without a kind; published intent/base, unconfirmed policy
and matching confirmation retain their diagnostic kinds. A test-only loss context
still requires review in **every** case, including matching receipt. Observation
locks acquired after death are not uninterrupted writer locks or retry authority.
Known-name cleanup follows verified death/reader closure and restores FD baseline;
unknown or incomplete captures never authorize unlinking.

The existing optional guest now requires148 ordered receipts:53 original store/
bootstrap/media and95 operation/reader receipts. It preserves all56 old tmpfs
SIGKILLs plus21 history SIGKILLs, the14 original ext4 losses and read-only/full
ext4 controls. Two Go PASS rows, closed selectors, normal unmounts and unchanged
base remain mandatory. Parser controls require2 valid/341 refused traces. The
isolated complete run fits unchanged shared Go45s/guest60s/outer180s limits;
the timing qualification below is deliberately narrower than a reliability fix.
No extra default CI stage, timeout increase or dropped old proof is introduced.

These history SIGKILLs still create tmpfs state only. They are syscall-success-boundary
process losses with the kernel alive, **not** in-flight kernel-I/O interruption,
power loss, persistent restart, physical-media durability or complete EIO/close/
watcher/constructor faults. The separate synthetic ext4 evidence below does not
qualify physical storage, writable restart, worst-case resources or product recovery.

## Sealed synthetic ext4 history writer prerequisite

A closed internal medium enum admits only the ordinary `/tmp` tmpfs profile or
the literal `/run/phantowd-revisionstore-media` fixture. The ext4 constructor
requires the marked root ARM VersatilePB guest, restricted mount flags, bounded
8–32MiB ext4 and the fixed `/dev/sdb` device identity before namespace creation.
It creates fresh generated state only. The old one-operation constructor remains
tmpfs-only; unknown profiles and ordinary native hosts refuse without effects.
This is not a product medium selector or an existing-state writer opener.

`TestRuntimeHistoryWriterOnExt4` enrolls four ordered cases: `normal`, `readonly`,
`full`, `process-boundary`. Two successive publications preserve the original
first record, original locks and exact policy/record evidence. Read-only testing
observes a real exclusive-create EROFS while retained guards still admit the
lifetime. Bounded sibling fillers establish actual ENOSPC and zero available
blocks. Failed publication retains the last confirmed policy and fences the
original writer; restoring space or write access never permits a retry/new ID.
Actual runtime history observation after verified close remains diagnosis only,
even when it finds a matching old local confirmation. Known-name disposal and
descriptor baseline checks remain mandatory.

The process-boundary case requires a separate producer's verified clean exit
after two publications, then a fresh reader subprocess on a read-only remount.
Bounded proofs bind the original PID, random challenge and generated root; parent
observations bracket the actual history reader and preserve exact bytes/full
captured statx including atime. This is **clean process-boundary observation**,
not an OS reboot, interrupted I/O, power cut, replay or writable Owner recovery.

The first extended run passed all four new cases in3.69s, but the complete lane
failed its conservatively remaining39s Go deadline during an older history-loss
case. A controlled same-source run without competing native/race work passed
all148 receipts; the new ext4 group took4.02s and the21-loss group15.10s. Limits
and mandatory proofs were unchanged. This supports load/budget sensitivity, not
a proven universal cause or repaired hosted CI. Run CPU-heavy native validators
before timed guests; worst-case timing margin remains an open engineering gate.
Native tagged units/vet/race3 and Windows checks pass their separate scopes;
ordinary native positive ext4/root admission is explicitly skipped or refused.
The standard ARM smoke also passes with its original two writer receipts.

## One-operation namespace and ownership

```text
/tmp/phantowd-transaction-<generated>/
  policy/
    nas-services.json
    .nas-services.pending
  operations/
    operation.json
    .operation.pending
```

Retain the original owned0700 root, its actual flock, unique kernel mount ID,
absolute-path witness and structural mutation watch. Retain the actual strict
Store child flocks in root → policy → operations order, without closing an
observer and reopening a writer. Descendants use no-symlink/no-magic-link/
no-cross-mount resolution. Missing tmpfs/unique-ID/proc support refuses; no weak
fallback. The fixture itself initializes revision1 and observes successful Store
commit/readback under those same locks. It never adopts an existing base.

The pointer lifetime serializes operations, refuses copies/zero handles and
keeps fixed Store methods, not caller-selected per-operation backends. Formatting
and generic JSON for writer copies/outcomes disclose no authority or identifiers.
Successful **and** uncertain operations both prevent a second logical attempt.
There are no external consumers of these freshly generated fixture directories;
this is not production/global-use exclusion.

## Private bundle codec

One flat schema1 document, maximum896KiB/depth2, contains format, schema_version,
revision, phase, installation_id, base, intent and receipt. Its format is
`phantowd-policy-operation-bundle-experimental`. Journal revision1/phase `intent`
has an explicitly empty receipt string; revision2/phase `local-confirmed` has a
matching receipt. Journal revisions are separate from policy revisions.

Base/intent/receipt are canonical standard base64 strings, not RawMessage: the
**exact historical base bytes**, including whitespace, survive JSON marshaling.
Decoded base is bounded by the whole-policy656128-byte ceiling; each existing
schema1 record is bounded to4096bytes. Reject unknown/duplicate/non-exact/null/
trailing/deep/oversized envelopes, noncanonical base64, invalid coherent policy,
foreign installation/bindings and mismatched phase/revision/receipt tuples.
Decoding failure returns no partial bundle. The base binding is validated;
candidate content is represented by its declared digest until actual readback.

This profile uses `operation.json`, NOT the older collector's separate
`intent.json`/`receipt.json`. Its `Open` entry still rejects the bundle profile;
the explicit `OpenBundle` entry rejects legacy/mixed roles. Neither autodetects,
migrates or supplies writer admission. A future product decision must reconcile
these profiles explicitly, not infer compatibility.

`MatchBundleObservation` is a portable bounded comparison over caller-owned
current/bundle slots. It validates present documents and expected installation,
decodes private owned bundle bytes, clears temporary buffers and returns only
the existing six redacted kinds. Invalid input returns a zero diagnosis and a
fixed error; absent/unavailable evidence is explicit, never inferred from IO.
Exact bytes matter. Foreign installation or mismatched content is inconsistent,
not usable confirmation. There is no IO, replay, write, provenance guarantee,
anti-rollback proof or assertion that a browser received a reply.

## Ordered attempt and uncertainty

1. Recheck root identity/watch/census, exact known base and absent operation.
   Prepare an owned candidate and internally generated operation ID. Invalid
   input or cancellation before admission performs no journal effect.
2. Fence the logical lifetime before its first mutation attempt. Commit journal
   revision1, preserving exact base and bound intent. Require successful Store
   file/directory synchronization and exact journal readback **before** policy.
3. Commit policy once, then reobserve exact prepared bytes. Only then construct
   the matching local receipt and commit journal revision2. Recheck policy,
   journal, root and context before returning a private locally verified outcome.

Every admitted error/cancellation preserves review, including errors returned
before/after an underlying successful commit. No retry, new-ID bypass, pending
deletion, rollback, service start or automatic reconciliation follows. Replacing
the context or restoring a faulted fixture namespace cannot revive the lifetime.
Receipt construction is a private data declaration, never a success capability.
Matching records can coexist with review: presence does not prove that the last
directory sync returned or that an HTTP response reached a browser.

Close does not delete evidence. Original Store/root closure stops on its first
uncertain return without raw-descriptor retry. A separate explicit fixture
disposal, after verified Close, removes only known files/empty directories in
the generated namespace; no recursive deletion or caller-selected root. This is
test cleanup, not product retention/reconciliation. Complete constructor,
temporary-cursor/witness, close and disposal fault coverage remains open.

## Verified scope and remaining product work

Portable tests cover exact-base roundtrip, tuple/privacy/zero/refusal controls,
full inclusive base/bundle bounds, canonical base64 and bounded fuzz. An initial
nil-versus-empty receipt roundtrip failure was fixed by normalizing explicit
absence, not weakening presence/binding checks.

The existing standard ARMv5 guest exercises18 scenarios twice, under the original
15s filesystem-fixture budget; no new stage, image or volume. Tests independently
check actual file phases, unchanged exact base, all three actual flock exclusions,
single concurrent winner, copied-handle refusal, no retry/effect after review,
normal closure/disposal and stable descriptor counts.

| Cases | Current policy | Journal | Owner outcome |
| --- | --- | --- | --- |
| Normal concurrent requests | Exact next | Confirmed | One local success, second refused |
| Root drift / cancellation before intent / intent-before error | Base | Absent | Review; never retry |
| Intent-after, policy-before, cancellation/root restoration after intent | Base | Intent | Review |
| Policy-after, readback mismatch/error, cancellation after policy/readback, receipt-before | Next | Intent | Review |
| Receipt-after / cancellation after receipt | Exact next | Matching confirmation | **Still review**, not inferred success |
| Policy byte drift before/after receipt | Changed next bytes | Intent/confirmation | Inconsistent evidence and review |

Commit failures are injected at captured whole-method boundaries. They are not
integrated real EIO/ENOSPC/close errors or SIGKILL/power-cut tests at every syscall.
The separate anchored Store has narrower syscall-fault tests; those do not
automatically qualify this whole protocol. WSL without unique mount IDs skips
positive writer/race cases explicitly; ARM concurrency is not race instrumentation.

Still required: product namespace/medium/provisioning decisions, trusted complete
boot state and consumer ownership, original-current/history fault coverage,
every interrupted journal/policy/receipt boundary on qualified filesystems,
durable-review recovery, qualified product observation, authorized
reconciliation/retention, multi-operation epochs and HTTP delivery/status wiring.
An empty journal after a failed initial attempt is **not durable quarantine**.
There is deliberately no opener that could adopt/retry this existing state.
Tmpfs synchronization is not physical persistence or power-loss qualification;
root provisioning/EX4/NAND/ECC/recovery and full/hosted release gates remain open.

## Actual process-loss observations — M1.3c.4a

`process_loss_qemu_linux_test.go` adds seven real SIGKILL boundaries: before/after
intent, before/after policy, after readback and before/after receipt. Everything
in that child/observer profile is in the Go **test binary**, not a product opener,
subprocess API or CLI. The separate syscall fixture below adds constructor-bound
QEMU hooks; it does not expose a product control.
Each child creates its own fresh tmpfs namespace. Its selected stage, original
PID and random challenge bind one bounded private gate; duplicate/prefetched
trailing proof is rejected. The parent verifies an actual SIGKILL exit, not
context expiry, a clean return or an injected error.

Before loss, retain separate original root/role/file references while the child
is frozen and independently verify all three locks are Busy. After verified
death acquire observation locks on those same directory references; compare
unique mount/path/named/held identities, complete census, exact policy/base/
records and captured statx metadata including atime across repeated no-atime
reads. SMB/NFS paths/permissions and desired iSCSI state change, not just counters.

The post-loss observer is also test-only. Every diagnosis requires review,
including empty journal and matching local-confirmation records. It refuses
before verified death/lock acquisition and never opens an Owner/Store, syncs,
promotes, replays or grants activation. These are **reacquired observation locks**,
not uninterrupted writer authority. Explicit fixed-name test teardown follows
observation and child reaping; it is not product retention or recovery.

Run `support/test-revisionstore-media.ps1`. Its existing snapshot-only, NIC-less
guest retains14 original ext4 SIGKILL/read-only/ENOSPC cases and adds28 tmpfs
process losses plus28 runtime-reader loss cases in a second test binary, now also
the21 history-reader losses described above, not a second boot. The45s Go allowance is
conservatively shared using remaining uptime seconds; hard60s guest/180s outer
and resource caps stay unchanged. Normal tmpfs/ext4 unmount,148 exact ordered
receipts and two Go PASS lines are mandatory. The closed original test selection
is checked against the verifier catalogue before compilation/boot: helper-only
SKIP or unregistered tests never become acceptable noise. Host parser controls
require2 valid and341 refused traces. Both binary selectors are closed and
checked against the mandatory verifier catalogue before boot.

An isolated actual ARMv5 run passes this complete lane, with the timing limitation
documented above. Native WSL explicitly skips the positive
process-loss profile without unique mount IDs; final native gate/stream controls,
tagged vet and scoped package race3 pass, not positive writer/process-loss race.
Initial fixture double-close and stale broad helper selection failures are
retained as unqualified runs, not retrospectively green. Non-QEMU builds and
ordinary Store constructors keep their semantics.

Still missing: arbitrary in-flight kernel-I/O interruption, real media errors,
all constructor/close faults, persistent process/system restart,
qualified medium/power loss, product observation wiring, durable review and
authorized reconciliation. Same-kernel tmpfs SIGKILL is none of those guarantees.

### Syscall boundaries — M1.3c.4b

An additional21 real SIGKILL cases cover intent, policy and receipt at seven
declared points: partial eight-byte write, full write, file sync, file close,
before rename, after rename and directory sync. These stop **at syscall success
boundaries inside Commit**, not while a kernel syscall is blocked. Partial write
is a deliberately short real write, not a claim to spontaneous device failure.

`revisionstore.NewQEMUCommitCrash` seals one point/revision/gate profile at strict
Store construction. The QEMU-only opener retains the same actual flock, codec
and real syscalls; it never adopts caller descriptors or chooses per-operation
backends. Only target revisions1/2 and the seven points are valid. A returning
gate reports failure and poisons the strict Store, never successful publication.
Native controls execute all seven boundaries, prove base revision1 is untouched
by a revision2 profile, exact current/pending bytes and refusal of every retry.

The private disposable-writer constructor admits a validated role/point plan
before creating a namespace; its ordinary entry always passes nil. There is no
new HTTP/CLI, product state opener or caller-controlled operation profile.
The standard ARM smoke repeats the original18 scenarios and all earlier checks
using that unchanged normal path. Positive whole-writer/crash race tests still
skip on unsupported WSL kernels; native Store-hook tests actually execute.

The test-only post-loss observer retains pending metadata without opening its
contents. Every pre-rename pending case yields review with **no matched kind**;
neither valid nor malformed staged bytes are promoted or used to manufacture
confirmation. A separate, explicitly labelled test oracle opens synthetic staged
files read-only/no-atime to check exact prefixes, coherent next policy and full
base/intent/receipt bindings. It is not part of the observer or a recovery path.
Original-reference/lock, bytes/statx, challenge/gate and normal FD disposal checks
remain mandatory for all28 cases. No new guest/image/volume, timeout relaxation,
physical storage, product recovery or full/hosted qualification follows.

### Runtime bundle reader after process loss — M1.3c.4c

The external Go test package repeats all28 declared gates with actual SIGKILL,
then opens the real `policyevidencefs.OpenBundle`, not the test-only oracle.
Original pre-loss references and metadata bracket its lifetime; its independently
acquired observation locks exclude both a second reader and the actual policy
Store. Observe twice must match the expected redacted kind, or return review
with no kind for all15 pending cases. Normal Close and unchanged bytes/statx/FD
counts are mandatory before the original independent oracle resumes. Fresh
observation locks are not uninterrupted writer authority or permission to retry.
Every kind still grants no action, including empty operation and matching receipt.

The separate standard ARM fixture also tests all six bundle kinds, both pending
roles with zero data-read calls, read failure, cancellation, restored drift and
mixed/legacy-profile refusal. It preserves the existing legacy collector and
18 normal writer scenarios within the unchanged fixture budget. Native positive
filesystem/crash cases skip explicitly on kernels lacking unique mount IDs;
portable comparison/fuzz and shared-engine checks are distinct evidence.

This is same-kernel process-loss diagnosis on synthetic tmpfs, not persistent
restart, power loss, complete fault coverage, recovery or product boot admission.

### Read-only ext4 diagnosis — M1.4c

`TestRuntimeBundleObserverOnReadOnlyExt4` additionally tests the actual runtime
reader with all six kinds and both pending roles after a verified read-only
remount. It prepares invented evidence first, retains independent original
references, and checks unchanged exact bytes/statx (including atime), root/policy
exclusion, normal closure and FD baseline. The fixture accepts only its fixed
bounded32MiB ext4 device in the marked ARM VersatilePB guest. Restoration to RW
precedes temporary-file cleanup; neither action is a product recovery operation.
Eight subcases and their parent receipt are mandatory in the existing media lane,
with unchanged time/resource bounds and no extra boot/image/volume.

This changes tests only. It establishes read-only diagnosis on synthetic ext4,
not media-error recovery, system restart, power-loss durability, physical EX4
placement, product format selection or permission to adopt a writer.
