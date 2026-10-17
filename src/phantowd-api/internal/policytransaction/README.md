<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Disposable one-operation protocol — experimental M1.3c

This package tests an actual **base/intent → policy → local receipt** sequence,
not a deployable state store. Its private writer is compiled only with `qemu &&
linux`. Its fixture writer entry accepts invented policy data and creates
a new owned tmpfs directory; there is no existing-state writer opener, HTTP route,
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

## Namespace and ownership

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
process losses plus28 runtime-reader loss cases in a second test binary, not a
second boot. The45s Go allowance is
conservatively shared using remaining uptime seconds; hard60s guest/180s outer
and resource caps stay unchanged. Normal tmpfs/ext4 unmount,121 exact ordered
receipts and two Go PASS lines are mandatory. The closed original test selection
is checked against the verifier catalogue before compilation/boot: helper-only
SKIP or unregistered tests never become acceptable noise. Host parser controls
require2 valid and283 refused traces. Both binary selectors are closed and
checked against the mandatory verifier catalogue before boot.

Actual ARMv5 passes this complete lane. Native WSL explicitly skips the positive
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
