<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Disposable one-operation protocol — experimental M1.3c

This package tests an actual **base/intent → policy → local receipt** sequence,
not a deployable state store. Its private writer is compiled only with `qemu &&
linux`. The only external entry point accepts invented policy data and creates
a new owned tmpfs directory; there is no existing-state/path opener, HTTP route,
service consumer, NAS operation or product installation path.

The portable codec is an internal experimental format, **not** an approved
product compatibility contract. Product bundle-versus-generation choice remains
open. Existing policy adapters and the read-only evidence collector are unchanged.

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
`intent.json`/`receipt.json`. That collector must continue rejecting this unknown
entry; it is not silently extended or used for writer admission. A future product
decision must reconcile these profiles explicitly, not infer compatibility.

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
durable-review recovery, retained read-only operation observation, authorized
reconciliation/retention, multi-operation epochs and HTTP delivery/status wiring.
An empty journal after a failed initial attempt is **not durable quarantine**.
There is deliberately no opener that could adopt/retry this existing state.
Tmpfs synchronization is not physical persistence or power-loss qualification;
root provisioning/EX4/NAND/ECC/recovery and full/hosted release gates remain open.

## Actual process-loss observations — M1.3c.4a

`process_loss_qemu_linux_test.go` adds seven real SIGKILL boundaries: before/after
intent, before/after policy, after readback and before/after receipt. Everything
new is in the Go **test binary**, not a product opener, subprocess API or CLI.
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
guest retains14 original ext4 SIGKILL/read-only/ENOSPC cases and adds these7 tmpfs
process losses in a second test binary, not a second boot. The45s Go allowance is
conservatively shared using remaining uptime seconds; hard60s guest/180s outer
and resource caps stay unchanged. Normal tmpfs/ext4 unmount,61 exact ordered
receipts and two Go PASS lines are mandatory. The closed original test selection
is checked against the verifier catalogue before compilation/boot: helper-only
SKIP or unregistered tests never become acceptable noise. Host parser controls
require2 valid and159 refused traces.

Actual ARMv5 passes this complete lane. Native WSL explicitly skips the positive
process-loss profile without unique mount IDs; final native gate/stream controls,
tagged vet and scoped package race3 pass, not positive writer/process-loss race.
Initial fixture double-close and stale broad helper selection failures are
retained as unqualified runs, not retrospectively green. Product code is unchanged.

Still missing: interruption **inside** every journal/policy/receipt write/sync/
close/rename, all constructor/close faults, persistent process/system restart,
qualified medium/power loss, a retained product observer, durable review and
authorized reconciliation. Same-kernel tmpfs SIGKILL is none of those guarantees.
