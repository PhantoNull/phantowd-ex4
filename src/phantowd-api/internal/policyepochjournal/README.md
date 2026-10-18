<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Policy-session declaration journal — experimental M1.2c.2

This internal Linux component records the private
[opening/closure declarations](../policyevidence/README.md#policy-session-declarations--experimental-m12c1-prerequisite).
It is **not** the complete product root Owner, a clean-shutdown detector,
recovery engine, whole-NAS provisioning or permission to start services.
No product entrypoint/HTTP endpoint uses it.

## Fixed role and original lifetime

`OpenFresh(ctx, originalParent, installation, sequence)` captures constructor
inputs and the fixed `policy-session` child of a borrowed original parent. The
child must already exist, be owned0700 and be **empty**. The adapter never creates
directories, initializes records, synchronizes, deletes or adopts existing state
while opening. Pending, unknown, malformed or existing records refuse and are
preserved. An empty child is not proof of a pristine NAS or a permitted retry.

The existing strict [anchored revision engine](../revisionstore/ANCHORED-STORE.md)
owns a new child descriptor and its actual exclusive directory flock. Descendant
access is fixed-name, no-follow/no-cross-mount/no-magic-link/no-atime, with private
0600 single-link regular records and bounded reads. The caller must retain the
original parent until verified child closure and provide trusted stable ancestors,
exclusive provisioning/cooperating writers and a suitable qualified local medium.

This defines a **separate experimental role**, not permission to add entries to
existing fixed policy/history censuses. No physical EX4 state path or frozen
product compatibility format is selected. The complete parent namespace and its
role-owner composition still require explicit qualification.

The private QEMU [history-writer session profile](../policytransaction/README.md#fresh-three-role-session-composition--m12c3)
now supplies one explicit fresh three-role parent, its actual root lock/unique
mount/path/watch guards and the existing policy/history locks. It records the
opening before edit admission and serializes an explicit closure declaration
with exact owned current/history checks. Old two-role profiles remain unchanged.
This is not product boot, existing-state admission or complete child ABA/watch
qualification; the remaining boundaries below still apply.

## Two declaration publications, one original writer

| Lifetime state | Allowed behavior | Not established |
| --- | --- | --- |
| Fresh role | Record one opening; observe supplied policy data | Pristine appliance, prior error absence or admission |
| Opening recorded | Record one closure; observe | Consumer drain, clean shutdown or historical sync outcome |
| Closure recorded | Observe, then release references | Recovery, service restart or another session |
| Review | Refuse observations and writes; explicit reference closure only | Permission to retry with another context or nonce |
| Verified closed | No authority; repeated Close is harmless | A closure declaration, evidence deletion or recovery |
| Uncertain Close | Terminal refusal; never retry the close callback | Continued kernel lock retention |

The instance serializes its methods. `RecordOpening` generates its own nonzero
epoch ID with one standard `crypto/rand` acquisition; callers cannot supply an
operation ID or backend. Installation and positive uint64 sequence are trusted
constructor data, not proven provenance, successor allocation or antirollback.
Entropy follows the pinned Go implementation and is not context-cancellable.
The public handle contains only an immutable pointer to private state; value and
pointer formatting/JSON stay private without copying mutable fields or a mutex.
Copied handles cannot observe, write or close the original lifetime.

`RecordClosure` validates a declaration against the retained exact opening and
the supplied coherent policy bytes. It does **not** stop consumers, close other
owners or certify their settlement. A future product coordinator must establish
those preconditions under the same qualified root authority before requesting it.
Policy input buffers must remain immutable until a method returns; no mutable
caller buffers are retained by the journal.
`Observe` rechecks this journal and compares only supplied policy DATA; it does
not establish the origin of a current policy read. All returned epoch kinds grant
no action, including `closure-matches-current`.

`ObserveHistory` additionally compares the same retained declaration file with
supplied exact checkpoint/current and complete operation DATA, under its original
journal mutex. The checkpoint must bind to the opening itself; a coherent later
suffix is inconsistent. An unconfirmed tail remains unresolved even with matching
closure data. No opening returns phase conflict; malformed supplied data returns
no partial diagnosis and does not rewrite records. Actual read/cancellation/drift
uncertainty still retains review, and restoration cannot revive the instance.
This method does not establish the caller data's origin or grant boot authority.
The private history writer supplies its actual retained census and exact current
under all original role locks; product startup/recovery remain unwired.

The pure `MatchObservedHistory` adapter also accepts a bounded existing journal
DATA slot and independently expected installation, checkpoint/current and decoded
history. It uses this same strict envelope/record/joined comparison, not another
format. Foreign identity cannot self-certify through the document's own field;
absent/unavailable journal remains incomplete and cannot hide malformed present
history. It performs no file access or authority transfer. The explicit
[read-only session/history collector](../policyevidencefs/README.md#explicit-sessionhistory-profile--m12c5)
supplies complete original-file reads under its own four directory locks. That
collector never upgrades this journal or adopts a writer; its separately acquired
observation locks are not uninterrupted writer authority or boot admission.

Each publication reuses the actual write/file-sync/close/rename/directory-sync
transaction once, then checks exact readback. Any admitted error, uncertain result
or late cancellation latches review, even if the complete record is visible.
Pre-effect invalid input/cancellation and repeated phases refuse without writes.
Restored entries or a new context cannot revive a reviewed instance.

`Close` releases references only: it never manufactures a closure declaration or
deletes evidence. A nonnil handle **with constructor error** is retained close
uncertainty, never usable admission; the caller must retain it and its parent.
No automatic disposal or recovery is provided.

## Encoding and bounds

The fixed files are `epoch.json` and `.epoch.pending`. The experimental schema1
envelope has exactly format, schema_version, revision, installation_id, opening
and closure. Transaction revision1 carries opening and explicit empty closure;
revision2 retains identical opening bytes plus closure. These two transaction
numbers are separate from the epoch sequence and policy revision.

Opening/closure use canonical standard base64 to preserve exact record bytes,
not JSON RawMessage normalization. Each decoded record retains its4096-byte
strict codec bound. The envelope is bounded to12KiB/depth2 with exact fields,
no duplicates/nulls/trailing or malformed Unicode, and zero/constant failures.
Policy bytes are validated/hashed, not copied into this journal. There are no
passwords, credential values or device paths in the role. Generic journal JSON
and formatting cannot disclose or transfer its lifetime.

## Qualification boundary and next work

Portable controls test exact opening preservation, strict envelope/record/phase
and canonical encoding with inclusive limits. Native Linux tests exercise actual
flock exclusion, one concurrent winner, no creation/adoption, preserved pending,
no-effect refusals, eight controlled before/after publication outcomes and two
controlled before/after Close failures. These injected errors are not kernel EIO.
An actual value-formatting identity disclosure was reproduced before switching
to the opaque handle. Copy privacy/invalid-lifetime checks and concurrent private
formatting during publications are now covered by native race tests and the guest.

The QEMU-only fixture runs on fresh owned tmpfs roots: normal publication, actual
opening commit followed by cancellation, and actual closure commit followed by
a reported error. It checks exact readback, reviewed no-retry, no declaration on
Close, refusal to adopt matching existing evidence, verified closure, known-name
nonrecursive disposal and FD balance. Original uncertain fixture references are
retained; no observer is promoted or old role modified. The same fixture can run
natively on tmpfs before ARM; ordinary non-tmpfs positive tests explicitly skip.

The anchored primitive has no complete absolute-parent/unique-mount witness or
original-current watch across calls. Byte-identical ABA between checks is not
qualified. Complete constructor/temporary-close/watch faults, parent lifetime,
durable review when no record survived, retained role/consumer/history ownership,
epoch succession/retention, writable restart and physical power-loss behavior are
still gates. Reopening even an empty role is never a way to erase known uncertainty.
Portable Windows units, pinned Linux Go1.26.8 vet/actual-I/O/fixture/race-count3
and the actual standard ARMv5 overlay pass this slice. The final guest requires
two exact journal receipts with `private_copies=true`, plus all prior checks;
the earlier pre-hardening I/O-only guest is not final-source qualification.
The first-release manual versus qualified automatic recovery decision remains
separate. No product bootstrap, activation, EX4/NAND or release follows here.
