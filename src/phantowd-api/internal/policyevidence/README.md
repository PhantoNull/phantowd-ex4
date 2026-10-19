<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors -->

# Private policy operation evidence — M1.3b.1/b.2

Strict in-memory codecs and a read-only diagnostic matcher for coherent desired
SMB/NFS/iSCSI policy. This is **not** a journal writer, retained filesystem
collector, recovery engine, boot permission or HTTP API. Existing Store/Owner/
BootstrapAuthority behavior is unchanged. The approved first slice implements
the [operation-evidence design](../revisionstore/RECOVERY-DESIGN.md); later writer,
publication, retention, reconciliation and provisioning work remains. The chosen
product protocol family is current policy plus per-operation bundles; that does
not freeze the experimental bytes or choose a physical state medium.

## Policy session declarations — experimental M1.2c.1 prerequisite

The strict `EpochOpening` / `EpochClosure` codecs describe one proposed policy
session; they do not create files or a boot lifecycle. Both carry installation
and epoch IDs, an exact positive uint64 sequence and a policy revision/SHA-256.
Closure additionally binds the **exact opening record bytes**. At the same policy
revision, differing bytes cannot be declared as closure; later revisions require
separate complete operation-history verification. Reformatting opening/current
JSON changes its binding even when decoded values are equal.

Each experimental schema1 record is bounded to4096 bytes/depth2, with exact keys,
no duplicate/null/trailing/invalid-Unicode data and constant zero-on-error results.
Explicit private encoders/decoders are separate from refused generic JSON and
redacted formatting. Inputs must remain immutable during calls; results retain
no mutable input buffers. Sequence and IDs are declaration data, not allocated
authority: a future trusted Owner must generate its own epoch, enforce successor/
overflow/reuse rules and retain its origin, never accept them from an HTTP caller.

`MatchEpoch` validates all present records/current policy before missing-input
diagnoses. It distinguishes no recorded epoch, observed opening, matching closure
declarations, incomplete and inconsistent evidence. Orphan/foreign/mismatched
epochs, revision rollback and changed exact bytes cannot become a matching pair.
**Every result still permits no action.** In particular, `closure-matches-current`
is not proof of actual consumer drain, Close/fsync returns, clean shutdown,
history completeness, whole-NAS state, qualified persistence or rollback resistance.
Record absence never proves pristine or permits enrollment.

No runtime collector, writer, durable review marker, state namespace/file role,
new HTTP route, recovery, boot admission or service restart is added. Do not insert
these records into existing fixed-census policy/history directories. The selected
first-release requirement is automatic recovery/restart after ordinary unclean
shutdown, not routine manual confirmation; see the
[boot recovery contract](../../../../STATE-OWNERSHIP.md#first-release-automatic-recovery-requirement).
That requirement does not make these diagnostic results admission authority or
change the need for qualified retained state, explicit recovery and medium behavior.
The existing standard ARM self-test exercises eight synthetic comparisons plus
malformed/private controls, before/after its API restart; no extra boot or I/O.
A separate [fresh-role journal component](../policyepochjournal/README.md) now
records those declarations through the existing anchored transaction engine.
It does not change these pure comparisons into boot/recovery authority or add
a role to existing policy/history namespaces. Product root/consumer composition,
medium qualification and recovery remain separate gates.

## Checkpoint-anchored operation history

### Unified session/history diagnosis — M1.2c.4

`MatchSessionHistory` joins the strict opening/closure comparison and the complete
operation history. The checkpoint must have the **same revision and exact-byte
hash as the opening**, not merely be a valid later revision. A coherent suffix
history and independently matching closure cannot silently rebase that checkpoint.
All present records/policies are validated before a diagnosis; known mismatches
take precedence over missing evidence. Inputs remain caller-owned and immutable.

Five private redacted kinds distinguish an open coherent history, a matching
closure with coherent history, an unresolved operation, incomplete evidence and
inconsistency. A matching closure with an unconfirmed tail remains unresolved.
Missing opening is incomplete, never pristine; every result grants **no action**.
Generic JSON refuses and formatting exposes only the fixed redacted kind.

The aggregate4MiB limit includes both declarations, checkpoint/current and all
operation fields, with the existing16-operation/4096-record/656128-policy bounds.
Limits do not authorize dropping records or changing the checkpoint. This is a
pure comparison, not a filesystem census, original-generation witness, successor
allocator, historical syscall-return proof, verified Close/consumer settlement,
clean shutdown, boot classification, recovery or service admission.

Portable/native controls cover all five diagnoses, coherent-suffix counterexample,
known mismatch with missing evidence, malformed present roles, immutable concurrent
inputs, inclusive4MiB/4096-byte/16-operation limits and zero/private results.
An opening-input fuzz campaign is bounded2,000 executions, not a full-history fuzz
claim. The private writer's actual ARM fixture checks original-file/census joining,
suffix refusal and unresolved publication with two strengthened receipts.

The fixed200-iteration Go1.26.8 Linux-native two-operation DATA microbenchmark
compares redundant independent+joined validation with joined-only validation:
42,718 versus22,445 allocations/op and1,532,518 versus805,080 bytes/op. Both branches
perform the same strict epoch/history checks. These are synthetic cumulative
allocations, not peak RSS, retained-file I/O, ARM timing or product throughput.

`MatchHistory` compares a complete supplied history with a trusted exact policy
checkpoint and current bytes. It orders validated operations by base revision,
rejects repeated operation IDs and requires contiguous exact revision/hash links
with local declarations for all interior records. The final operation retains
the original six no-action diagnoses, including unconfirmed publication and
incomplete evidence. All present records are validated before diagnosis, even
when another record is unavailable; invalid data yields no partial result.

The16-operation/4MiB bounds are inclusive inspection limits, not filesystem
quotas or permission to prune/rebase a history. Completeness, checkpoint origin,
pending-file exclusion, durable confirmation and rollback/cloned-state protection
are not established by this pure function. It opens nothing and performs no
write/replay/recovery, HTTP or service action. Input buffers must remain immutable
during the call; private results retain no references to them.

## Private operation preparation — M1.3c.1

`Prepare(installationID, exactBaseBytes, nextConfig)` is namespace-independent
operation data, **not** a writer, confirmation, single-use token or retained
authority. It strictly validates both whole coherent policies, all revisions
and byte bounds before generating one nonzero128-bit operation ID internally
with `crypto/rand.Read`. Positive base revision and exactly base+1 are required;
initial enrollment and overflow refuse. No request chooses an operation ID,
digest or entropy provider. The trusted future Owner supplies its captured
installation ID and actual base; this function cannot prove their provenance.

Preparation also refuses retained NFS IDs whose logical volume/filesystem/root
changes, before entropy acquisition or any admitted intent. This prevents the
experimental writers from turning a known-invalid transition into uncertain
operation evidence. It is an adjacent-document check, not lifetime ID reservation;
see the [complete scope](../../nfsconfig/README.md#export-identity-continuity).

Keep an owned copy of **exact** base bytes, including whitespace, not merely a
digest. Encode the candidate with the same `encoding/json` contract used by the
current transaction engine, independently decode it, and bind both hashes and
revisions in the existing private intent schema. Immutable Prepared values share
private storage safely; byte accessors return defensive copies and Intent remains
private data. Zero values refuse; generic JSON and ordinary formatting disclose
neither policies nor identifiers. Inputs must remain stable during preparation;
this is not protection against malicious in-process code or memory inspection.

No receipt, file, sync, publication, transaction retry or service action is made.
Generating a fresh ID cannot clear an unresolved prior operation. The future
coordinator still must retain authority, exclude consumers/unresolved work and
durably preserve base/intent **before** attempting the policy write. Bare current
Store.Commit may remove a valid old pending file on a later call: never use that
behavior as recovery or retry in the new protocol. Successful candidate
publication with no receipt remains `publication-unconfirmed`, not success.

Retained data is bounded by two whole-policy documents plus the intent tuple;
validation and defensive accessors allocate additional bounded temporaries.
No concurrency admission, retention budget or memory-zeroization guarantee is
implemented here. System entropy is not a context-cancellable read. The pinned
Go SDK's `crypto/rand.Read` terminates the process on an irrecoverable source
failure; this occurs before any journal effect in this preparation layer.
Private short/error/zero-output test seams check fixed refusals/no application
retry, not recovery from the production RNG's fatal path. Random IDs alone prove
neither installation provenance, uniqueness history nor rollback resistance.

Host controls cover exact/base-versus-candidate encoding, defensive ownership,
zero/privacy, invalid-before-entropy, short/error/zero-ID refusal, full656128-byte
base bound and maximum uint64 transition. A separate Linux temporary-Store test
and existing ARM fixture verify actual persisted bytes and unconfirmed outcome;
these are codec-parity probes, not durable journal transactions. Bounded fuzz
mutates base inputs up to4096bytes; explicit units cover the full policy bound.
No new image stage or additional default fuzz campaign is added.

## Private record schema

Both flat schema1 records have `format`, `schema_version`, `installation_id`,
`operation_id`, `base_revision`, `next_revision`, `base_sha256`, `next_sha256`.
Format is `phantowd-nas-policy-intent` or `phantowd-nas-policy-receipt`; the
receipt additionally requires exactly `phase: "local-confirmed"`.

IDs are nonzero32-character lowercase hexadecimal values, separately supplied
by a future trusted coordinator, not derived from a bay/path/device identifier.
Positive uint64 base/next revisions are consecutive without overflow. Digests
are64-character lowercase SHA-256 strings binding **exact policy bytes**, not a
JSON re-encoding or semantic equivalence. A record asserts these bindings; it
does not itself prove the reads, identifier provenance or synchronization.

Decoders accept bounded readers (at most4096bytes per record, depth2), reusing
the existing envelope's exact-key/duplicate/null/Unicode/trailing checks. Fields
cannot contain secrets, arbitrary paths, timestamps or response acknowledgements.
Unknown phases/versions, malformed values, read failures and oversized inputs
return zero values and a fixed error. Byte bounds are not an I/O deadline on a
caller-supplied reader. Explicit Encode/Decode functions handle private records;
normal JSON serialization/deserialization is refused and normal `fmt` output
is redacted for records, evidence slots, input and diagnosis. This is not a
defence against reflection, malicious in-process code or root.

## Matcher contract

The trusted caller supplies the expected installation ID and three explicit
slots: intent, receipt and current policy. Each is Present, Absent or Unavailable
(the zero state). Absent/Unavailable cannot carry bytes; Present requires bytes.
Failed reads must never become Absent. Missing/unavailable roles yield incomplete
evidence without parsing partial contents. Unknown state values and present
empty slots fail; malformed contents fail when all roles are known. Callers
retain their slices and must not mutate them
concurrently; no references to them are retained after the call.

When complete, Match decodes both records and validates the current **whole
coherent NAS policy**, all component schemas/revisions and its existing656128-
byte ceiling. It compares the tuple and the current revision plus exact SHA-256.
Only the observed current policy is validated: a non-current digest remains a
record assertion, not proof of valid historical base/candidate bytes.

| Complete observations | Redacted kind |
| --- | --- |
| Valid policy, both records absent | `no-recorded-operation` — not pristine or boot-authorized |
| Intent only, exact base current | `intent-base-observed` — no replay permission |
| Intent only, exact next current | `publication-unconfirmed` |
| Matching intent/receipt, exact next current | `local-confirmation-observed` — matching records, not proof of historical syscall returns or browser receipt |
| Orphan/mismatched/foreign records, unrelated policy, receipt with base current | `inconsistent-evidence` |
| Any unavailable role or missing current policy | `incomplete-evidence` |

**Every result authorizes no action.** Hashes are not authentication; caller
assertions are not retained-origin evidence. Restoring an old complete bundle
or cloning installation IDs is not detected by this slice. It opens/syncs/
writes/renames/deletes nothing, generates no IDs or receipt, issues no lease,
and never initializes, recovers, retries or activates anything.

## Verification and next step

Unit controls use a nonempty three-protocol before/after pair, all kinds and
tuple bindings, malformed records/policies, orphan/foreign/incomplete evidence,
exact-byte versus semantic changes, maximum uint64 revisions, inclusive byte
limits, privacy and zero-on-error. Two bounded fuzz targets exercise codecs and
matching; the matching campaign caps current-policy mutation input at8192bytes,
while explicit units cover the full656128-byte bound. Local execution evidence
is recorded in [implementation status](../../../../IMPLEMENTATION-STATUS.md).

A pure QEMU-tagged fixture reuses synthetic policy definitions, checks all six
kinds, exact-byte refusal and private codec/diagnostic boundaries in the existing
standard smoke. It adds no filesystem operation or guest boot. Compilation is
not execution; ARM evidence is separate from physical EX4/media qualification.

Next is a separately scoped retained read-only collector over a defined complete
role namespace, with no-follow/same-medium/permissions/identity/lifetime and
drift/cancellation/close-fault checks. Do not add record files to the existing
two-name policy directory: its census intentionally rejects unknown entries.
Writer/provisioning/reconciliation and state-root atomicity remain later gates.
The [proposed product collector contract](COLLECTOR-DESIGN.md) records exact
lock/namespace/lifetime and refusal requirements. A separate experimental
[Linux collector](../policyevidencefs/README.md) now supplies retained file reads
in host/QEMU fixtures; existing codec/matcher behavior and all no-action meanings
are unchanged. Preparation above adds only private bound data and entropy use.
